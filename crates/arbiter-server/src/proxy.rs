//! Execute a policy-issued remote XRPC request, authenticated as the stewarded
//! account.
//!
//! The arbiter's Rego policy issues remote calls via the `xrpc` host function;
//! the host (this module) executes them. Authentication is always as the
//! *stewarded* account (the DID the arbiter server holds credentials for): we
//! `com.atproto.server.createSession` against the PDS endpoint resolved from
//! the steward's DID doc with the steward DID + `creds.password`, then route to
//! the policy-supplied endpoint via the atproto proxy header
//! (`did#service`). Sessions are cached per steward DID with `moka` so we don't
//! re-login on every proxied request.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use arbiter_core::xrpc::{XrpcError, XrpcRequest, XrpcResult};
use atrium_api::agent::CloneWithProxy;
use atrium_api::agent::atp_agent::CredentialSession;
use atrium_api::agent::atp_agent::store::MemorySessionStore;
use atrium_api::types::string::Did;
use atrium_xrpc::XrpcClient;
use atrium_xrpc::error::{ErrorResponseBody, XrpcErrorKind};
use atrium_xrpc_client::reqwest::ReqwestClient;
use moka::future::Cache;
use serde_json::Value;
use tracing::warn;

/// An authenticated session against a stewarded account's PDS.
type Session = CredentialSession<MemorySessionStore, ReqwestClient>;

/// Per-stewarded-account authenticated sessions, keyed by the steward DID.
/// Reused across requests so we don't re-`createSession` on every proxy call.
static SESSIONS: LazyLock<Cache<String, Arc<Session>>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(10_000)
        .time_to_idle(Duration::from_secs(30 * 60))
        .build()
});

/// Build an XRPC error envelope for a non-XRPC failure (transport/serde/etc.).
fn upstream_error(status: axum::http::StatusCode, msg: impl Into<String>) -> XrpcError {
    XrpcError {
        status,
        error: Some(XrpcErrorKind::Undefined(ErrorResponseBody {
            error: Some("UpstreamError".into()),
            message: Some(msg.into()),
        })),
    }
}

/// Fetch (or create + login) the authenticated session for `stewarded_did`
/// against the PDS at `pds_endpoint` (resolved from the steward's DID doc).
async fn get_or_login(
    stewarded_did: &str,
    pds_endpoint: &str,
    password: &str,
) -> Result<Arc<Session>, XrpcError> {
    if let Some(session) = SESSIONS.get(stewarded_did).await {
        return Ok(session);
    }
    login_fresh(stewarded_did, pds_endpoint, password).await
}

/// Always create a fresh session via `createSession`, cache it, and return it.
///
/// Used both for first-time login and for the re-login fallback when a cached
/// session's access **and** refresh tokens have both been revoked. Overwrites
/// any stale cached session for the steward.
async fn login_fresh(
    stewarded_did: &str,
    pds_endpoint: &str,
    password: &str,
) -> Result<Arc<Session>, XrpcError> {
    let client = ReqwestClient::new(pds_endpoint);
    let session = Arc::new(CredentialSession::new(
        client,
        MemorySessionStore::default(),
    ));
    if let Err(e) = session.login(stewarded_did, password).await {
        warn!(stewarded_did, pds = %pds_endpoint, "proxy session login failed: {e:?}");
        return Err(upstream_error(
            axum::http::StatusCode::BAD_GATEWAY,
            format!("proxy session login failed: {e}"),
        ));
    }
    // Insert; another racer may have populated it concurrently — that's fine,
    // both sessions are authenticated against the same account.
    SESSIONS
        .insert(stewarded_did.to_string(), Arc::clone(&session))
        .await;
    Ok(session)
}

/// Whether an XRPC error envelope is a PDS `ExpiredToken` response.
///
/// Mirrors `atrium`'s `is_expired`: the upstream rejected our access token
/// (usually because the refresh token is also dead and `refreshSession` failed,
/// since a live refresh token is handled transparently by the client).
fn is_expired_token(err: &XrpcError) -> bool {
    match &err.error {
        Some(XrpcErrorKind::Undefined(body)) => body.error.as_deref() == Some("ExpiredToken"),
        _ => false,
    }
}

/// Send `request` to `endpoint` (`did#service`), authenticating to the
/// destination as the stewarded account.
///
/// `pds_endpoint` is the steward's PDS URL resolved from its DID doc; the
/// steward logs in there with `password`. The endpoint is split into a target
/// DID and service fragment; the target is reached via the atproto proxy header
/// set on a per-request clone of the authenticated session (so concurrent
/// requests with different targets don't race on the shared session's proxy
/// header).
pub async fn execute_remote(
    stewarded_did: &str,
    pds_endpoint: &str,
    password: &str,
    endpoint: &str,
    request: &XrpcRequest,
) -> XrpcResult {
    // Split `did#service`; default to `atproto_pds` when no fragment is given.
    let (target_did_str, service) = match endpoint.split_once('#') {
        Some((d, s)) => (d.to_string(), s.to_string()),
        None => (endpoint.to_string(), String::from("atproto_pds")),
    };
    let target_did = match Did::new(target_did_str) {
        Ok(d) => d,
        Err(e) => {
            return Err(upstream_error(
                axum::http::StatusCode::BAD_GATEWAY,
                format!("invalid endpoint DID `{endpoint}`: {e}"),
            ));
        }
    };

    let session = get_or_login(stewarded_did, pds_endpoint, password).await?;
    // Clone with a per-request proxy header targeting the policy-supplied
    // endpoint. The clone shares the authenticated session store but gets its
    // own inner client, so the proxy header isn't raced across requests.
    let proxied = session.clone_with_proxy(target_did.clone(), &service);

    let result = proxied
        .send_xrpc::<Value, Value, Value, Value>(request)
        .await;

    // Re-login fallback: if the upstream rejected the token (both access and
    // refresh are dead — atrium already retried via refreshSession once), drop
    // the cached session, log in fresh with the steward password, and retry
    // exactly once. If the fresh login itself fails, propagate the original.
    if let Err(atrium_xrpc::Error::XrpcResponse(xrpc_err)) = &result
        && is_expired_token(xrpc_err)
    {
        warn!(
            stewarded_did,
            "proxy session token fully revoked; re-logging in"
        );
        match login_fresh(stewarded_did, pds_endpoint, password).await {
            Ok(fresh) => {
                let retried = fresh
                    .clone_with_proxy(target_did, &service)
                    .send_xrpc::<Value, Value, Value, Value>(request)
                    .await;
                return match retried {
                    Ok(ok) => Ok(ok),
                    Err(atrium_xrpc::Error::XrpcResponse(xrpc_err)) => return Err(xrpc_err),
                    Err(e) => {
                        warn!(endpoint, "proxy retry send_xrpc failed: {e:?}");
                        return Err(upstream_error(
                            axum::http::StatusCode::BAD_GATEWAY,
                            format!("proxy retry failed: {e}"),
                        ));
                    }
                };
            }
            Err(_) => warn!(stewarded_did, "re-login failed after ExpiredToken"),
        }
    }

    match result {
        Ok(ok) => Ok(ok),
        Err(atrium_xrpc::Error::XrpcResponse(xrpc_err)) => {
            // The upstream returned an XRPC error envelope; surface it as-is.
            Err(xrpc_err)
        }
        Err(e) => {
            warn!(endpoint, "proxy send_xrpc failed: {e:?}");
            Err(upstream_error(
                axum::http::StatusCode::BAD_GATEWAY,
                format!("proxy request failed: {e}"),
            ))
        }
    }
}
