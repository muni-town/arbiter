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

use crate::CONFIG;
use arbiter_core::xrpc::{XrpcError, XrpcRequest, XrpcResult};
use atrium_api::agent::CloneWithProxy;
use atrium_api::agent::atp_agent::CredentialSession;
use atrium_api::agent::atp_agent::store::MemorySessionStore;
use atrium_api::types::string::Did;
use atrium_xrpc::XrpcClient;
use atrium_xrpc::error::{ErrorResponseBody, XrpcErrorKind};
use atrium_xrpc_client::reqwest::{ReqwestClient, ReqwestClientBuilder};
use moka::future::Cache;
use serde_json::Value;
use tracing::warn;

/// An authenticated session against a stewarded account's PDS.
type Session = CredentialSession<MemorySessionStore, ReqwestClient>;

/// Per-stewarded-account authenticated sessions, keyed by the steward DID.
/// Reused across requests so we don't re-`createSession` on every proxy call.
///
/// A cached session is kept until it stops working: the proxy transparently
/// refreshes the access token while the refresh token is valid, and re-logins
/// from the stored steward password when both are revoked (`ExpiredToken`). A
/// session is only dropped when that re-login happens, so a valid session is
/// reused rather than discarded speculatively.
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

/// Build an XRPC error envelope for a server-side policy abort (e.g. a policy
/// exceeding the per-request remote-call limit).
pub fn policy_aborted(msg: &str) -> XrpcError {
    XrpcError {
        status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        error: Some(XrpcErrorKind::Undefined(ErrorResponseBody {
            error: Some("PolicyAborted".into()),
            message: Some(msg.to_string()),
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

/// Total timeout for a single proxied upstream HTTP request (including body
/// read). reqwest's defaults impose no total timeout, so a PDS that accepts a
/// connection but never responds would otherwise pin the request (and the
/// policy machine task) indefinitely.
const PROXY_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

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
    // Build the client with a total timeout so a hung PDS cannot stall the
    // request forever (mirrors `policy::pds_read_client`).
    let client = ReqwestClientBuilder::new(pds_endpoint)
        .client(
            reqwest::Client::builder()
                .timeout(PROXY_HTTP_TIMEOUT)
                .build()
                .map_err(|e| {
                    upstream_error(
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        format!("building proxy HTTP client: {e}"),
                    )
                })?,
        )
        .build();
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

/// Reject a proxied upstream response whose body exceeds
/// [`MAX_PROXIED_RESPONSE_BYTES`], replacing it with a 502. Operates on the raw
/// `send_xrpc` result (before the caller maps the error into an `XrpcError`),
/// so an oversized upstream body never reaches the policy machine's buffers.
fn enforce_response_size(
    result: atrium_xrpc::Result<atrium_xrpc::OutputDataOrBytes<Value>, Value>,
) -> atrium_xrpc::Result<atrium_xrpc::OutputDataOrBytes<Value>, Value> {
    let output = match result {
        Ok(output) => output,
        Err(e) => return Err(e),
    };
    let len = match &output {
        atrium_xrpc::OutputDataOrBytes::Data(json) => {
            serde_json::to_vec(json).map_or(0, |v| v.len())
        }
        atrium_xrpc::OutputDataOrBytes::Bytes(bytes) => bytes.len(),
    };
    if len > MAX_PROXIED_RESPONSE_BYTES {
        return Err(atrium_xrpc::error::Error::XrpcResponse(upstream_error(
            axum::http::StatusCode::BAD_GATEWAY,
            "upstream response exceeded size limit",
        )));
    }
    Ok(output)
}

/// Max size of a proxied upstream response body. `send_xrpc` fully buffers
/// the response, and the policy machine copies it into its own `buffers`, so
/// an unbounded upstream body would let a hostile policy force unbounded
/// memory use per request even though the final relay would refuse to send it
/// out. We reject oversized responses here, before they reach the machine.
const MAX_PROXIED_RESPONSE_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

/// Reject a policy-issued remote XRPC call whose target DID is the arbiter
/// server itself (`CONFIG.server_did`): the arbiter must never proxy to
/// itself — a pipeline issuing `installPolicy` (or any other arbiter NSID)
/// back at the arbiter would loop pipeline → install → pipeline. Mirrors the
/// machine's unknown-host-fn path: the issuing policy receives the error
/// envelope and decides how to handle it.
fn self_target_error(endpoint: &str) -> XrpcError {
    XrpcError {
        status: axum::http::StatusCode::BAD_REQUEST,
        error: Some(XrpcErrorKind::Undefined(ErrorResponseBody {
            error: Some("SelfProxyForbidden".into()),
            message: Some(format!(
                "refusing to proxy to the arbiter server itself (`{endpoint}`): \
                 the arbiter must never proxy to itself"
            )),
        })),
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
    // Recursion guard, before any dispatch (no session login is attempted):
    // a target DID equal to this server's own DID is always a self-proxy.
    if target_did_str == CONFIG.server_did {
        warn!(
            stewarded_did,
            endpoint, "policy tried to proxy to the arbiter server itself; refusing"
        );
        return Err(self_target_error(endpoint));
    }
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
    let result = enforce_response_size(result);

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
                return match enforce_response_size(retried) {
                    Ok(ok) => Ok(ok),
                    Err(atrium_xrpc::Error::XrpcResponse(xrpc_err)) => Err(xrpc_err),
                    Err(e) => {
                        warn!(endpoint, "proxy retry send_xrpc failed: {e:?}");
                        Err(upstream_error(
                            axum::http::StatusCode::BAD_GATEWAY,
                            format!("proxy retry failed: {e}"),
                        ))
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
