//! XRPC routing.
//!
//! All requests come through one axum catch-all `/xrpc/{nsid}`. The handler
//! enforces `lxm == nsid` (the `CallerDid` extractor can't see the path),
//! dispatches the built-in provisioning NSIDs (`createArbiter` /
//! `createAppPasswordArbiter`) internally, and otherwise drives the arbiter's
//! Rego policy machine — proxying any `RemoteXrpcRequest` it emits to the
//! policy-supplied endpoint authenticated as the stewarded account.

use std::collections::HashMap;
use std::sync::Arc;

use arbiter_core::arbiter::{ArbiterReqMachineStep, RequestCtx};
use arbiter_core::xrpc::{XrpcOutput, XrpcRequest, XrpcResult};
use atrium_api::agent::Agent;
use atrium_api::agent::atp_agent::CredentialSession;
use atrium_api::agent::atp_agent::store::MemorySessionStore;
use atrium_api::com::atproto::repo::create_record;
use atrium_api::com::atproto::server::create_account;
use atrium_api::types::TryIntoUnknown;
use atrium_api::types::string::{AtIdentifier, Handle, Nsid, RecordKey};
use atrium_xrpc::InputDataOrBytes;
use atrium_xrpc_client::reqwest::ReqwestClient;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use rand::RngCore;
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;

use crate::AppState;
use crate::CONFIG;
use crate::auth::CallerDid;
use crate::credstore::PdsCredentials;
use crate::error::AppError;
use crate::policy;
use crate::proxy;
use crate::resolver;

/// Built-in NSID: provision a brand-new stewarded PDS account.
const NSID_CREATE_ARBITER: &str = "town.muni.arbiter.createArbiter";
/// Built-in NSID: import an existing account (via app password) as a steward.
const NSID_CREATE_APP_PASSWORD_ARBITER: &str = "town.muni.arbiter.createAppPasswordArbiter";

/// A typed agent over an authenticated `CredentialSession` against a PDS.
type SessionAgent = Agent<CredentialSession<MemorySessionStore, ReqwestClient>>;

pub fn router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/xrpc/{nsid}", axum::routing::any(xrpc_handler))
        .with_state(state)
        .layer(CorsLayer::permissive())
}

async fn xrpc_handler(
    State(state): State<Arc<AppState>>,
    CallerDid { did: caller, lxm }: CallerDid,
    Path(nsid): Path<String>,
    method: Method,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> Result<Response, AppError> {
    // The extractor can't see the path; enforce the serviceAuth binding here.
    if lxm != nsid {
        return Err(AppError::Unauthorized(format!(
            "serviceAuth lxm `{lxm}` does not match request nsid `{nsid}`"
        )));
    }

    // Built-in provisioning NSIDs never use the proxy header.
    match nsid.as_str() {
        NSID_CREATE_ARBITER => return create_arbiter(&state, &caller).await,
        NSID_CREATE_APP_PASSWORD_ARBITER => {
            return create_app_password_arbiter(&state, &caller, &body).await;
        }
        _ => {}
    }

    // ---- steady-state proxy ------------------------------------------------
    let arbiter_did = header_str(&headers, "arbiter-did")?
        .ok_or_else(|| AppError::MissingHeader("arbiter-did"))?;
    let arbiter_proxy = header_str(&headers, "arbiter-proxy")?
        .ok_or_else(|| AppError::MissingHeader("arbiter-proxy"))?;

    let pds_endpoint = resolver::resolve_pds_endpoint(&*state.resolver, &arbiter_did).await?;

    // Build the XRPC request the arbiter policy will evaluate. Query params are
    // surfaced to the policy for GET; the body is parsed as JSON for non-GET.
    let parameters = if method == Method::GET {
        Some(serde_json::to_value(&query).unwrap_or(Value::Null))
    } else {
        None
    };
    let input = if method == Method::GET {
        None
    } else {
        let body_json = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
        Some(InputDataOrBytes::Data(body_json))
    };
    let req = XrpcRequest {
        method,
        nsid: nsid.clone(),
        parameters,
        input,
        encoding: Some("application/json".to_string()),
    };

    let ctx = RequestCtx {
        arbiter_did: arbiter_did.clone(),
        pds_endpoint: pds_endpoint.clone(),
        caller_did: caller,
        xrpc_endpoint: arbiter_proxy,
    };

    let drive = state.arbiters.begin_request(&arbiter_did, req, ctx).await?;
    let mut machine = drive.machine;

    let mut step = machine.start();
    let result: XrpcResult = loop {
        match step {
            ArbiterReqMachineStep::Completed(result) => break result,
            ArbiterReqMachineStep::RemoteXrpcRequest { endpoint, request } => {
                let creds = state
                    .store
                    .get(&arbiter_did)
                    .await
                    .map_err(AppError::from)?
                    .ok_or_else(|| {
                        AppError::Other(anyhow::anyhow!(
                            "no stored credentials for arbiter {arbiter_did}"
                        ))
                    })?;
                let resp = proxy::execute_remote(&arbiter_did, &endpoint, &request, &creds).await;
                step = machine.resume(resp);
            }
        }
    };

    Ok(xrpc_result_to_response(result))
}

/// Map a final `XrpcResult` to an axum `Response`.
fn xrpc_result_to_response(result: XrpcResult) -> Response {
    match result {
        Ok(XrpcOutput::Data(json)) => (StatusCode::OK, Json(json)).into_response(),
        Ok(XrpcOutput::Bytes(bytes)) => (StatusCode::OK, bytes).into_response(),
        Err(xrpc_err) => {
            let body = json!({
                "$type": "town.muni.arbiter.server.v1.xrpcError",
                "error": xrpc_err.error,
            });
            (xrpc_err.status, Json(body)).into_response()
        }
    }
}

/// Read a header value as a trimmed string, returning `None` when absent.
/// Rejects header values that aren't valid UTF-8.
fn header_str(headers: &HeaderMap, name: &'static str) -> Result<Option<String>, AppError> {
    match headers.get(name) {
        None => Ok(None),
        Some(value) => {
            let s = value
                .to_str()
                .map_err(|e| AppError::InvalidHeader(name, format!("{e}")))?;
            Ok(Some(s.trim().to_string()))
        }
    }
}

// ----- built-in provisioning ----------------------------------------------

/// Provision a brand-new stewarded PDS account (`town.muni.arbiter.createArbiter`).
///
/// Creates the account against `CONFIG.default_pds` with a random password +
/// `CONFIG.invite_code`, stores the credentials, writes the
/// `town.muni.arbiter.service/self` + `town.muni.arbiter.recovery/self` records
/// from the new account's session, then brings the arbiter online.
async fn create_arbiter(state: &AppState, caller: &str) -> Result<Response, AppError> {
    let pds_url = CONFIG.default_pds.clone();
    let password = random_secret(24);
    let handle =
        random_handle().map_err(|e| AppError::Other(anyhow::anyhow!("invalid handle: {e}")))?;

    let provisioning = Agent::new(CredentialSession::new(
        ReqwestClient::new(&pds_url),
        MemorySessionStore::default(),
    ));
    let account = provisioning
        .api
        .com
        .atproto
        .server
        .create_account(
            create_account::InputData {
                email: None,
                handle,
                invite_code: CONFIG.invite_code.clone(),
                password: Some(password.clone()),
                did: None,
                plc_op: None,
                recovery_key: None,
                verification_code: None,
                verification_phone: None,
            }
            .into(),
        )
        .await
        .map_err(|e| AppError::Other(anyhow::anyhow!("createAccount: {e}")))?;

    let new_did = account.data.did.as_str().to_string();

    // Write the service + recovery records from the new account's session.
    let writer = login_session(&new_did, &password, &pds_url).await?;
    write_service_and_recovery(&writer, &new_did, caller).await?;

    // Bring the arbiter online (loads policies + lifecycle checks).
    policy::load_and_onboard(state, &new_did)
        .await
        .map_err(AppError::from)?;

    // Persist credentials last, only once the account is fully provisioned and
    // the arbiter is online. If any earlier step failed we return an error
    // without storing credentials, so startup never retries an arbiter against
    // a half-created account.
    state
        .store
        .store(new_did, PdsCredentials { pds_url, password })
        .await
        .map_err(AppError::from)?;

    Ok(ok_response())
}

/// Import an existing account (`town.muni.arbiter.createAppPasswordArbiter`).
///
/// Input carries `arbiterDid` + `appPassword` (+ optional `pdsUrl`, else
/// resolved from the DID). Stores credentials, writes the
/// `service/self` + `recovery/self` records from the account's session, then
/// brings the arbiter online.
async fn create_app_password_arbiter(
    state: &AppState,
    caller: &str,
    body: &Bytes,
) -> Result<Response, AppError> {
    let body_json: Value = serde_json::from_slice(body)
        .map_err(|e| AppError::Other(anyhow::anyhow!("invalid json body: {e}")))?;
    let arbiter_did = body_json
        .get("arbiterDid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Other(anyhow::anyhow!("missing arbiterDid")))?
        .to_string();
    let app_password = body_json
        .get("appPassword")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Other(anyhow::anyhow!("missing appPassword")))?
        .to_string();
    let pds_url = match body_json.get("pdsUrl").and_then(|v| v.as_str()) {
        Some(u) => u.to_string(),
        None => resolver::resolve_pds_endpoint(&*state.resolver, &arbiter_did).await?,
    };

    let writer = login_session(&arbiter_did, &app_password, &pds_url).await?;
    write_service_and_recovery(&writer, &arbiter_did, caller).await?;

    policy::load_and_onboard(state, &arbiter_did)
        .await
        .map_err(AppError::from)?;

    // Persist credentials last, only once the account is fully provisioned and
    // the arbiter is online. If any earlier step failed we return an error
    // without storing credentials.
    state
        .store
        .store(
            arbiter_did,
            PdsCredentials {
                pds_url,
                password: app_password,
            },
        )
        .await
        .map_err(AppError::from)?;

    Ok(ok_response())
}

/// Log in as `did`/`password` against `pds_url` and wrap the session in an
/// `Agent` for typed record writes.
async fn login_session(did: &str, password: &str, pds_url: &str) -> Result<SessionAgent, AppError> {
    let session =
        CredentialSession::new(ReqwestClient::new(pds_url), MemorySessionStore::default());
    session
        .login(did, password)
        .await
        .map_err(|e| AppError::Other(anyhow::anyhow!("login {did}: {e}")))?;
    Ok(Agent::new(session))
}

/// Write the `town.muni.arbiter.service/self` (did = server) and
/// `town.muni.arbiter.recovery/self` (did = caller) records into `repo`'s
/// repository, authenticated via `agent`.
async fn write_service_and_recovery(
    agent: &SessionAgent,
    repo: &str,
    caller: &str,
) -> Result<(), AppError> {
    write_record(
        agent,
        repo,
        "town.muni.arbiter.service",
        "self",
        &CONFIG.server_did,
    )
    .await?;
    write_record(agent, repo, "town.muni.arbiter.recovery", "self", caller).await?;
    Ok(())
}

/// Create a single record in `collection`/`rkey` with a `did` field.
async fn write_record(
    agent: &SessionAgent,
    repo: &str,
    collection: &str,
    rkey: &str,
    did: &str,
) -> Result<(), AppError> {
    let record = serde_json::json!({ "$type": collection, "did": did })
        .try_into_unknown()
        .map_err(|e| AppError::Other(anyhow::anyhow!("build record: {e}")))?;
    let input = create_record::InputData {
        collection: collection
            .parse::<Nsid>()
            .map_err(|e| AppError::Other(anyhow::anyhow!("invalid nsid `{collection}`: {e}")))?,
        record,
        repo: repo
            .parse::<AtIdentifier>()
            .map_err(|e| AppError::Other(anyhow::anyhow!("invalid repo `{repo}`: {e}")))?,
        rkey: Some(
            rkey.parse::<RecordKey>()
                .map_err(|e| AppError::Other(anyhow::anyhow!("invalid rkey `{rkey}`: {e}")))?,
        ),
        swap_commit: None,
        validate: None,
    }
    .into();
    agent
        .api
        .com
        .atproto
        .repo
        .create_record(input)
        .await
        .map_err(|e| AppError::Other(anyhow::anyhow!("createRecord {collection}/{rkey}: {e}")))?;
    Ok(())
}

fn ok_response() -> Response {
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

// ----- small helpers ------------------------------------------------------

/// A random opaque secret used as a server-generated steward password.
///
/// Drawn from a CSPRNG (`rand`) and base64-encoded (URL-safe, unpadded) so the
/// password has full entropy per byte and no ambiguous characters. The password
/// is stored by the credential store and used to authenticate as the steward.
fn random_secret(len: usize) -> String {
    use base64::Engine;
    // `len` is the number of *base64 characters* we return, not bytes. Each byte
    // of output carries `len * 6/8` bits of entropy; round up to a whole number
    // of bytes and let the encoding trim to the requested length.
    let byte_len = (len * 6).div_ceil(8);
    let mut bytes = vec![0u8; byte_len];
    rand::rng().fill_bytes(&mut bytes);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
    encoded.chars().take(len).collect()
}

/// A random-ish valid handle using the configured suffix
/// (`arbiter-<pid>-<nanos><suffix>`).
fn random_handle() -> Result<Handle, &'static str> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    Handle::new(format!("arbiter-{pid:x}-{nanos:x}{}", CONFIG.handle_suffix))
}
