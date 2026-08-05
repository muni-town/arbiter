//! XRPC routing.
//!
//! Requests come through one axum catch-all `/xrpc/{nsid}`. The handler
//! enforces `lxm == nsid` (the `CallerDid` extractor can't see the path),
//! dispatches the built-in provisioning NSIDs (`createArbiter` /
//! `createAppPasswordArbiter`) internally, and routes everything else to the
//! `town.muni.arbiter.proxy` endpoint — which drives the arbiter's Rego policy
//! machine and proxies any `RemoteXrpcRequest` it emits to the policy-supplied
//! endpoint authenticated as the stewarded account.

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
use axum::extract::{Path, State};
use axum::http::{Method, StatusCode};
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
use crate::resolver::IdentityResolverExt;

/// Built-in NSID: provision a brand-new stewarded PDS account.
const NSID_CREATE_ARBITER: &str = "town.muni.arbiter.createArbiter";
/// Built-in NSID: import an existing account (via app password) as a steward.
const NSID_CREATE_APP_PASSWORD_ARBITER: &str = "town.muni.arbiter.createAppPasswordArbiter";
/// Built-in NSID: proxy an arbitrary XRPC request through an arbiter's policy.
const NSID_PROXY: &str = "town.muni.arbiter.proxy";
/// Built-in NSID: reset a stewarded arbiter's root policy (recovery admin only).
const NSID_RESET_POLICY: &str = "town.muni.arbiter.resetPolicy";

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
    body: Bytes,
) -> Result<Response, AppError> {
    // The extractor can't see the path; enforce the serviceAuth binding here.
    if lxm != nsid {
        return Err(AppError::Unauthorized(format!(
            "serviceAuth lxm `{lxm}` does not match request nsid `{nsid}`"
        )));
    }

    // Built-in NSIDs are dispatched explicitly; anything else is rejected.
    match nsid.as_str() {
        NSID_CREATE_ARBITER => create_arbiter(&state, &caller).await,
        NSID_CREATE_APP_PASSWORD_ARBITER => {
            create_app_password_arbiter(&state, &caller, &body).await
        }
        NSID_PROXY => proxy_request(&state, &caller, &body).await,
        NSID_RESET_POLICY => reset_policy(&state, &caller, &body).await,
        other => Err(AppError::BadRequest(format!("unknown nsid `{other}`"))),
    }
}

/// A proxied XRPC request: the outer `town.muni.arbiter.proxy` procedure's
/// body names the arbiter to act on behalf of, the destination `did#service`,
/// and the inner XRPC request to evaluate.
#[derive(serde::Deserialize)]
struct ProxyBody {
    #[serde(rename = "arbiterDid")]
    arbiter_did: String,
    /// Destination `did#service` for the proxied request.
    target: String,
    /// HTTP method for the inner request.
    method: String,
    /// Inner XRPC request NSID.
    nsid: String,
    /// Optional query parameters for the inner request.
    #[serde(default)]
    parameters: Option<Value>,
    /// Optional JSON body for the inner request.
    #[serde(default)]
    body: Option<Value>,
}

/// Handle a `town.muni.arbiter.proxy` request: drive the named arbiter's Rego
/// policy over the inner request, executing any proxied XRPC call it emits.
async fn proxy_request(state: &AppState, caller: &str, body: &Bytes) -> Result<Response, AppError> {
    let proxy: ProxyBody = serde_json::from_slice(body)
        .map_err(|e| AppError::BadRequest(format!("invalid proxy body: {e}")))?;
    let arbiter_did = proxy.arbiter_did;
    let pds_endpoint = state.resolver.resolve_pds_endpoint(&arbiter_did).await?;

    let method: Method = proxy
        .method
        .parse()
        .map_err(|_| AppError::BadRequest(format!("invalid method `{}`", proxy.method)))?;
    let req = XrpcRequest {
        method,
        nsid: proxy.nsid,
        parameters: proxy.parameters,
        input: proxy.body.map(InputDataOrBytes::Data),
        encoding: Some("application/json".to_string()),
    };

    let ctx = RequestCtx {
        arbiter_did: arbiter_did.clone(),
        pds_endpoint: pds_endpoint.clone(),
        caller_did: caller.to_string(),
        xrpc_endpoint: proxy.target,
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
                let resp = proxy::execute_remote(
                    &arbiter_did,
                    &pds_endpoint,
                    &creds.password,
                    &endpoint,
                    &request,
                )
                .await;
                step = machine.resume(resp);
            }
        }
    };

    Ok(xrpc_result_to_response(result))
}

/// The `town.muni.arbiter.resetPolicy` request body.
#[derive(serde::Deserialize)]
struct ResetPolicyBody {
    #[serde(rename = "arbiterDid")]
    arbiter_did: String,
    /// Replacement Rego source for the root policy.
    policy: String,
}

/// Handle `town.muni.arbiter.resetPolicy`: authorize the caller as the
/// designated recovery admin, write the replacement root policy record to the
/// steward's PDS, and re-onboard the arbiter so the new policy takes effect.
async fn reset_policy(state: &AppState, caller: &str, body: &Bytes) -> Result<Response, AppError> {
    let body: ResetPolicyBody = serde_json::from_slice(body)
        .map_err(|e| AppError::BadRequest(format!("invalid resetPolicy body: {e}")))?;

    // Only the designated recovery admin may reset the policy.
    let admin = policy::recovery_admin(state, &body.arbiter_did)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::Forbidden("no recovery admin is set".to_string()))?;
    if caller != admin {
        return Err(AppError::Forbidden(format!(
            "caller `{caller}` is not the designated recovery admin `{admin}`"
        )));
    }

    // Validate the replacement policy before writing it.
    policy::compile_root(&body.policy).map_err(|e| {
        AppError::BadRequest(format!("replacement policy failed to compile: {e:#}"))
    })?;

    // Resolve the steward's PDS + credentials, then overwrite the root policy
    // record (upsert via putRecord).
    let pds_endpoint = state.resolver.resolve_pds_endpoint(&body.arbiter_did).await?;
    let creds = state
        .store
        .get(&body.arbiter_did)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| {
            AppError::Other(anyhow::anyhow!(
                "no stored credentials for arbiter {}",
                body.arbiter_did
            ))
        })?;
    let writer = login_session(&body.arbiter_did, &creds.password, &pds_endpoint).await?;
    put_root_policy(&writer, &body.arbiter_did, &body.policy).await?;

    // Re-onboard so the new policy is active.
    policy::load_and_onboard(state, &body.arbiter_did)
        .await
        .map_err(AppError::from)?;

    Ok(ok_response())
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
    // a half-created account. Only the password is stored; the PDS endpoint is
    // always resolved from the account's DID doc.
    state
        .store
        .store(new_did, PdsCredentials { password })
        .await
        .map_err(AppError::from)?;

    Ok(ok_response())
}

/// Import an existing account (`town.muni.arbiter.createAppPasswordArbiter`).
///
/// Input carries `arbiterDid` + `appPassword`. The PDS endpoint is always
/// resolved from the account's DID doc (`#atproto_pds`); no URL override is
/// permitted. Stores the password, writes the `service/self` +
/// `recovery/self` records from the account's session, then brings the arbiter
/// online.
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
    let pds_endpoint = state.resolver.resolve_pds_endpoint(&arbiter_did).await?;

    let writer = login_session(&arbiter_did, &app_password, &pds_endpoint).await?;
    write_service_and_recovery(&writer, &arbiter_did, caller).await?;

    policy::load_and_onboard(state, &arbiter_did)
        .await
        .map_err(AppError::from)?;

    // Persist credentials last, only once the account is fully provisioned and
    // the arbiter is online. If any earlier step failed we return an error
    // without storing credentials. Only the password is stored; the PDS
    // endpoint is always resolved from the account's DID doc.
    state
        .store
        .store(
            arbiter_did,
            PdsCredentials {
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

/// Overwrite the `town.muni.arbiter.policy.root/self` record with `policy`
/// (the Rego source), authenticated as the steward.
async fn put_root_policy(
    agent: &SessionAgent,
    repo: &str,
    policy: &str,
) -> Result<(), AppError> {
    let record = serde_json::json!({
        "$type": policy::ROOT_COLLECTION,
        "policy": policy,
    })
    .try_into_unknown()
    .map_err(|e| AppError::Other(anyhow::anyhow!("build root policy record: {e}")))?;
    let input = atrium_api::com::atproto::repo::put_record::InputData {
        collection: policy::ROOT_COLLECTION
            .parse::<Nsid>()
            .map_err(|e| AppError::Other(anyhow::anyhow!("invalid nsid: {e}")))?,
        record,
        repo: repo
            .parse::<AtIdentifier>()
            .map_err(|e| AppError::Other(anyhow::anyhow!("invalid repo `{repo}`: {e}")))?,
        rkey: policy::ROOT_RKEY
            .parse::<RecordKey>()
            .map_err(|e| AppError::Other(anyhow::anyhow!("invalid rkey: {e}")))?,
        swap_commit: None,
        swap_record: None,
        validate: None,
    }
    .into();
    agent
        .api
        .com
        .atproto
        .repo
        .put_record(input)
        .await
        .map_err(|e| AppError::Other(anyhow::anyhow!("putRecord root policy: {e}")))?;
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

/// A random valid handle using the configured suffix (`<base32><suffix>`).
///
/// The local label is a cryptographically random value (CSPRNG) base32-encoded
/// (RFC 4648, no padding). Base32 uses only `[A-Z2-7]`, a strict subset of the
/// characters permitted in a handle label, and is more compact than hex for
/// the same entropy (13 chars vs 16 for 8 bytes). The trailing suffix supplies
/// the TLD, which must start with a letter.
fn random_handle() -> Result<Handle, &'static str> {
    use data_encoding::BASE32_NOPAD;
    let mut bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    let encoded = BASE32_NOPAD.encode(&bytes);
    Handle::new(format!("{encoded}{}", CONFIG.handle_suffix))
}
