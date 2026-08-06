//! XRPC routing.
//!
//! Requests come through one axum catch-all `/xrpc/{nsid}`. The handler
//! enforces `lxm == nsid` (the `CallerDid` extractor can't see the path),
//! dispatches the built-in provisioning NSIDs (`createArbiter` /
//! `createAppPasswordArbiter`) internally, and routes everything else to the
//! `town.muni.arbiter.proxy` endpoint — which drives the arbiter's Rego policy
//! machine and proxies any `RemoteXrpcRequest` it emits to the policy-supplied
//! endpoint authenticated as the stewarded account.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use arbiter_core::arbiter::{ArbiterReqMachineStep, RequestCtx};
use arbiter_core::xrpc::{XrpcOutput, XrpcRequest, XrpcResult};
use atrium_api::agent::Agent;
use atrium_api::agent::atp_agent::CredentialSession;
use atrium_api::agent::atp_agent::store::MemorySessionStore;
use atrium_api::com::atproto::repo::put_record;
use atrium_api::com::atproto::server::create_account;
use atrium_api::types::TryIntoUnknown;
use atrium_api::types::string::{AtIdentifier, Handle, Nsid, RecordKey};
use atrium_xrpc::InputDataOrBytes;
use atrium_xrpc_client::reqwest::{ReqwestClient, ReqwestClientBuilder};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::extract::DefaultBodyLimit;
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

/// Cap on inbound request body size. The policy machine copies request bodies
/// into memory (and may proxy them), so a client must not be able to force
/// unbounded buffering.
const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

/// Cap on the total response body size returned to the client. A proxied
/// upstream response is buffered before being relayed, so we bound it here to
/// avoid relaying an arbitrarily large payload.
const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

pub fn router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/xrpc/{nsid}", axum::routing::any(xrpc_handler))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        // Arbitrary web clients are a goal, so we allow any origin. This is safe
        // for a Bearer-token API: the caller's token travels in the Authorization
        // header set by the client's own JS, which a cross-origin site cannot read
        // or set, so permissive CORS does not let a malicious site act on the
        // caller's behalf (no cookie-based ambient credentials). A hostile site
        // can only trigger requests *without* a token, which are rejected as
        // unauthorized.
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

/// Maximum number of remote XRPC calls a single policy evaluation may issue
/// while servicing one request. Bounds the outbound amplification a hostile or
/// compromised policy can cause per request.
const MAX_REMOTE_XRPC_CALLS: usize = 12;

/// Semaphore bounding concurrently-executing `proxy` requests (see
/// [`ServerConfig::max_concurrent_proxies`]). Initialized lazily on first
/// proxy request.
static PROXY_SEMAPHORE: LazyLock<Option<Arc<tokio::sync::Semaphore>>> = LazyLock::new(|| {
    if CONFIG.max_concurrent_proxies > 0 {
        Some(Arc::new(tokio::sync::Semaphore::new(CONFIG.max_concurrent_proxies)))
    } else {
        None
    }
});

/// Handle a `town.muni.arbiter.proxy` request: drive the named arbiter's Rego
/// policy over the inner request, executing any proxied XRPC call it emits.
///
/// Each request can buffer up to (remote-call limit × response cap) bytes, so
/// concurrency is bounded by a semaphore (configurable via
/// `MAX_CONCURRENT_PROXIES`) to cap the worst-case memory footprint.
async fn proxy_request(state: &AppState, caller: &str, body: &Bytes) -> Result<Response, AppError> {
    // Acquire a concurrency slot. This bounds total in-flight proxy memory
    // independent of policy; requests beyond the cap wait.
    let _permit = match PROXY_SEMAPHORE.as_ref() {
        Some(semaphore) => Some(
            Arc::clone(semaphore)
                .acquire_owned()
                .await
                .map_err(|_| AppError::Other(anyhow::anyhow!("proxy semaphore closed")))?,
        ),
        None => None,
    };

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
    let mut remote_calls = 0usize;
    let result: XrpcResult = loop {
        match step {
            ArbiterReqMachineStep::Completed(result) => break result,
            ArbiterReqMachineStep::RemoteXrpcRequest { endpoint, request } => {
                remote_calls += 1;
                if remote_calls > MAX_REMOTE_XRPC_CALLS {
                    tracing::warn!(
                        arbiter_did,
                        remote_calls,
                        "policy exceeded max remote xrpc calls; aborting request"
                    );
                    break Err(proxy::policy_aborted(
                        "policy exceeded max remote xrpc calls",
                    ));
                }
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

    // Optimistic concurrency: fetch the current repo head commit CID and
    // require the write to swap against it. If the repo changed between this
    // read and the write (e.g. another reset or any other concurrent repo
    // write won the race), putRecord fails and this reset does not clobber it.
    // The repo head (not the root-policy record CID) is used so the very first
    // policy install — when no root policy record exists yet — is also guarded.
    let swap_commit = policy::repo_head_cid(state, &body.arbiter_did)
        .await
        .map_err(AppError::from)?;
    put_root_policy(&writer, &body.arbiter_did, &body.policy, swap_commit.as_deref()).await?;

    // Re-onboard so the new policy is active.
    policy::load_and_onboard(state, &body.arbiter_did)
        .await
        .map_err(AppError::from)?;

    Ok(ok_response())
}

/// Map a final `XrpcResult` to an axum `Response`.
///
/// The response is buffered (the policy machine and the atrium proxy both
/// buffer bodies), so refuse to relay anything over
/// [`MAX_RESPONSE_BODY_BYTES`] rather than returning an unbounded payload.
fn xrpc_result_to_response(result: XrpcResult) -> Response {
    match result {
        Ok(XrpcOutput::Data(json)) => {
            let body = serde_json::to_vec(&json).unwrap_or_default();
            if body.len() > MAX_RESPONSE_BODY_BYTES {
                return oversized_response();
            }
            (StatusCode::OK, Json(json)).into_response()
        }
        Ok(XrpcOutput::Bytes(bytes)) => {
            if bytes.len() > MAX_RESPONSE_BODY_BYTES {
                return oversized_response();
            }
            (StatusCode::OK, bytes).into_response()
        }
        Err(xrpc_err) => {
            let body = json!({
                "$type": "town.muni.arbiter.server.v1.xrpcError",
                "error": xrpc_err.error,
            });
            (xrpc_err.status, Json(body)).into_response()
        }
    }
}

/// A 502 response for an upstream body that exceeded the size cap.
fn oversized_response() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({
            "$type": "town.muni.arbiter.server.v1.error",
            "error": "upstream response exceeded size limit",
        })),
    )
        .into_response()
}

// ----- built-in provisioning ----------------------------------------------

/// Per-caller rate limiter for `createArbiter`, keyed by caller DID. Bulk
/// creation is not allowed unless the admin raises the limit explicitly via
/// config (`CREATE_ARBITER_RATE_LIMIT`). The counter is approximate (get/insert)
/// which is acceptable for a rate limit.
static CREATE_ARBITER_COUNTS: LazyLock<moka::future::Cache<String, u64>> = LazyLock::new(|| {
    moka::future::Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(
            CONFIG.create_arbiter_rate_window_secs,
        ))
        .build()
});

/// Enforce the per-caller `createArbiter` rate limit. Returns an error if the
/// caller has exceeded `CREATE_ARBITER_RATE_LIMIT` calls in the window (or if
/// the limit is 0, meaning creation is disabled).
async fn check_create_arbiter_rate(caller: &str) -> Result<(), AppError> {
    let limit = CONFIG.create_arbiter_rate_limit;
    if limit == 0 {
        return Err(AppError::Forbidden(
            "createArbiter is disabled (CREATE_ARBITER_RATE_LIMIT=0)".into(),
        ));
    }
    let count = CREATE_ARBITER_COUNTS
        .get(caller)
        .await
        .unwrap_or(0);
    if count >= limit {
        return Err(AppError::Forbidden(format!(
            "createArbiter rate limit exceeded ({limit} per {}s)",
            CONFIG.create_arbiter_rate_window_secs
        )));
    }
    CREATE_ARBITER_COUNTS.insert(caller.to_string(), count + 1).await;
    Ok(())
}

/// Provision a brand-new stewarded PDS account (`town.muni.arbiter.createArbiter`).
///
/// Creates the account against `CONFIG.default_pds` with a random password +
/// `CONFIG.invite_code`, stores the credentials, writes the
/// `town.muni.arbiter.service/self` + `town.muni.arbiter.recovery/self` records
/// from the new account's session, then returns. No initial policy is written:
/// the arbiter stays offline (fail-closed) until the recovery admin calls
/// `resetPolicy` to install the first policy — the same flow an imported
/// account uses.
///
/// Credentials are persisted **before** the record writes so a half-provisioned
/// account is never orphaned: if a write fails, startup onboarding will retry
/// it (and the arbiter remains offline until the policy lands).
async fn create_arbiter(state: &AppState, caller: &str) -> Result<Response, AppError> {
    check_create_arbiter_rate(caller).await?;

    let pds_url = CONFIG.default_pds.clone();
    let password = random_secret(24);
    let handle =
        random_handle().map_err(|e| AppError::Other(anyhow::anyhow!("invalid handle: {e}")))?;

    let provisioning = Agent::new(CredentialSession::new(
        time_bound_reqwest(&pds_url),
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

    // Persist credentials first: even if the record writes below fail, the
    // account is not orphaned — startup onboarding will find it (via
    // `provisioned = false`) and repair the missing bootstrap records.
    state
        .store
        .store(
            new_did.clone(),
            PdsCredentials {
                password: password.clone(),
                recovery_admin: caller.to_string(),
                provisioned: false,
            },
        )
        .await
        .map_err(AppError::from)?;

    let writer = login_session(&new_did, &password, &pds_url).await?;
    write_service_and_recovery(&writer, &new_did, caller).await?;

    // Bootstrap records written; the account is now fully provisioned.
    state
        .store
        .mark_provisioned(&new_did)
        .await
        .map_err(AppError::from)?;

    Ok(ok_response())
}

/// Import an existing account (`town.muni.arbiter.createAppPasswordArbiter`).
///
/// Input carries `arbiterDid` + `appPassword`. The PDS endpoint is always
/// resolved from the account's DID doc (`#atproto_pds`); no URL override is
/// permitted.
///
/// The caller authenticates as the account (via the app password), which is the
/// authorization to take stewardship: the account's `service/self` record is
/// (re)written to point at this server and `recovery/self` to the caller. Any
/// holder of a valid app password may assume stewardship without the previous
/// arbiter's permission. No policy is written; the arbiter stays offline until
/// `resetPolicy` installs the first policy.
///
/// Credentials are persisted before the record writes so a partial failure is
/// retried by startup onboarding rather than lost.
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

    // Authenticating as the account proves control (app password) and is what
    // authorizes stewardship takeover.
    let writer = login_session(&arbiter_did, &app_password, &pds_endpoint).await?;

    // Persist credentials first so startup onboarding can repair the bootstrap
    // records if a write below fails (`provisioned = false`).
    state
        .store
        .store(
            arbiter_did.clone(),
            PdsCredentials {
                password: app_password,
                recovery_admin: caller.to_string(),
                provisioned: false,
            },
        )
        .await
        .map_err(AppError::from)?;

    write_service_and_recovery(&writer, &arbiter_did, caller).await?;

    // Bootstrap records written; the account is now fully provisioned.
    state
        .store
        .mark_provisioned(&arbiter_did)
        .await
        .map_err(AppError::from)?;

    Ok(ok_response())
}

/// Log in as `did`/`password` against `pds_url` and wrap the session in an
/// `Agent` for typed record writes.
async fn login_session(did: &str, password: &str, pds_url: &str) -> Result<SessionAgent, AppError> {
    let session = CredentialSession::new(
        time_bound_reqwest(pds_url),
        MemorySessionStore::default(),
    );
    session
        .login(did, password)
        .await
        .map_err(|e| AppError::Other(anyhow::anyhow!("login {did}: {e}")))?;
    Ok(Agent::new(session))
}

/// Total timeout for provisioning / policy-write HTTP requests (createAccount,
/// createSession, putRecord). A hung PDS must not pin these tasks indefinitely.
const PROVISIONING_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Build a reqwest client with a total timeout for the provisioning / write
/// paths (mirrors the proxy and PDS-read clients).
fn time_bound_reqwest(base_uri: &str) -> ReqwestClient {
    ReqwestClientBuilder::new(base_uri)
        .client(
            reqwest::Client::builder()
                .timeout(PROVISIONING_HTTP_TIMEOUT)
                .build()
                .expect("building reqwest client"),
        )
        .build()
}

/// Number of attempts for each bootstrap record write during provisioning.
/// Records are written idempotently (via `putRecord`), so a retry cannot
/// duplicate or corrupt state.
const BOOTSTRAP_WRITE_ATTEMPTS: u32 = 5;

/// Write the `town.muni.arbiter.service/self` (did = server) and
/// `town.muni.arbiter.recovery/self` (did = caller) records into `repo`'s
/// repository, authenticated via `agent`.
///
/// Each record write is retried with a short backoff so a transient PDS blip
/// during provisioning does not leave the account half-configured (credentials
/// are already persisted by the caller, so startup onboarding would retry, but
/// finishing here is cleaner).
async fn write_service_and_recovery(
    agent: &SessionAgent,
    repo: &str,
    caller: &str,
) -> Result<(), AppError> {
    write_record_retry(
        agent,
        repo,
        "town.muni.arbiter.service",
        "self",
        &CONFIG.server_did,
    )
    .await?;
    write_record_retry(agent, repo, "town.muni.arbiter.recovery", "self", caller).await?;
    Ok(())
}

/// Repair a partially-provisioned account: rewrite the bootstrap
/// `service/self` + `recovery/self` records (using the persisted recovery
/// admin) and mark it provisioned.
///
/// Called by onboarding when it finds an account marked `provisioned = false`
/// whose bootstrap records are missing, so a failed `createArbiter` /
/// `createAppPasswordArbiter` write is retried at startup / on reconnect rather
/// than leaving an unrecoverable half-provisioned account. Returns `Ok(())` on
/// success (and marks the account provisioned); errors propagate so the caller
/// can retry later.
pub async fn repair_provisioning(
    state: &AppState,
    did: &str,
    creds: &PdsCredentials,
    pds_endpoint: &str,
) -> Result<(), AppError> {
    let writer = login_session(did, &creds.password, pds_endpoint).await?;
    write_service_and_recovery(&writer, did, &creds.recovery_admin).await?;
    state
        .store
        .mark_provisioned(did)
        .await
        .map_err(AppError::from)?;
    Ok(())
}

/// Write `collection`/`rkey` with a `did` field, retrying transient failures.
async fn write_record_retry(
    agent: &SessionAgent,
    repo: &str,
    collection: &str,
    rkey: &str,
    did: &str,
) -> Result<(), AppError> {
    let mut attempt = 0u32;
    loop {
        match write_record(agent, repo, collection, rkey, did).await {
            Ok(()) => return Ok(()),
            Err(e) if attempt < BOOTSTRAP_WRITE_ATTEMPTS => {
                attempt += 1;
                tracing::warn!(
                    repo, collection, rkey, attempt,
                    error = %e,
                    "bootstrap record write failed; retrying"
                );
                tokio::time::sleep(Duration::from_millis(250 * u64::from(attempt))).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Write (upsert) a single record in `collection`/`rkey` with a `did` field,
/// via `com.atproto.repo.putRecord` (idempotent, so retries are safe).
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
    let input = put_record::InputData {
        collection: collection
            .parse::<Nsid>()
            .map_err(|e| AppError::Other(anyhow::anyhow!("invalid nsid `{collection}`: {e}")))?,
        record,
        repo: repo
            .parse::<AtIdentifier>()
            .map_err(|e| AppError::Other(anyhow::anyhow!("invalid repo `{repo}`: {e}")))?,
        rkey: rkey
            .parse::<RecordKey>()
            .map_err(|e| AppError::Other(anyhow::anyhow!("invalid rkey `{rkey}`: {e}")))?,
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
        .map_err(|e| AppError::Other(anyhow::anyhow!("putRecord {collection}/{rkey}: {e}")))?;
    Ok(())
}

/// Overwrite the `town.muni.arbiter.policy.root/self` record with `policy`
/// (the Rego source), authenticated as the steward.
///
/// `swap_commit`, if present, is the repo head commit CID the repo must
/// currently be at for the write to succeed (compare-and-swap on the whole
/// repo). Using the repo head rather than the record CID means the very first
/// policy install (no root policy record yet) is also guarded. Pass `None` to
/// overwrite unconditionally.
async fn put_root_policy(
    agent: &SessionAgent,
    repo: &str,
    policy: &str,
    swap_commit: Option<&str>,
) -> Result<(), AppError> {
    let record = serde_json::json!({
        "$type": policy::ROOT_COLLECTION,
        "policy": policy,
    })
    .try_into_unknown()
    .map_err(|e| AppError::Other(anyhow::anyhow!("build root policy record: {e}")))?;
    let swap_commit = match swap_commit {
        Some(cid) => Some(
            cid.parse::<atrium_api::types::string::Cid>()
                .map_err(|e| AppError::Other(anyhow::anyhow!("invalid swap CID `{cid}`: {e}")))?,
        ),
        None => None,
    };
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
        swap_commit,
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
/// password carries no ambiguous characters. `len` is the number of *base64
/// characters* returned, not bytes: each character carries 6 bits of entropy,
/// so `len` characters encode `len*6` bits. For the default `24` chars that is
/// 144 bits of entropy.
fn random_secret(len: usize) -> String {
    use base64::Engine;
    // Round the requested bit count up to a whole number of bytes, then let the
    // encoding trim to the requested length.
    let byte_len = (len * 6).div_ceil(8);
    let mut bytes = vec![0u8; byte_len];
    rand::rng().fill_bytes(&mut bytes);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
    encoded.chars().take(len).collect()
}

/// A random valid handle using the configured suffix (`<base32><suffix>`).
///
/// The local label is a cryptographically random value (CSPRNG) base32-encoded
/// (RFC 4648, no padding, lowercased). Base32 uses only `[a-z2-7]`, a strict
/// subset of the characters permitted in a handle label, and lowercase matches
/// the ecosystem's handle normalization (some PDSes lowercase handles on
/// registration), so the created account's handle equals the generated value.
/// 8 bytes of entropy → 13 base32 chars. The trailing suffix supplies the TLD,
/// which must start with a letter.
fn random_handle() -> Result<Handle, &'static str> {
    use data_encoding::BASE32_NOPAD;
    let mut bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    // Encode (uppercase `[A-Z2-7]`), then lowercase to match the ecosystem's
    // handle normalization. `data-encoding` has no lowercase base32 output
    // encoding constant.
    let encoded = BASE32_NOPAD.encode(&bytes).to_ascii_lowercase();
    Handle::new(format!("{encoded}{}", CONFIG.handle_suffix))
}
