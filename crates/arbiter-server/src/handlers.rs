//! XRPC routing.
//!
//! Requests come through one axum catch-all `/xrpc/{nsid}`. The handler
//! enforces `lxm == nsid` (the `CallerDid` extractor can't see the path) and
//! dispatches the built-in NSIDs (`createArbiter`, `createAppPasswordArbiter`,
//! `town.muni.arbiter.proxy`, `installPolicy`, `resetConfig`) internally. Any
//! other NSID ending in `.arbiter.proxy` routes to the scoped proxy handler
//! (same body shape as the built-in proxy; the lxm check already binds the
//! serviceAuth to the scoped NSID) — which gates the request through the
//! account's trusted scopes + the scope's permission-set policy, then drives
//! the arbiter's community policy pipeline. Anything else is rejected.
//!
//! `installPolicy` is itself gated: the recovery admin designated in the
//! account's `town.muni.arbiter.recovery/self` record installs directly
//! (bypassing the pipeline — the bootstrap path, which works even while the
//! arbiter is offboarded); anyone else's install request is evaluated by the
//! account's installed pipeline, whose layers may approve it by handing it
//! back to the built-in handler. An install is purely appenditive: the
//! referenced policy layer joins the END of the pipeline (lowest priority)
//! and trusted scopes are unioned in — nothing installed is ever removed or
//! reordered. `resetConfig` is the recovery-admin-only hatch that replaces
//! the config record wholesale with no policy evaluation, and works while
//! the arbiter is offboarded.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use arbiter_core::arbiter::{ArbiterReqMachine, ArbiterReqMachineStep, RequestCtx};
use arbiter_core::xrpc::{XrpcError, XrpcOutput, XrpcRequest, XrpcResult};
use atrium_api::agent::Agent;
use atrium_api::agent::atp_agent::CredentialSession;
use atrium_api::agent::atp_agent::store::MemorySessionStore;
use atrium_api::com::atproto::repo::put_record;
use atrium_api::com::atproto::server::create_account;
use atrium_api::types::TryIntoUnknown;
use atrium_api::types::string::{AtIdentifier, Handle, Nsid, RecordKey};
use atrium_xrpc::InputDataOrBytes;
use atrium_xrpc::error::{ErrorResponseBody, XrpcErrorKind};
use atrium_xrpc_client::reqwest::{ReqwestClient, ReqwestClientBuilder};
use axum::Json;
use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::extract::{Path, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
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
use crate::record_store;
use crate::resolver::IdentityResolverExt;

/// Built-in NSID: provision a brand-new stewarded PDS account.
const NSID_CREATE_ARBITER: &str = "town.muni.arbiter.createArbiter";
/// Built-in NSID: import an existing account (via app password) as a steward.
const NSID_CREATE_APP_PASSWORD_ARBITER: &str = "town.muni.arbiter.createAppPasswordArbiter";
/// Built-in NSID: proxy an arbitrary XRPC request through an arbiter's policy.
const NSID_PROXY: &str = "town.muni.arbiter.proxy";
/// Built-in NSID: install a stewarded arbiter's policy pipeline + trusted
/// scopes (gated on the recovery admin or the installed policy pipeline).
const NSID_INSTALL_POLICY: &str = "town.muni.arbiter.installPolicy";
/// Built-in NSID: the recovery-admin-only hatch replacing the config record
/// wholesale (no policy evaluation; works while the arbiter is offboarded).
const NSID_RESET_CONFIG: &str = "town.muni.arbiter.resetConfig";
/// Suffix marking a scoped wildcard endpoint; any NSID ending in this (other
/// than the built-ins above) routes to the scoped proxy handler.
const SCOPED_PROXY_SUFFIX: &str = ".arbiter.proxy";

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
        //
        // `Authorization` must be explicitly listed (not just `*`): browsers do
        // not treat `*` as covering the non-simple Authorization header, so the
        // preflight would pass but the response would be unreadable cross-origin.
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers([AUTHORIZATION, CONTENT_TYPE]),
        )
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

    // Built-in NSIDs are dispatched explicitly; scoped wildcard endpoints
    // (`<scope>.arbiter.proxy`) route to the scoped proxy handler; anything
    // else is rejected.
    match nsid.as_str() {
        NSID_CREATE_ARBITER => create_arbiter(&state, &caller).await,
        NSID_CREATE_APP_PASSWORD_ARBITER => {
            create_app_password_arbiter(&state, &caller, &body).await
        }
        NSID_PROXY => proxy_request(&state, &caller, &body).await,
        NSID_INSTALL_POLICY => install_policy(&state, &caller, &body, 0).await,
        NSID_RESET_CONFIG => reset_config(&state, &caller, &body).await,
        scoped if scoped.ends_with(SCOPED_PROXY_SUFFIX) => {
            scoped_proxy_request(&state, &caller, scoped, &body).await
        }
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
    /// Optional body for the inner request.
    ///
    /// Either a JSON value (the common case) or the AT Protocol binary marker
    /// `{ "$bytes": <base64> }` (carrying an arbitrary byte payload, e.g. a
    /// blob upload). See [`decode_proxy_body`].
    #[serde(default)]
    body: Option<Value>,
    /// Optional content-type (`encoding`) for the inner request body.
    #[serde(default)]
    encoding: Option<String>,
}

/// The AT Protocol JSON encoding of a binary payload: `{ "$bytes": base64 }`.
/// Mirrors `@atproto/lex-json`'s `encodeLexBytes` / `parseLexBytes`.
const BYTES_BODY_KEY: &str = "$bytes";

/// Convert a proxy-envelope body value into the inner request's input.
///
/// A `{ "$bytes": <base64> }` object is decoded to raw bytes (so blob uploads
/// pass through the policy machine untouched); any other value is forwarded as
/// JSON data. Both padded and unpadded base64 are accepted.
fn decode_proxy_body(body: Value) -> Result<InputDataOrBytes<Value>, AppError> {
    use base64::Engine;
    let bytes = body.as_object().and_then(|obj| {
        if obj.len() == 1 {
            obj.get(BYTES_BODY_KEY)
        } else {
            None
        }
    });
    match bytes {
        Some(Value::String(b64)) => {
            // Accept both padded and unpadded base64 (the client's
            // `encodeLexBytes` emits unpadded, but a padded form is valid too),
            // mirroring the AT `$bytes` convention.
            let engine = base64::engine::general_purpose::GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                base64::engine::general_purpose::GeneralPurposeConfig::new()
                    .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
            );
            let raw = engine.decode(b64).map_err(|e| {
                AppError::BadRequest(format!("invalid base64 in `$bytes` body: {e}"))
            })?;
            Ok(InputDataOrBytes::Bytes(raw))
        }
        _ => Ok(InputDataOrBytes::Data(body)),
    }
}

/// Maximum number of remote XRPC calls a single policy evaluation may issue
/// while servicing one request. Bounds the outbound amplification a hostile or
/// compromised policy can cause per request.
const MAX_REMOTE_XRPC_CALLS: usize = 12;

/// Semaphore bounding concurrently-executing proxy requests (the built-in
/// `town.muni.arbiter.proxy` endpoint and the scoped `*.arbiter.proxy` family;
/// see [`ServerConfig::max_concurrent_proxies`]). Initialized lazily on first
/// proxy request.
static PROXY_SEMAPHORE: LazyLock<Option<Arc<tokio::sync::Semaphore>>> = LazyLock::new(|| {
    if CONFIG.max_concurrent_proxies > 0 {
        Some(Arc::new(tokio::sync::Semaphore::new(
            CONFIG.max_concurrent_proxies,
        )))
    } else {
        None
    }
});

/// Acquire a proxy concurrency slot. This bounds total in-flight proxy memory
/// independent of policy; requests beyond the cap wait.
async fn acquire_proxy_permit() -> Result<Option<tokio::sync::OwnedSemaphorePermit>, AppError> {
    match PROXY_SEMAPHORE.as_ref() {
        Some(semaphore) => {
            Ok(Some(Arc::clone(semaphore).acquire_owned().await.map_err(
                |_| AppError::Other(anyhow::anyhow!("proxy semaphore closed")),
            )?))
        }
        None => Ok(None),
    }
}

/// Parse the proxy envelope body and build the inner request + request
/// context. Shared by the built-in `town.muni.arbiter.proxy` endpoint and the
/// scoped `<scope>.arbiter.proxy` family (identical body shape). Returns
/// `(request, ctx, arbiter did, steward pds endpoint)`.
async fn proxy_parts(
    state: &AppState,
    caller: &str,
    body: &Bytes,
) -> Result<(XrpcRequest, RequestCtx, String, String), AppError> {
    let proxy: ProxyBody = serde_json::from_slice(body)
        .map_err(|e| AppError::BadRequest(format!("invalid proxy body: {e}")))?;
    let arbiter_did = proxy.arbiter_did;
    let pds_endpoint = state.resolver.resolve_pds_endpoint(&arbiter_did).await?;

    let method: Method = proxy
        .method
        .parse()
        .map_err(|_| AppError::BadRequest(format!("invalid method `{}`", proxy.method)))?;
    let input = proxy.body.map(decode_proxy_body).transpose()?;
    // JSON bodies default to `application/json` (the historical behavior); the
    // prior code always sent `application/json` even with no body. A raw-bytes
    // body carries the caller-supplied `encoding` (e.g. image/png).
    let encoding = match (&input, proxy.encoding.as_deref()) {
        (_, Some(enc)) => Some(enc.to_string()),
        (Some(InputDataOrBytes::Bytes(_)), None) => None,
        _ => Some("application/json".to_string()),
    };
    let req = XrpcRequest {
        method,
        nsid: proxy.nsid,
        parameters: proxy.parameters,
        input,
        encoding,
    };

    let ctx = RequestCtx {
        arbiter_did: arbiter_did.clone(),
        pds_endpoint: pds_endpoint.clone(),
        caller_did: caller.to_string(),
        xrpc_endpoint: proxy.target,
    };
    Ok((req, ctx, arbiter_did, pds_endpoint))
}

/// Handle a `town.muni.arbiter.proxy` request: drive the named arbiter's
/// community policy pipeline over the inner request, executing any proxied
/// XRPC call a layer emits.
///
/// Each request can buffer up to (remote-call limit × response cap) bytes, so
/// concurrency is bounded by a semaphore (configurable via
/// `MAX_CONCURRENT_PROXIES`) to cap the worst-case memory footprint. The
/// permit is taken here, at depth 0, only: a nested built-in handoff
/// dispatch (see [`serve_builtin`]) belongs to the same request and must not
/// take a second permit — a saturated semaphore full of parents each waiting
/// for a child permit would otherwise deadlock.
async fn proxy_request(state: &AppState, caller: &str, body: &Bytes) -> Result<Response, AppError> {
    let _permit = acquire_proxy_permit().await?;
    proxy_request_at(state, caller, body, 0).await
}

/// Like [`proxy_request`], but carries the built-in-handoff nesting `depth`
/// (see [`serve_builtin`]): a pipeline that always hands its request back to
/// the built-in handlers must still terminate. No permit is acquired here —
/// callers at depth > 0 are part of a request that already holds one.
async fn proxy_request_at(
    state: &AppState,
    caller: &str,
    body: &Bytes,
    handoff_depth: usize,
) -> Result<Response, AppError> {
    let (req, ctx, arbiter_did, pds_endpoint) = proxy_parts(state, caller, body).await?;
    // Registry dispatch on handoff needs the inner request's NSID + body; the
    // machine consumes the request, so they are lifted out first.
    let handoff_nsid = req.nsid.clone();
    let handoff_body = registry_body(req.input.as_ref())?;
    let drive = state.arbiters.begin_request(&arbiter_did, req, ctx).await?;
    drive_request(
        state,
        caller,
        &arbiter_did,
        &pds_endpoint,
        handoff_depth,
        drive.machine,
        BuiltinHandoff::Registry {
            nsid: &handoff_nsid,
            body: handoff_body,
        },
    )
    .await
}

/// Handle a scoped `<scope>.arbiter.proxy` request (the router's wildcard
/// branch). Same body shape as `town.muni.arbiter.proxy`; the serviceAuth
/// `lxm` is already bound to the scoped NSID.
///
/// Flow (before the community pipeline sees anything):
///
/// 1. **Trusted-scope gate** — strip the `.arbiter.proxy` suffix; the
///    account's loaded config record's `trustedScopes` must contain the
///    prefix. Untrusted scopes are rejected outright (403) before any policy
///    runs.
/// 2. **Scope policy** — resolve the scope's permission-set lexicon and
///    evaluate its embedded Rego as a pure [`arbiter_core::arbiter::ScopePolicy`]
///    predicate over the request core (method/nsid/parameters/body/encoding —
///    no caller/arbiter DIDs or endpoints): the entrypoint `data.arbiter.allow`
///    must be boolean `true` to continue. An unusable (unresolvable or
///    uncompilable) permission set, a denial, or an evaluation failure is a 403.
/// 3. **Community pipeline** — the regular machine flow (layers may suspend
///    on `xrpc` host calls; executed as the steward).
async fn scoped_proxy_request(
    state: &AppState,
    caller: &str,
    nsid: &str,
    body: &Bytes,
) -> Result<Response, AppError> {
    let _permit = acquire_proxy_permit().await?;
    let (req, ctx, arbiter_did, pds_endpoint) = proxy_parts(state, caller, body).await?;

    let prefix = nsid
        .strip_suffix(SCOPED_PROXY_SUFFIX)
        .expect("router only dispatches `.arbiter.proxy` suffixed NSIDs here");
    state
        .arbiters
        .check_trusted_scope(&arbiter_did, prefix)
        .await?;

    let scope = state
        .scopes
        .scope_policy(prefix)
        .await
        .map_err(|e| AppError::Forbidden(format!("scope `{prefix}` is unavailable: {e:#}")))?;
    match scope.evaluate(&req) {
        Ok(true) => {}
        Ok(false) => {
            return Err(AppError::Forbidden("request denied by scope policy".into()));
        }
        Err(e) => {
            // Fail-closed: evaluation errors deny the request.
            return Err(AppError::Forbidden(format!(
                "scope policy evaluation failed: {e:#}"
            )));
        }
    }

    let handoff_nsid = req.nsid.clone();
    let handoff_body = registry_body(req.input.as_ref())?;
    let drive = state.arbiters.begin_request(&arbiter_did, req, ctx).await?;
    drive_request(
        state,
        caller,
        &arbiter_did,
        &pds_endpoint,
        0,
        drive.machine,
        BuiltinHandoff::Registry {
            nsid: &handoff_nsid,
            body: handoff_body,
        },
    )
    .await
}

/// How a pipeline [`ArbiterReqMachineStep::HandToBuiltin`] step is served on
/// this path.
///
/// The machine is generic — a layer's `{ "handleBuiltin": true }` output only
/// marks the handoff; the server maps the step onto its built-in handler
/// registry (see [`serve_builtin`]) or, on the installPolicy path, straight
/// onto the install the pipeline just approved.
enum BuiltinHandoff<'a> {
    /// Dispatch the handed-off request to the server's built-in handlers; an
    /// NSID with no built-in is surfaced as an error response.
    Registry {
        /// The handed-off request's NSID.
        nsid: &'a str,
        /// The handed-off request's serialized body (`None` when empty).
        body: Option<Bytes>,
    },
    /// The pipeline approved this very install request: perform it (the
    /// shared install logic — validation + record writes + re-onboard).
    Install {
        body: &'a InstallPolicyBody,
        creds: &'a PdsCredentials,
    },
}

/// Max nested built-in handoffs. Each level requires the next arbiter's
/// community pipeline to approve the handoff, but a pipeline that always
/// hands off must still terminate: past this depth the handoff is refused
/// with an error response.
const MAX_BUILTIN_HANDOFF_DEPTH: usize = 8;

/// Drive a begun request machine to completion, executing any remote XRPC
/// call a layer suspends on (authenticated as the stewarded account). Shared
/// by the built-in and scoped proxy paths and the pipeline-gated install.
///
/// A [`ArbiterReqMachineStep::HandToBuiltin`] step is terminal: it is mapped
/// per [`BuiltinHandoff`]. Infrastructure failures (credential store access)
/// surface as `AppError` and propagate to the handler boundary; the machine's
/// own outcome — its output, an XRPC error (e.g. a policy abort), or a
/// built-in handler's response — is returned in `Ok`.
async fn drive_request(
    state: &AppState,
    caller: &str,
    arbiter_did: &str,
    pds_endpoint: &str,
    handoff_depth: usize,
    mut machine: ArbiterReqMachine,
    handoff: BuiltinHandoff<'_>,
) -> Result<Response, AppError> {
    let mut step = machine.start();
    let mut remote_calls = 0usize;
    loop {
        match step {
            ArbiterReqMachineStep::Completed(result) => return Ok(xrpc_result_to_response(result)),
            ArbiterReqMachineStep::RemoteXrpcRequest { endpoint, request } => {
                remote_calls += 1;
                if remote_calls > MAX_REMOTE_XRPC_CALLS {
                    tracing::warn!(
                        arbiter_did,
                        remote_calls,
                        "policy exceeded max remote xrpc calls; aborting request"
                    );
                    return Ok(xrpc_result_to_response(Err(proxy::policy_aborted(
                        "policy exceeded max remote xrpc calls",
                    ))));
                }
                let creds = state
                    .store
                    .get(arbiter_did)
                    .await
                    .map_err(AppError::from)?
                    .ok_or_else(|| {
                        AppError::Other(anyhow::anyhow!(
                            "no stored credentials for arbiter {arbiter_did}"
                        ))
                    })?;
                let resp = proxy::execute_remote(
                    arbiter_did,
                    pds_endpoint,
                    &creds.password,
                    &endpoint,
                    &request,
                )
                .await;
                step = machine.resume(resp);
            }
            ArbiterReqMachineStep::HandToBuiltin => match handoff {
                BuiltinHandoff::Registry { nsid, body } => {
                    // Boxed: serve_builtin dispatches back into the proxy /
                    // install handlers, which drive request machines again —
                    // an async recursion cycle the compiler requires an
                    // indirection for. Bounded by MAX_BUILTIN_HANDOFF_DEPTH.
                    return Box::pin(serve_builtin(state, caller, nsid, body, handoff_depth + 1))
                        .await;
                }
                BuiltinHandoff::Install { body, creds } => {
                    return perform_install(state, body, creds).await;
                }
            },
        }
    }
}

/// Serialize a machine request's input into the body bytes the built-in
/// handlers take (registry dispatch re-issues the handed-off request's body).
fn registry_body(input: Option<&InputDataOrBytes<Value>>) -> Result<Option<Bytes>, AppError> {
    match input {
        None => Ok(None),
        Some(InputDataOrBytes::Data(json)) => {
            Ok(Some(Bytes::from(serde_json::to_vec(json).map_err(
                |e| AppError::Other(anyhow::anyhow!("serializing handed-off body: {e}")),
            )?)))
        }
        Some(InputDataOrBytes::Bytes(bytes)) => Ok(Some(Bytes::from(bytes.clone()))),
    }
}

/// Serve a pipeline handoff (`HandToBuiltin`) by dispatching the handed-off
/// request onto the server's built-in handler registry — the same handlers
/// the catch-all router dispatches. Each built-in applies its own
/// authorization, so a handoff never bypasses a gate; an NSID with no
/// built-in (the common case for proxied scope requests) is an error
/// response, per the machine's contract that the caller surfaces one.
async fn serve_builtin(
    state: &AppState,
    caller: &str,
    nsid: &str,
    body: Option<Bytes>,
    depth: usize,
) -> Result<Response, AppError> {
    if depth > MAX_BUILTIN_HANDOFF_DEPTH {
        return Ok(builtin_handoff_error(
            StatusCode::BAD_REQUEST,
            "BuiltInHandoffTooDeep",
            "the policy pipeline handed the request to built-in handlers too many times",
        ));
    }
    let body = body.unwrap_or_default();
    match nsid {
        NSID_CREATE_ARBITER => create_arbiter(state, caller).await,
        NSID_CREATE_APP_PASSWORD_ARBITER => create_app_password_arbiter(state, caller, &body).await,
        NSID_PROXY => proxy_request_at(state, caller, &body, depth).await,
        NSID_INSTALL_POLICY => install_policy(state, caller, &body, depth).await,
        NSID_RESET_CONFIG => reset_config(state, caller, &body).await,
        other => Ok(builtin_handoff_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            &format!(
                "the policy pipeline handed the request to a built-in handler, but \
                 `{other}` has no built-in implementation"
            ),
        )),
    }
}

/// An error response for a pipeline handoff the server cannot serve (no
/// built-in for the NSID, or the handoff nesting cap).
fn builtin_handoff_error(status: StatusCode, code: &str, message: &str) -> Response {
    xrpc_result_to_response(Err(XrpcError {
        status,
        error: Some(XrpcErrorKind::Undefined(ErrorResponseBody {
            error: Some(code.to_string()),
            message: Some(message.to_string()),
        })),
    }))
}

/// The `town.muni.arbiter.installPolicy` request body (pinned lexicon).
///
/// APPEND semantics: `policy` (when carried) is the at:// URI of an existing
/// `town.muni.arbiter.policy` record — written to a repo by the caller
/// beforehand — to append as the pipeline's last (lowest-priority) layer;
/// `trustedScopes` are unioned into the existing set. Nothing already
/// installed is ever removed or reordered.
#[derive(serde::Deserialize)]
struct InstallPolicyBody {
    #[serde(rename = "arbiterDid")]
    arbiter_did: String,
    /// At-uri of the `town.muni.arbiter.policy` record to append at the end
    /// of the pipeline. Optional: omitting it changes trusted scopes only
    /// (the scope-only append the scopes editors drive).
    #[serde(default)]
    policy: Option<String>,
    /// NSID scopes to union into the arbiter's trusted scopes. Required by
    /// the lexicon; may be empty (a policy-only or no-op install).
    #[serde(rename = "trustedScopes")]
    trusted_scopes: Vec<String>,
}

/// Handle `town.muni.arbiter.installPolicy`.
///
/// The request is authorized one of two ways:
///
/// 1. **Recovery-admin bypass** — the caller is the DID designated in the
///    account's `town.muni.arbiter.recovery/self` record (an identity gate —
///    serviceAuth scopes cannot distinguish installers, so only the
///    designated DID can; the record is re-read from the repo on every call,
///    so rewriting it rotates the recovery admin with effect on the next
///    call). The install is performed directly, bypassing the pipeline — the
///    bootstrap path, which works even while the arbiter is offboarded. The
///    chicken-and-egg of the very first install resolves itself: setup/import
///    writes `recovery/self` naming the caller, so the first install always
///    comes from the recovery admin.
/// 2. **Community pipeline** — anyone else's install request is evaluated by
///    the arbiter's installed pipeline (the machine request's NSID is
///    `town.muni.arbiter.installPolicy`): a layer may deny, answer itself (a
///    policy may perform the install itself via the `xrpc` host fn), approve
///    the install by handing it to the built-in handler
///    (`{ "handleBuiltin": true }` → [`perform_install`]), or pass — falling
///    off the end denies (fail-closed). This path requires the arbiter to be
///    online; an offboarded arbiter (no loadable pipeline) denies with a
///    pointer to `town.muni.arbiter.resetConfig`, the recovery admin's
///    offline-capable hatch.
async fn install_policy(
    state: &AppState,
    caller: &str,
    body: &Bytes,
    handoff_depth: usize,
) -> Result<Response, AppError> {
    // The raw body is kept for the machine request below (the pipeline
    // evaluates the install request verbatim); both parses happen before
    // `body` is shadowed by the typed struct.
    let raw_body: Value = serde_json::from_slice(body)
        .map_err(|e| AppError::BadRequest(format!("invalid installPolicy body: {e}")))?;
    let body: InstallPolicyBody = serde_json::from_slice(body)
        .map_err(|e| AppError::BadRequest(format!("invalid installPolicy body: {e}")))?;

    // The credentials row gates every path: the record writes (bypass path)
    // and any policy-issued proxied call (pipeline path) authenticate as the
    // stewarded account, which only exists if this server stewards it. The
    // stored designation is the bootstrap value `repair_provisioning` uses to
    // (re)write the record for half-provisioned accounts — not the runtime
    // authority (see `credstore::PdsCredentials::recovery_admin`).
    let creds = state
        .store
        .get(&body.arbiter_did)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| {
            AppError::PermissionDenied("account is not stewarded by this server".to_string())
        })?;

    // Identity gate: the `town.muni.arbiter.recovery/self` record is the
    // authority, fetched fresh from the repo on every call — rewriting it
    // rotates the recovery admin with effect on the next call. Fail closed
    // when no valid record exists, per the lexicon contract.
    let record_admin = policy::recovery_admin(state, &body.arbiter_did)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| {
            AppError::PermissionDenied(
                "no recovery admin is designated in town.muni.arbiter.recovery/self".to_string(),
            )
        })?;
    if caller == record_admin {
        // Recovery-admin bypass: perform the install directly, never touching
        // the (possibly broken or denying) pipeline.
        return perform_install(state, &body, &creds).await;
    }

    // The pipeline's remote calls share the proxy concurrency budget: this
    // evaluation buffers up to (remote-call limit × response cap) bytes, the
    // same worst-case memory profile as a proxy request. Entered from the
    // router (handoff depth 0) it is its own top-level request and takes a
    // proxy permit — the same [`acquire_proxy_permit`] slot the proxy paths
    // take; reached through a built-in handoff (depth > 0) the request
    // already holds the parent's permit, and a second acquisition from a
    // child would risk the saturated-semaphore deadlock described there.
    // The recovery-admin bypass above deliberately stays outside the budget:
    // it drives no policy machine and must remain reachable while the
    // semaphore is saturated — it is the repair hatch.
    let _permit = if handoff_depth == 0 {
        acquire_proxy_permit().await?
    } else {
        None
    };

    // Pipeline-gated install: drive the arbiter's community policy over the
    // install request itself.
    let pds_endpoint = state
        .resolver
        .resolve_pds_endpoint(&body.arbiter_did)
        .await?;
    let req = XrpcRequest {
        method: Method::POST,
        nsid: NSID_INSTALL_POLICY.to_string(),
        parameters: None,
        input: Some(InputDataOrBytes::Data(raw_body)),
        encoding: Some("application/json".to_string()),
    };
    let ctx = RequestCtx {
        arbiter_did: body.arbiter_did.clone(),
        pds_endpoint: pds_endpoint.clone(),
        caller_did: caller.to_string(),
        // The install request's default forward target: the arbiter's own
        // PDS, where a policy performing the install would write the records.
        xrpc_endpoint: format!("{}#atproto_pds", body.arbiter_did),
    };
    let drive = state
        .arbiters
        .begin_request(&body.arbiter_did, req, ctx)
        .await
        .map_err(|e| match e {
            AppError::ArbiterNotReady(did) => AppError::PermissionDenied(format!(
                "the arbiter for {did} is offline (its policy pipeline is not loadable), so \
                 the install request cannot be evaluated by its community policy; the \
                 designated recovery admin can restore it with town.muni.arbiter.resetConfig"
            )),
            other => other,
        })?;
    drive_request(
        state,
        caller,
        &body.arbiter_did,
        &pds_endpoint,
        0,
        drive.machine,
        BuiltinHandoff::Install {
            body: &body,
            creds: &creds,
        },
    )
    .await
}

/// Perform a validated policy install — APPEND semantics: the referenced
/// policy layer (an existing `town.muni.arbiter.policy` record the caller
/// wrote to a repo beforehand) is appended at the END of the current
/// pipeline (lowest priority: it only sees requests the community's layers
/// pass), trusted scopes are unioned in (deduped, existing order kept), and
/// the merged config is written to `town.muni.arbiter.config/self` via the
/// steward session (repo-head CAS) only when something actually changed,
/// then the arbiter is re-onboarded. Nothing already installed is ever
/// removed or reordered; a re-install of an already-installed URI keeps its
/// position and skips the config write (updated record content propagates
/// over Jetstream / the re-onboard).
///
/// Shared by the recovery-admin bypass and the pipeline's `HandToBuiltin`
/// handoff — the pipeline approved the request, the built-in performs it.
async fn perform_install(
    state: &AppState,
    body: &InstallPolicyBody,
    creds: &PdsCredentials,
) -> Result<Response, AppError> {
    // Validate the config inputs before anything is read or written:
    // malformed trusted scopes or a malformed/foreign-collection policy URI
    // would otherwise install fine and only surface as a fail-closed onboard
    // failure the installer cannot act on.
    let pipeline_entry: &[String] = match &body.policy {
        Some(uri) => std::slice::from_ref(uri),
        None => &[],
    };
    policy::validate_config_inputs(&body.trusted_scopes, pipeline_entry)
        .map_err(|e| AppError::InvalidPolicy(format!("invalid install payload: {e:#}")))?;
    // The store may serve pre-write values: the caller writes the policy
    // record externally right before installing (its jetstream event may
    // not have landed yet), and a prior install's config write may likewise
    // still be in flight. Drop both so validation and the reads below
    // observe current PDS state.
    if let Some(uri) = &body.policy {
        record_store::invalidate(uri).await;
    }
    record_store::invalidate(&policy::config_record_uri(&body.arbiter_did)).await;
    let repo = body
        .arbiter_did
        .parse::<AtIdentifier>()
        .map_err(|e| AppError::InvalidPolicy(format!("invalid arbiter DID: {e}")))?;

    // The referenced policy record must exist and compile exactly the way
    // the re-onboard below will resolve it (see
    // policy::validate_pipeline_records): a ghost URI — a record neither
    // written to the stewarded repo nor to any other repo this server can
    // resolve — a record without a string `policy` field, or an
    // uncompilable one would otherwise pass the checks above, land in the
    // config record, and then fail the re-onboard as an undeclared 500 the
    // installer cannot act on. The caller writes the record itself before
    // installing; this endpoint never writes policy records.
    let pds_endpoint = state
        .resolver
        .resolve_pds_endpoint(&body.arbiter_did)
        .await?;
    let local_api = policy::pds_read_client(&pds_endpoint)?;
    if let Some(uri) = &body.policy {
        policy::validate_pipeline_records(
            state,
            &local_api,
            &body.arbiter_did,
            std::slice::from_ref(uri),
        )
        .await
        .map_err(|e| AppError::InvalidPolicy(format!("invalid install payload: {e:#}")))?;
    }

    // Read the CURRENT config: absent (bootstrap) → the empty config the
    // first install appends onto; present → its trusted scopes + pipeline.
    // A present-but-malformed record is a broken state an append cannot be
    // computed against — the recovery admin's `resetConfig` repairs it.
    let current = policy::current_config(&local_api, &repo)
        .await
        .map_err(AppError::from)?;

    // Append the policy URI at the END of the pipeline when it is not
    // installed yet; a re-install of an installed layer keeps its position
    // (no duplicate, no priority elevation). Union the trusted scopes,
    // deduped, preserving the existing order. Nothing existing is ever
    // removed or reordered.
    let mut pipeline = current.policy_layers;
    let mut pipeline_changed = false;
    if let Some(uri) = &body.policy {
        if !pipeline.contains(uri) {
            pipeline.push(uri.clone());
            pipeline_changed = true;
        }
    }
    let mut scopes = current.trusted_scopes;
    let mut scopes_changed = false;
    for scope in &body.trusted_scopes {
        if !scopes.contains(scope) {
            scopes.push(scope.clone());
            scopes_changed = true;
        }
    }

    // The config write is the install's atomic activation point — and it is
    // skipped entirely when the install changes nothing (the config record's
    // content is already exactly what this request would produce). When it
    // runs: optimistic concurrency — fetch the current repo head commit CID
    // and require the write to swap against it, so a concurrent install (or
    // any other concurrent repo write) winning the race makes putRecord fail
    // instead of silently clobbering it. The head is read immediately before
    // the write (the repo head, not a record CID, so a very first install —
    // no records yet — is guarded too), and the steward session is opened
    // only when a write is actually due.
    if pipeline_changed || scopes_changed {
        let writer = login_session(&body.arbiter_did, &creds.password, &pds_endpoint).await?;
        let swap_commit = policy::repo_head_cid(state, &body.arbiter_did)
            .await
            .map_err(AppError::from)?;
        put_config_record(
            &writer,
            &body.arbiter_did,
            scopes,
            &pipeline,
            swap_commit.as_deref(),
        )
        .await?;
        // The config write just changed the record on the PDS; the entry
        // current_config cached is now stale until the write's jetstream
        // event lands. Drop it so the re-onboard below observes the write.
        record_store::invalidate(&policy::config_record_uri(&body.arbiter_did)).await;
    }

    // Re-onboard so the appended layer is active (and an already-installed
    // layer's updated record content is picked up: the caller-written
    // policy record and the just-written config were invalidated above, so
    // the reload observes current values from the store).
    policy::load_and_onboard(state, &body.arbiter_did)
        .await
        .map_err(AppError::from)?;

    Ok(ok_response())
}

/// The `town.muni.arbiter.resetConfig` request body (pinned lexicon).
///
/// The typed shape IS the shape validation: `trustedScopes` and `policyLayers`
/// must be arrays of strings — that is all this endpoint checks. Deliberately
/// no compile checks and no record-existence checks: this is the recovery
/// hatch for a broken config, and if the new config is also bad, reset again.
#[derive(serde::Deserialize)]
struct ResetConfigBody {
    #[serde(rename = "arbiterDid")]
    arbiter_did: String,
    /// NSID prefixes the arbiter accepts for its scoped `*.arbiter.proxy`
    /// endpoints. Written to the config record verbatim.
    #[serde(rename = "trustedScopes")]
    trusted_scopes: Vec<String>,
    /// Ordered `at://` URIs of `town.muni.arbiter.policy` records forming the
    /// policy layers. Written to the config record verbatim.
    #[serde(rename = "policyLayers")]
    policy_layers: Vec<String>,
}

/// Handle `town.muni.arbiter.resetConfig`: the recovery-admin-only hatch that
/// replaces the account's `town.muni.arbiter.config/self` record wholesale
/// and re-onboards the arbiter.
///
/// Unlike `installPolicy` this is never evaluated through the policy pipeline
/// and must work while the arbiter is offboarded — a broken config is exactly
/// what it repairs — so it is a direct handler and never `begin_request`s.
/// Authorization is the same identity gate as `installPolicy` (the
/// freshly-read `town.muni.arbiter.recovery/self` record; fail-closed when
/// absent or invalid); the write uses the same repo-head CAS machinery as
/// `installPolicy`'s activation write, so two concurrent resets (or any
/// concurrent repo write) cannot silently clobber each other. If the new
/// config fails to load, reset again.
async fn reset_config(state: &AppState, caller: &str, body: &Bytes) -> Result<Response, AppError> {
    let body: ResetConfigBody = serde_json::from_slice(body)
        .map_err(|e| AppError::BadRequest(format!("invalid resetConfig body: {e}")))?;

    // Identity gate — the same authority as installPolicy: the recovery/self
    // record, fetched fresh from the repo on every call (rewriting it
    // rotates the admin with effect on the next call). Fail closed when no
    // valid record exists.
    let record_admin = policy::recovery_admin(state, &body.arbiter_did)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| {
            AppError::PermissionDenied(
                "no recovery admin is designated in town.muni.arbiter.recovery/self".to_string(),
            )
        })?;
    if caller != record_admin {
        return Err(AppError::PermissionDenied(format!(
            "caller `{caller}` is not the designated recovery admin `{record_admin}`"
        )));
    }
    // Credentials row for the steward session that writes the config record.
    let creds = state
        .store
        .get(&body.arbiter_did)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| {
            AppError::PermissionDenied("account is not stewarded by this server".to_string())
        })?;

    let pds_endpoint = state
        .resolver
        .resolve_pds_endpoint(&body.arbiter_did)
        .await?;
    let writer = login_session(&body.arbiter_did, &creds.password, &pds_endpoint).await?;
    let swap_commit = policy::repo_head_cid(state, &body.arbiter_did)
        .await
        .map_err(AppError::from)?;
    put_config_record(
        &writer,
        &body.arbiter_did,
        body.trusted_scopes,
        &body.policy_layers,
        swap_commit.as_deref(),
    )
    .await?;
    // The config write just changed the record; the store must not serve
    // the pre-write value to the re-onboard below.
    record_store::invalidate(&policy::config_record_uri(&body.arbiter_did)).await;

    // Re-onboard so the replacement config takes effect. This is the regular
    // load path, not a request against the (previously broken) arbiter, so
    // it works while offboarded.
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
        .time_to_live(Duration::from_secs(CONFIG.create_arbiter_rate_window_secs))
        .build()
});

/// Enforce the per-caller `createArbiter` rate limit. Returns an error if the
/// caller has exceeded `CREATE_ARBITER_RATE_LIMIT` calls in the window (or if
/// the limit is 0, meaning creation is disabled).
async fn check_create_arbiter_rate(caller: &str) -> Result<(), AppError> {
    let limit = CONFIG.create_arbiter_rate_limit;
    if limit == 0 {
        return Err(AppError::PermissionDenied(
            "createArbiter is disabled (CREATE_ARBITER_RATE_LIMIT=0)".into(),
        ));
    }
    let count = CREATE_ARBITER_COUNTS.get(caller).await.unwrap_or(0);
    if count >= limit {
        return Err(AppError::PermissionDenied(format!(
            "createArbiter rate limit exceeded ({limit} per {}s)",
            CONFIG.create_arbiter_rate_window_secs
        )));
    }
    CREATE_ARBITER_COUNTS
        .insert(caller.to_string(), count + 1)
        .await;
    Ok(())
}

/// Provision a brand-new stewarded PDS account (`town.muni.arbiter.createArbiter`).
///
/// Creates the account against `CONFIG.default_pds` with a random password +
/// `CONFIG.invite_code`, stores the credentials, writes the
/// `town.muni.arbiter.service/self` + `town.muni.arbiter.recovery/self` records
/// from the new account's session, then returns. No initial policy is written:
/// the arbiter stays offline (fail-closed) until the recovery admin
/// designated in the just-written `recovery/self` record calls `installPolicy`
/// to install the first policy — the same flow an imported account uses.
///
/// Credentials are persisted **before** the record writes so a half-provisioned
/// account is never orphaned: if a write fails, startup onboarding will retry
/// it (and the arbiter remains offline until the policy lands).
async fn create_arbiter(state: &AppState, caller: &str) -> Result<Response, AppError> {
    check_create_arbiter_rate(caller).await?;

    let pds_url = state.default_pds.clone();
    let password = random_secret(24);
    let local_label = random_local_label();
    let handle = Handle::new(format!("{local_label}{}", CONFIG.handle_suffix))
        .map_err(|e| AppError::Other(anyhow::anyhow!("invalid handle: {e}")))?;
    // The reference PDS requires an email on createAccount; use a synthetic
    // address sharing the handle's random local label so it is valid + unique.
    let email = format!("{local_label}@{}", CONFIG.steward_email_domain);

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
                email: Some(email),
                handle,
                invite_code: state.invite_code.clone(),
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
        .map_err(|e| AppError::ProvisioningFailed(format!("createAccount: {e}")))?;

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

    // The account was just created with the password we generated, so any
    // login failure (including a 401) is a provisioning problem, not a caller
    // permission issue.
    let writer = login_session(&new_did, &password, &pds_url)
        .await
        .map_err(|e| AppError::ProvisioningFailed(format!("login after createAccount: {e}")))?;
    write_service_and_recovery(&writer, &new_did, caller)
        .await
        .map_err(|e| AppError::ProvisioningFailed(format!("bootstrap record write: {e}")))?;

    // Bootstrap records written; the account is now fully provisioned.
    state
        .store
        .mark_provisioned(&new_did)
        .await
        .map_err(AppError::from)?;

    // Return the created account's DID so the caller can identify and manage
    // it (the server generated the handle/DID, so the caller has no other way
    // to learn it). The HTTP 200 status signals success.
    Ok((StatusCode::OK, Json(json!({ "did": new_did }))).into_response())
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
/// `installPolicy` installs the first policy.
///
/// Credentials are persisted before the record writes so a partial failure is
/// retried by startup onboarding rather than lost.
async fn create_app_password_arbiter(
    state: &AppState,
    caller: &str,
    body: &Bytes,
) -> Result<Response, AppError> {
    let body_json: Value = serde_json::from_slice(body)
        .map_err(|e| AppError::BadRequest(format!("invalid json body: {e}")))?;
    let arbiter_did = body_json
        .get("arbiterDid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing arbiterDid".to_string()))?
        .to_string();
    let app_password = body_json
        .get("appPassword")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("missing appPassword".to_string()))?
        .to_string();

    let pds_endpoint = state.resolver.resolve_pds_endpoint(&arbiter_did).await?;

    // Authenticating as the account proves control (app password) and is what
    // authorizes stewardship takeover. `login_session` classifies the failure:
    // a 401 (bad app password) -> ErrPermissionDenied; a transport error ->
    // ErrProvisioningFailed.
    let writer = login_session(&arbiter_did, &app_password, &pds_endpoint).await?;

    // Persist credentials first so startup onboarding can repair the bootstrap
    // records if a write below fails (`provisioned = false`). The insert is
    // atomic against concurrent imports: if a row already exists, the insert is
    // a no-op. A fully-provisioned row means the arbiter is already stewarded
    // -> reject the duplicate. A `provisioned = false` row means a previous
    // attempt inserted credentials but failed before the bootstrap records
    // landed; treat that as a retry and proceed with the writes (the account
    // is not yet stewarded, so re-importing is safe and idempotent).
    let inserted = state
        .store
        .store_if_absent(
            arbiter_did.clone(),
            PdsCredentials {
                password: app_password.clone(),
                recovery_admin: caller.to_string(),
                provisioned: false,
            },
        )
        .await
        .map_err(AppError::from)?;
    if !inserted {
        let existing = state
            .store
            .get(&arbiter_did)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| {
                AppError::Other(anyhow::anyhow!(
                    "store_if_absent reported a conflict but no row exists for `{arbiter_did}`"
                ))
            })?;
        if existing.provisioned {
            return Err(AppError::ArbiterAlreadyExists(format!(
                "an arbiter for `{arbiter_did}` already exists on this server"
            )));
        }
        // Partial-failure retry: overwrite the stale credentials with the
        // current caller/password and proceed to (re)write the bootstrap
        // records.
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
    }

    write_service_and_recovery(&writer, &arbiter_did, caller)
        .await
        .map_err(|e| AppError::ProvisioningFailed(format!("bootstrap record write: {e}")))?;

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
///
/// Login failures are classified: an authentication failure (the PDS rejected
/// the credentials, HTTP 401) maps to [`AppError::PermissionDenied`], while a
/// transport error (PDS unreachable, timeout, 5xx) maps to
/// [`AppError::ProvisioningFailed`]. Callers that only ever expect a reachable
/// PDS (e.g. the create path, which just created the account) can treat any
/// error as provisioning failure.
async fn login_session(did: &str, password: &str, pds_url: &str) -> Result<SessionAgent, AppError> {
    let session =
        CredentialSession::new(time_bound_reqwest(pds_url), MemorySessionStore::default());
    session
        .login(did, password)
        .await
        .map_err(|e| classify_login_error(did, e))?;
    Ok(Agent::new(session))
}

/// Classify a `CredentialSession::login` error into an [`AppError`].
///
/// An authentication failure — an `XrpcResponse` with a 401 status, or an
/// `Error::Authentication` (atrium surfaces a `WWW-Authenticate`-carrying 401
/// as this variant) — means the PDS rejected the credentials (bad app password
/// / account takedown). Anything else (transport, timeout, 5xx, malformed
/// response) is a provisioning failure, not a credential problem.
fn classify_login_error(
    did: &str,
    e: atrium_xrpc::Error<atrium_api::com::atproto::server::create_session::Error>,
) -> AppError {
    use atrium_xrpc::Error as XrpcError;
    match &e {
        XrpcError::XrpcResponse(resp) if resp.status == StatusCode::UNAUTHORIZED => {
            AppError::PermissionDenied(format!("login as `{did}` rejected: {e}"))
        }
        XrpcError::Authentication(_) => {
            AppError::PermissionDenied(format!("login as `{did}` rejected: {e}"))
        }
        _ => AppError::ProvisioningFailed(format!("login as `{did}` failed: {e}")),
    }
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
/// `town.muni.arbiter.recovery/self` (did = the designated admin) records into
/// `repo`'s repository, authenticated via `agent`.
///
/// The `recovery/self` record written here is the runtime authority for
/// `installPolicy` once it exists; the admin DID it carries is the
/// provisioning caller at bootstrap, and the persisted bootstrap designation
/// during repair (see `credstore::PdsCredentials::recovery_admin`).
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
/// `service/self` + `recovery/self` records (from the persisted bootstrap
/// designation — the record is the runtime authority for `installPolicy` once
/// it exists) and mark it provisioned.
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

/// Overwrite the `town.muni.arbiter.config/self` record with the trusted
/// scopes + ordered pipeline, authenticated as the steward.
///
/// `swap_commit`, if present, is the repo head commit CID the repo must
/// currently be at for the write to succeed (compare-and-swap on the whole
/// repo). This write is the install's activation point: only after it lands
/// does the pipeline actually change.
async fn put_config_record(
    agent: &SessionAgent,
    repo: &str,
    trusted_scopes: Vec<String>,
    pipeline: &[String],
    swap_commit: Option<&str>,
) -> Result<(), AppError> {
    let record = serde_json::json!({
        "$type": policy::CONFIG_COLLECTION,
        "trustedScopes": trusted_scopes,
        "policyLayers": pipeline,
    })
    .try_into_unknown()
    .map_err(|e| AppError::Other(anyhow::anyhow!("build config record: {e}")))?;
    let swap_commit = match swap_commit {
        Some(cid) => Some(
            cid.parse::<atrium_api::types::string::Cid>()
                .map_err(|e| AppError::Other(anyhow::anyhow!("invalid swap CID `{cid}`: {e}")))?,
        ),
        None => None,
    };
    let input = atrium_api::com::atproto::repo::put_record::InputData {
        collection: policy::CONFIG_COLLECTION
            .parse::<Nsid>()
            .map_err(|e| AppError::Other(anyhow::anyhow!("invalid nsid: {e}")))?,
        record,
        repo: repo
            .parse::<AtIdentifier>()
            .map_err(|e| AppError::Other(anyhow::anyhow!("invalid repo `{repo}`: {e}")))?,
        rkey: policy::CONFIG_RKEY
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
        .map_err(|e| AppError::Other(anyhow::anyhow!("putRecord config: {e}")))?;
    Ok(())
}

/// Upsert a record in `collection`/`rkey` (unconditionally, no CAS),
/// authenticated as the steward session.
async fn put_record_value(
    agent: &SessionAgent,
    repo: &str,
    collection: &str,
    rkey: &str,
    record: serde_json::Value,
) -> Result<(), AppError> {
    let input = atrium_api::com::atproto::repo::put_record::InputData {
        collection: collection
            .parse::<Nsid>()
            .map_err(|e| AppError::Other(anyhow::anyhow!("invalid nsid `{collection}`: {e}")))?,
        record: record
            .try_into_unknown()
            .map_err(|e| AppError::Other(anyhow::anyhow!("build {collection} record: {e}")))?,
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

/// A cryptographically random handle local label: 8 bytes of entropy base32-
/// encoded (RFC 4648, no padding, lowercased) → 13 chars from `[a-z2-7]`.
fn random_local_label() -> String {
    use data_encoding::BASE32_NOPAD;
    let mut bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    // Encode (uppercase `[A-Z2-7]`), then lowercase to match the ecosystem's
    // handle normalization. `data-encoding` has no lowercase base32 output
    // encoding constant.
    BASE32_NOPAD.encode(&bytes).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrium_xrpc::InputDataOrBytes;

    /// A `{ "$bytes": <base64> }` body decodes to raw bytes (blob upload).
    ///
    /// The payload is deliberately *not* a multiple of 3 bytes, so its unpadded
    /// base64 length is not a multiple of 4 — the case that must decode despite
    /// missing padding.
    #[test]
    fn bytes_body_decodes_to_raw_bytes() {
        use base64::Engine;
        // 16 bytes (not divisible by 3) → unpadded base64 of length 22 (not a
        // multiple of 4).
        let payload = b"\x89PNG\r\n\x1a\n\x00\x01\x02\x03\x04\x05\x06\x07".to_vec();
        assert_ne!(payload.len() % 3, 0);
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&payload);
        assert_ne!(encoded.len() % 4, 0);
        let body = json!({ BYTES_BODY_KEY: encoded });
        match decode_proxy_body(body).unwrap() {
            InputDataOrBytes::Bytes(bytes) => assert_eq!(bytes, payload),
            _ => panic!("expected bytes body, got data"),
        }
    }

    /// Padded base64 is also accepted; both forms must round-trip to the same
    /// bytes.
    #[test]
    fn bytes_body_accepts_padded_base64() {
        use base64::Engine;
        let payload = b"hello".to_vec();
        let padded = base64::engine::general_purpose::STANDARD.encode(&payload);
        assert!(padded.ends_with('='));
        let body = json!({ BYTES_BODY_KEY: padded });
        match decode_proxy_body(body).unwrap() {
            InputDataOrBytes::Bytes(bytes) => assert_eq!(bytes, payload),
            _ => panic!("expected bytes body, got data"),
        }
    }

    /// A `$bytes` value that is not valid base64 is surfaced as a request error
    /// rather than silently degrading the upload to a JSON body.
    #[test]
    fn invalid_bytes_base64_is_an_error() {
        let body = json!({ BYTES_BODY_KEY: "not-valid-base64!!!" });
        assert!(decode_proxy_body(body).is_err());
    }

    /// An ordinary JSON body passes through as JSON data (unchanged).
    #[test]
    fn json_body_passes_through_as_data() {
        let body = json!({ "record": { "text": "hi" } });
        match decode_proxy_body(body.clone()).unwrap() {
            InputDataOrBytes::Data(json) => assert_eq!(json, body),
            _other => panic!("expected json data, got bytes"),
        }
    }

    /// A `{ "$bytes": ... }` object with extra fields is treated as plain
    /// JSON, not bytes (matches the strict AT `$bytes` shape).
    #[test]
    fn non_singleton_bytes_object_stays_json() {
        let body = json!({ BYTES_BODY_KEY: "aGk=", "extra": 1 });
        match decode_proxy_body(body.clone()).unwrap() {
            InputDataOrBytes::Data(json) => assert_eq!(json, body),
            _other => panic!("expected json data, got bytes"),
        }
    }
}
