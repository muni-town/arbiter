//! Integration tests for the `arbiter-server` library crate.
//!
//! These tests drive the server end-to-end against an in-process mock PDS and a
//! mock identity resolver, covering the riskiest behaviours from
//! SERVER_PLAN.md §10: policy loading + onboarding, fail-closed startup,
//! serviceAuth verification, hot-reload, and the §4 auto-delete lifecycle.
//!
//! All regular dependencies of `arbiter-server` are available to integration
//! tests without dev-dependencies.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use arbiter_core::arbiter::{ArbiterReqMachineStep, RequestCtx};
use arbiter_core::xrpc::{XrpcOutput, XrpcRequest};
use async_trait::async_trait;
use atproto_identity::key::{KeyData, KeyType, generate_key, to_public};
use atproto_identity::model::{Document, Service, VerificationMethod};
use atproto_identity::traits::IdentityResolver;
use atproto_jetstream::{EventHandler, JetstreamEvent, JetstreamEventCommit};
use atproto_oauth::jwt::{Claims, Header, JoseClaims, mint};
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use arbiter_server::AppState;
use arbiter_server::credstore::PdsCredentials;
use arbiter_server::handlers;
use arbiter_server::jetstream::ReloadHandler;
use arbiter_server::permission_set::{AtprotoLexiconSource, LexiconSource, ScopeResolver};
use arbiter_server::policy;
use arbiter_server::state::ArbiterCollection;
use arbiter_server::storage::TursoCredentialStore;

/// The mock PDS record map keyed by `(repo, collection, rkey)`.
type RecordMap = Arc<Mutex<HashMap<(String, String, String), Value>>>;

// ─── constants matching the server's record layout ──────────────────────────

const SERVICE_COLLECTION: &str = "town.muni.arbiter.service";
const SERVICE_RKEY: &str = "self";
const CONFIG_COLLECTION: &str = "town.muni.arbiter.config";
const CONFIG_RKEY: &str = "self";
const POLICY_COLLECTION: &str = "town.muni.arbiter.policy";
/// The rkey of the single echo policy record the shared setups install.
const ECHO_POLICY_RKEY: &str = "echo";

/// Default `CONFIG.server_did` (no env vars set in tests → clap defaults).
/// Port is percent-encoded per the did:web spec.
const SERVER_DID: &str = "did:web:localhost%3A8203";

/// A pipeline layer that echoes `input.nsid` back in `output.got`.
const ECHO_POLICY: &str =
    "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": input.nsid } }";


/// A pipeline layer that approves any request by handing it to the arbiter's
/// built-in handler (the `installPolicy` pipeline-gate approval marker).
const HANDLE_BUILTIN_POLICY: &str = "package arbiter\nresult := { \"handleBuiltin\": true }";

/// A pipeline layer that denies the request with an explicit error envelope.
const DENY_INSTALL_POLICY: &str = "package arbiter\nresult := { \"ok\": false, \"error\": { \"status\": 403, \"error\": \"InstallDenied\", \"message\": \"installs are not allowed\" } }";

/// A pipeline layer that passes everything: falling off the end of the
/// pipeline denies (fail-closed).
const PASS_INSTALL_POLICY: &str = "package arbiter\nresult := { \"pass\": true }";

/// A pipeline layer that issues an `xrpc` host call to the arbiter server's
/// own DID and reports the returned error envelope in its output.
fn self_proxy_policy(server_did: &str) -> String {
    format!(
        "package arbiter\nresult := {{ \"ok\": true, \"output\": {{ \"selfProxy\": resp }} }}\n\
         resp := xrpc({{ \"did\": \"{server_did}#atproto_pds\", \"method\": \"GET\", \
         \"nsid\": \"com.example.self\", \"parameters\": null, \"body\": null }})"
    )
}

/// The trusted scope prefix the shared setups install; scoped endpoints
/// `community.test.authCalendar.arbiter.proxy` are accepted for it.
const TRUSTED_SCOPE: &str = "community.test.authCalendar";
/// The scoped NSID for [`TRUSTED_SCOPE`].
const SCOPED_NSID: &str = "community.test.authCalendar.arbiter.proxy";
/// A pure scope policy that allows GET requests against calendar NSIDs.
const ALLOW_SCOPE_REGO: &str = r#"
package arbiter
default allow := false
allow if {
    input.method == "GET"
    startswith(input.nsid, "com.example.calendars")
}
"#;
/// A pure scope policy that denies everything (fail-closed layer-1 gate).
const DENY_SCOPE_REGO: &str = r#"
package arbiter
default allow := false
"#;

/// A published permission-set lexicon document carrying the embedded arbiter
/// scope policy under the `x-town-muni-arbiter` convention key.
fn scope_lexicon_doc(policy: &str) -> Value {
    json!({
        "lexicon": 1,
        "id": TRUSTED_SCOPE,
        "defs": {
            "main": {
                "type": "permission-set",
                "permissions": [],
                "x-town-muni-arbiter": { "policy": policy },
            }
        }
    })
}

/// Build credentials for a test steward, defaulting to a fully-provisioned
/// account (so auto-delete lifecycle tests behave as expected).
fn test_creds(password: &str) -> PdsCredentials {
    PdsCredentials {
        password: password.to_string(),
        recovery_admin: "did:plc:testadmin".to_string(),
        provisioned: true,
    }
}

// ─── small shared helpers ───────────────────────────────────────────────────

/// Monotonic counter yielding unique DID strings per test run, so the
/// process-wide `moka` caches (PDS signing keys, resolved `#atproto_pds`
/// endpoints) cannot collide across tests that run in parallel.
static DID_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_did(tag: &str) -> String {
    // Valid PLC DIDs are `did:plc:` + exactly 24 base32-sortable characters
    // (`[a-z2-7]`). The arbiter validates DID syntax when parsing `at://`
    // pipeline URIs via `atproto-record`, so fixture DIDs must be
    // spec-shaped: keep a tag prefix (filtered to the alphabet) and encode
    // the monotonic counter in the remainder.
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let n = DID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut suffix: Vec<u8> = tag
        .chars()
        .map(|c| c.to_ascii_lowercase() as u8)
        .filter(|c| ALPHABET.contains(c))
        .take(8)
        .collect();
    let mut digits = Vec::new();
    let mut n = n;
    loop {
        digits.push(ALPHABET[(n % 32) as usize]);
        n /= 32;
        if n == 0 {
            break;
        }
    }
    digits.reverse();
    suffix.extend(std::iter::repeat(b'a').take(24 - suffix.len() - digits.len()));
    suffix.extend(digits);
    format!("did:plc:{}", String::from_utf8(suffix).expect("fixture DID suffix is ASCII"))
}

/// Monotonic counter yielding unique Turso database file paths per run, so a
/// persisted credential DB from a previous run is never re-read across tests
/// running in parallel.
static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fresh_creds_db() -> std::path::PathBuf {
    let n = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("arbiter-test-{}-{}.db", std::process::id(), n))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// Build a DID document with an `#atproto_pds` service and, optionally, a
/// `Multikey` verification method carrying a signing key.
fn did_doc(did: &str, pds_url: &str, signing_key_multibase: Option<&str>) -> Document {
    let mut verification_method = Vec::new();
    if let Some(mb) = signing_key_multibase {
        verification_method.push(VerificationMethod::Multikey {
            id: format!("{did}#signing"),
            controller: did.to_string(),
            public_key_multibase: mb.to_string(),
            extra: HashMap::new(),
        });
    }
    Document {
        context: vec!["https://www.w3.org/ns/did/v1".to_string()],
        id: did.to_string(),
        also_known_as: Vec::new(),
        service: vec![Service {
            id: "#atproto_pds".to_string(),
            r#type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: pds_url.to_string(),
            extra: HashMap::new(),
        }],
        verification_method,
        extra: HashMap::new(),
    }
}

/// Like [`did_doc`], but exposes multiple `Multikey` verification methods (in
/// order), so tests can exercise `kid`-based key selection and rotation.
fn did_doc_multi(
    did: &str,
    pds_url: &str,
    signing_key_multibases: &[&str],
) -> Document {
    let verification_method = signing_key_multibases
        .iter()
        .enumerate()
        .map(|(i, mb)| VerificationMethod::Multikey {
            id: format!("{did}#signing{i}"),
            controller: did.to_string(),
            public_key_multibase: mb.to_string(),
            extra: HashMap::new(),
        })
        .collect();
    Document {
        context: vec!["https://www.w3.org/ns/did/v1".to_string()],
        id: did.to_string(),
        also_known_as: Vec::new(),
        service: vec![Service {
            id: "#atproto_pds".to_string(),
            r#type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: pds_url.to_string(),
            extra: HashMap::new(),
        }],
        verification_method,
        extra: HashMap::new(),
    }
}

// ─── mock identity resolver ─────────────────────────────────────────────────

struct MockResolver {
    docs: HashMap<String, Document>,
}

#[async_trait]
impl IdentityResolver for MockResolver {
    async fn resolve(&self, subject: &str) -> anyhow::Result<Document> {
        self.docs
            .get(subject)
            .cloned()
            .ok_or_else(|| anyhow!("mock resolver has no DID document for {subject}"))
    }
}

// ─── AppState construction ──────────────────────────────────────────────────

fn make_state(resolver: Arc<dyn IdentityResolver>) -> Arc<AppState> {
    let scopes = Arc::new(AtprotoLexiconSource::new(resolver.clone()));
    make_state_with_scope_source(resolver, scopes)
}

/// Like [`make_state`], but with an injected permission-set lexicon source, so
/// scoped-endpoint tests can serve scope documents from a mock.
fn make_state_with_scope_source(
    resolver: Arc<dyn IdentityResolver>,
    scopes: Arc<dyn LexiconSource>,
) -> Arc<AppState> {
    Arc::new(AppState {
        arbiters: ArbiterCollection::new(),
        store: Box::new(
            TursoCredentialStore::new(fresh_creds_db().to_string_lossy().into_owned())
                .expect("fresh credential store"),
        ),
        resolver,
        scopes: ScopeResolver::new(scopes),
        default_pds: String::new(),
        invite_code: None,
    })
}

/// Like [`make_state`], but with the provisioning config (default PDS URL +
/// invite code) set, so `createArbiter` can be exercised against a mock PDS.
fn make_state_with_provisioning(
    resolver: Arc<dyn IdentityResolver>,
    default_pds: String,
    invite_code: Option<String>,
) -> Arc<AppState> {
    Arc::new(AppState {
        arbiters: ArbiterCollection::new(),
        store: Box::new(
            TursoCredentialStore::new(fresh_creds_db().to_string_lossy().into_owned())
                .expect("fresh credential store"),
        ),
        resolver: resolver.clone(),
        scopes: ScopeResolver::new(Arc::new(AtprotoLexiconSource::new(resolver))),
        default_pds,
        invite_code,
    })
}

/// Build a simple GET XRPC request for `com.example.foo` with no body/params.
fn make_req() -> XrpcRequest {
    XrpcRequest {
        method: atrium_xrpc::http::Method::GET,
        nsid: "com.example.foo".to_string(),
        parameters: None,
        input: None,
        encoding: None,
    }
}

/// Whether the server is currently serving an arbiter for `did` (i.e. it is
/// onboarded and active). Mirrors the removed `ArbiterCollection::contains`
/// check that this test file used to rely on.
async fn is_serving(state: &AppState, did: &str) -> bool {
    state
        .arbiters
        .begin_request(did, make_req(), RequestCtx::default())
        .await
        .is_ok()
}

// ─── mock PDS ───────────────────────────────────────────────────────────────

#[derive(Clone)]
struct PdsState {
    records: RecordMap,
    /// Current repo head commit CID per repo DID, used to enforce `swapCommit`
    /// on `putRecord` (the mock's compare-and-swap check).
    heads: Arc<Mutex<HashMap<String, String>>>,
    /// When true, `createAccount` returns a 500 so tests can exercise the
    /// `ErrProvisioningFailed` path.
    fail_create_account: Arc<std::sync::atomic::AtomicBool>,
    /// When true, `createSession` returns a 401 so tests can exercise the
    /// `ErrPermissionDenied` path (failed app-password login).
    fail_create_session: Arc<std::sync::atomic::AtomicBool>,
}

/// A deterministic, parseable CIDv1 (raw codec, sha2-256 multihash over the
/// canonical serialization of the record value) — the same shape a real PDS
/// computes.
///
/// The mock needs *distinct, stable-per-value, valid* CIDs so the server's
/// `(at:// uri, record cid)` compiled-layer cache sees a real change when a
/// record's value is updated (and no cache hit serves a stale layer). The
/// digest must therefore cover the WHOLE serialized value: a truncation (e.g.
/// an identity multihash over the first N bytes) collides for records whose
/// values differ only late in the string, which silently defeats hot reload.
fn record_cid(value: &Value) -> String {
    use data_encoding::BASE32_NOPAD;
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(value).expect("serialize record value");
    let digest = Sha256::digest(&bytes);
    // multihash: sha2-256 code (0x12) + size (0x20) + digest; CIDv1 + raw codec (0x55).
    let mut cid_bytes = vec![0x01u8, 0x55, 0x12, 0x20];
    cid_bytes.extend(digest);
    format!("b{}", BASE32_NOPAD.encode(&cid_bytes).to_ascii_lowercase())
}

async fn get_record_handler(
    State(st): State<PdsState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let repo = q.get("repo").cloned().unwrap_or_default();
    let collection = q.get("collection").cloned().unwrap_or_default();
    let rkey = q.get("rkey").cloned().unwrap_or_default();
    let value = {
        let map = st.records.lock().await;
        map.get(&(repo.clone(), collection.clone(), rkey.clone()))
            .cloned()
    };
    match value {
        Some(v) => {
            let uri = format!("at://{repo}/{collection}/{rkey}");
            (
                StatusCode::OK,
                Json(json!({
                    "uri": uri,
                    "cid": record_cid(&v),
                    "value": v
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "RecordNotFound" })),
        )
            .into_response(),
    }
}

async fn list_records_handler(
    State(st): State<PdsState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let repo = q.get("repo").cloned().unwrap_or_default();
    let collection = q.get("collection").cloned().unwrap_or_default();
    let map = st.records.lock().await;
    let records: Vec<Value> = map
        .iter()
        .filter_map(|((r, c, rk), v)| {
            if r == &repo && c == &collection {
                Some(json!({
                    "uri": format!("at://{r}/{c}/{rk}"),
                    "cid": record_cid(v),
                    "value": v
                }))
            } else {
                None
            }
        })
        .collect();
    (StatusCode::OK, Json(json!({ "records": records }))).into_response()
}

async fn create_session_handler(State(st): State<PdsState>) -> Response {
    if st.fail_create_session.load(std::sync::atomic::Ordering::SeqCst) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "AuthFactorTokenRequired" })),
        )
            .into_response();
    }
    // `did`/`handle` must be syntactically valid for atrium's session parsing.
    Json(json!({
        "accessJwt": "fake-jwt",
        "did": "did:plc:mockpds",
        "handle": "mock.pds.example",
        "refreshJwt": "fake-refresh",
    }))
    .into_response()
}

async fn create_account_handler(State(st): State<PdsState>) -> Response {
    if st.fail_create_account.load(std::sync::atomic::Ordering::SeqCst) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "InternalServerError" })),
        )
            .into_response();
    }
    // `did`/`handle` must be syntactically valid for atrium's response parsing.
    // The DID is fixed (like create_session_handler); the created account's
    // repo is keyed by this DID in the mock's record map.
    Json(json!({
        "did": "did:plc:mockpds",
        "handle": "mock.pds.example",
        "accessJwt": "fake-jwt",
        "refreshJwt": "fake-refresh",
    }))
    .into_response()
}

/// Valid multihash CIDs used as mock repo heads (parseable by atrium's strict
/// `Cid` deserializer, e.g. when `getLatestCommit` feeds `swap_commit`).
/// Distinct values let the mock observe head advancement.
const MOCK_HEAD_A: &str = "bafkreihrh44kmzei6twcurpcnywrkiexyhmd4qkj55ivkvyqt3eokl3dg4";
const MOCK_HEAD_B: &str = "bafkreiehdmbxxtwm46tkz6giymuyljrxfzzwdzfmeweufl3oaus7ubywpa";

/// Handle `com.atproto.repo.putRecord`: upsert the record into the shared map,
/// enforcing `swapCommit` (repo head compare-and-swap) and `swapRecord` (record
/// CID compare-and-swap) so the server's optimistic-concurrency path is
/// exercised.
async fn put_record_handler(
    State(st): State<PdsState>,
    Json(body): Json<Value>,
) -> Response {
    let repo = body.get("repo").and_then(|v| v.as_str()).unwrap_or_default();
    let collection = body
        .get("collection")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let rkey = body.get("rkey").and_then(|v| v.as_str()).unwrap_or_default();
    let swap_commit = body.get("swapCommit").and_then(|v| v.as_str());
    let record = match body.get("record").cloned() {
        Some(v) => v,
        None => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "InvalidRequest" })))
                .into_response()
        }
    };

    let mut map = st.records.lock().await;
    let key = (repo.to_string(), collection.to_string(), rkey.to_string());

    // Enforce swapCommit: the repo head must match, else InvalidSwap. This
    // exercises the server's optimistic-concurrency path (installPolicy's
    // config write passes the repo head it fetched via getLatestCommit). A
    // repo with no recorded head is at MOCK_HEAD_A (matching
    // get_latest_commit_handler's default).
    if let Some(expected) = swap_commit {
        let head = st
            .heads
            .lock()
            .await
            .get(repo)
            .cloned()
            .unwrap_or_else(|| MOCK_HEAD_A.to_string());
        if head != expected {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "InvalidSwap", "message": "repo head changed" })),
            )
                .into_response();
        }
    }

    map.insert(key, record);
    let uri = format!("at://{repo}/{collection}/{rkey}");
    // Advance the repo head so a subsequent swapCommit on the old head fails.
    st.heads.lock().await.insert(repo.to_string(), MOCK_HEAD_B.to_string());
    (StatusCode::OK, Json(json!({ "uri": uri, "cid": MOCK_HEAD_B }))).into_response()
}

/// Serve `com.atproto.sync.getLatestCommit` with the current repo head.
async fn get_latest_commit_handler(
    State(st): State<PdsState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let repo = q.get("did").cloned().unwrap_or_default();
    let cid = st.heads.lock().await.get(&repo).cloned().unwrap_or_else(|| MOCK_HEAD_A.to_string());
    Json(json!({ "cid": cid, "rev": MOCK_REPO_REV })).into_response()
}

/// Start a mock PDS on a random port backed by the shared record map. The
/// server runs for the lifetime of the test's tokio runtime.
async fn start_mock_pds(records: RecordMap) -> SocketAddr {
    start_mock_pds_with_flags(records, false, false).await
}

/// Like [`start_mock_pds`], but with `createAccount` failing when
/// `fail_create_account` is true (to exercise the `ErrProvisioningFailed`
/// path).
async fn start_mock_pds_with_fail(records: RecordMap, fail_create_account: bool) -> SocketAddr {
    start_mock_pds_with_flags(records, fail_create_account, false).await
}

/// Like [`start_mock_pds`], but with `createSession` failing when
/// `fail_create_session` is true (to exercise the `ErrPermissionDenied` path
/// for a failed app-password login).
async fn start_mock_pds_with_fail_session(
    records: RecordMap,
    fail_create_session: bool,
) -> SocketAddr {
    start_mock_pds_with_flags(records, false, fail_create_session).await
}

/// Start a mock PDS with configurable `createAccount` / `createSession`
/// failure flags.
async fn start_mock_pds_with_flags(
    records: RecordMap,
    fail_create_account: bool,
    fail_create_session: bool,
) -> SocketAddr {
    let state = PdsState {
        records,
        heads: Arc::new(Mutex::new(HashMap::new())),
        fail_create_account: Arc::new(std::sync::atomic::AtomicBool::new(fail_create_account)),
        fail_create_session: Arc::new(std::sync::atomic::AtomicBool::new(fail_create_session)),
    };
    let app = axum::Router::new()
        .route(
            "/xrpc/com.atproto.repo.getRecord",
            axum::routing::get(get_record_handler),
        )
        .route(
            "/xrpc/com.atproto.repo.listRecords",
            axum::routing::get(list_records_handler),
        )
        .route(
            "/xrpc/com.atproto.server.createSession",
            axum::routing::post(create_session_handler),
        )
        .route(
            "/xrpc/com.atproto.server.createAccount",
            axum::routing::post(create_account_handler),
        )
        .route(
            "/xrpc/com.atproto.sync.getRepoStatus",
            axum::routing::get(get_repo_status_handler),
        )
        .route(
            "/xrpc/com.atproto.sync.getLatestCommit",
            axum::routing::get(get_latest_commit_handler),
        )
        .route(
            "/xrpc/com.atproto.repo.putRecord",
            axum::routing::post(put_record_handler),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock pds");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// Serve `com.atproto.sync.getRepoStatus` with a stable, valid TID rev so
/// `load_and_onboard` gets a deterministic rev floor. The repo DID is echoed
/// back (atrium parses it as a DID string type; a non-DID value fails
/// deserialization and would leave the rev floor unset).
const MOCK_REPO_REV: &str = "3lyileto4q52k";

async fn get_repo_status_handler(
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let did = q
        .get("did")
        .cloned()
        .unwrap_or_else(|| "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_string());
    Json(json!({
        "active": true,
        "did": did,
        "rev": MOCK_REPO_REV,
    }))
    .into_response()
}
/// Populate the service, config, and policy records for `steward_did`: the
/// service record points at this server, a single `echo` policy record carries
/// `policy_source`, and the config record trusts [`TRUSTED_SCOPE`] with the
/// echo record as the sole pipeline layer. The mock PDS serves these.
async fn populate_standard_records(records: &RecordMap, steward_did: &str, policy_source: &str) {
    let mut m = records.lock().await;
    m.insert(
        (
            steward_did.to_string(),
            SERVICE_COLLECTION.into(),
            SERVICE_RKEY.into(),
        ),
        json!({ "did": SERVER_DID }),
    );
    m.insert(
        (
            steward_did.to_string(),
            POLICY_COLLECTION.into(),
            ECHO_POLICY_RKEY.into(),
        ),
        json!({ "policy": policy_source }),
    );
    m.insert(
        (
            steward_did.to_string(),
            CONFIG_COLLECTION.into(),
            CONFIG_RKEY.into(),
        ),
        json!({
            "trustedScopes": [TRUSTED_SCOPE],
            "policyLayers": [format!("at://{steward_did}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}")],
        }),
    );
}

// ─── shared onboarding setup ────────────────────────────────────────────────

struct PolicyEnv {
    state: Arc<AppState>,
    records: RecordMap,
    steward_did: String,
}

/// Start a mock PDS serving the given policy + a service record pointing at
/// this server, onboard the steward, and return the live state + record map.
async fn policy_setup(policy_source: &str) -> PolicyEnv {
    let steward_did = unique_did("steward");
    let records = Arc::new(Mutex::new(HashMap::new()));
    populate_standard_records(&records, &steward_did, policy_source).await;
    let pds_addr = start_mock_pds(records.clone()).await;
    let pds_url = format!("http://{pds_addr}");
    let mut docs = HashMap::new();
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);
    policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("initial onboard");
    PolicyEnv {
        state,
        records,
        steward_did,
    }
}

/// Drive a freshly begun request machine to completion and assert it produces
/// the expected JSON output.
fn assert_policy_output(step: ArbiterReqMachineStep, expected: Value) {
    match step {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json, expected, "unexpected policy output");
        }
        other => panic!("expected immediate completion with Data output, got {other:?}"),
    }
}

// ─── crypto / JWT helpers ───────────────────────────────────────────────────

/// Generate a P-256 key pair: `(private, public)`.
fn pds_keypair() -> (KeyData, KeyData) {
    let priv_key = generate_key(KeyType::P256Private).expect("generate p256 key");
    let pub_key = to_public(&priv_key).expect("derive public key");
    (priv_key, pub_key)
}

/// Mint a serviceAuth-style JWT signed by `priv_key` (the caller account's
/// key). Canonical ATProto serviceAuth tokens carry `iss` = caller DID and no
/// `sub` claim.
fn mint_service_auth(
    priv_key: &KeyData,
    iss: &str,
    aud: &str,
    lxm: &str,
    exp_secs: u64,
) -> String {
    let header = Header::try_from(priv_key.clone()).expect("jwt header from key");
    // Unique jti so the replay cache (keyed by (iss, jti)) never rejects a
    // freshly-minted token across tests that run in parallel.
    let jti = format!("test-{}", DID_COUNTER.fetch_add(1, Ordering::Relaxed));
    let claims = Claims {
        jose: JoseClaims {
            issuer: Some(iss.to_string()),
            audience: Some(aud.to_string()),
            expiration: Some(exp_secs),
            issued_at: Some(now_secs()),
            json_web_token_id: Some(jti),
            ..Default::default()
        },
        private: {
            let mut m = BTreeMap::new();
            m.insert("lxm".to_string(), Value::String(lxm.to_string()));
            m
        },
    };
    mint(priv_key, &header, &claims).expect("mint jwt")
}

/// Mint a serviceAuth-style JWT with an explicit `iat` and no `jti`.
fn mint_service_auth_with_iat(
    priv_key: &KeyData,
    iss: &str,
    aud: &str,
    lxm: &str,
    iat_secs: u64,
    exp_secs: u64,
    jti: Option<&str>,
) -> String {
    let header = Header::try_from(priv_key.clone()).expect("jwt header from key");
    let claims = Claims {
        jose: JoseClaims {
            issuer: Some(iss.to_string()),
            audience: Some(aud.to_string()),
            expiration: Some(exp_secs),
            issued_at: Some(iat_secs),
            json_web_token_id: jti.map(|s| s.to_string()),
            ..Default::default()
        },
        private: {
            let mut m = BTreeMap::new();
            m.insert("lxm".to_string(), Value::String(lxm.to_string()));
            m
        },
    };
    mint(priv_key, &header, &claims).expect("mint jwt")
}

// ─── auth test environment ──────────────────────────────────────────────────

struct AuthEnv {
    addr: SocketAddr,
    /// The caller account's signing keypair (serviceAuth tokens are signed by
    /// the caller, with `iss` = the caller DID).
    caller_priv: KeyData,
    caller_did: String,
    steward_did: String,
}

/// Stand up a full on-boarded server with a caller account holding a signing
/// key, start the axum router on a random port, and return everything the
/// auth tests need.
async fn auth_setup() -> AuthEnv {
    auth_setup_with(ECHO_POLICY).await
}

/// Like [`auth_setup`], but seeds the steward's pipeline with the given
/// policy source instead of [`ECHO_POLICY`].
async fn auth_setup_with(policy_source: &str) -> AuthEnv {
    let (caller_priv, caller_pub) = pds_keypair();
    // `KeyData::Display` emits `did:key:z...`; the verification method stores
    // the raw multibase (the part after `did:key:`).
    let pub_did_key = caller_pub.to_string();
    let multibase = pub_did_key
        .strip_prefix("did:key:")
        .expect("pub key is did:key: prefixed")
        .to_string();

    let steward_did = unique_did("steward");
    let caller_did = unique_did("caller");

    let records = Arc::new(Mutex::new(HashMap::new()));
    populate_standard_records(&records, &steward_did, policy_source).await;
    let pds_addr = start_mock_pds(records).await;
    let pds_url = format!("http://{pds_addr}");

    let mut docs = HashMap::new();
    // The caller account's DID doc exposes its signing key (serviceAuth tokens
    // are signed by the caller account, verified against its own DID doc).
    docs.insert(
        caller_did.clone(),
        did_doc(&caller_did, &pds_url, Some(&multibase)),
    );
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);
    // Credentials for the steward: the proxy path needs them to execute any
    // remote call a policy layer issues (the echo policy never issues one,
    // so the other auth tests are unaffected).
    state
        .store
        .store(
            steward_did.clone(),
            PdsCredentials {
                password: "steward-pw".to_string(),
                recovery_admin: "did:plc:testadmin".to_string(),
                provisioned: true,
            },
        )
        .await
        .expect("store creds for auth test");
    policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("onboard for auth test");

    let app = handlers::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind router");
    let addr = listener.local_addr().expect("router local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    AuthEnv {
        addr,
        caller_priv,
        caller_did,
        steward_did,
    }
}

/// Send a proxied request to `POST /xrpc/town.muni.arbiter.proxy`, optionally
/// with a Bearer JWT. The body names the arbiter DID, target, and inner
/// request (nsid = `com.example.foo`).
async fn xrpc_get(
    env: &AuthEnv,
    jwt: Option<String>,
    arbiter_did: Option<&str>,
) -> reqwest::Response {
    let url = format!("http://{}/xrpc/town.muni.arbiter.proxy", env.addr);
    let client = reqwest::Client::new();
    let mut req = client.post(&url);
    if let Some(j) = jwt {
        req = req.bearer_auth(j);
    }
    let mut body = json!({ "method": "GET", "nsid": "com.example.foo" });
    if let Some(d) = arbiter_did {
        body["arbiterDid"] = Value::String(d.to_string());
        body["target"] = Value::String(format!("{d}#atproto_pds"));
    }
    req.json(&body).send().await.expect("request sent")
}

/// A valid serviceAuth JWT bound to the proxy NSID for the given env.
fn valid_jwt(env: &AuthEnv) -> String {
    mint_service_auth(
        &env.caller_priv,
        &env.caller_did,
        SERVER_DID,
        "town.muni.arbiter.proxy",
        now_secs() + 60,
    )
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════

// ─── 1. policy loading + onboard ─────────────────────────────────────────────

#[tokio::test]
async fn policy_loading() {
    let env = policy_setup(ECHO_POLICY).await;

    assert!(
        is_serving(&env.state, &env.steward_did).await,
        "steward must be onboarded"
    );

    let mut drive = env
        .state
        .arbiters
        .begin_request(&env.steward_did, make_req(), RequestCtx::default())
        .await
        .expect("begin_request succeeds for onboarded arbiter");

    assert_policy_output(drive.machine.start(), json!({ "got": "com.example.foo" }));
}

// ─── 2. fail-closed when the PDS is unreachable ──────────────────────────────

#[tokio::test]
async fn fail_closed_when_pds_unreachable() {
    let did = unique_did("steward");
    // Resolver returns a valid DID doc, but its PDS endpoint is unreachable.
    let unreachable = "http://127.0.0.1:1";
    let mut docs = HashMap::new();
    docs.insert(did.clone(), did_doc(&did, unreachable, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);

    // Seed the credential store so `startup_onboard` has an account to load.
    state
        .store
        .store(
            did.clone(),
            test_creds("irrelevant"),
        )
        .await
        .expect("store creds");

    // `startup_onboard` retries with exponential backoff; the PDS never comes
    // up, so the arbiter must never be onboarded (fail-closed).
    let task_state = state.clone();
    let handle = tokio::spawn(async move { policy::startup_onboard(task_state).await });

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !is_serving(&state, &did).await,
        "PDS unreachable must not onboard the arbiter"
    );
    handle.abort();
}

// ─── 3. auth verification matrix ────────────────────────────────────────────

#[tokio::test]
async fn auth_valid_token() {
    let env = auth_setup().await;
    let resp = xrpc_get(&env, Some(valid_jwt(&env)), Some(env.steward_did.as_str())).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "valid token must be accepted"
    );
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(body, json!({ "got": "com.example.foo" }));
}

#[tokio::test]
async fn auth_invalid_signature() {
    let env = auth_setup().await;
    // Mint with a completely different key pair: the caller DID doc still
    // exposes the original public key, so verification must fail.
    let (other_priv, _) = pds_keypair();
    let jwt = mint_service_auth(
        &other_priv,
        &env.caller_did,
        SERVER_DID,
        "town.muni.arbiter.proxy",
        now_secs() + 60,
    );
    let resp = xrpc_get(&env, Some(jwt), Some(env.steward_did.as_str())).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "bad signature must be rejected"
    );
}

#[tokio::test]
async fn auth_expired_token() {
    let env = auth_setup().await;
    let jwt = mint_service_auth(
        &env.caller_priv,
        &env.caller_did,
        SERVER_DID,
        "town.muni.arbiter.proxy",
        now_secs().saturating_sub(10),
    );
    let resp = xrpc_get(&env, Some(jwt), Some(env.steward_did.as_str())).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "expired token must be rejected"
    );
}

#[tokio::test]
async fn auth_wrong_lxm() {
    let env = auth_setup().await;
    // Valid signature/aud/exp, but the bound lxm differs from the requested
    // (proxy) NSID.
    let jwt = mint_service_auth(
        &env.caller_priv,
        &env.caller_did,
        SERVER_DID,
        "town.muni.arbiter.somethingElse",
        now_secs() + 60,
    );
    let resp = xrpc_get(&env, Some(jwt), Some(env.steward_did.as_str())).await;
    assert!(
        resp.status().is_client_error(),
        "lxm/path mismatch must be rejected, got {}",
        resp.status()
    );
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_wrong_aud() {
    let env = auth_setup().await;
    let jwt = mint_service_auth(
        &env.caller_priv,
        &env.caller_did,
        "did:web:other.example",
        "town.muni.arbiter.proxy",
        now_secs() + 60,
    );
    let resp = xrpc_get(&env, Some(jwt), Some(env.steward_did.as_str())).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "wrong aud must be rejected"
    );
}

#[tokio::test]
async fn auth_missing_header() {
    let env = auth_setup().await;
    // No Authorization header at all.
    let resp = xrpc_get(&env, None, Some(env.steward_did.as_str())).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "missing Authorization must be rejected"
    );
}

#[tokio::test]
async fn auth_missing_arbiter_did() {
    let env = auth_setup().await;
    // Valid JWT, but the proxy body omits `arbiterDid` → 400.
    let resp = xrpc_get(&env, Some(valid_jwt(&env)), None).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "missing arbiterDid must be a 400"
    );
}

#[tokio::test]
async fn auth_replay_rejected() {
    // A token replayed with the same `jti` must be rejected the second time.
    let env = auth_setup().await;
    let jwt = mint_service_auth_with_iat(
        &env.caller_priv,
        &env.caller_did,
        SERVER_DID,
        "town.muni.arbiter.proxy",
        now_secs(),
        now_secs() + 60,
        Some("fixed-jti"),
    );
    let first = xrpc_get(&env, Some(jwt.clone()), Some(env.steward_did.as_str())).await;
    assert_eq!(first.status(), StatusCode::OK, "first use must be accepted");
    let second = xrpc_get(&env, Some(jwt), Some(env.steward_did.as_str())).await;
    assert_eq!(
        second.status(),
        StatusCode::UNAUTHORIZED,
        "replayed jti must be rejected"
    );
}

#[tokio::test]
async fn auth_missing_jti_rejected() {
    // A validly-signed token without a `jti` must be rejected.
    let env = auth_setup().await;
    let jwt = mint_service_auth_with_iat(
        &env.caller_priv,
        &env.caller_did,
        SERVER_DID,
        "town.muni.arbiter.proxy",
        now_secs(),
        now_secs() + 60,
        None,
    );
    let resp = xrpc_get(&env, Some(jwt), Some(env.steward_did.as_str())).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "missing jti must be rejected"
    );
}

#[tokio::test]
async fn auth_stale_iat_rejected() {
    // A token issued far in the past must be rejected even if `exp` is in the
    // future.
    let env = auth_setup().await;
    let jwt = mint_service_auth_with_iat(
        &env.caller_priv,
        &env.caller_did,
        SERVER_DID,
        "town.muni.arbiter.proxy",
        now_secs().saturating_sub(10 * 60), // 10 minutes ago
        now_secs() + 3600,
        Some("stale-jti"),
    );
    let resp = xrpc_get(&env, Some(jwt), Some(env.steward_did.as_str())).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "stale iat must be rejected"
    );
}

/// Stand up a server whose PDS DID doc exposes the given signing keys (in
/// order). The steward is onboarded and the router is listening.
async fn auth_setup_with_keys(caller_privs: &[&KeyData]) -> (SocketAddr, String, String, String) {
    let steward_did = unique_did("steward");
    let caller_did = unique_did("caller");

    let records = Arc::new(Mutex::new(HashMap::new()));
    populate_standard_records(&records, &steward_did, ECHO_POLICY).await;
    let pds_addr = start_mock_pds(records).await;
    let pds_url = format!("http://{pds_addr}");

    // `KeyData::Display` emits `did:key:z...`; the DID doc stores the raw
    // multibase (the part after `did:key:`).
    let multibases: Vec<String> = caller_privs
        .iter()
        .map(|p| {
            to_public(p)
                .expect("pub key")
                .to_string()
                .strip_prefix("did:key:")
                .expect("did:key: prefixed")
                .to_string()
        })
        .collect();
    let mb_refs: Vec<&str> = multibases.iter().map(|s| s.as_str()).collect();

    let mut docs = HashMap::new();
    // The caller account's DID doc exposes its signing keys (serviceAuth
    // tokens are signed by the caller account, verified against its own DID
    // document).
    docs.insert(
        caller_did.clone(),
        did_doc_multi(&caller_did, &pds_url, &mb_refs),
    );
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });

    let state = make_state(resolver);
    policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("onboard");

    let app = handlers::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind router");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (addr, caller_did.clone(), steward_did, caller_did)
}

#[tokio::test]
async fn auth_selects_key_by_kid_when_multiple() {
    // A PDS exposing two signing keys; a token signed by the SECOND key must
    // verify, because the verifier matches the token header `kid` rather than
    // blindly taking the first key.
    let (k1_priv, _) = pds_keypair();
    let (k2_priv, _) = pds_keypair();
    let (addr, caller_did, steward_did, _) =
        auth_setup_with_keys(&[&k1_priv, &k2_priv]).await;

    // Mint with the second key; its header `kid` is that key's did:key:.
    let jwt = mint_service_auth(
        &k2_priv,
        &caller_did,
        SERVER_DID,
        "town.muni.arbiter.proxy",
        now_secs() + 60,
    );
    let url = format!("http://{addr}/xrpc/town.muni.arbiter.proxy");
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&jwt)
        .json(&json!({
            "method": "GET",
            "nsid": "com.example.foo",
            "arbiterDid": steward_did,
            "target": format!("{steward_did}#atproto_pds"),
        }))
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "token signed by the second key must verify (kid-matched)"
    );
}

#[tokio::test]
async fn auth_key_rotation_not_served_stale() {
    // Rotate the PDS signing key: a DID doc change from key A to key B must be
    // picked up immediately (kid-keyed cache), not keep trusting the old key
    // for the whole TTL.
    let (old_priv, _) = pds_keypair();
    let (new_priv, _) = pds_keypair();
    let (addr, caller_did, steward_did, _) =
        auth_setup_with_keys(&[&old_priv, &new_priv]).await;

    let mint = |key: &KeyData| {
        mint_service_auth(
            key,
            &caller_did,
            SERVER_DID,
            "town.muni.arbiter.proxy",
            now_secs() + 60,
        )
    };

    // A token signed by the NEW key must verify even though the OLD key is
    // first in the DID doc.
    let url = format!("http://{addr}/xrpc/town.muni.arbiter.proxy");
    let client = reqwest::Client::new();
    let send = |jwt: String| {
        client
            .post(&url)
            .bearer_auth(&jwt)
            .json(&json!({
                "method": "GET",
                "nsid": "com.example.foo",
                "arbiterDid": steward_did,
                "target": format!("{steward_did}#atproto_pds"),
            }))
            .send()
    };

    // First a token with the old key (establishes a cached entry for old kid).
    let resp = send(mint(&old_priv)).await.expect("send old");
    assert_eq!(resp.status(), StatusCode::OK, "old-key token verifies");
    // Now a token with the new key — the DID doc still lists old first, but the
    // new key must be found by its kid and accepted (not rejected for a stale
    // cache entry).
    let resp = send(mint(&new_priv)).await.expect("send new");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "rotated-to key must verify (kid-keyed cache)"
    );
}

// ─── 4. hot reload updates policy ───────────────────────────────────────────

#[tokio::test]
async fn hot_reload_updates_policy() {
    // v1 returns a fixed "v1".
    let env = policy_setup(
        "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"v1\" } }",
    )
    .await;

    // Confirm v1 is active.
    let mut drive = env
        .state
        .arbiters
        .begin_request(&env.steward_did, make_req(), RequestCtx::default())
        .await
        .expect("begin v1");
    assert_policy_output(drive.machine.start(), json!({ "got": "v1" }));

    // Swap the pipeline's policy record to v2 and reload (simulates a
    // Jetstream reload after a `town.muni.arbiter.policy` write).
    {
        let mut m = env.records.lock().await;
        m.insert(
            (
                env.steward_did.clone(),
                POLICY_COLLECTION.into(),
                ECHO_POLICY_RKEY.into(),
            ),
            json!({ "policy": "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"v2\" } }" }),
        );
    }
    policy::load_and_onboard(&env.state, &env.steward_did)
        .await
        .expect("reload onboard");

    let mut drive = env
        .state
        .arbiters
        .begin_request(&env.steward_did, make_req(), RequestCtx::default())
        .await
        .expect("begin v2");
    assert_policy_output(drive.machine.start(), json!({ "got": "v2" }));
}

// ─── 5. auto-delete lifecycle ───────────────────────────────────────────────

#[tokio::test]
async fn auto_delete_service_absent() {
    let env = policy_setup(ECHO_POLICY).await;

    // Store credentials so we can assert they survive the offboard.
    env.state
        .store
        .store(
            env.steward_did.clone(),
            test_creds("kept"),
        )
        .await
        .expect("store creds");
    assert!(is_serving(&env.state, &env.steward_did).await);

    // Remove the service record → §4 lifecycle offboards but keeps credentials.
    {
        let mut m = env.records.lock().await;
        m.remove(&(
            env.steward_did.clone(),
            SERVICE_COLLECTION.into(),
            SERVICE_RKEY.into(),
        ));
    }
    policy::load_and_onboard(&env.state, &env.steward_did)
        .await
        .expect("reload after service removal");

    assert!(
        !is_serving(&env.state, &env.steward_did).await,
        "absent service record must offboard the arbiter"
    );
    let creds = env
        .state
        .store
        .get(&env.steward_did)
        .await
        .expect("store get");
    assert!(
        creds.is_some(),
        "credentials must be kept when the service record is merely absent"
    );
}

#[tokio::test]
async fn reimport_after_offboard_reonboards() {
    // Regression: after an offboard (service record absent), restoring the
    // service record and re-running onboarding must bring the arbiter back
    // online. The jetstream handler gates events with `is_newer`, which must
    // accept events for a DID that is currently offboarded (no floor to
    // regress) — otherwise a re-import never re-onboards.
    let env = policy_setup(ECHO_POLICY).await;

    env.state
        .store
        .store(
            env.steward_did.clone(),
            test_creds("kept"),
        )
        .await
        .expect("store creds");
    assert!(is_serving(&env.state, &env.steward_did).await);

    // Remove the service record → offboard.
    {
        let mut m = env.records.lock().await;
        m.remove(&(
            env.steward_did.clone(),
            SERVICE_COLLECTION.into(),
            SERVICE_RKEY.into(),
        ));
    }
    policy::load_and_onboard(&env.state, &env.steward_did)
        .await
        .expect("reload after service removal");
    assert!(
        !is_serving(&env.state, &env.steward_did).await,
        "absent service record must offboard the arbiter"
    );

    // Restore the service record (as a re-import would) and re-onboard.
    {
        let mut m = env.records.lock().await;
        m.insert(
            (
                env.steward_did.clone(),
                SERVICE_COLLECTION.into(),
                SERVICE_RKEY.into(),
            ),
            json!({ "did": SERVER_DID }),
        );
    }
    policy::load_and_onboard(&env.state, &env.steward_did)
        .await
        .expect("reload after service restore");
    assert!(
        is_serving(&env.state, &env.steward_did).await,
        "restored service record must re-onboard the arbiter"
    );
}

#[tokio::test]
async fn auto_delete_service_repointed() {
    let env = policy_setup(ECHO_POLICY).await;

    env.state
        .store
        .store(
            env.steward_did.clone(),
            test_creds("purge-me"),
        )
        .await
        .expect("store creds");
    assert!(is_serving(&env.state, &env.steward_did).await);

    // Repoint the service record at a different arbiter server.
    {
        let mut m = env.records.lock().await;
        m.insert(
            (
                env.steward_did.clone(),
                SERVICE_COLLECTION.into(),
                SERVICE_RKEY.into(),
            ),
            json!({ "did": "did:web:other.example" }),
        );
    }
    policy::load_and_onboard(&env.state, &env.steward_did)
        .await
        .expect("reload after service repoint");

    assert!(
        !is_serving(&env.state, &env.steward_did).await,
        "repointed service record must offboard the arbiter"
    );
    let creds = env
        .state
        .store
        .get(&env.steward_did)
        .await
        .expect("store get");
    assert!(
        creds.is_none(),
        "credentials must be purged when the service record is repointed at another server"
    );
}

#[tokio::test]
async fn unprovisioned_account_is_repaired_not_offboarded() {
    // A partially-provisioned account (bootstrap records never fully written,
    // `provisioned = false`) must be repaired by onboarding — its missing
    // service/recovery records rewritten — rather than offboarded as a
    // deliberate auto-delete.
    let steward_did = unique_did("steward");
    let records = Arc::new(Mutex::new(HashMap::new()));
    // Policy + config records present, but NO service record: mimics a
    // createArbiter that wrote credentials but failed before the bootstrap
    // records landed.
    {
        let mut m = records.lock().await;
        m.insert(
            (
                steward_did.clone(),
                POLICY_COLLECTION.to_string(),
                ECHO_POLICY_RKEY.to_string(),
            ),
            json!({ "policy": ECHO_POLICY }),
        );
        m.insert(
            (
                steward_did.clone(),
                CONFIG_COLLECTION.to_string(),
                CONFIG_RKEY.to_string(),
            ),
            json!({
                "trustedScopes": [TRUSTED_SCOPE],
                "policyLayers": [format!("at://{steward_did}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}")],
            }),
        );
    }
    let pds_addr = start_mock_pds(records.clone()).await;
    let pds_url = format!("http://{pds_addr}");

    let mut docs = HashMap::new();
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);

    // Store credentials marked UN-provisioned with the original recovery admin.
    state
        .store
        .store(
            steward_did.clone(),
            PdsCredentials {
                password: "unprovisioned-pw".to_string(),
                recovery_admin: "did:plc:creator".to_string(),
                provisioned: false,
            },
        )
        .await
        .expect("store creds");

    // Onboarding should repair the bootstrap records and bring the arbiter up.
    let pds = match policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("onboard repairs unprovisioned account")
    {
        policy::OnboardOutcome::Onboarded { pds_endpoint } => pds_endpoint,
        policy::OnboardOutcome::Offboarded { .. } => {
            panic!("repaired account must be onboarded, not offboarded")
        }
    };
    assert!(
        is_serving(&state, &steward_did).await,
        "repaired account must be serving"
    );
    assert_eq!(pds, pds_url);

    // The service + recovery records must now exist in the PDS.
    let svc = records
        .lock()
        .await
        .get(&(steward_did.clone(), SERVICE_COLLECTION.to_string(), SERVICE_RKEY.to_string()))
        .cloned();
    assert_eq!(
        svc.and_then(|v| v.get("did").and_then(|d| d.as_str()).map(String::from)),
        Some(SERVER_DID.to_string()),
        "service record must be repaired to point at this server"
    );
    let recovery = records
        .lock()
        .await
        .get(&(
            steward_did.clone(),
            "town.muni.arbiter.recovery".to_string(),
            "self".to_string(),
        ))
        .cloned();
    assert_eq!(
        recovery.and_then(|v| v.get("did").and_then(|d| d.as_str()).map(String::from)),
        Some("did:plc:creator".to_string()),
        "recovery record must be repaired with the persisted recovery admin"
    );

    // The account must now be marked provisioned.
    let creds = state
        .store
        .get(&steward_did)
        .await
        .expect("store get")
        .expect("creds present");
    assert!(creds.provisioned, "account must be marked provisioned after repair");
}

// ─── 5b. createArbiter (new-account provisioning) ────────────────────────────

/// Stand up a server whose `default_pds` points at a mock PDS, with a caller
/// account holding a signing key, and return the router address + caller
/// keypair/DID + the live state + the mock PDS record map.
async fn create_arbiter_setup() -> (SocketAddr, KeyData, String, Arc<AppState>, RecordMap) {
    let (caller_priv, caller_pub) = pds_keypair();
    let pub_did_key = caller_pub.to_string();
    let multibase = pub_did_key
        .strip_prefix("did:key:")
        .expect("pub key is did:key: prefixed")
        .to_string();

    let caller_did = unique_did("caller");
    let records = Arc::new(Mutex::new(HashMap::new()));
    let pds_addr = start_mock_pds(records.clone()).await;
    let pds_url = format!("http://{pds_addr}");

    let mut docs = HashMap::new();
    docs.insert(
        caller_did.clone(),
        did_doc(&caller_did, &pds_url, Some(&multibase)),
    );
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state_with_provisioning(resolver, pds_url, Some("test-invite".to_string()));

    let app = handlers::router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind router");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (addr, caller_priv, caller_did, state, records)
}

/// Mint a caller JWT bound to `createArbiter` for the given caller (issuer).
fn create_arbiter_jwt(caller_priv: &KeyData, caller_did: &str) -> String {
    mint_service_auth(
        caller_priv,
        caller_did,
        SERVER_DID,
        "town.muni.arbiter.createArbiter",
        now_secs() + 60,
    )
}

#[tokio::test]
async fn create_arbiter_provisions_account_and_stays_offline() {
    let (addr, caller_priv, caller_did, state, records) = create_arbiter_setup().await;
    let jwt = create_arbiter_jwt(&caller_priv, &caller_did);

    let url = format!("http://{addr}/xrpc/town.muni.arbiter.createArbiter");
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("createArbiter request");
    assert_eq!(resp.status(), StatusCode::OK, "createArbiter should succeed");
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body.get("did").and_then(|v| v.as_str()),
        Some("did:plc:mockpds"),
        "createArbiter must return the created account's DID"
    );

    // The mock PDS returns a fixed DID for every created account; the server
    // must have persisted credentials for it, marked provisioned (bootstrap
    // records written).
    let created_did = "did:plc:mockpds";
    let creds = state
        .store
        .get(created_did)
        .await
        .expect("store get")
        .expect("credentials persisted for created account");
    assert!(creds.provisioned, "account must be marked provisioned");
    assert_eq!(
        creds.recovery_admin, caller_did,
        "recovery admin must be the creating caller"
    );

    // The service + recovery bootstrap records must have been written to the
    // new account's repo on the mock PDS.
    let svc = records
        .lock()
        .await
        .get(&(
            created_did.to_string(),
            SERVICE_COLLECTION.to_string(),
            SERVICE_RKEY.to_string(),
        ))
        .cloned();
    assert_eq!(
        svc.and_then(|v| v.get("did").and_then(|d| d.as_str()).map(String::from)),
        Some(SERVER_DID.to_string()),
        "service record must point at this server"
    );
    let recovery = records
        .lock()
        .await
        .get(&(
            created_did.to_string(),
            "town.muni.arbiter.recovery".to_string(),
            "self".to_string(),
        ))
        .cloned();
    assert_eq!(
        recovery.and_then(|v| v.get("did").and_then(|d| d.as_str()).map(String::from)),
        Some(caller_did.clone()),
        "recovery record must designate the creating caller"
    );

    // No policy/config records are written and the arbiter is NOT brought
    // online: it stays offline (fail-closed) until installPolicy performs the
    // first install.
    let records_map = records.lock().await;
    let policy = records_map.get(&(
        created_did.to_string(),
        POLICY_COLLECTION.to_string(),
        ECHO_POLICY_RKEY.to_string(),
    ));
    let config = records_map.get(&(
        created_did.to_string(),
        CONFIG_COLLECTION.to_string(),
        CONFIG_RKEY.to_string(),
    ));
    assert!(
        policy.is_none() && config.is_none(),
        "no policy/config record may be written by createArbiter"
    );
}

#[tokio::test]
async fn create_arbiter_returns_provisioning_failed_on_pds_error() {
    // A mock PDS whose createAccount fails must surface the lexicon's
    // `ErrProvisioningFailed` error (not a generic 500), so clients can
    // distinguish a provisioning failure from other server errors.
    let (caller_priv, caller_pub) = pds_keypair();
    let multibase = caller_pub
        .to_string()
        .strip_prefix("did:key:")
        .expect("pub key is did:key: prefixed")
        .to_string();
    let caller_did = unique_did("caller");
    let records = Arc::new(Mutex::new(HashMap::new()));
    let pds_addr = start_mock_pds_with_fail(records, true).await;
    let pds_url = format!("http://{pds_addr}");

    let mut docs = HashMap::new();
    docs.insert(
        caller_did.clone(),
        did_doc(&caller_did, &pds_url, Some(&multibase)),
    );
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state_with_provisioning(resolver, pds_url, Some("test-invite".to_string()));
    let app = handlers::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind router");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let jwt = create_arbiter_jwt(&caller_priv, &caller_did);
    let url = format!("http://{addr}/xrpc/town.muni.arbiter.createArbiter");
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("createArbiter request");
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "provisioning failure must be a 500"
    );
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("ErrProvisioningFailed"),
        "error code must match the lexicon's ErrProvisioningFailed"
    );
    assert!(
        body.get("message")
            .and_then(|v| v.as_str())
            .is_some_and(|m| m.contains("createAccount")),
        "error message should carry the createAccount detail"
    );
}

// ─── 5c. createAppPasswordArbiter (import existing account) ────────────────

/// Stand up a server with a mock PDS and a caller account holding a signing
/// key, and return the router address + caller keypair/DID + the live state +
/// the mock PDS record map. `arbiter_did` is the account to import; its DID
/// doc points at the mock PDS.
async fn create_app_password_setup(
    arbiter_did: &str,
) -> (SocketAddr, KeyData, String, Arc<AppState>, RecordMap) {
    let (caller_priv, caller_pub) = pds_keypair();
    let multibase = caller_pub
        .to_string()
        .strip_prefix("did:key:")
        .expect("pub key is did:key: prefixed")
        .to_string();
    let caller_did = unique_did("caller");
    let records = Arc::new(Mutex::new(HashMap::new()));
    let pds_addr = start_mock_pds(records.clone()).await;
    let pds_url = format!("http://{pds_addr}");

    let mut docs = HashMap::new();
    docs.insert(
        caller_did.clone(),
        did_doc(&caller_did, &pds_url, Some(&multibase)),
    );
    docs.insert(
        arbiter_did.to_string(),
        did_doc(arbiter_did, &pds_url, None),
    );
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);

    let app = handlers::router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind router");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (addr, caller_priv, caller_did, state, records)
}

/// Mint a caller JWT bound to `createAppPasswordArbiter` for the given caller.
fn create_app_password_jwt(caller_priv: &KeyData, caller_did: &str) -> String {
    mint_service_auth(
        caller_priv,
        caller_did,
        SERVER_DID,
        "town.muni.arbiter.createAppPasswordArbiter",
        now_secs() + 60,
    )
}

#[tokio::test]
async fn create_app_password_arbiter_imports_and_stays_offline() {
    let arbiter_did = unique_did("import");
    let (addr, caller_priv, caller_did, state, records) =
        create_app_password_setup(&arbiter_did).await;
    let jwt = create_app_password_jwt(&caller_priv, &caller_did);

    let url = format!("http://{addr}/xrpc/town.muni.arbiter.createAppPasswordArbiter");
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&jwt)
        .json(&json!({ "arbiterDid": arbiter_did, "appPassword": "app-pw" }))
        .send()
        .await
        .expect("createAppPasswordArbiter request");
    assert_eq!(resp.status(), StatusCode::OK, "import should succeed");
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(body, json!({ "ok": true }));

    // Credentials persisted, marked provisioned, recovery admin = caller.
    let creds = state
        .store
        .get(&arbiter_did)
        .await
        .expect("store get")
        .expect("credentials persisted for imported account");
    assert!(creds.provisioned, "account must be marked provisioned");
    assert_eq!(creds.recovery_admin, caller_did);

    // Service + recovery records written to the imported account's repo.
    let svc = records
        .lock()
        .await
        .get(&(
            arbiter_did.clone(),
            SERVICE_COLLECTION.to_string(),
            SERVICE_RKEY.to_string(),
        ))
        .cloned();
    assert_eq!(
        svc.and_then(|v| v.get("did").and_then(|d| d.as_str()).map(String::from)),
        Some(SERVER_DID.to_string()),
        "service record must point at this server"
    );
    let recovery = records
        .lock()
        .await
        .get(&(
            arbiter_did.clone(),
            "town.muni.arbiter.recovery".to_string(),
            "self".to_string(),
        ))
        .cloned();
    assert_eq!(
        recovery.and_then(|v| v.get("did").and_then(|d| d.as_str()).map(String::from)),
        Some(caller_did.clone()),
        "recovery record must designate the importing caller"
    );

    // No policy/config records are written; the arbiter stays offline until
    // installPolicy performs the first install.
    let records_map = records.lock().await;
    let policy = records_map.get(&(
        arbiter_did.clone(),
        POLICY_COLLECTION.to_string(),
        ECHO_POLICY_RKEY.to_string(),
    ));
    let config = records_map.get(&(
        arbiter_did.clone(),
        CONFIG_COLLECTION.to_string(),
        CONFIG_RKEY.to_string(),
    ));
    assert!(
        policy.is_none() && config.is_none(),
        "no policy/config record may be written by import"
    );
}

#[tokio::test]
async fn create_app_password_arbiter_rejects_duplicate() {
    let arbiter_did = unique_did("import");
    let (addr, caller_priv, caller_did, state, _records) =
        create_app_password_setup(&arbiter_did).await;
    // Pre-seed credentials so the arbiter already exists on this server.
    state
        .store
        .store(
            arbiter_did.clone(),
            test_creds("existing-pw"),
        )
        .await
        .expect("store creds");
    let jwt = create_app_password_jwt(&caller_priv, &caller_did);

    let url = format!("http://{addr}/xrpc/town.muni.arbiter.createAppPasswordArbiter");
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&jwt)
        .json(&json!({ "arbiterDid": arbiter_did, "appPassword": "app-pw" }))
        .send()
        .await
        .expect("createAppPasswordArbiter request");
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "duplicate import must be a 409"
    );
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("ErrArbiterAlreadyExists"),
        "error code must match the lexicon's ErrArbiterAlreadyExists"
    );
}

#[tokio::test]
async fn create_app_password_arbiter_denies_bad_app_password() {
    // A mock PDS whose createSession fails (bad app password) must surface the
    // lexicon's `ErrPermissionDenied` error.
    let arbiter_did = unique_did("import");
    let (caller_priv, caller_pub) = pds_keypair();
    let multibase = caller_pub
        .to_string()
        .strip_prefix("did:key:")
        .expect("pub key is did:key: prefixed")
        .to_string();
    let caller_did = unique_did("caller");
    let records = Arc::new(Mutex::new(HashMap::new()));
    let pds_addr = start_mock_pds_with_fail_session(records, true).await;
    let pds_url = format!("http://{pds_addr}");

    let mut docs = HashMap::new();
    docs.insert(
        caller_did.clone(),
        did_doc(&caller_did, &pds_url, Some(&multibase)),
    );
    docs.insert(
        arbiter_did.clone(),
        did_doc(&arbiter_did, &pds_url, None),
    );
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);
    let app = handlers::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind router");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let jwt = create_app_password_jwt(&caller_priv, &caller_did);
    let url = format!("http://{addr}/xrpc/town.muni.arbiter.createAppPasswordArbiter");
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&jwt)
        .json(&json!({ "arbiterDid": arbiter_did, "appPassword": "wrong-pw" }))
        .send()
        .await
        .expect("createAppPasswordArbiter request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "bad app password must be forbidden"
    );
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("ErrPermissionDenied"),
        "error code must match the lexicon's ErrPermissionDenied"
    );
}



// ─── 6. installPolicy (recovery admin) ──────────────────────────────────────

/// Start the axum router for `state` on a random port.
async fn start_router(state: Arc<AppState>) -> SocketAddr {
    let app = handlers::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind router");
    let addr = listener.local_addr().expect("router local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// Everything [`install_setup_full`] provisions, plus a second non-admin
/// caller identity (signing keypair + DID doc), for exercising the
/// pipeline-gated `installPolicy` and `resetConfig` paths.
struct InstallEnv {
    addr: SocketAddr,
    admin_priv: KeyData,
    admin_did: String,
    steward_did: String,
    records: RecordMap,
    state: Arc<AppState>,
    caller_priv: KeyData,
    caller_did: String,
}

/// Stand up a server where the steward's `town.muni.arbiter.recovery/self`
/// record designates `admin_did` (the credential row keeps the same DID as its
/// bootstrap designation), and return the router address + a signing keypair
/// for minting the admin's JWTs + the steward/admin DIDs + the mock PDS record
/// map + the live state (the router keeps its own clone).
async fn install_setup() -> (SocketAddr, KeyData, String, String, RecordMap, Arc<AppState>) {
    let env = install_setup_full().await;
    (
        env.addr,
        env.admin_priv,
        env.admin_did,
        env.steward_did,
        env.records,
        env.state,
    )
}

/// Like [`install_setup`], but also provisions a non-admin caller account and
/// returns everything as an [`InstallEnv`].
async fn install_setup_full() -> InstallEnv {
    let steward_did = unique_did("steward");
    let admin_did = unique_did("admin");
    let caller_did = unique_did("caller");
    let records = Arc::new(Mutex::new(HashMap::new()));

    populate_standard_records(&records, &steward_did, ECHO_POLICY).await;
    {
        let mut m = records.lock().await;
        m.insert(
            (
                steward_did.clone(),
                "town.muni.arbiter.recovery".to_string(),
                "self".to_string(),
            ),
            json!({ "did": admin_did }),
        );
    }

    let pds_addr = start_mock_pds(records.clone()).await;
    let pds_url = format!("http://{pds_addr}");

    // The admin and caller accounts carry signing keys, so their serviceAuth
    // JWTs verify against their own DID docs.
    let (admin_priv, admin_pub) = pds_keypair();
    let admin_multibase = admin_pub
        .to_string()
        .strip_prefix("did:key:")
        .expect("pub key is did:key: prefixed")
        .to_string();
    let (caller_priv, caller_pub) = pds_keypair();
    let caller_multibase = caller_pub
        .to_string()
        .strip_prefix("did:key:")
        .expect("pub key is did:key: prefixed")
        .to_string();

    let mut docs = HashMap::new();
    docs.insert(
        admin_did.clone(),
        did_doc(&admin_did, &pds_url, Some(&admin_multibase)),
    );
    docs.insert(
        caller_did.clone(),
        did_doc(&caller_did, &pds_url, Some(&caller_multibase)),
    );
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);
    // The credential row's recovery_admin is the bootstrap designation (used
    // by repair_provisioning); the record seeded above is the runtime authority.
    state
        .store
        .store(
            steward_did.clone(),
            PdsCredentials {
                password: "steward-pw".to_string(),
                recovery_admin: admin_did.clone(),
                provisioned: true,
            },
        )
        .await
        .expect("store creds");
    policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("onboard");

    let addr = start_router(state.clone()).await;
    InstallEnv {
        addr,
        admin_priv,
        admin_did,
        steward_did,
        records,
        state,
        caller_priv,
        caller_did,
    }
}

/// Mint a caller JWT bound to `installPolicy` for the given admin (issuer).
fn install_jwt(admin_priv: &KeyData, admin_did: &str) -> String {
    mint_service_auth(
        admin_priv,
        admin_did,
        SERVER_DID,
        "town.muni.arbiter.installPolicy",
        now_secs() + 60,
    )
}

/// Mint a caller JWT bound to `resetConfig` for the given admin (issuer).
fn reset_jwt(admin_priv: &KeyData, admin_did: &str) -> String {
    mint_service_auth(
        admin_priv,
        admin_did,
        SERVER_DID,
        "town.muni.arbiter.resetConfig",
        now_secs() + 60,
    )
}
#[tokio::test]
async fn install_policy_as_recovery_admin() {
    let (addr, admin_priv, admin_did, steward_did, records, state) = install_setup().await;
    let jwt = install_jwt(&admin_priv, &admin_did);

    // The caller writes the policy record to a repo themselves (here: the
    // stewarded repo, via the mock PDS map); installPolicy only references
    // it — it must never write policy records.
    let installed_rkey = "installed";
    let installed_uri =
        format!("at://{steward_did}/{POLICY_COLLECTION}/{installed_rkey}");
    let installed_src =
        "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"installed\" } }";
    records.lock().await.insert(
        (
            steward_did.clone(),
            POLICY_COLLECTION.to_string(),
            installed_rkey.to_string(),
        ),
        json!({ "policy": installed_src }),
    );

    let url = format!("http://{addr}/xrpc/town.muni.arbiter.installPolicy");
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(&jwt)
        .json(&json!({
            "arbiterDid": steward_did,
            "policy": installed_uri,
            "trustedScopes": ["community.other.thing"],
        }))
        .send()
        .await
        .expect("send installPolicy");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "recovery admin must be able to install the policy"
    );
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(body, json!({ "ok": true }));

    // The install APPENDED: the config carries echo (still first) + the
    // installed layer, and the scopes are unioned (existing order kept).
    let echo_uri = format!("at://{steward_did}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}");
    let map = records.lock().await;
    let config = map
        .get(&(
            steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record written by install");
    assert_eq!(
        config.get("policyLayers").and_then(|v| v.as_array()),
        Some(&vec![json!(echo_uri), json!(installed_uri)]),
        "the referenced layer must be appended at the END of the pipeline"
    );
    assert_eq!(
        config.get("trustedScopes").and_then(|v| v.as_array()),
        Some(&vec![json!(TRUSTED_SCOPE), json!("community.other.thing")]),
        "trusted scopes must be unioned, preserving the existing order"
    );
    // The referenced record is exactly what the caller wrote — the server
    // must not have touched (or added) any policy record.
    assert_eq!(
        map.get(&(
            steward_did.clone(),
            POLICY_COLLECTION.to_string(),
            installed_rkey.to_string(),
        )),
        Some(&json!({ "policy": installed_src })),
        "the referenced policy record must be the caller's write, verbatim"
    );
    let server_written: Vec<_> = map
        .keys()
        .filter(|(r, c, _)| r == &steward_did && c == POLICY_COLLECTION)
        .map(|(_, _, rk)| rk.clone())
        .collect();
    assert_eq!(
        server_written.len(),
        2,
        "no policy records beyond the caller's may be written: {server_written:?}"
    );
    drop(map);

    // The install re-onboarded the arbiter with the appended pipeline: it is
    // serving, and the FIRST layer (echo) still answers — an appended layer
    // only sees requests the existing layers pass.
    assert!(
        is_serving(&state, &steward_did).await,
        "install must re-onboard the arbiter with the appended pipeline"
    );
    let mut drive = state
        .arbiters
        .begin_request(&steward_did, make_req(), RequestCtx::default())
        .await
        .expect("begin appended pipeline");
    assert_policy_output(drive.machine.start(), json!({ "got": "com.example.foo" }));
}

/// POST an installPolicy call as the recovery admin: `policy_uri` (when
/// carried) is appended at the end of the pipeline, `scopes` are unioned in.
async fn admin_append(
    addr: &SocketAddr,
    admin_priv: &KeyData,
    admin_did: &str,
    steward_did: &str,
    policy_uri: Option<&str>,
    scopes: &[&str],
) -> reqwest::Response {
    let mut body = json!({
        "arbiterDid": steward_did,
        "trustedScopes": scopes,
    });
    if let Some(uri) = policy_uri {
        body["policy"] = json!(uri);
    }
    let jwt = install_jwt(admin_priv, admin_did);
    install_call(*addr, &jwt, body).await
}

/// Seed a policy record the CALLER wrote (installPolicy never writes policy
/// records) and return nothing; the map is the mock PDS's record store.
async fn seed_policy_record(records: &RecordMap, repo: &str, rkey: &str, src: &str) {
    records.lock().await.insert(
        (
            repo.to_string(),
            POLICY_COLLECTION.to_string(),
            rkey.to_string(),
        ),
        json!({ "policy": src }),
    );
}
/// Read the current config record for `steward_did` from the mock PDS map.
async fn stored_config(records: &RecordMap, steward_did: &str) -> Value {
    records
        .lock()
        .await
        .get(&(
            steward_did.to_string(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record")
}

#[tokio::test]
async fn install_policy_appends_sequential_entries_in_order() {
    // (a) Two sequential installs append two entries, in order, after the
    // existing layers. (f) The append lands at the END: echo stays first and
    // keeps answering — an appended layer only sees requests the community's
    // existing layers pass.
    let (addr, admin_priv, admin_did, steward_did, records, state) = install_setup().await;

    let a_uri = format!("at://{steward_did}/{POLICY_COLLECTION}/layer-a");
    let b_uri = format!("at://{steward_did}/{POLICY_COLLECTION}/layer-b");
    seed_policy_record(
        &records,
        &steward_did,
        "layer-a",
        "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"a\" } }",
    )
    .await;
    seed_policy_record(
        &records,
        &steward_did,
        "layer-b",
        "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"b\" } }",
    )
    .await;

    let resp = admin_append(&addr, &admin_priv, &admin_did, &steward_did, Some(&a_uri), &[TRUSTED_SCOPE]).await;
    assert_eq!(resp.status(), StatusCode::OK, "the first append must succeed");
    let resp = admin_append(&addr, &admin_priv, &admin_did, &steward_did, Some(&b_uri), &[]).await;
    assert_eq!(resp.status(), StatusCode::OK, "the second append must succeed");

    let echo_uri = format!("at://{steward_did}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}");
    let config = records
        .lock()
        .await
        .get(&(
            steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record");
    assert_eq!(
        config.get("policyLayers").and_then(|v| v.as_array()),
        Some(&vec![json!(echo_uri), json!(a_uri), json!(b_uri)]),
        "sequential installs must append in order after the existing layers"
    );

    // Echo (the first layer) still answers: existing layers keep priority.
    let mut drive = state
        .arbiters
        .begin_request(&steward_did, make_req(), RequestCtx::default())
        .await
        .expect("begin appended pipeline");
    assert_policy_output(drive.machine.start(), json!({ "got": "com.example.foo" }));
}

#[tokio::test]
async fn install_policy_reinstall_keeps_position_and_updates_record() {
    // (b) Re-installing a policy whose URI is already in the pipeline does
    // not duplicate the entry or elevate its priority: the position is kept.
    // The record content changed in the caller's repo (v1 → v2); the
    // re-onboard picks it up (compiled layers are keyed by record CID).
    let (addr, admin_priv, admin_did, steward_did, records, state) = install_setup().await;

    let uri = format!("at://{steward_did}/{POLICY_COLLECTION}/shared");
    let v1 = "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"v1\" } }";
    let v2 = "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"v2\" } }";
    seed_policy_record(&records, &steward_did, "shared", v1).await;

    let resp = admin_append(&addr, &admin_priv, &admin_did, &steward_did, Some(&uri), &[TRUSTED_SCOPE]).await;
    assert_eq!(resp.status(), StatusCode::OK, "the first install must succeed");

    // The caller updates the record in their repo, then re-installs the
    // SAME URI.
    seed_policy_record(&records, &steward_did, "shared", v2).await;
    let resp = admin_append(&addr, &admin_priv, &admin_did, &steward_did, Some(&uri), &[TRUSTED_SCOPE]).await;
    assert_eq!(resp.status(), StatusCode::OK, "the re-install must succeed");

    let echo_uri = format!("at://{steward_did}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}");
    {
        let map = records.lock().await;
        let config = map
            .get(&(
                steward_did.clone(),
                CONFIG_COLLECTION.to_string(),
                CONFIG_RKEY.to_string(),
            ))
            .cloned()
            .expect("config record");
        assert_eq!(
            config.get("policyLayers").and_then(|v| v.as_array()),
            Some(&vec![json!(echo_uri), json!(uri)]),
            "the re-install must keep the entry's position without duplicating it"
        );
        assert_eq!(
            map.get(&(
                steward_did.clone(),
                POLICY_COLLECTION.to_string(),
                "shared".to_string(),
            )),
            Some(&json!({ "policy": v2 })),
            "the referenced record must carry the caller's updated content"
        );
    }

    // Prove the updated content is live: reset the pipeline to just the
    // shared layer and drive a request — it answers with v2.
    let jwt = reset_jwt(&admin_priv, &admin_did);
    let resp = reset_call(
        addr,
        &jwt,
        json!({
            "arbiterDid": steward_did,
            "trustedScopes": [TRUSTED_SCOPE],
            "policyLayers": [uri],
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "reset to the shared layer");
    let mut drive = state
        .arbiters
        .begin_request(&steward_did, make_req(), RequestCtx::default())
        .await
        .expect("begin shared layer");
    assert_policy_output(drive.machine.start(), json!({ "got": "v2" }));
}

#[tokio::test]
async fn install_policy_scopes_union_dedupes_preserving_order() {
    // (c) trustedScopes are UNIONED: already-trusted entries keep their
    // position, new ones append, duplicates are dropped — installing with a
    // subset + one new scope never removes or reorders the existing set.
    let (addr, admin_priv, admin_did, steward_did, records, _state) = install_setup().await;

    let resp = admin_append(
        &addr,
        &admin_priv,
        &admin_did,
        &steward_did,
        None,
        &[TRUSTED_SCOPE, "community.new.thing"],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "the scope install must succeed");

    assert_eq!(
        stored_config(&records, &steward_did)
            .await
            .get("trustedScopes")
            .and_then(|v| v.as_array()),
        Some(&vec![json!(TRUSTED_SCOPE), json!("community.new.thing")]),
        "the union must dedupe and preserve the existing order"
    );

    // Another install with overlapping + one more new scope keeps appending.
    let resp = admin_append(
        &addr,
        &admin_priv,
        &admin_did,
        &steward_did,
        None,
        &["community.other.thing", TRUSTED_SCOPE],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        stored_config(&records, &steward_did)
            .await
            .get("trustedScopes")
            .and_then(|v| v.as_array()),
        Some(&vec![
            json!(TRUSTED_SCOPE),
            json!("community.new.thing"),
            json!("community.other.thing"),
        ]),
        "repeated installs must keep appending new scopes without reordering"
    );
}

#[tokio::test]
async fn install_policy_scope_only_appends_scopes_without_pipeline_change() {
    // A scope-only install (no `policy` field) unions the scopes and leaves
    // the pipeline untouched — the scopes editor's single-call save.
    let (addr, admin_priv, admin_did, steward_did, records, _state) = install_setup().await;

    let echo_uri = format!("at://{steward_did}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}");
    let resp = admin_append(&addr, &admin_priv, &admin_did, &steward_did, None, &["community.other.thing"]).await;
    assert_eq!(resp.status(), StatusCode::OK, "the scope-only install must succeed");

    let config = records
        .lock()
        .await
        .get(&(
            steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record");
    assert_eq!(
        config.get("trustedScopes").and_then(|v| v.as_array()),
        Some(&vec![json!(TRUSTED_SCOPE), json!("community.other.thing")]),
        "the scope-only install must union the scopes"
    );
    assert_eq!(
        config.get("policyLayers").and_then(|v| v.as_array()),
        Some(&vec![json!(echo_uri)]),
        "the scope-only install must not touch the pipeline"
    );
}

#[tokio::test]
async fn install_policy_empty_scopes_preserve_existing_scopes() {
    // (d) An install with an EMPTY trustedScopes array (a policy-only
    // install) preserves the existing scopes entirely.
    let (addr, admin_priv, admin_did, steward_did, records, state) = install_setup().await;

    let uri = format!("at://{steward_did}/{POLICY_COLLECTION}/scoped");
    seed_policy_record(
        &records,
        &steward_did,
        "scoped",
        "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"scoped\" } }",
    )
    .await;
    let resp = admin_append(&addr, &admin_priv, &admin_did, &steward_did, Some(&uri), &[]).await;
    assert_eq!(resp.status(), StatusCode::OK, "the policy-only install must succeed");

    let echo_uri = format!("at://{steward_did}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}");
    let config = records
        .lock()
        .await
        .get(&(
            steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record");
    assert_eq!(
        config.get("trustedScopes").and_then(|v| v.as_array()),
        Some(&vec![json!(TRUSTED_SCOPE)]),
        "an empty trustedScopes array must preserve the existing scopes"
    );
    assert_eq!(
        config.get("policyLayers").and_then(|v| v.as_array()),
        Some(&vec![json!(echo_uri), json!(uri)]),
        "the policy-only install must still append the layer"
    );
    assert!(
        is_serving(&state, &steward_did).await,
        "the arbiter must re-onboard with the appended layer"
    );
}

#[tokio::test]
async fn install_policy_references_remote_repo_record() {
    // (e) The referenced record may live in ANY repo: a shared app-owned
    // record is appended without the server writing any local record —
    // one shared record can serve many communities.
    let steward_did = unique_did("steward");
    let admin_did = unique_did("admin");
    let remote_did = unique_did("app");
    let records = Arc::new(Mutex::new(HashMap::new()));

    populate_standard_records(&records, &steward_did, ECHO_POLICY).await;
    {
        let mut m = records.lock().await;
        m.insert(
            (
                steward_did.clone(),
                "town.muni.arbiter.recovery".to_string(),
                "self".to_string(),
            ),
            json!({ "did": admin_did }),
        );
    }
    // The shared app-owned policy record, written by its owner.
    let shared_uri = format!("at://{remote_did}/{POLICY_COLLECTION}/shared");
    let shared_src =
        "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"shared\" } }";
    seed_policy_record(&records, &remote_did, "shared", shared_src).await;

    let pds_addr = start_mock_pds(records.clone()).await;
    let pds_url = format!("http://{pds_addr}");
    let (admin_priv, admin_pub) = pds_keypair();
    let admin_multibase = admin_pub
        .to_string()
        .strip_prefix("did:key:")
        .expect("pub key is did:key: prefixed")
        .to_string();
    let mut docs = HashMap::new();
    docs.insert(
        admin_did.clone(),
        did_doc(&admin_did, &pds_url, Some(&admin_multibase)),
    );
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    docs.insert(remote_did.clone(), did_doc(&remote_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);
    state
        .store
        .store(
            steward_did.clone(),
            PdsCredentials {
                password: "steward-pw".to_string(),
                recovery_admin: admin_did.clone(),
                provisioned: true,
            },
        )
        .await
        .expect("store creds");
    policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("onboard");
    let addr = start_router(state.clone()).await;

    let resp = admin_append(&addr, &admin_priv, &admin_did, &steward_did, Some(&shared_uri), &[TRUSTED_SCOPE]).await;
    assert_eq!(resp.status(), StatusCode::OK, "the remote-reference install must succeed");

    let echo_uri = format!("at://{steward_did}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}");
    let map = records.lock().await;
    let config = map
        .get(&(
            steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record");
    assert_eq!(
        config.get("policyLayers").and_then(|v| v.as_array()),
        Some(&vec![json!(echo_uri), json!(shared_uri)]),
        "the remote record's URI must be appended at the end"
    );
    // No LOCAL policy record was written by the install: the steward's repo
    // carries only the pre-existing echo record.
    let steward_policy_records: Vec<_> = map
        .keys()
        .filter(|(r, c, _)| r == &steward_did && c == POLICY_COLLECTION)
        .map(|(_, _, rk)| rk.clone())
        .collect();
    assert_eq!(
        steward_policy_records,
        vec![ECHO_POLICY_RKEY.to_string()],
        "installPolicy must not write any policy record: {steward_policy_records:?}"
    );
    drop(map);
    assert!(
        is_serving(&state, &steward_did).await,
        "the arbiter must re-onboard with the remote layer"
    );
}

#[tokio::test]
async fn install_policy_noop_reinstall_skips_config_write() {
    // (g) A re-install that changes nothing (URI already installed, scopes
    // unchanged) must NOT rewrite the config record: its content is already
    // exactly what the request would produce. Asserted on the mock's record
    // map: the stored value is identical after the no-op install.
    let (addr, admin_priv, admin_did, steward_did, records, _state) = install_setup().await;

    let uri = format!("at://{steward_did}/{POLICY_COLLECTION}/noop");
    seed_policy_record(
        &records,
        &steward_did,
        "noop",
        "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"noop\" } }",
    )
    .await;
    let resp = admin_append(&addr, &admin_priv, &admin_did, &steward_did, Some(&uri), &[TRUSTED_SCOPE]).await;
    assert_eq!(resp.status(), StatusCode::OK, "the first install must succeed");

    let config_key = (
        steward_did.clone(),
        CONFIG_COLLECTION.to_string(),
        CONFIG_RKEY.to_string(),
    );
    let before = records
        .lock()
        .await
        .get(&config_key)
        .cloned()
        .expect("config record after first install");

    let resp = admin_append(&addr, &admin_priv, &admin_did, &steward_did, Some(&uri), &[TRUSTED_SCOPE]).await;
    assert_eq!(resp.status(), StatusCode::OK, "the no-op re-install must succeed");

    let after = records
        .lock()
        .await
        .get(&config_key)
        .cloned()
        .expect("config record after no-op re-install");
    assert_eq!(
        after, before,
        "a no-op re-install must skip the config write entirely"
    );
}

#[tokio::test]
async fn install_policy_bootstraps_onto_absent_config() {
    // Bootstrap: with NO config record in the repo (a provisioned-but-
    // unconfigured arbiter), the first install appends onto the empty
    // config — the created pipeline is exactly the referenced layer and the
    // arbiter comes online.
    let (addr, admin_priv, admin_did, steward_did, records, state) = install_setup().await;
    records.lock().await.remove(&(
        steward_did.clone(),
        CONFIG_COLLECTION.to_string(),
        CONFIG_RKEY.to_string(),
    ));

    let uri = format!("at://{steward_did}/{POLICY_COLLECTION}/first");
    let first_src =
        "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"installed\" } }";
    seed_policy_record(&records, &steward_did, "first", first_src).await;
    let resp = admin_append(&addr, &admin_priv, &admin_did, &steward_did, Some(&uri), &["community.other.thing"]).await;
    assert_eq!(resp.status(), StatusCode::OK, "the bootstrap install must succeed");

    let config = records
        .lock()
        .await
        .get(&(
            steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record written by the bootstrap install");
    assert_eq!(
        config,
        json!({
            "$type": CONFIG_COLLECTION,
            "trustedScopes": ["community.other.thing"],
            "policyLayers": [uri],
        }),
        "the first install must build the config from the empty bootstrap state"
    );
    assert!(
        is_serving(&state, &steward_did).await,
        "the bootstrap install must bring the arbiter online"
    );
    let mut drive = state
        .arbiters
        .begin_request(&steward_did, make_req(), RequestCtx::default())
        .await
        .expect("begin bootstrap pipeline");
    assert_policy_output(drive.machine.start(), json!({ "got": "installed" }));
}

#[tokio::test]
async fn install_policy_rejects_uncompilable_policy() {
    // A referenced record that exists but whose Rego fails to compile must
    // be rejected with ErrInvalidPolicy BEFORE anything is written: the
    // re-onboard would otherwise fail in Layer::compile as an undeclared
    // 500, and the config write's reload event would offboard a previously-
    // serving arbiter. (This also covers the old inline-policies variant:
    // the caller's own uncompilable record is exactly this case.)
    let (addr, admin_priv, admin_did, steward_did, records, _state) = install_setup().await;

    // The caller wrote a record that does not compile.
    seed_policy_record(
        &records,
        &steward_did,
        "broken",
        "package arbiter\nthis is not rego",
    )
    .await;
    let broken_uri = format!("at://{steward_did}/{POLICY_COLLECTION}/broken");
    let resp = admin_append(&addr, &admin_priv, &admin_did, &steward_did, Some(&broken_uri), &["community.other.thing"]).await;

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "uncompilable referenced policy must be a 400"
    );
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("ErrInvalidPolicy"),
        "error code must match the lexicon's ErrInvalidPolicy"
    );
    assert!(
        body.get("message")
            .and_then(|v| v.as_str())
            .is_some_and(|m| m.contains("compiling pipeline layer") && m.contains("broken")),
        "the error must name the referenced record and its compile failure: {body}"
    );

    // Nothing was written: the config still points at the echo pipeline.
    let map = records.lock().await;
    let config = map
        .get(&(
            steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record still present");
    assert!(
        config.to_string().contains(&format!("/{ECHO_POLICY_RKEY}")),
        "config pipeline must be unchanged after a rejected install"
    );
    assert!(
        map.get(&(
            steward_did.clone(),
            POLICY_COLLECTION.to_string(),
            "broken".to_string(),
        ))
        .is_some(),
        "the caller's uncompilable record must remain exactly as they wrote it"
    );
}
#[tokio::test]
async fn install_policy_rejects_invalid_config_inputs() {
    // Malformed trusted scopes or a malformed / foreign-collection policy
    // at-uri must be rejected with ErrInvalidPolicy BEFORE anything is
    // written or fetched, not surface later as a fail-closed onboard
    // failure.
    let (addr, admin_priv, admin_did, steward_did, records, _state) = install_setup().await;

    for payload in [
        // A trusted scope that is not a valid NSID.
        json!({
            "arbiterDid": steward_did,
            "trustedScopes": ["not an nsid"],
        }),
        // A policy at-uri missing the record key.
        json!({
            "arbiterDid": steward_did,
            "trustedScopes": ["community.other.thing"],
            "policy": format!("at://{steward_did}/{POLICY_COLLECTION}"),
        }),
        // A policy at-uri with a trailing segment (record-level URIs only).
        json!({
            "arbiterDid": steward_did,
            "trustedScopes": ["community.other.thing"],
            "policy": format!("at://{steward_did}/{POLICY_COLLECTION}/rkey/extra"),
        }),
        // A policy at-uri naming a collection other than
        // `town.muni.arbiter.policy` (such an entry would load once at
        // onboard and then never hot-reload — the Jetstream reload path
        // dispatches policy-record writes only for that collection).
        json!({
            "arbiterDid": steward_did,
            "trustedScopes": ["community.other.thing"],
            "policy": format!("at://{steward_did}/com.example.custom/foo"),
        }),
    ] {
        let jwt = install_jwt(&admin_priv, &admin_did);
        let resp = install_call(addr, &jwt, payload).await;
        let status = resp.status();
        let body: Value = resp.json().await.expect("json body");
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "invalid config inputs must be a 400: {body}"
        );
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("ErrInvalidPolicy"),
            "error code must match the lexicon's ErrInvalidPolicy: {body}"
        );
    }

    // Nothing was written: the config still points at the echo pipeline.
    let map = records.lock().await;
    let config = map
        .get(&(
            steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record still present");
    assert!(
        config.to_string().contains(&format!("/{ECHO_POLICY_RKEY}")),
        "config pipeline must be unchanged after a rejected install"
    );
}
#[tokio::test]
async fn install_policy_rejects_ghost_local_pipeline_entry() {
    // A policy at-uri that is syntactically valid but references a record
    // that does not exist in the repo must be rejected with ErrInvalidPolicy
    // BEFORE the config write: the re-onboard would otherwise fail closed
    // ("pipeline policy record not found") as an undeclared 500 and leave an
    // unloadable config behind.
    let (addr, admin_priv, admin_did, steward_did, records, _state) = install_setup().await;

    let ghost_uri = format!("at://{steward_did}/{POLICY_COLLECTION}/ghost");
    let resp = admin_append(&addr, &admin_priv, &admin_did, &steward_did, Some(&ghost_uri), &[TRUSTED_SCOPE]).await;
    let status = resp.status();
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a ghost local policy reference must be a 400: {body}"
    );
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("ErrInvalidPolicy"),
        "error code must match the lexicon's ErrInvalidPolicy: {body}"
    );
    assert!(
        body.get("message")
            .and_then(|v| v.as_str())
            .is_some_and(|m| m.contains("ghost")),
        "the error must name the missing policy record: {body}"
    );

    // Nothing was written: no ghost policy record landed and the config still
    // points at the echo pipeline.
    let map = records.lock().await;
    assert!(
        !map.contains_key(&(
            steward_did.clone(),
            POLICY_COLLECTION.to_string(),
            "ghost".to_string()
        )),
        "no ghost policy record must be written for a rejected install"
    );
    let config = map
        .get(&(
            steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record still present");
    assert!(
        config.to_string().contains(&format!("/{ECHO_POLICY_RKEY}")),
        "config pipeline must be unchanged after a rejected install"
    );
}
#[tokio::test]
async fn install_policy_rejects_ghost_remote_pipeline_entry() {
    // A policy at-uri owned by ANOTHER repo (here the recovery admin's,
    // whose DID doc resolves to the same mock PDS) must be fetched via that
    // repo's PDS and rejected with ErrInvalidPolicy when the referenced
    // record does not exist there.
    let (addr, admin_priv, admin_did, steward_did, records, _state) = install_setup().await;

    let ghost_uri = format!("at://{admin_did}/{POLICY_COLLECTION}/ghost");
    let resp = admin_append(&addr, &admin_priv, &admin_did, &steward_did, Some(&ghost_uri), &[TRUSTED_SCOPE]).await;
    let status = resp.status();
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a ghost remote policy reference must be a 400: {body}"
    );
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("ErrInvalidPolicy"),
        "error code must match the lexicon's ErrInvalidPolicy: {body}"
    );

    // Nothing was written: the config still points at the echo pipeline.
    let map = records.lock().await;
    let config = map
        .get(&(
            steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record still present");
    assert!(
        config.to_string().contains(&format!("/{ECHO_POLICY_RKEY}")),
        "config pipeline must be unchanged after a rejected install"
    );
}

#[tokio::test]
async fn install_policy_non_admin_is_policy_gated() {
    // The `town.muni.arbiter.recovery/self` record designates admin_did, but
    // a DIFFERENT caller (intruder) holds their own verifiable key. JWT
    // verification resolves the ISSUER's DID doc, so this test spins its own
    // server with an intruder-aware resolver. The intruder is not the admin,
    // so their install request is not performed via the bypass: it is
    // evaluated by the installed pipeline, which decides its fate.
    let steward_did = unique_did("steward");
    let admin_did = unique_did("admin");
    let intruder_did = unique_did("intruder");
    let records = Arc::new(Mutex::new(HashMap::new()));

    populate_standard_records(&records, &steward_did, ECHO_POLICY).await;
    {
        let mut m = records.lock().await;
        m.insert(
            (
                steward_did.clone(),
                "town.muni.arbiter.recovery".to_string(),
                "self".to_string(),
            ),
            json!({ "did": admin_did.clone() }),
        );
    }
    let pds_addr = start_mock_pds(records.clone()).await;
    let pds_url = format!("http://{pds_addr}");

    let (intruder_priv, intruder_pub) = pds_keypair();
    let intruder_multibase = intruder_pub
        .to_string()
        .strip_prefix("did:key:")
        .expect("pub key is did:key: prefixed")
        .to_string();

    let mut docs = HashMap::new();
    docs.insert(
        intruder_did.clone(),
        did_doc(&intruder_did, &pds_url, Some(&intruder_multibase)),
    );
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);
    // The record (seeded above) designates admin_did; the intruder is NOT the
    // admin. The stored row holds the same DID as its bootstrap designation.
    state
        .store
        .store(
            steward_did.clone(),
            PdsCredentials {
                password: "steward-pw".to_string(),
                recovery_admin: admin_did,
                provisioned: true,
            },
        )
        .await
        .expect("store creds");
    policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("onboard");

    let addr = start_router(state).await;

    let jwt = mint_service_auth(
        &intruder_priv,
        &intruder_did,
        SERVER_DID,
        "town.muni.arbiter.installPolicy",
        now_secs() + 60,
    );

    let url = format!("http://{addr}/xrpc/town.muni.arbiter.installPolicy");
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&jwt)
        .json(&json!({
            "arbiterDid": steward_did,
            "policy": format!("at://{steward_did}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}"),
            "trustedScopes": [TRUSTED_SCOPE],
        }))
        .send()
        .await
        .expect("send installPolicy");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the pipeline decides the non-admin request (the echo layer answers it)"
    );
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body,
        json!({ "got": "town.muni.arbiter.installPolicy" }),
        "the response must be the layer's, not the built-in install's"
    );
    // Nothing was installed: the config record still names the echo pipeline.
    let config = records
        .lock()
        .await
        .get(&(
            steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record still present");
    assert!(
        config.to_string().contains(&format!("/{ECHO_POLICY_RKEY}")),
        "no install may be performed by a caller the pipeline did not approve"
    );
}

#[tokio::test]
async fn install_policy_forbidden_without_recovery_admin() {
    // With no `town.muni.arbiter.recovery/self` record in the repo (and no
    // stored credentials either), the endpoint fails closed:
    // ErrPermissionDenied per the lexicon.
    let steward_did = unique_did("steward");
    let caller_did = unique_did("caller");
    let records = Arc::new(Mutex::new(HashMap::new()));
    populate_standard_records(&records, &steward_did, ECHO_POLICY).await;
    let pds_addr = start_mock_pds(records.clone()).await;
    let pds_url = format!("http://{pds_addr}");

    let (caller_priv, caller_pub) = pds_keypair();
    let multibase = caller_pub
        .to_string()
        .strip_prefix("did:key:")
        .expect("pub key is did:key: prefixed")
        .to_string();
    let mut docs = HashMap::new();
    docs.insert(
        caller_did.clone(),
        did_doc(&caller_did, &pds_url, Some(&multibase)),
    );
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);
    // NOTE: no credentials stored and no recovery record seeded — the gate
    // fails on the missing record.
    policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("onboard");
    let addr = start_router(state).await;

    let jwt = mint_service_auth(
        &caller_priv,
        &caller_did,
        SERVER_DID,
        "town.muni.arbiter.installPolicy",
        now_secs() + 60,
    );
    let url = format!("http://{addr}/xrpc/town.muni.arbiter.installPolicy");
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&jwt)
        .json(&json!({
            "arbiterDid": steward_did,
            "policy": format!("at://{steward_did}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}"),
            "trustedScopes": [TRUSTED_SCOPE],
        }))
        .send()
        .await
        .expect("send installPolicy");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("ErrPermissionDenied"),
        "no recovery admin must be forbidden per the lexicon"
    );
}

#[tokio::test]
async fn install_policy_rotates_with_recovery_record_rewrite() {
    // The `town.muni.arbiter.recovery/self` record is the runtime authority:
    // rewriting it in the repo must rotate the recovery admin with effect on
    // the next installPolicy call — the OLD admin loses the bypass (their
    // requests fall to the pipeline), the NEW one may still install.
    let steward_did = unique_did("steward");
    let old_admin_did = unique_did("oldadmin");
    let new_admin_did = unique_did("newadmin");
    let records = Arc::new(Mutex::new(HashMap::new()));

    populate_standard_records(&records, &steward_did, ECHO_POLICY).await;
    {
        let mut m = records.lock().await;
        m.insert(
            (
                steward_did.clone(),
                "town.muni.arbiter.recovery".to_string(),
                "self".to_string(),
            ),
            json!({ "did": old_admin_did }),
        );
    }

    let pds_addr = start_mock_pds(records.clone()).await;
    let pds_url = format!("http://{pds_addr}");

    // Both admins carry signing keys, so their serviceAuth JWTs verify
    // against their own DID docs.
    let (old_priv, old_pub) = pds_keypair();
    let (new_priv, new_pub) = pds_keypair();
    let mut docs = HashMap::new();
    for (did, pub_key) in [(&old_admin_did, &old_pub), (&new_admin_did, &new_pub)] {
        let multibase = pub_key
            .to_string()
            .strip_prefix("did:key:")
            .expect("pub key is did:key: prefixed")
            .to_string();
        docs.insert(did.clone(), did_doc(did, &pds_url, Some(&multibase)));
    }
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);
    // The credential row holds only the bootstrap designation (the old
    // admin); it must NOT keep the gate open after the record rotates.
    state
        .store
        .store(
            steward_did.clone(),
            PdsCredentials {
                password: "steward-pw".to_string(),
                recovery_admin: old_admin_did.clone(),
                provisioned: true,
            },
        )
        .await
        .expect("store creds");
    policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("onboard");

    let addr = start_router(state).await;
    let url = format!("http://{addr}/xrpc/town.muni.arbiter.installPolicy");
    // A scope-append body: whichever admin calls, the observable effect is
    // the unioned trustedScopes (the pipeline is untouched).
    let scopes = [TRUSTED_SCOPE, "community.other.thing"];
    let body = json!({ "arbiterDid": steward_did, "trustedScopes": scopes });
    // The record-designated (old) admin can install.
    let jwt = install_jwt(&old_priv, &old_admin_did);
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&jwt)
        .json(&body)
        .send()
        .await
        .expect("send installPolicy as old admin");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the record-designated admin must be able to install"
    );

    // The old admin's install APPENDED the scopes: observable in the config.
    let config_after_first = records
        .lock()
        .await
        .get(&(
            steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record after the old admin's install");
    assert_eq!(
        config_after_first.get("trustedScopes").and_then(|v| v.as_array()),
        Some(&vec![json!(TRUSTED_SCOPE), json!("community.other.thing")]),
        "the old admin's bypass install must union the scopes"
    );

    // Rotate: rewrite the record in the repo to name the new admin.
    {
        let mut m = records.lock().await;
        m.insert(
            (
                steward_did.clone(),
                "town.muni.arbiter.recovery".to_string(),
                "self".to_string(),
            ),
            json!({ "did": new_admin_did }),
        );
    }

    // The old admin is now forbidden (fresh JWT per request: replay cache).
    let jwt = install_jwt(&old_priv, &old_admin_did);
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&jwt)
        .json(&body)
        .send()
        .await
        .expect("send installPolicy as rotated-out admin");
    // The rotated-out old admin no longer bypasses the pipeline: their
    // request is evaluated by the installed pipeline (the echo layer answers
    // it) and NO install is performed.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the rotated-out admin's request is policy-gated, not bypassed"
    );
    let resp_body: Value = resp.json().await.expect("json body");
    assert_eq!(
        resp_body,
        json!({ "got": "town.muni.arbiter.installPolicy" }),
        "the response must be the layer's, not the built-in install's"
    );
    let config = records
        .lock()
        .await
        .get(&(
            steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record still present");
    assert_eq!(
        config, config_after_first,
        "the rotated-out admin must not be able to perform an install"
    );

    // The NEW admin can install (fresh JWT per request: replay cache).
    let jwt = install_jwt(&new_priv, &new_admin_did);
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&jwt)
        .json(&body)
        .send()
        .await
        .expect("send installPolicy as new admin");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the newly-designated admin must be able to install after rotation"
    );
}

#[tokio::test]
async fn install_policy_forbidden_when_recovery_record_removed() {
    // The record is the authority: removing `town.muni.arbiter.recovery/self`
    // from the repo while the credential row still exists must fail closed —
    // the stored bootstrap designation must NOT keep the gate open.
    let (addr, admin_priv, admin_did, steward_did, records, _state) = install_setup().await;

    {
        let mut m = records.lock().await;
        m.remove(&(
            steward_did.clone(),
            "town.muni.arbiter.recovery".to_string(),
            "self".to_string(),
        ));
    }

    let jwt = install_jwt(&admin_priv, &admin_did);
    let url = format!("http://{addr}/xrpc/town.muni.arbiter.installPolicy");
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&jwt)
        .json(&json!({
            "arbiterDid": steward_did,
            "policy": format!("at://{steward_did}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}"),
            "trustedScopes": [TRUSTED_SCOPE],
        }))
        .send()
        .await
        .expect("send installPolicy with record removed");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a removed record must fail closed even with a stored designation"
    );
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("ErrPermissionDenied"),
        "error code must match the lexicon's ErrPermissionDenied"
    );
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert!(
        message.contains("no recovery admin is designated"),
        "missing-record failure must report the missing designation: {message}"
    );
}

// ─── 6b. pipeline-gated installPolicy + resetConfig recovery hatch ──────────

/// POST an `installPolicy` request with the given body and JWT.
async fn install_call(addr: SocketAddr, jwt: &str, body: Value) -> reqwest::Response {
    let url = format!("http://{addr}/xrpc/town.muni.arbiter.installPolicy");
    reqwest::Client::new()
        .post(&url)
        .bearer_auth(jwt)
        .json(&body)
        .send()
        .await
        .expect("send installPolicy")
}

/// POST a `resetConfig` request with the given body and JWT.
async fn reset_call(addr: SocketAddr, jwt: &str, body: Value) -> reqwest::Response {
    let url = format!("http://{addr}/xrpc/town.muni.arbiter.resetConfig");
    reqwest::Client::new()
        .post(&url)
        .bearer_auth(jwt)
        .json(&body)
        .send()
        .await
        .expect("send resetConfig")
}
/// Seed a gate layer record (`layer_rkey` → `policy_src`, written by the
/// caller into the mock PDS) and have the recovery admin `resetConfig` the
/// pipeline to JUST that layer — the wholesale hatch replaces the config, so
/// a single-layer pipeline can gate the install tests. Returns the raw
/// resetConfig response.
async fn admin_reset_layer(
    env: &InstallEnv,
    layer_rkey: &str,
    policy_src: &str,
) -> reqwest::Response {
    seed_policy_record(&env.records, &env.steward_did, layer_rkey, policy_src).await;
    let jwt = reset_jwt(&env.admin_priv, &env.admin_did);
    reset_call(
        env.addr,
        &jwt,
        json!({
            "arbiterDid": env.steward_did,
            "trustedScopes": [TRUSTED_SCOPE],
            "policyLayers": [format!("at://{}/{POLICY_COLLECTION}/{layer_rkey}", env.steward_did)],
        }),
    )
    .await
}

/// A non-admin installPolicy body that APPENDS the pre-existing echo policy
/// record (valid: the record exists and compiles).

fn echo_install_body(env: &InstallEnv) -> Value {
    json!({
        "arbiterDid": env.steward_did,
        "policy": format!("at://{}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}", env.steward_did),
        "trustedScopes": [TRUSTED_SCOPE],
    })
}

/// A non-admin serviceAuth JWT bound to `nsid`.
fn caller_jwt(env: &InstallEnv, nsid: &str) -> String {
    mint_service_auth(&env.caller_priv, &env.caller_did, SERVER_DID, nsid, now_secs() + 60)
}

/// Break the steward's config record (pipeline references a policy record
/// that does not exist) and drive the fail-closed offboard the way the
/// Jetstream handler does on a failed reload.
async fn break_config_and_offboard(env: &InstallEnv) {
    {
        let mut m = env.records.lock().await;
        m.insert(
            (
                env.steward_did.clone(),
                CONFIG_COLLECTION.to_string(),
                CONFIG_RKEY.to_string(),
            ),
            json!({
                "trustedScopes": [TRUSTED_SCOPE],
                "policyLayers": [format!("at://{}/{POLICY_COLLECTION}/missing", env.steward_did)],
            }),
        );
    }
    let handler = ReloadHandler::new(env.state.clone());
    let commit = |did: &str, rev: &str, collection: &str, rkey: &str, record: Value| {
        JetstreamEvent::Commit {
            did: did.to_string(),
            time_us: 0,
            kind: "commit".into(),
            commit: JetstreamEventCommit {
                rev: rev.to_string(),
                operation: "update".into(),
                collection: collection.to_string(),
                rkey: rkey.to_string(),
                cid: "bafkreih000000000000000000000000000000000000000000".into(),
                record,
            },
        }
    };
    handler
        .handle_event(Arc::new(commit(
            &env.steward_did,
            "3lyileto4q52l",
            CONFIG_COLLECTION,
            CONFIG_RKEY,
            json!({
                "trustedScopes": [TRUSTED_SCOPE],
                "policyLayers": [format!("at://{}/{POLICY_COLLECTION}/missing", env.steward_did)],
            }),
        )))
        .await
        .expect("handle broken-config commit event");
    assert!(
        !is_serving(&env.state, &env.steward_did).await,
        "a broken config must offboard the arbiter (fail-closed)"
    );
}

#[tokio::test]
async fn install_policy_pipeline_handoff_performs_install() {
    // (a) A non-admin installPolicy request is evaluated by the installed
    // pipeline: a layer that completes with `{ "handleBuiltin": true }`
    // approves the install, and the built-in handler performs the APPEND.
    let env = install_setup_full().await;
    let resp = admin_reset_layer(&env, "gate", HANDLE_BUILTIN_POLICY).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the recovery admin must be able to reset the handoff layer in"
    );

    let jwt = caller_jwt(&env, "town.muni.arbiter.installPolicy");
    let resp = install_call(env.addr, &jwt, echo_install_body(&env)).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the pipeline's handleBuiltin approval must perform the install"
    );
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body,
        json!({ "ok": true }),
        "the response must be the built-in install's, not the layer output"
    );

    // The install actually landed as an APPEND: the echo layer joins at the
    // END of the gate pipeline, and the re-onboarded arbiter serves it.
    let gate_uri = format!("at://{}/{POLICY_COLLECTION}/gate", env.steward_did);
    let echo_uri = format!(
        "at://{}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}",
        env.steward_did
    );
    let config = env
        .records
        .lock()
        .await
        .get(&(
            env.steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record written by the handed-off install");
    assert_eq!(
        config.get("policyLayers").and_then(|v| v.as_array()),
        Some(&vec![json!(gate_uri), json!(echo_uri)]),
        "the handed-off install must append echo after the existing gate layer"
    );
    assert!(
        is_serving(&env.state, &env.steward_did).await,
        "the install must re-onboard the arbiter"
    );

}
#[tokio::test]
async fn install_policy_pipeline_layer_deny_is_surfaced() {
    // (b) A pipeline layer that denies the install request wins: the layer's
    // error envelope is the response.
    let env = install_setup_full().await;
    let resp = admin_reset_layer(&env, "gate", DENY_INSTALL_POLICY).await;
    assert_eq!(resp.status(), StatusCode::OK, "admin resets the deny layer in");

    let jwt = caller_jwt(&env, "town.muni.arbiter.installPolicy");
    let resp = install_call(env.addr, &jwt, echo_install_body(&env)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "a denying layer must deny the install");
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body.get("error").and_then(|e| e.get("error")).and_then(|v| v.as_str()),
        Some("InstallDenied"),
        "the layer's error envelope must be surfaced"
    );
}

#[tokio::test]
async fn install_policy_pipeline_pass_falls_off_end_denies() {
    // (c) A pipeline where every layer passes falls off the end: default
    // fail-closed deny.
    let env = install_setup_full().await;
    let resp = admin_reset_layer(&env, "gate", PASS_INSTALL_POLICY).await;
    assert_eq!(resp.status(), StatusCode::OK, "admin resets the pass layer in");

    let jwt = caller_jwt(&env, "town.muni.arbiter.installPolicy");
    let resp = install_call(env.addr, &jwt, echo_install_body(&env)).await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "falling off the end of the pipeline must deny the install"
    );
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body.get("error").and_then(|e| e.get("error")).and_then(|v| v.as_str()),
        Some("Denied"),
        "the default deny envelope must be surfaced"
    );
}

#[tokio::test]
async fn install_policy_recovery_admin_bypasses_denying_pipeline() {
    // (d) The recovery admin installs directly, bypassing the (denying)
    // pipeline: the bypass is the recovery path while a pipeline is active.
    let env = install_setup_full().await;
    let resp = admin_reset_layer(&env, "gate", DENY_INSTALL_POLICY).await;
    assert_eq!(resp.status(), StatusCode::OK, "admin resets the deny layer in");

    let jwt = install_jwt(&env.admin_priv, &env.admin_did);
    let resp = install_call(env.addr, &jwt, echo_install_body(&env)).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the recovery admin must bypass the denying pipeline"
    );
    assert!(
        is_serving(&env.state, &env.steward_did).await,
        "the bypass install must re-onboard the arbiter"
    );
}

#[tokio::test]
async fn install_policy_offboarded_points_at_reset_config() {
    // (e) With the arbiter offboarded (broken config), a non-admin install
    // request cannot be evaluated by the pipeline: the denial must point the
    // recovery admin at resetConfig.
    let env = install_setup_full().await;
    break_config_and_offboard(&env).await;

    let jwt = caller_jwt(&env, "town.muni.arbiter.installPolicy");
    let resp = install_call(env.addr, &jwt, echo_install_body(&env)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("ErrPermissionDenied"),
        "error code must match the lexicon's ErrPermissionDenied"
    );
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert!(
        message.contains("resetConfig"),
        "the denial must point the recovery admin at resetConfig: {message}"
    );
}

#[tokio::test]
async fn reset_config_recovers_offboarded_arbiter() {
    // (f) The recovery admin can reset the config record of an offboarded
    // arbiter (no policy evaluation; the record is replaced wholesale) and
    // the arbiter re-onboards and serves.
    let env = install_setup_full().await;
    break_config_and_offboard(&env).await;

    let jwt = mint_service_auth(
        &env.admin_priv,
        &env.admin_did,
        SERVER_DID,
        "town.muni.arbiter.resetConfig",
        now_secs() + 60,
    );
    let resp = reset_call(
        env.addr,
        &jwt,
        json!({
            "arbiterDid": env.steward_did,
            "trustedScopes": [TRUSTED_SCOPE],
            "policyLayers": [format!("at://{}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}", env.steward_did)],
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the recovery admin must be able to reset the config while offboarded"
    );
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(body, json!({ "ok": true }));

    assert!(
        is_serving(&env.state, &env.steward_did).await,
        "the reset must re-onboard the arbiter"
    );
    let mut drive = env
        .state
        .arbiters
        .begin_request(&env.steward_did, make_req(), RequestCtx::default())
        .await
        .expect("begin reset pipeline");
    assert_policy_output(drive.machine.start(), json!({ "got": "com.example.foo" }));
}

#[tokio::test]
async fn reset_config_rejects_non_admin() {
    // (g) resetConfig is recovery-admin-only: any other caller is rejected
    // with the lexicon's ErrPermissionDenied.
    let env = install_setup_full().await;
    let jwt = caller_jwt(&env, "town.muni.arbiter.resetConfig");
    let resp = reset_call(
        env.addr,
        &jwt,
        json!({
            "arbiterDid": env.steward_did,
            "trustedScopes": [TRUSTED_SCOPE],
            "policyLayers": [format!("at://{}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}", env.steward_did)],
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("ErrPermissionDenied"),
        "error code must match the lexicon's ErrPermissionDenied"
    );
}
#[tokio::test]
async fn reset_config_shape_validates_body() {
    // (h) resetConfig shape-validates only: a non-string pipeline entry is a
    // 400, and nothing is written (deliberately no compile/record checks —
    // if the new config is also bad, reset again).
    let env = install_setup_full().await;
    let jwt = mint_service_auth(
        &env.admin_priv,
        &env.admin_did,
        SERVER_DID,
        "town.muni.arbiter.resetConfig",
        now_secs() + 60,
    );
    let resp = reset_call(
        env.addr,
        &jwt,
        json!({
            "arbiterDid": env.steward_did,
            "trustedScopes": [TRUSTED_SCOPE],
            "policyLayers": [format!("at://{}/{POLICY_COLLECTION}/ok", env.steward_did), 7],
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // The config record is untouched by the rejected reset.
    let config = env
        .records
        .lock()
        .await
        .get(&(
            env.steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record still present");
    assert_eq!(
        config.get("trustedScopes").and_then(|v| v.as_array()).map(|a| a.len()),
        Some(1),
        "the rejected reset must not touch the config record"
    );
}

// ─── 6c. builtin-handoff registry (HandToBuiltin → serve_builtin) ────────────

/// The proxy envelope the built-in `town.muni.arbiter.proxy` endpoint takes:
/// the arbiter to act on behalf of, the forward target, and the inner request.
fn proxy_envelope(steward_did: &str, method: &str, nsid: &str, body: Value) -> Value {
    json!({
        "arbiterDid": steward_did,
        "target": format!("{steward_did}#atproto_pds"),
        "method": method,
        "nsid": nsid,
        "body": body,
    })
}

/// POST a proxy request with the given envelope body and JWT.
async fn proxy_call(addr: SocketAddr, jwt: &str, body: Value) -> reqwest::Response {
    let url = format!("http://{addr}/xrpc/town.muni.arbiter.proxy");
    reqwest::Client::new()
        .post(&url)
        .bearer_auth(jwt)
        .json(&body)
        .send()
        .await
        .expect("send proxy")
}

#[tokio::test]
async fn builtin_handoff_registry_dispatches_proxied_management_nsid() {
    // The registry maps a handed-off request's inner NSID onto the same
    // built-in handlers the router dispatches. A proxied request whose inner
    // NSID is `town.muni.arbiter.installPolicy` and whose pipeline approves
    // it with `{ "handleBuiltin": true }` therefore reaches the real install
    // built-in: the handed-off body is performed exactly as if the router
    // had served it, and the built-in's response is relayed back through the
    // proxy path (the handoff terminates at depth 1).
    let env = install_setup_full().await;
    let resp = admin_reset_layer(&env, "gate", HANDLE_BUILTIN_POLICY).await;
    assert_eq!(resp.status(), StatusCode::OK, "admin resets the handoff layer in");

    let jwt = caller_jwt(&env, "town.muni.arbiter.proxy");
    let resp = proxy_call(
        env.addr,
        &jwt,
        proxy_envelope(
            &env.steward_did,
            "POST",
            "town.muni.arbiter.installPolicy",
            echo_install_body(&env),
        ),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the registry must dispatch the handed-off install onto the built-in"
    );
    let out: Value = resp.json().await.expect("json body");
    assert_eq!(
        out,
        json!({ "ok": true }),
        "the response must be the built-in install's, not the layer output"
    );

    // The install actually landed: the config record names the echo pipeline
    // and the re-onboarded arbiter serves it.
    let config = env
        .records
        .lock()
        .await
        .get(&(
            env.steward_did.clone(),
            CONFIG_COLLECTION.to_string(),
            CONFIG_RKEY.to_string(),
        ))
        .cloned()
        .expect("config record written by the registry-dispatched install");
    let gate_uri = format!("at://{}/{POLICY_COLLECTION}/gate", env.steward_did);
    let echo_uri = format!(
        "at://{}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}",
        env.steward_did
    );
    assert_eq!(
        config.get("policyLayers").and_then(|v| v.as_array()),
        Some(&vec![json!(gate_uri), json!(echo_uri)]),
        "the handed-off install must append echo after the existing gate layer"
    );
    assert!(
        is_serving(&env.state, &env.steward_did).await,
        "the registry-dispatched install must re-onboard the arbiter"
    );
}
#[tokio::test]
async fn builtin_handoff_unknown_nsid_is_invalid_request() {
    // An NSID with no built-in — the common case for proxied scope requests —
    // surfaces the machine contract's error response: 400 InvalidRequest
    // naming the NSID, not a panic and not a success.
    let env = install_setup_full().await;
    let resp = admin_reset_layer(&env, "gate", HANDLE_BUILTIN_POLICY).await;
    assert_eq!(resp.status(), StatusCode::OK, "admin resets the handoff layer in");

    let unknown = "com.example.calendar.listEvents";
    let jwt = caller_jwt(&env, "town.muni.arbiter.proxy");
    let resp = proxy_call(
        env.addr,
        &jwt,
        proxy_envelope(&env.steward_did, "GET", unknown, Value::Null),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a handoff with no built-in implementation must be a 400"
    );
    let out: Value = resp.json().await.expect("json body");
    assert_eq!(
        out.get("error").and_then(|e| e.get("error")).and_then(|v| v.as_str()),
        Some("InvalidRequest"),
        "the unknown-NSID handoff must surface the InvalidRequest envelope: {out}"
    );
    let message = out
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|v| v.as_str())
        .expect("error message present");
    assert!(
        message.contains(unknown) && message.contains("no built-in implementation"),
        "the message must name the NSID and the missing built-in: {message}"
    );
}

#[tokio::test]
async fn builtin_handoff_chain_beyond_depth_bound_terminates() {
    // A pipeline that hands every request back to the proxy built-in makes
    // each dispatch re-enter the pipeline; serve_builtin's nesting cap
    // (MAX_BUILTIN_HANDOFF_DEPTH = 8) must terminate the recursion with
    // BuiltInHandoffTooDeep. The chain nests one more proxy envelope than
    // the cap allows: the router's request (depth 0) hands off to depth 1,
    // and the depth-9 dispatch trips the bound.
    let env = install_setup_full().await;
    let resp = admin_reset_layer(&env, "gate", HANDLE_BUILTIN_POLICY).await;
    assert_eq!(resp.status(), StatusCode::OK, "admin resets the handoff layer in");

    // Nest nine self-similar proxy envelopes (the cap + 1): each level names
    // the proxy NSID and carries the next level's envelope as its body, so
    // every level parses cleanly and hands off again. The innermost leaf is
    // never parsed — the depth bound trips first.
    let mut body = proxy_envelope(&env.steward_did, "POST", "town.muni.arbiter.proxy", Value::Null);
    for _ in 0..8 {
        body = proxy_envelope(&env.steward_did, "POST", "town.muni.arbiter.proxy", body);
    }
    let jwt = caller_jwt(&env, "town.muni.arbiter.proxy");
    let resp = proxy_call(env.addr, &jwt, body).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "the handoff chain must terminate at the nesting cap"
    );
    let out: Value = resp.json().await.expect("json body");
    assert_eq!(
        out.get("error").and_then(|e| e.get("error")).and_then(|v| v.as_str()),
        Some("BuiltInHandoffTooDeep"),
        "the depth-bound trip must surface BuiltInHandoffTooDeep: {out}"
    );
}

#[tokio::test]
async fn policy_xrpc_to_arbiter_self_receives_error_envelope() {
    // A pipeline issuing an `xrpc` host call to the arbiter server's own DID
    // must receive the error envelope and terminate — the arbiter must never
    // proxy to itself (pipeline → installPolicy → pipeline loops).
    let env = auth_setup_with(&self_proxy_policy(SERVER_DID)).await;
    let resp = xrpc_get(&env, Some(valid_jwt(&env)), Some(env.steward_did.as_str())).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the layer handles the request after receiving the error envelope"
    );
    let body: Value = resp.json().await.expect("json body");
    let self_proxy = body
        .get("selfProxy")
        .expect("the layer reports the host-call result");
    assert_eq!(
        self_proxy.get("ok"),
        Some(&Value::Bool(false)),
        "the self-targeted host call must be refused: {self_proxy}"
    );
    let err = self_proxy.get("error").expect("error envelope");
    assert_eq!(err.get("status"), Some(&json!(400)));
    assert_eq!(
        err.get("error"),
        Some(&Value::String("SelfProxyForbidden".to_string())),
        "the policy must receive the self-proxy error envelope"
    );
}


// ─── 7. optimistic concurrency (swapCommit) is enforced by the mock ─────────

#[tokio::test]
async fn put_record_rejects_stale_swap_commit() {
    // Prove the mock PDS enforces swapCommit: a putRecord carrying a stale repo
    // head must fail with InvalidSwap, and a current head must succeed. This
    // is the compare-and-swap path installPolicy's config write relies on.
    let steward_did = unique_did("steward");
    let records = Arc::new(Mutex::new(HashMap::new()));
    populate_standard_records(&records, &steward_did, ECHO_POLICY).await;
    let pds_addr = start_mock_pds(records).await;
    let pds_url = format!("http://{pds_addr}");
    let client = reqwest::Client::new();
    let put = |swap: Option<&str>| {
        let url = format!("{pds_url}/xrpc/com.atproto.repo.putRecord");
        let mut body = json!({
            "repo": steward_did,
            "collection": POLICY_COLLECTION,
            "rkey": ECHO_POLICY_RKEY,
            "record": { "$type": POLICY_COLLECTION, "policy": "pkg" },
        });
        if let Some(s) = swap {
            body["swapCommit"] = Value::String(s.to_string());
        }
        client.post(&url).json(&body)
    };

    // Current head is MOCK_HEAD_A for a fresh repo; a stale head must be rejected.
    let stale = put(Some(MOCK_HEAD_B)).send().await.expect("stale send");
    assert_eq!(stale.status(), StatusCode::CONFLICT, "stale swapCommit must be rejected");

    // The current head succeeds and advances the repo head.
    let ok = put(Some(MOCK_HEAD_A)).send().await.expect("current send");
    assert_eq!(ok.status(), StatusCode::OK, "current swapCommit must succeed");

    // Now MOCK_HEAD_A is stale; another write against it is rejected.
    let again = put(Some(MOCK_HEAD_A)).send().await.expect("again send");
    assert_eq!(again.status(), StatusCode::CONFLICT, "old head must be rejected after advance");
}

// ─── 8. scoped endpoints (`<scope>.arbiter.proxy` wildcard) ─────────────────

/// An injectable [`LexiconSource`] serving lexicon documents from a map, so
/// scoped-endpoint tests never touch DNS/HTTP.
struct MockLexiconSource {
    docs: HashMap<String, Value>,
}

#[async_trait]
impl LexiconSource for MockLexiconSource {
    async fn fetch_lexicon(&self, nsid: &str) -> anyhow::Result<Value> {
        self.docs
            .get(nsid)
            .cloned()
            .ok_or_else(|| anyhow!("mock lexicon source has no document for {nsid}"))
    }
}

struct ScopedEnv {
    addr: SocketAddr,
    caller_priv: KeyData,
    caller_did: String,
    steward_did: String,
    state: Arc<AppState>,
}

/// Stand up an onboarded server whose config trusts [`TRUSTED_SCOPE`] and
/// whose permission set embeds `scope_rego`; caller serviceAuths verify
/// against their own DID doc.
async fn scoped_setup(trusted_scopes: &[&str], scope_rego: &str) -> ScopedEnv {
    let steward_did = unique_did("steward");
    let caller_did = unique_did("caller");
    let records = Arc::new(Mutex::new(HashMap::new()));
    populate_standard_records(&records, &steward_did, ECHO_POLICY).await;
    // Rewrite the config's trustedScopes to the caller-supplied list.
    {
        let mut m = records.lock().await;
        m.insert(
            (
                steward_did.clone(),
                CONFIG_COLLECTION.into(),
                CONFIG_RKEY.into(),
            ),
            json!({
                "trustedScopes": trusted_scopes,
                "policyLayers": [format!("at://{steward_did}/{POLICY_COLLECTION}/{ECHO_POLICY_RKEY}")],
            }),
        );
    }

    let pds_addr = start_mock_pds(records).await;
    let pds_url = format!("http://{pds_addr}");

    let (caller_priv, caller_pub) = pds_keypair();
    let multibase = caller_pub
        .to_string()
        .strip_prefix("did:key:")
        .expect("pub key is did:key: prefixed")
        .to_string();
    let mut docs = HashMap::new();
    docs.insert(
        caller_did.clone(),
        did_doc(&caller_did, &pds_url, Some(&multibase)),
    );
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });

    let mut lexicons = HashMap::new();
    lexicons.insert(TRUSTED_SCOPE.to_string(), scope_lexicon_doc(scope_rego));
    let state = make_state_with_scope_source(resolver, Arc::new(MockLexiconSource { docs: lexicons }));
    policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("onboard for scoped test");

    let addr = start_router(state.clone()).await;
    ScopedEnv {
        addr,
        caller_priv,
        caller_did,
        steward_did,
        state,
    }
}

/// POST a scoped proxy request with the standard proxy body shape.
async fn scoped_post(env: &ScopedEnv, jwt: &str, nsid: &str, body: Value) -> reqwest::Response {
    let url = format!("http://{}/xrpc/{nsid}", env.addr);
    reqwest::Client::new()
        .post(&url)
        .bearer_auth(jwt)
        .json(&body)
        .send()
        .await
        .expect("send scoped request")
}

/// A valid serviceAuth JWT for a scoped request: aud is the `<server
/// did>#arbiter` fragment form a PDS proxy sends, lxm is the scoped NSID.
fn scoped_jwt(env: &ScopedEnv, nsid: &str) -> String {
    mint_service_auth(
        &env.caller_priv,
        &env.caller_did,
        &format!("{SERVER_DID}#arbiter"),
        nsid,
        now_secs() + 60,
    )
}

/// The standard scoped proxy body: steward arbiter + inner calendar request.
fn scoped_body(steward_did: &str) -> Value {
    json!({
        "arbiterDid": steward_did,
        "target": format!("{steward_did}#atproto_pds"),
        "method": "GET",
        "nsid": "com.example.calendars.readEvents",
    })
}

#[tokio::test]
async fn scoped_endpoint_happy_path() {
    // serviceAuth with the `#arbiter` fragment aud + trusted scope prefix +
    // an allowing embedded scope policy -> the community pipeline runs and
    // its single echo layer handles the request.
    let env = scoped_setup(&[TRUSTED_SCOPE], ALLOW_SCOPE_REGO).await;
    let jwt = scoped_jwt(&env, SCOPED_NSID);
    let resp = scoped_post(&env, &jwt, SCOPED_NSID, scoped_body(&env.steward_did)).await;
    assert_eq!(resp.status(), StatusCode::OK, "scoped request must be handled");
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(body, json!({ "got": "com.example.calendars.readEvents" }));
}

#[tokio::test]
async fn scoped_endpoint_rejects_untrusted_scope() {
    // The requested prefix is NOT in the config's trustedScopes: the request
    // must be rejected 403 before any policy runs (the echo pipeline layer
    // would otherwise have handled it).
    let env = scoped_setup(&["community.other.unrelated"], ALLOW_SCOPE_REGO).await;
    let jwt = scoped_jwt(&env, SCOPED_NSID);
    let resp = scoped_post(&env, &jwt, SCOPED_NSID, scoped_body(&env.steward_did)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(body.get("error").and_then(|v| v.as_str()), Some("Forbidden"));
}

#[tokio::test]
async fn scoped_endpoint_denied_by_scope_policy() {
    // Trusted prefix, but the permission set's embedded scope policy denies:
    // layer-1 denies before the community pipeline runs.
    let env = scoped_setup(&[TRUSTED_SCOPE], DENY_SCOPE_REGO).await;
    let jwt = scoped_jwt(&env, SCOPED_NSID);
    let resp = scoped_post(&env, &jwt, SCOPED_NSID, scoped_body(&env.steward_did)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(body.get("error").and_then(|v| v.as_str()), Some("Forbidden"));
}

#[tokio::test]
async fn scoped_endpoint_unusable_permission_set_denies() {
    let env = scoped_setup(&["community.unknown.otherwise"], ALLOW_SCOPE_REGO).await;
    let unknown = "community.unknown.otherwise.arbiter.proxy";
    // The prefix is trusted, but the permission-set lexicon cannot be
    // resolved (mock source has no document for it): the scope is unusable
    // -> fail-closed 403.
    let jwt = scoped_jwt(&env, unknown);
    let resp = scoped_post(&env, &jwt, unknown, scoped_body(&env.steward_did)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(body.get("error").and_then(|v| v.as_str()), Some("Forbidden"));
}

// ─── 9. fail-closed lifecycle ────────────────────────────────────────────────

#[tokio::test]
async fn fail_closed_when_config_record_absent() {
    // An arbiter is only online with a parseable config record; with the
    // config missing the load fails and the arbiter stays offboarded
    // (fail-closed), even though the service record exists.
    let steward_did = unique_did("steward");
    let records = Arc::new(Mutex::new(HashMap::new()));
    {
        let mut m = records.lock().await;
        m.insert(
            (
                steward_did.clone(),
                SERVICE_COLLECTION.into(),
                SERVICE_RKEY.into(),
            ),
            json!({ "did": SERVER_DID }),
        );
        m.insert(
            (
                steward_did.clone(),
                POLICY_COLLECTION.into(),
                ECHO_POLICY_RKEY.into(),
            ),
            json!({ "policy": ECHO_POLICY }),
        );
        // NO config record.
    }
    let pds_addr = start_mock_pds(records).await;
    let pds_url = format!("http://{pds_addr}");
    let mut docs = HashMap::new();
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);

    let result = policy::load_and_onboard(&state, &steward_did).await;
    assert!(
        result.is_err(),
        "missing config record must fail the load (fail-closed)"
    );
    assert!(
        !is_serving(&state, &steward_did).await,
        "a failed load must leave the arbiter offboarded"
    );
}

#[tokio::test]
async fn fail_closed_when_pipeline_record_missing() {
    // The config record exists but its pipeline references a record that does
    // not exist: fail-closed, the arbiter never comes online.
    let steward_did = unique_did("steward");
    let records = Arc::new(Mutex::new(HashMap::new()));
    {
        let mut m = records.lock().await;
        m.insert(
            (
                steward_did.clone(),
                SERVICE_COLLECTION.into(),
                SERVICE_RKEY.into(),
            ),
            json!({ "did": SERVER_DID }),
        );
        m.insert(
            (
                steward_did.clone(),
                CONFIG_COLLECTION.into(),
                CONFIG_RKEY.into(),
            ),
            json!({
                "trustedScopes": [TRUSTED_SCOPE],
                "policyLayers": [format!("at://{steward_did}/{POLICY_COLLECTION}/ghost")],
            }),
        );
        // The `ghost` policy record does not exist.
    }
    let pds_addr = start_mock_pds(records).await;
    let pds_url = format!("http://{pds_addr}");
    let mut docs = HashMap::new();
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);

    let result = policy::load_and_onboard(&state, &steward_did).await;
    assert!(result.is_err(), "missing pipeline record must fail the load");
    assert!(!is_serving(&state, &steward_did).await);
}

// ─── 10. remote pipeline layers + reverse index ─────────────────────────────

#[tokio::test]
async fn remote_pipeline_layer_resolves_and_hot_reloads() {
    // A pipeline entry may reference a policy record in ANOTHER repo (an
    // app-owned shared layer). The layer resolves from the remote repo's PDS,
    // the reverse index maps the record's at:// URI back to this arbiter, and
    // a remote record update reloads the arbiter to the new layer (the path
    // the Jetstream policy-record handler drives).
    let steward_did = unique_did("steward");
    let remote_did = unique_did("remote");
    let records = Arc::new(Mutex::new(HashMap::new()));
    let shared_uri = format!("at://{remote_did}/{POLICY_COLLECTION}/shared");
    {
        let mut m = records.lock().await;
        m.insert(
            (
                steward_did.clone(),
                SERVICE_COLLECTION.into(),
                SERVICE_RKEY.into(),
            ),
            json!({ "did": SERVER_DID }),
        );
        m.insert(
            (
                steward_did.clone(),
                CONFIG_COLLECTION.into(),
                CONFIG_RKEY.into(),
            ),
            json!({
                "trustedScopes": [TRUSTED_SCOPE],
                "policyLayers": [shared_uri],
            }),
        );
        // The remote (app-owned) shared policy record, v1.
        m.insert(
            (
                remote_did.clone(),
                POLICY_COLLECTION.into(),
                "shared".into(),
            ),
            json!({ "policy": "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"v1\" } }" }),
        );
    }
    let pds_addr = start_mock_pds(records.clone()).await;
    let pds_url = format!("http://{pds_addr}");
    let mut docs = HashMap::new();
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    docs.insert(remote_did.clone(), did_doc(&remote_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);

    policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("onboard with remote layer");
    assert!(is_serving(&state, &steward_did).await);
    let mut drive = state
        .arbiters
        .begin_request(&steward_did, make_req(), RequestCtx::default())
        .await
        .expect("begin v1");
    assert_policy_output(drive.machine.start(), json!({ "got": "v1" }));

    // The reverse index maps the remote record's at:// URI to this steward.
    assert_eq!(
        policy::referencing_arbiters(&shared_uri),
        vec![steward_did.clone()],
        "reverse index must track the arbiters referencing the record"
    );

    // Update the REMOTE record (a Jetstream commit event for `remote_did` in
    // the policy collection would trigger exactly this reload) and reload.
    {
        let mut m = records.lock().await;
        m.insert(
            (
                remote_did.clone(),
                POLICY_COLLECTION.into(),
                "shared".into(),
            ),
            json!({ "policy": "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"v2\" } }" }),
        );
    }
    policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("reload with updated remote layer");
    let mut drive = state
        .arbiters
        .begin_request(&steward_did, make_req(), RequestCtx::default())
        .await
        .expect("begin v2");
    assert_policy_output(drive.machine.start(), json!({ "got": "v2" }));
}

// ─── 10b. Jetstream handler dispatch: remote-record event → reload ──────────

#[tokio::test]
async fn jetstream_handler_reloads_remote_record_despite_lower_rev() {
    // Drives `ReloadHandler` directly — the same dispatch path the live
    // WebSocket uses. A `town.muni.arbiter.policy` commit from the REMOTE
    // repo whose rev sorts BELOW the steward's rev floor must still reload
    // the referencing arbiter: repo revs are per-repo TID streams, so a
    // remote rev cannot be compared against the steward's floor, and gating
    // it would silently skip updates whenever the remote PDS clock lags the
    // steward's. A steward-repo event at the same stale rev is discarded
    // (rev gating kept for the steward repo); a newer-rev steward event
    // reloads.
    let steward_did = unique_did("steward");
    let remote_did = unique_did("remote");
    let records = Arc::new(Mutex::new(HashMap::new()));
    let shared_uri = format!("at://{remote_did}/{POLICY_COLLECTION}/shared");
    {
        let mut m = records.lock().await;
        m.insert(
            (
                steward_did.clone(),
                SERVICE_COLLECTION.into(),
                SERVICE_RKEY.into(),
            ),
            json!({ "did": SERVER_DID }),
        );
        m.insert(
            (
                steward_did.clone(),
                CONFIG_COLLECTION.into(),
                CONFIG_RKEY.into(),
            ),
            json!({
                "trustedScopes": [TRUSTED_SCOPE],
                "policyLayers": [shared_uri],
            }),
        );
        // The remote (app-owned) shared policy record, v1.
        m.insert(
            (
                remote_did.clone(),
                POLICY_COLLECTION.into(),
                "shared".into(),
            ),
            json!({ "policy": "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"v1\" } }" }),
        );
    }
    let pds_addr = start_mock_pds(records.clone()).await;
    let pds_url = format!("http://{pds_addr}");
    let mut docs = HashMap::new();
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    docs.insert(remote_did.clone(), did_doc(&remote_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);

    // The handler reloads only arbiters the server currently stewards.
    state
        .store
        .store_if_absent(steward_did.clone(), test_creds("steward"))
        .await
        .expect("store creds");

    policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("onboard with remote layer");
    assert!(is_serving(&state, &steward_did).await);

    // The mock PDS reports the same rev for every repo, so the steward's
    // floor is that constant; a rev sorting below it would be discarded by
    // the steward-repo gate — exactly the rev the remote event carries.
    let stale_rev = "3kzzzzzzzzzzz";
    assert!(
        !state.arbiters.is_newer(&steward_did, stale_rev).await,
        "precondition: stale rev must compare below the steward's floor"
    );

    let handler = ReloadHandler::new(state.clone());
    let commit = |did: &str,
                  rev: &str,
                  collection: &str,
                  rkey: &str,
                  record: Value| {
        JetstreamEvent::Commit {
            did: did.to_string(),
            time_us: 0,
            kind: "commit".into(),
            commit: JetstreamEventCommit {
                rev: rev.to_string(),
                operation: "update".into(),
                collection: collection.to_string(),
                rkey: rkey.to_string(),
                cid: "bafkreih000000000000000000000000000000000000000000".into(),
                record,
            },
        }
    };

    // A remote-repo policy-record write: update the record, then dispatch a
    // commit event for the remote repo (rev below the steward's floor).
    let v2 = json!({ "policy": "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"v2\" } }" });
    {
        let mut m = records.lock().await;
        m.insert(
            (
                remote_did.clone(),
                POLICY_COLLECTION.into(),
                "shared".into(),
            ),
            v2.clone(),
        );
    }
    handler
        .handle_event(Arc::new(commit(
            &remote_did,
            stale_rev,
            POLICY_COLLECTION,
            "shared",
            v2,
        )))
        .await
        .expect("handle remote policy-record event");

    // The reload re-resolved the remote layer to v2 despite the event rev
    // comparing below the steward's floor, and the reverse index still
    // mirrors the serving pipeline.
    let mut drive = state
        .arbiters
        .begin_request(&steward_did, make_req(), RequestCtx::default())
        .await
        .expect("begin after remote-record event");
    assert_policy_output(drive.machine.start(), json!({ "got": "v2" }));
    assert_eq!(
        policy::referencing_arbiters(&shared_uri),
        vec![steward_did.clone()],
        "reverse index must track the arbiters referencing the record"
    );

    // A steward-repo config event at the same stale rev is discarded: the
    // steward branch keeps rev gating (the floor is the steward repo's own
    // head). The arbiter keeps serving v2 even though the remote record has
    // since moved to v3.
    let v3 = json!({ "policy": "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"v3\" } }" });
    {
        let mut m = records.lock().await;
        m.insert(
            (
                remote_did.clone(),
                POLICY_COLLECTION.into(),
                "shared".into(),
            ),
            v3.clone(),
        );
    }
    handler
        .handle_event(Arc::new(commit(
            &steward_did,
            stale_rev,
            CONFIG_COLLECTION,
            CONFIG_RKEY,
            json!({ "trustedScopes": [TRUSTED_SCOPE], "policyLayers": [shared_uri] }),
        )))
        .await
        .expect("handle stale steward-repo event");
    let mut drive = state
        .arbiters
        .begin_request(&steward_did, make_req(), RequestCtx::default())
        .await
        .expect("begin after gated steward-repo event");
    assert_policy_output(drive.machine.start(), json!({ "got": "v2" }));

    // The same steward-repo event with a rev above the floor reloads and
    // picks up v3.
    handler
        .handle_event(Arc::new(commit(
            &steward_did,
            "3lyileto4q52l",
            CONFIG_COLLECTION,
            CONFIG_RKEY,
            json!({ "trustedScopes": [TRUSTED_SCOPE], "policyLayers": [shared_uri] }),
        )))
        .await
        .expect("handle newer steward-repo event");
    let mut drive = state
        .arbiters
        .begin_request(&steward_did, make_req(), RequestCtx::default())
        .await
        .expect("begin after ungated steward-repo event");
    assert_policy_output(drive.machine.start(), json!({ "got": "v3" }));
}
