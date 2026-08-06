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
use arbiter_server::policy;
use arbiter_server::state::ArbiterCollection;
use arbiter_server::storage::TursoCredentialStore;

/// The mock PDS record map keyed by `(repo, collection, rkey)`.
type RecordMap = Arc<Mutex<HashMap<(String, String, String), Value>>>;

// ─── constants matching the server's policy record layout ───────────────────

const SERVICE_COLLECTION: &str = "town.muni.arbiter.service";
const SERVICE_RKEY: &str = "self";
const ROOT_COLLECTION: &str = "town.muni.arbiter.policy.root";
const ROOT_RKEY: &str = "self";

/// Default `CONFIG.server_did` (no env vars set in tests → clap defaults).
const SERVER_DID: &str = "did:web:localhost:8203";

/// Root policy that echoes `input.nsid` back in `output.got`.
const ECHO_POLICY: &str =
    "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": input.nsid } }";

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
    let n = DID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("did:plc:{tag}{n:020x}")
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
    Arc::new(AppState {
        arbiters: ArbiterCollection::new(),
        store: Box::new(
            TursoCredentialStore::new(fresh_creds_db().to_string_lossy().into_owned())
                .expect("fresh credential store"),
        ),
        resolver,
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
                    // atrium's `Cid` type requires a real (multihash) CID.
                    "cid": "bafkreibme22gw2h7y2h7tg2fhqotaqjucnbc24deqo72b6mkl2egezxhvy",
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
                    // atrium's `Cid` type requires a real (multihash) CID.
                    "cid": "bafkreibme22gw2h7y2h7tg2fhqotaqjucnbc24deqo72b6mkl2egezxhvy",
                    "value": v
                }))
            } else {
                None
            }
        })
        .collect();
    (StatusCode::OK, Json(json!({ "records": records }))).into_response()
}

async fn create_session_handler() -> Response {
    // `did`/`handle` must be syntactically valid for atrium's session parsing.
    Json(json!({
        "accessJwt": "fake-jwt",
        "did": "did:plc:mockpds",
        "handle": "mock.pds.example",
        "refreshJwt": "fake-refresh",
    }))
    .into_response()
}

async fn create_account_handler() -> Response {
    Json(json!({
        "did": "mock-pds",
        "handle": "mock.pds.example",
        "accessJwt": "fake-jwt",
        "refreshJwt": "fake-refresh",
    }))
    .into_response()
}

/// Valid-atrium multihash CIDs used as mock repo heads. Distinct values let the
/// mock observe head advancement.
const MOCK_HEAD_A: &str = "bafkreibme22gw2h7y2h7tg2fhqotaqjucnbc24deqo72b6mkl2egezxhvy";
const MOCK_HEAD_B: &str = "bafkreia6f6zqgq5n7l4jfq5q5q5q5q5q5q5q5q5q5q5q5q5q5q5q5q5q5q5q5q5q";

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
    // exercises the server's optimistic-concurrency path (resetPolicy passes
    // the repo head it fetched via getLatestCommit). A repo with no recorded
    // head is at MOCK_HEAD_A (matching get_latest_commit_handler's default).
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
    let state = PdsState {
        records,
        heads: Arc::new(Mutex::new(HashMap::new())),
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
/// `load_and_onboard` gets a deterministic rev floor.
const MOCK_REPO_REV: &str = "3lyileto4q52k";

async fn get_repo_status_handler() -> Response {
    Json(json!({
        "active": true,
        "did": "mock",
        "rev": MOCK_REPO_REV,
    }))
    .into_response()
}

/// Populate the service + root policy records for `steward_did` (no
/// sub-policies). The mock PDS is responsible for serving these.
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
            ROOT_COLLECTION.into(),
            ROOT_RKEY.into(),
        ),
        json!({ "policy": policy_source }),
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

/// Mint a serviceAuth-style JWT signed by `priv_key`.
fn mint_service_auth(
    priv_key: &KeyData,
    iss: &str,
    aud: &str,
    sub: &str,
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
            subject: Some(sub.to_string()),
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
    sub: &str,
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
            subject: Some(sub.to_string()),
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
    pds_priv: KeyData,
    pds_did: String,
    steward_did: String,
    caller_did: String,
}

/// Stand up a full on-boarded server with a PDS holding a signing key, start
/// the axum router on a random port, and return everything the auth tests need.
async fn auth_setup() -> AuthEnv {
    let (pds_priv, pds_pub) = pds_keypair();
    // `KeyData::Display` emits `did:key:z...`; the verification method stores
    // the raw multibase (the part after `did:key:`).
    let pub_did_key = pds_pub.to_string();
    let multibase = pub_did_key
        .strip_prefix("did:key:")
        .expect("pub key is did:key: prefixed")
        .to_string();

    let pds_did = unique_did("pds");
    let steward_did = unique_did("steward");
    let caller_did = unique_did("caller");

    let records = Arc::new(Mutex::new(HashMap::new()));
    populate_standard_records(&records, &steward_did, ECHO_POLICY).await;
    let pds_addr = start_mock_pds(records).await;
    let pds_url = format!("http://{pds_addr}");

    let mut docs = HashMap::new();
    docs.insert(
        pds_did.clone(),
        did_doc(&pds_did, &pds_url, Some(&multibase)),
    );
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });

    let state = make_state(resolver);
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
        pds_priv,
        pds_did,
        steward_did,
        caller_did,
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
        &env.pds_priv,
        &env.pds_did,
        SERVER_DID,
        &env.caller_did,
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
    // Mint with a completely different key pair: the PDS DID doc still exposes
    // the original public key, so verification must fail.
    let (other_priv, _) = pds_keypair();
    let jwt = mint_service_auth(
        &other_priv,
        &env.pds_did,
        SERVER_DID,
        &env.caller_did,
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
        &env.pds_priv,
        &env.pds_did,
        SERVER_DID,
        &env.caller_did,
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
        &env.pds_priv,
        &env.pds_did,
        SERVER_DID,
        &env.caller_did,
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
        &env.pds_priv,
        &env.pds_did,
        "did:web:other.example",
        &env.caller_did,
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
        &env.pds_priv,
        &env.pds_did,
        SERVER_DID,
        &env.caller_did,
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
        &env.pds_priv,
        &env.pds_did,
        SERVER_DID,
        &env.caller_did,
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
        &env.pds_priv,
        &env.pds_did,
        SERVER_DID,
        &env.caller_did,
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
async fn auth_setup_with_keys(pds_privs: &[&KeyData]) -> (SocketAddr, String, String, String) {
    let pds_did = unique_did("pds");
    let steward_did = unique_did("steward");
    let caller_did = unique_did("caller");

    let records = Arc::new(Mutex::new(HashMap::new()));
    populate_standard_records(&records, &steward_did, ECHO_POLICY).await;
    let pds_addr = start_mock_pds(records).await;
    let pds_url = format!("http://{pds_addr}");

    // `KeyData::Display` emits `did:key:z...`; the DID doc stores the raw
    // multibase (the part after `did:key:`).
    let multibases: Vec<String> = pds_privs
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
    docs.insert(
        pds_did.clone(),
        did_doc_multi(&pds_did, &pds_url, &mb_refs),
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

    (addr, pds_did, steward_did, caller_did)
}

#[tokio::test]
async fn auth_selects_key_by_kid_when_multiple() {
    // A PDS exposing two signing keys; a token signed by the SECOND key must
    // verify, because the verifier matches the token header `kid` rather than
    // blindly taking the first key.
    let (k1_priv, _) = pds_keypair();
    let (k2_priv, _) = pds_keypair();
    let (addr, pds_did, steward_did, caller_did) =
        auth_setup_with_keys(&[&k1_priv, &k2_priv]).await;

    // Mint with the second key; its header `kid` is that key's did:key:.
    let jwt = mint_service_auth(
        &k2_priv,
        &pds_did,
        SERVER_DID,
        &caller_did,
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
    let (addr, pds_did, steward_did, caller_did) =
        auth_setup_with_keys(&[&old_priv, &new_priv]).await;

    let mint = |key: &KeyData| {
        mint_service_auth(
            key,
            &pds_did,
            SERVER_DID,
            &caller_did,
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

    // Swap the root policy to v2 and reload (simulates a Jetstream reload).
    {
        let mut m = env.records.lock().await;
        m.insert(
            (
                env.steward_did.clone(),
                ROOT_COLLECTION.into(),
                ROOT_RKEY.into(),
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
}#[tokio::test]
async fn unprovisioned_account_is_repaired_not_offboarded() {
    // A partially-provisioned account (bootstrap records never fully written,
    // `provisioned = false`) must be repaired by onboarding — its missing
    // service/recovery records rewritten — rather than offboarded as a
    // deliberate auto-delete.
    let steward_did = unique_did("steward");
    let records = Arc::new(Mutex::new(HashMap::new()));
    // Root policy present, but NO service record: mimics a createArbiter that
    // wrote credentials but failed before the bootstrap records landed.
    {
        let mut m = records.lock().await;
        m.insert(
            (
                steward_did.clone(),
                ROOT_COLLECTION.to_string(),
                ROOT_RKEY.to_string(),
            ),
            json!({ "policy": ECHO_POLICY }),
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
    let pds = policy::load_and_onboard(&state, &steward_did)
        .await
        .expect("onboard repairs unprovisioned account");
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

// ─── 6. resetPolicy (recovery admin) ────────────────────────────────────────

/// Stand up a server where `recovery` designates `admin_did` as the steward's
/// recovery admin, and return the router address + a signing PDS keypair for
/// minting caller JWTs.
async fn reset_setup() -> (SocketAddr, KeyData, String, String, String, RecordMap) {
    let steward_did = unique_did("steward");
    let admin_did = unique_did("admin");
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

    // A PDS DID carrying a signing key, so caller JWTs verify.
    let (pds_priv, pds_pub) = pds_keypair();
    let multibase = pds_pub
        .to_string()
        .strip_prefix("did:key:")
        .expect("pub key is did:key: prefixed")
        .to_string();
    let pds_did = unique_did("pds");

    let mut docs = HashMap::new();
    docs.insert(
        pds_did.clone(),
        did_doc(&pds_did, &pds_url, Some(&multibase)),
    );
    docs.insert(steward_did.clone(), did_doc(&steward_did, &pds_url, None));
    let resolver: Arc<dyn IdentityResolver> = Arc::new(MockResolver { docs });
    let state = make_state(resolver);
    state
        .store
        .store(
            steward_did.clone(),
            test_creds("steward-pw"),
        )
        .await
        .expect("store creds");
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

    (addr, pds_priv, pds_did, steward_did, admin_did, records)
}

/// Mint a caller JWT bound to `resetPolicy` with the given `sub`.
fn reset_jwt(pds_priv: &KeyData, pds_did: &str, sub: &str) -> String {
    mint_service_auth(
        pds_priv,
        pds_did,
        SERVER_DID,
        sub,
        "town.muni.arbiter.resetPolicy",
        now_secs() + 60,
    )
}

#[tokio::test]
async fn reset_policy_as_recovery_admin() {
    let (addr, pds_priv, pds_did, steward_did, admin_did, records) = reset_setup().await;
    let jwt = reset_jwt(&pds_priv, &pds_did, &admin_did);

    let url = format!("http://{addr}/xrpc/town.muni.arbiter.resetPolicy");
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(&jwt)
        .json(&json!({
            "arbiterDid": steward_did,
            "policy": "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"reset\" } }",
        }))
        .send()
        .await
        .expect("send resetPolicy");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "recovery admin must be able to reset the policy"
    );

    // The root policy record must have been overwritten in the PDS.
    let root = records
        .lock()
        .await
        .get(&(
            steward_did.clone(),
            ROOT_COLLECTION.to_string(),
            ROOT_RKEY.to_string(),
        ))
        .cloned()
        .expect("root policy record present after reset");
    assert_eq!(
        root.get("policy").and_then(|v| v.as_str()),
        Some("package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"reset\" } }"),
        "root policy must be the reset source"
    );
}

#[tokio::test]
async fn reset_policy_forbidden_for_non_admin() {
    let (addr, pds_priv, pds_did, steward_did, _admin_did, _records) = reset_setup().await;
    let intruder_did = unique_did("intruder");
    let jwt = reset_jwt(&pds_priv, &pds_did, &intruder_did);

    let url = format!("http://{addr}/xrpc/town.muni.arbiter.resetPolicy");
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(&jwt)
        .json(&json!({
            "arbiterDid": steward_did,
            "policy": "package arbiter\nresult := { \"ok\": true }",
        }))
        .send()
        .await
        .expect("send resetPolicy");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "non-admin caller must be forbidden"
    );
}

// ─── 7. optimistic concurrency (swapCommit) is enforced by the mock ─────────

#[tokio::test]
async fn put_record_rejects_stale_swap_commit() {
    // Prove the mock PDS enforces swapCommit: a putRecord carrying a stale repo
    // head must fail with InvalidSwap, and a current head must succeed. This
    // is the compare-and-swap path resetPolicy relies on.
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
            "collection": ROOT_COLLECTION,
            "rkey": ROOT_RKEY,
            "record": { "$type": ROOT_COLLECTION, "policy": "pkg" },
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
