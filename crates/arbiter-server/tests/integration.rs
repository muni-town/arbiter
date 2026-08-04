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
    Json(json!({ "accessJwt": "fake-jwt", "did": "mock-pds" })).into_response()
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

/// Start a mock PDS on a random port backed by the shared record map. The
/// server runs for the lifetime of the test's tokio runtime.
async fn start_mock_pds(records: RecordMap) -> SocketAddr {
    let state = PdsState { records };
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
        json!({ "source": policy_source }),
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
    let claims = Claims {
        jose: JoseClaims {
            issuer: Some(iss.to_string()),
            audience: Some(aud.to_string()),
            subject: Some(sub.to_string()),
            expiration: Some(exp_secs),
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

/// Send `GET /xrpc/com.example.foo` to the running server, optionally with a
/// Bearer JWT and the `arbiter-did`/`arbiter-proxy` headers.
async fn xrpc_get(
    env: &AuthEnv,
    jwt: Option<String>,
    arbiter_did: Option<&str>,
) -> reqwest::Response {
    let url = format!("http://{}/xrpc/com.example.foo", env.addr);
    let client = reqwest::Client::new();
    let mut req = client.get(&url);
    if let Some(j) = jwt {
        req = req.bearer_auth(j);
    }
    if let Some(d) = arbiter_did {
        req = req
            .header("arbiter-did", d)
            .header("arbiter-proxy", format!("{d}#atproto_pds"));
    }
    req.send().await.expect("request sent")
}

/// A valid serviceAuth JWT bound to `com.example.foo` for the given env.
fn valid_jwt(env: &AuthEnv) -> String {
    mint_service_auth(
        &env.pds_priv,
        &env.pds_did,
        SERVER_DID,
        &env.caller_did,
        "com.example.foo",
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
        .store(did.clone(), PdsCredentials { password: "irrelevant".to_string() })
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
        "com.example.foo",
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
        "com.example.foo",
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
    // Valid signature/aud/exp, but the bound lxm differs from the request path.
    let jwt = mint_service_auth(
        &env.pds_priv,
        &env.pds_did,
        SERVER_DID,
        &env.caller_did,
        "com.example.bar",
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
        "com.example.foo",
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
    // Valid JWT, but no arbiter-did header → MissingHeader → 400.
    let resp = xrpc_get(&env, Some(valid_jwt(&env)), None).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "missing arbiter-did must be a 400"
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
            json!({ "source": "package arbiter\nresult := { \"ok\": true, \"output\": { \"got\": \"v2\" } }" }),
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
            PdsCredentials { password: "kept".to_string() },
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
            PdsCredentials { password: "purge-me".to_string() },
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
