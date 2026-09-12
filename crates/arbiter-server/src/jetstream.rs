//! Jetstream subscription for config/policy/service-record hot reload + auto-delete.
//!
//! Subscribes to ATProto Jetstream over a **WebSocket driven by `reqwest`**
//! (via `reqwest-websocket`), parsing each message with `atproto-jetstream`'s
//! `JetstreamEvent` type. Using reqwest for the transport means the connection
//! honors the `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` environment variables and
//! any custom TLS roots configured on the reqwest client — unlike
//! `atproto-jetstream`'s bundled `tokio-websockets` client, which opens a bare
//! `TcpStream` and cannot go through a proxy or use a custom certificate.
//!
//! The subscription is *not* DID-filtered server-side — it watches every repo —
//! and each event is accepted or dropped by whether the server currently
//! stewards the affected account. This way an arbiter created *after* the
//! subscription is live still receives policy hot-reload and auto-delete
//! without waiting for a reconnect. Only the record collections this server
//! cares about are watched:
//!
//! - `town.muni.arbiter.service` (the `self` service record) — arbiter
//!   lifecycle (absent or repointed -> offboard).
//! - `town.muni.arbiter.config` (the `self` config record) — trusted scopes +
//!   pipeline hot reload.
//! - `town.muni.arbiter.policy` — policy-record writes in **any** repo. A
//!   policy record may be local (the stewarded account's repo) or a remote
//!   (app-owned) shared layer; the policy module's reverse index maps each
//!   record's `at://` URI to the arbiters whose pipeline references it, so a
//!   write reloads exactly those arbiters.
//!
//! Rev gating is per-repo. Steward-repo events (service/config records, which
//! exist only in a stewarded account's own repo) are gated through
//! [`crate::state::ArbiterCollection::is_newer`]: the entry's `rev_floor` is
//! that repo's own head, so an older/duplicate rev is discarded. Remote-record
//! events (`town.muni.arbiter.policy` writes in *another* repo) are
//! deliberately NOT gated: each repo's rev stream is an independent TID
//! timeline, so a remote rev compared against the steward's floor is
//! meaningless and could silently skip a real update whenever the remote PDS
//! clock lags the steward's floor. Every accepted event reloads the arbiter
//! via [`crate::policy::load_and_onboard`], which re-fetches the *current*
//! records from the PDS and reapplies the lifecycle — so an ungated remote
//! event can only cause a redundant reload, never a missed or regressed
//! update (the same tradeoff `is_newer` accepts when no floor is known), and
//! because `load_and_onboard` never applies the event payload, a reordered or
//! duplicate event can never regress policy.
//!
//! `subscribe` owns reconnection (with bounded backoff) — a single connect is
//! driven by [`run_subscription`].

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use atproto_jetstream::EventHandler;
use atproto_jetstream::JetstreamEvent;
use futures_util::stream::{self, StreamExt};
use futures_util::SinkExt;
use moka::future::Cache;
use reqwest_websocket::{Message, RequestBuilderExt};

use crate::policy::{
    OnboardOutcome, RecordSource, ONBOARD_CONCURRENCY, load_and_onboard_with,
    refresh_all_after_reconnect,
};
use crate::{AppState, CONFIG};
/// Collections this server watches on Jetstream.
const WATCHED_COLLECTIONS: &[&str] = &[
    "town.muni.arbiter.service",
    "town.muni.arbiter.config",
    "town.muni.arbiter.policy",
];

/// Subscribe to Jetstream and drive:
///  - `town.muni.arbiter.policy` writes (any repo) -> reload exactly the
///    arbiters whose pipeline references the record (reverse index). Not
///    rev-gated: the event rev belongs to the record's repo, while the floor
///    gate compares against the steward repo's head (see `ReloadHandler::reload`)
///  - `town.muni.arbiter.config/self` writes
///    in a stewarded repo -> monotonic-rev reload (`load_and_onboard`)
///  - `town.muni.arbiter.service/self` writes/deletes -> auto-delete lifecycle
///    (absent -> offboard; repointed at another server -> offboard + store.remove)
///
/// The subscription is not DID-filtered: every event is evaluated against the
/// current set of stewarded accounts, so accounts created while the stream is
/// live are picked up immediately.
///
/// Runs forever, reconnecting with bounded backoff on disconnect or error.
/// Each connect is driven by [`run_subscription`]; this loop owns reconnection.
pub async fn subscribe(state: Arc<AppState>) {
    let mut backoff = Duration::from_secs(2);
    loop {
        match run_subscription(&state).await {
            Ok(()) => {
                // Stream ended cleanly; reconnect promptly and reset backoff.
                tracing::info!("jetstream stream ended; reconnecting");
                backoff = Duration::from_secs(2);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => {
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "jetstream subscription error; reconnecting in {backoff:?}"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }

        // The subscription was down; re-fetch current PDS state for every
        // steward so any policy/service-record write missed while disconnected
        // is picked up, closing the fail-open window (see
        // `refresh_all_after_reconnect`). This is distinct from startup
        // onboarding: it runs on every reconnect, not just boot.
        let refresh_state = state.clone();
        tokio::spawn(async move {
            refresh_all_after_reconnect(refresh_state).await;
        });
    }
}

/// Connect once and pump events until the stream closes or errors.
///
/// The subscription is deliberately not DID-filtered: it subscribes to every
/// repo, and [`ReloadHandler`] accepts only events for accounts the server
/// currently stewards. An account created after this subscription is live
/// therefore still gets hot-reload/auto-delete without a reconnect.
///
/// The transport is a WebSocket driven by `reqwest` (via `reqwest-websocket`),
/// so it honors `HTTP(S)_PROXY` and any custom TLS roots on the reqwest client.
/// Each text frame is parsed into an [`atproto_jetstream::JetstreamEvent`] and
/// dispatched to [`ReloadHandler`].
///
/// A watchdog cancels the connection if no message arrives within
/// [`JETSTREAM_STALL_TIMEOUT`]. reqwest-websocket has no read timeout of its
/// own, so a half-open connection would otherwise stall the subscription
/// indefinitely, silently disabling hot-reload/auto-delete. Cancelling forces
/// a reconnect, which re-runs [`crate::policy::refresh_all_after_reconnect`] to
/// re-fetch current PDS state.
async fn run_subscription(state: &Arc<AppState>) -> anyhow::Result<()> {
    // Build a reqwest client with the system-native trust roots. reqwest reads
    // HTTP_PROXY/HTTPS_PROXY/ALL_PROXY from the environment by default, so the
    // WebSocket (like the rest of the server's reqwest traffic) goes through a
    // configured proxy and trusts a custom system CA.
    //
    // Force HTTP/1.1: reqwest-websocket only supports HTTP/1.1 WebSocket
    // upgrades and fails ("websocket upgrade failed") if the connection
    // negotiates HTTP/2.
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        // Force HTTP/1.1: reqwest-websocket only supports HTTP/1.1 WebSocket
        // upgrades and fails ("websocket upgrade failed") if the connection
        // negotiates HTTP/2.
        .http1_only()
        .build()
        .context("building jetstream reqwest client")?;

    let url = jetstream_subscribe_url();
    let mut ws = client
        .get(url)
        .upgrade()
        .send()
        .await
        .map_err(|e| anyhow!("jetstream websocket upgrade failed: {e}"))?
        .into_websocket()
        .await
        .map_err(|e| anyhow!("jetstream websocket handshake failed: {e}"))?;

    tracing::info!(host = %CONFIG.jetstream_host, "jetstream websocket connected");

    // Send the Jetstream "options_update" message so the server applies our
    // wanted collections (mirrors what atproto-jetstream sends on connect).
    ws.send(jetstream_update_message()).await
        .map_err(|e| anyhow!("jetstream update message send failed: {e}"))?;

    let handler = ReloadHandler::new(Arc::clone(state));

    // Pump frames. The WebSocket is a `Stream<Item = Result<Message, Error>>`.
    // Each `next()` is wrapped in `JETSTREAM_STALL_TIMEOUT` so a half-open
    // connection (which yields no frame) cannot stall the subscription
    // indefinitely; the timeout breaks the loop and forces a reconnect.
    loop {
        let next = tokio::time::timeout(JETSTREAM_STALL_TIMEOUT, ws.next()).await;
        match next {
            Err(_) => {
                tracing::warn!("jetstream connection stalled; reconnecting");
                break;
            }
            Ok(None) => {
                tracing::warn!("jetstream connection closed");
                break;
            }
            Ok(Some(Err(e))) => {
                return Err(anyhow!("jetstream recv error: {e}"));
            }
            Ok(Some(Ok(Message::Text(text)))) => {
                match serde_json::from_str::<JetstreamEvent>(&text) {
                    Ok(event) => {
                        if let Err(e) = handler.handle_event(Arc::new(event)).await {
                            tracing::error!(error = %format!("{e:#}"), "jetstream handler error");
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "skipping unparseable jetstream frame");
                    }
                }
            }
            Ok(Some(Ok(Message::Binary(_)))) => {
                // Compression is disabled; Jetstream sends text frames only.
                tracing::debug!("ignoring unexpected binary jetstream frame");
            }
            Ok(Some(Ok(_))) => {
                // Ping/Pong/Close frames: ignore.
            }
        }
    }
    Ok(())
}

/// The WebSocket subscribe URL for the configured Jetstream host.
fn jetstream_subscribe_url() -> reqwest::Url {
    let collections = WATCHED_COLLECTIONS
        .iter()
        .map(|c| format!("wantedCollections={c}"))
        .collect::<Vec<_>>()
        .join("&");
    reqwest::Url::parse(&format!(
        "wss://{}/subscribe?compress=false&requireHello=false&{collections}",
        CONFIG.jetstream_host
    ))
    .expect("valid jetstream subscribe URL")
}

/// The JSON `options_update` message Jetstream expects once connected.
fn jetstream_update_message() -> Message {
    let wanted = WATCHED_COLLECTIONS
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    Message::Text(
        serde_json::json!({
            "type": "options_update",
            "payload": {
                "wantedCollections": wanted,
                "wantedDids": [],
                "maxMessageSizeBytes": 56_000,
            },
        })
        .to_string(),
    )
}

/// Maximum time the Jetstream subscription may go without receiving any message
/// before it is reconnected. Guards against a half-open connection stalling
/// hot-reload/auto-delete indefinitely.
const JETSTREAM_STALL_TIMEOUT: Duration = Duration::from_secs(300);

/// Handler that reloads arbiters on watched config/policy/service-record events.
///
/// The subscription is not DID-filtered (see [`subscribe`]), so this handler
/// checks, per event, that the server currently stewards the affected account.
///
/// Public so integration tests can drive individual events through the same
/// dispatch path the live WebSocket uses, without a real Jetstream connection.
pub struct ReloadHandler {
    /// Shared server state the handler reloads against.
    state: Arc<AppState>,
}

#[async_trait]
impl EventHandler for ReloadHandler {
    async fn handle_event(&self, event: Arc<JetstreamEvent>) -> anyhow::Result<()> {
        // Only repo commit/delete events carry record changes; identity and
        // account events are irrelevant to policy.
        let (did, rev, collection, rkey) = match &*event {
            JetstreamEvent::Commit { did, commit, .. } => (
                did,
                commit.rev.as_str(),
                commit.collection.as_str(),
                commit.rkey.as_str(),
            ),
            JetstreamEvent::Delete { did, commit, .. } => (
                did,
                commit.rev.as_str(),
                commit.collection.as_str(),
                commit.rkey.as_str(),
            ),
            _ => return Ok(()),
        };

        // Only watch the record collections we care about.
        if !is_watched_collection(collection) {
            return Ok(());
        }

        if collection == crate::policy::POLICY_COLLECTION {
            // A policy-record write in ANY repo: local records and remote
            // (app-owned) shared layers are the same shape, so look up the
            // record's `at://` URI in the policy module's reverse index and
            // reload exactly the arbiters whose pipeline references it.
            let uri = format!("at://{did}/{collection}/{rkey}");
            // Reload the referencing arbiters bounded-concurrently and
            // coalesce their record fetches within this dispatch: a widely
            // shared layer can reference thousands of arbiters, and without
            // both, one record write means thousands of SEQUENTIAL reloads
            // (pinning the event pump past the stall watchdog, triggering a
            // reconnect storm) that re-fetch the same record once per
            // arbiter (a guaranteed 429 storm on the layer's PDS). The
            // cache is scoped to this dispatch, so the next event always
            // fetches fresh.
            let layer_fetches = &Cache::new(4096);
            let mut reloads = stream::iter(crate::policy::referencing_arbiters(&uri))
                .map(|arbiter_did| async move {
                    // Index backlinks can outlive an offboard/purge; only reload
                    // accounts we currently steward (a redundant reload for a
                    // purged DID would just re-apply the lifecycle, but skipping
                    // keeps the stream cheap).
                    if self.is_stewarded(&arbiter_did).await {
                        // Ungated (rev = None): the event rev belongs to the
                        // record's repo, while the rev-floor gate compares against
                        // the steward repo's head — cross-repo revs are
                        // incomparable (see `reload`).
                        self.reload(&arbiter_did, None, Some(layer_fetches)).await;
                    }
                })
                .buffer_unordered(ONBOARD_CONCURRENCY);
            while reloads.next().await.is_some() {}
            return Ok(());
        }

        // Service + config records only exist in a stewarded account's own
        // repo. Only process accounts we actually steward (have credentials
        // for): the subscription is not DID-filtered, so this per-event check
        // is what limits the stream to our stewarded accounts. It also
        // handles a DID purged after a repoint.
        if self.is_stewarded(did).await {
            // Rev-gated (Some): these collections exist only in the steward
            // repo — the same repo whose head is the load-time rev floor.
            self.reload(did, Some(rev), None).await;
        }
        Ok(())
    }

    fn handler_id(&self) -> &str {
        "arbiter-policy-reload"
    }
}

impl ReloadHandler {
    /// Create a handler over `state`. The production subscription builds one
    /// per connect; tests build one to dispatch events directly.
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Whether the server currently stewards `did` (holds credentials for it).
    ///
    /// The subscription is not DID-filtered, so this per-event check is what
    /// limits the stream to our stewarded accounts.
    async fn is_stewarded(&self, did: &str) -> bool {
        match self.state.store.get(did).await {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(
                    did,
                    error = %format!("{e:#}"),
                    "credential lookup failed; skipping jetstream event"
                );
                false
            }
        }
    }

    /// Reload a single arbiter: re-fetch current PDS state and reapply the
    /// lifecycle + pipeline. Shared by every event path.
    ///
    /// `rev` gates the reload — but only for steward-repo events (`Some`):
    /// the load-time `rev_floor` is the *steward* repo's own head (see
    /// `ArbiterCollection::is_newer`), so an event at or below it refers to
    /// state already reflected in the loaded records and is discarded.
    /// Remote-record events pass `None` and skip the gate: each repo's rev
    /// stream is an independent TID timeline, so comparing a remote rev
    /// against the steward's floor is meaningless and could silently skip a
    /// real update whenever the remote PDS clock lags the floor. Skipping
    /// the gate only risks a redundant reload — every reload re-fetches
    /// current state, never the event payload — the same tradeoff
    /// `is_newer` accepts when no floor is known.
    ///
    /// `layer_fetches` coalesces pipeline-record fetches across a dispatch
    /// wave (the policy-event branch passes a dispatch-scoped cache, since
    /// every referencing arbiter loads the same pipeline); `None` — single
    /// arbiter events — always fetches fresh.
    async fn reload(
        &self,
        did: &str,
        rev: Option<&str>,
        layer_fetches: Option<&Cache<String, RecordSource>>,
    ) {
        // Discard steward-repo events at or below the load-time rev floor:
        // their state is already reflected in the loaded records.
        if let Some(rev) = rev {
            if !self.state.arbiters.is_newer(did, rev).await {
                return;
            }
        }

        // Re-fetch the current PDS state and reapply the lifecycle + policies.
        // This never applies the event payload directly, so reordered/duplicate
        // events cannot regress policy. `load_and_onboard` sets the new rev
        // floor from the PDS head it just read, so the next gating decision
        // reflects the freshest state.
        //
        // TODO: maybe we should try to surgically update instead of refreshing the
        // whole policy by re-loading all the records in the future, but we need to
        // analyze carefully for correctness before doing that.
        match load_and_onboard_with(&self.state, did, layer_fetches).await {
            Ok(OnboardOutcome::Onboarded { pds_endpoint }) => {
                tracing::info!(did, pds = %pds_endpoint, "reloaded arbiter from jetstream event");
            }
            Ok(OnboardOutcome::Offboarded { pds_endpoint }) => {
                tracing::info!(
                    did,
                    pds = %pds_endpoint,
                    "offboarded arbiter from jetstream event (service record absent or repointed)"
                );
            }
            Err(e) => {
                // Fail closed: stop serving until the next reload succeeds.
                tracing::warn!(
                    did,
                    error = %format!("{e:#}"),
                    "jetstream-triggered reload failed; offboarding (fail-closed)"
                );
                self.state.arbiters.offboard(did).await;
            }
        }
    }
}

/// Whether a Jetstream record collection is one this server watches.
fn is_watched_collection(collection: &str) -> bool {
    WATCHED_COLLECTIONS.iter().any(|c| c == &collection)
}
