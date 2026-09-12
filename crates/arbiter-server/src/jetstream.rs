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
use futures_util::SinkExt;
use futures_util::stream::{self, StreamExt};
use reqwest_websocket::{Message, RequestBuilderExt};

use crate::policy::{
    ONBOARD_CONCURRENCY, OnboardOutcome, load_and_onboard, refresh_all_after_reconnect,
};
use crate::record_store;
use crate::{AppState, CONFIG};
/// Collections this server watches on Jetstream.
const WATCHED_COLLECTIONS: &[&str] = &[
    "town.muni.arbiter.service",
    "town.muni.arbiter.config",
    "town.muni.arbiter.policy",
];

/// Maximum disconnect for which a reconnect resumes via the Jetstream
/// `cursor` parameter (replaying events since the last processed one) rather
/// than falling back to a full record-store invalidation.
///
/// This is an operator contract, not a safety net: Jetstream gives no signal
/// when a cursor predates its retention (it silently starts from the earliest
/// retained event), so this MUST NOT exceed the configured Jetstream's event
/// retention — see `CONFIG.jetstream_cursor_max_gap_secs`. The first
/// replayed event's timestamp is checked as a coarse backstop: it catches a
/// server that replays nothing useful, but partial retention loss is
/// invisible to the client. Set the config to `0` to disable cursor resume.
fn jetstream_cursor_max_gap_us() -> u64 {
    CONFIG
        .jetstream_cursor_max_gap_secs
        .saturating_mul(1_000_000)
}

/// Current Unix time in microseconds (the unit Jetstream cursors use).
fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

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
    let mut last_event_us: Option<u64> = None;
    loop {
        // Resume from the last processed event when the disconnect is short
        // enough to trust Jetstream replay (see `jetstream_cursor_max_gap_us()`):
        // replayed events refill the record store rev-gated (duplicates are
        // skipped), so the post-reconnect refresh runs against a warm store.
        // A gap longer than the window drops the cursor entirely — that is
        // NOT a fresh boot: the store still holds pre-disconnect entries that
        // missed every write during the outage, so `gap_unknown` forces the
        // full refresh below (the pump connects live, replaying nothing).
        let resume_from =
            last_event_us.filter(|t| now_us().saturating_sub(*t) <= jetstream_cursor_max_gap_us());
        let gap_unknown = last_event_us.is_some() && resume_from.is_none();
        match run_subscription(&state, resume_from).await {
            Ok((processed, gap_covered)) => {
                // Stream ended cleanly; reconnect promptly and reset backoff.
                tracing::info!("jetstream stream ended; reconnecting");
                last_event_us = Some(processed);
                backoff = Duration::from_secs(2);
                tokio::time::sleep(Duration::from_secs(1)).await;

                // Reconnect refresh, tiered by how much we trust the store:
                // a verified cursor replay (or a fresh boot, whose baseline
                // is the just-finished startup onboard) leaves the store
                // current, so only arbiters that are NOT serving need a
                // load. An unverified gap invalidated the store first and
                // needs the full pass (fail-closed; see
                // `refresh_all_after_reconnect`).
                let refresh_state = state.clone();
                tokio::spawn(async move {
                    refresh_all_after_reconnect(refresh_state, !gap_covered || gap_unknown).await;
                });
            }
            Err(e) => {
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "jetstream subscription error; reconnecting in {backoff:?}"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                // No refresh here: the store's currency is unknown (the
                // stream errored at an arbitrary point), and the reconnect
                // below will resume from the cursor — or invalidate the
                // store and run the full pass when the replay cannot be
                // trusted. A refresh against a possibly-stale store would
                // re-onboard from stale records.
            }
        }
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
async fn run_subscription(
    state: &Arc<AppState>,
    resume_from: Option<u64>,
) -> anyhow::Result<(u64, bool)> {
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

    let url = jetstream_subscribe_url(resume_from);
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
    ws.send(jetstream_update_message())
        .await
        .map_err(|e| anyhow!("jetstream update message send failed: {e}"))?;

    let handler = ReloadHandler::new(Arc::clone(state));
    let mut last_event_us = resume_from;

    // Whether the record store provably reflects the stream up to now: a
    // fresh boot (startup onboard just built the store) or a cursor resume
    // that replays the disconnect gap. The first-replayed-event check below
    // can flip this to false when Jetstream could not honor the cursor.
    let mut gap_covered = last_event_us.is_none();

    // Verify a cursor resume actually happened: Jetstream silently starts
    // from its earliest retained event when the cursor predates its
    // retention, which would leave the record store missing the disconnect
    // gap. A first replayed event far past the resume point means the gap
    // was NOT replayed: drop the cached records so the post-reconnect
    // refresh re-fetches current state (the fallback path).
    let mut verify_resume = resume_from;

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
                        if let Some(resume) = verify_resume.take() {
                            let time_us = event_time_us(&event).unwrap_or(0);
                            if time_us.saturating_sub(resume) > jetstream_cursor_max_gap_us() {
                                tracing::warn!(
                                    resume_from = resume,
                                    first_event_us = time_us,
                                    "jetstream cursor not honored; invalidating record store for full refresh"
                                );
                                record_store::invalidate_all();
                                gap_covered = false;
                            } else {
                                // Cursor honored: the replay covers the gap.
                                gap_covered = true;
                            }
                        }
                        last_event_us = event_time_us(&event).or(last_event_us);
                        if let Err(e) = handler.handle_event(Arc::new(event)).await {
                            tracing::error!(error = %format!("{e:#}"), "jetstream handler error");
                        }
                    }
                    Err(e) => {
                        // A wrong-version Jetstream host delivers frames this
                        // client cannot parse — silence here would leave the
                        // server connected but blind. Surface loudly.
                        tracing::warn!(error = %e, "skipping unparseable jetstream frame");
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
    Ok((
        last_event_us.unwrap_or_else(|| resume_from.unwrap_or(0)),
        gap_covered,
    ))
}

/// The stream-position timestamp of any Jetstream event (used for cursor
/// tracking; every event kind carries `time_us`).
fn event_time_us(event: &JetstreamEvent) -> Option<u64> {
    match event {
        JetstreamEvent::Commit { time_us, .. } => Some(*time_us),
        JetstreamEvent::Delete { time_us, .. } => Some(*time_us),
        JetstreamEvent::Identity { time_us, .. } => Some(*time_us),
        JetstreamEvent::Account { time_us, .. } => Some(*time_us),
    }
}

/// Microseconds rewound from the last processed event when building the
/// resume cursor: the Jetstream README recommends a small negative buffer
/// for gapless playback, because a cursor exactly at the last event's
/// `time_us` may skip an event sharing that microsecond. The rewound
/// duplicates are free here — store folds and reload gates are rev-gated
/// and idempotent.
const CURSOR_REWIND_US: u64 = 5_000_000;

/// The WebSocket subscribe URL for the configured Jetstream host, resuming
/// from `cursor` (the last processed event's `time_us`, rewound by
/// [`CURSOR_REWIND_US`]) when set. If the cursor is older than Jetstream's
/// retention the server starts from the earliest retained event;
/// `run_subscription` verifies that and falls back to a full refresh when
/// the replay cannot be trusted.
fn jetstream_subscribe_url(cursor: Option<u64>) -> reqwest::Url {
    let collections = WATCHED_COLLECTIONS
        .iter()
        .map(|c| format!("wantedCollections={c}"))
        .collect::<Vec<_>>()
        .join("&");
    let cursor = cursor
        .map(|c| format!("&cursor={}", c.saturating_sub(CURSOR_REWIND_US)))
        .unwrap_or_default();
    reqwest::Url::parse(&format!(
        "wss://{}/subscribe?compress=false&requireHello=false&{collections}{cursor}",
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
        let (did, rev, collection, rkey, record) = match &*event {
            JetstreamEvent::Commit { did, commit, .. } => (
                did,
                commit.rev.as_str(),
                commit.collection.as_str(),
                commit.rkey.as_str(),
                Some(&commit.record),
            ),
            JetstreamEvent::Delete { did, commit, .. } => (
                did,
                commit.rev.as_str(),
                commit.collection.as_str(),
                commit.rkey.as_str(),
                None,
            ),
            _ => return Ok(()),
        };

        // Only watch the record collections we care about.
        if !is_watched_collection(collection) {
            return Ok(());
        }

        // Fold the event into the record store BEFORE any reload dispatch:
        // for Create/Update the payload IS the record's new content (applied
        // rev-gated, no fetch); for Delete it evicts the entry. The reload
        // waves below then read current values without fetching (see
        // `record_store`). The recovery record is deliberately not stored
        // (authorization gate — see `record_store::is_storeable_collection`).
        let uri = format!("at://{did}/{collection}/{rkey}");
        if record_store::is_storeable_collection(collection) {
            match record {
                Some(record) => {
                    let record = record_store::from_commit_record(record)?;
                    record_store::apply_update(&uri, rev, record).await;
                }
                None => record_store::apply_delete(&uri, rev).await,
            }
        }

        if collection == crate::policy::POLICY_COLLECTION {
            // A policy-record write in ANY repo: local records and remote
            // (app-owned) shared layers are the same shape, so look up the
            // record's `at://` URI in the policy module's reverse index and
            // reload exactly the arbiters whose pipeline references it.
            // Reload bounded-concurrently: a widely shared layer can
            // reference thousands of arbiters, and sequential reloads would
            // pin the event pump past the stall watchdog (triggering a
            // reconnect storm). Loads read the store — no record fetches.
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
                        self.reload(&arbiter_did, None).await;
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
            self.reload(did, Some(rev)).await;
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

    /// Reload a single arbiter: reapply the lifecycle + pipeline from the
    /// record store. Shared by every event path.
    ///
    /// `rev` gates the reload — but only for steward-repo events (`Some`):
    /// the load-time `rev_floor` is the *steward* repo's own head (see
    /// `ArbiterCollection::is_newer`), so an event at or below it refers to
    /// state already reflected in the loaded records and is discarded.
    /// Remote-record events pass `None` and skip the gate: each repo's rev
    /// stream is an independent TID timeline, so comparing a remote rev
    /// against the steward's floor is meaningless and could silently skip a
    /// real update whenever the remote PDS clock lags the floor. Skipping
    /// the gate only risks a redundant reload.
    ///
    /// Record values are served by the global record store, which this
    /// event's dispatch already updated (rev-gated — reordered or duplicate
    /// events cannot regress an entry), so reloads read current state
    /// without re-fetching records.
    async fn reload(&self, did: &str, rev: Option<&str>) {
        // Discard steward-repo events at or below the load-time rev floor:
        // their state is already reflected in the loaded records.
        if let Some(rev) = rev {
            if !self.state.arbiters.is_newer(did, rev).await {
                return;
            }
        }

        // Reload from the record store: the event was already folded in
        // (rev-gated) by `handle_event`, so this observes current state
        // without re-fetching records. `load_and_onboard` sets the new rev
        // floor from the PDS head it just read, so the next gating decision
        // reflects the freshest state.
        //
        // TODO: maybe we should try to surgically update instead of refreshing the
        // whole policy by re-loading all the records in the future, but we need to
        // analyze carefully for correctness before doing that.
        match load_and_onboard(&self.state, did).await {
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
