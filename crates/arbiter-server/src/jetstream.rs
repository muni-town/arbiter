//! Jetstream subscription for policy/service-record hot reload + auto-delete.
//!
//! Subscribes to ATProto Jetstream using the `atproto-jetstream` consumer
//! library (typed events, WebSocket + parsing handled by the library). The
//! subscription is *not* DID-filtered server-side — it watches every repo — and
//! each event is accepted or dropped by whether the server currently stewards
//! the affected account. This way an arbiter created *after* the subscription
//! is live still receives policy hot-reload and auto-delete without waiting for
//! a reconnect. Only the record collections this server cares about are watched:
//!
//! - `town.muni.arbiter.service` (the `self` service record) — arbiter
//!   lifecycle (absent or repointed -> offboard).
//! - `town.muni.arbiter.policy.root` / `town.muni.arbiter.policy.sub` — policy
//!   hot reload.
//!
//! On every relevant `commit`/`delete` event, the record's `rev` is gated
//! through [`crate::state::ArbiterCollection::is_newer`] (older/duplicate revs
//! are discarded) and, if newer, the arbiter is reloaded via
//! [`crate::policy::load_and_onboard`], which re-fetches the *current* records
//! from the PDS and reapplies the lifecycle. Because `load_and_onboard` always
//! reads the latest PDS state (never the event payload), a reordered or
//! duplicate event can never regress policy.
//!
//! The library does **not** reconnect automatically — `subscribe` keeps the
//! outer reconnect-with-backoff loop and drives the consumer on each attempt.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use atproto_jetstream::{
    CancellationToken, Consumer, ConsumerTaskConfig, EventHandler, JetstreamEvent,
};

use crate::policy::{load_and_onboard, refresh_all_after_reconnect};
use crate::{AppState, CONFIG};

/// Collections this server watches on Jetstream.
const WATCHED_COLLECTIONS: &[&str] = &[
    "town.muni.arbiter.service",
    "town.muni.arbiter.policy.root",
    "town.muni.arbiter.policy.sub",
];

/// Subscribe to Jetstream and drive:
///  - `town.muni.arbiter.policy.*` writes -> monotonic-rev reload
///    (`load_and_onboard`, gated by `is_newer`/`set_rev`)
///  - `town.muni.arbiter.service/self` writes/deletes -> auto-delete lifecycle
///    (absent -> offboard; repointed at another server -> offboard + store.remove)
///
/// The subscription is not DID-filtered: every event is evaluated against the
/// current set of stewarded accounts, so accounts created while the stream is
/// live are picked up immediately.
///
/// Runs forever, reconnecting with bounded backoff on disconnect or error. The
/// underlying `atproto-jetstream` consumer does not reconnect itself; this loop
/// owns reconnection.
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
/// The consumer is deliberately not DID-filtered: it subscribes to every repo,
/// and `ReloadHandler` accepts only events for accounts the server currently
/// stewards. An account created after this subscription is live therefore still
/// gets hot-reload/auto-delete without a reconnect.
///
/// A watchdog cancels the consumer if no message arrives within
/// [`JETSTREAM_STALL_TIMEOUT`]. The underlying consumer loop has no read
/// timeout of its own and only exits on WS close or cancellation, so a
/// half-open connection would otherwise stall the subscription indefinitely,
/// silently disabling hot-reload/auto-delete. Cancelling forces a reconnect,
/// which re-runs [`crate::policy::refresh_all_after_reconnect`] to re-fetch
/// current PDS state.
async fn run_subscription(state: &Arc<AppState>) -> anyhow::Result<()> {
    let config = ConsumerTaskConfig {
        user_agent: format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        // TODO(compression): consider enabling Zstandard compression to save on
        // bandwidth. Requires vendoring the Jetstream zstd dictionary file and
        // wiring a config path to it (the library hard-reads
        // `zstd_dictionary_location` at connect time, so a missing/mismatched
        // dictionary fails the whole subscription). Deferred for simplicity.
        compression: false,
        zstd_dictionary_location: String::new(),
        jetstream_hostname: CONFIG.jetstream_host.clone(),
        collections: WATCHED_COLLECTIONS.iter().map(|s| s.to_string()).collect(),
        // Subscribe to all DIDs; each event is filtered per-event by whether the
        // server stewards the affected account (see `ReloadHandler`).
        dids: Vec::new(),
        max_message_size_bytes: None,
        cursor: None,
        require_hello: false,
    };

    let consumer = Consumer::new(config);
    let handler = Arc::new(ReloadHandler {
        state: Arc::clone(state),
    });
    consumer
        .register_handler(handler)
        .await
        .context("registering jetstream handler")?;

    let cancel = CancellationToken::new();
    // Clone for the consumer task; the original is held for the watchdog.
    let consumer_cancel = cancel.clone();
    let handle = tokio::spawn(async move { consumer.run_background(consumer_cancel).await });

    // Watchdog: if the consumer makes no progress for `JETSTREAM_STALL_TIMEOUT`,
    // cancel it to force a reconnect. A false positive is safe — the reconnect
    // path re-fetches current PDS state for every steward.
    let watchdog = tokio::spawn(async move {
        tokio::time::sleep(JETSTREAM_STALL_TIMEOUT).await;
        tracing::warn!("jetstream subscription stalled; cancelling to force reconnect");
        cancel.cancel();
    });

    let outcome = match handle.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(anyhow!("jetstream consumer task panicked: {e}")),
    };
    watchdog.abort();
    outcome
}

/// Maximum time the Jetstream consumer may go without receiving any message
/// before it is cancelled and reconnected. Guards against a half-open
/// connection stalling hot-reload/auto-delete indefinitely.
const JETSTREAM_STALL_TIMEOUT: Duration = Duration::from_secs(300);

/// Handler that reloads arbiters on watched policy/service-record events.
///
/// The subscription is not DID-filtered (see [`subscribe`]), so this handler
/// checks, per event, that the server currently stewards the affected account.
struct ReloadHandler {
    state: Arc<AppState>,
}

#[async_trait]
impl EventHandler for ReloadHandler {
    async fn handle_event(&self, event: Arc<JetstreamEvent>) -> anyhow::Result<()> {
        // Only repo commit/delete events carry record changes; identity and
        // account events are irrelevant to policy.
        let (did, rev, collection) = match &*event {
            JetstreamEvent::Commit { did, commit, .. } => (
                did,
                commit.rev.as_str(),
                commit.collection.as_str(),
            ),
            JetstreamEvent::Delete { did, commit, .. } => (
                did,
                commit.rev.as_str(),
                commit.collection.as_str(),
            ),
            _ => return Ok(()),
        };

        // Only watch the record collections we care about.
        if !is_watched_collection(collection) {
            return Ok(());
        }
        // Only process accounts we actually steward (have credentials for).
        // The subscription is not DID-filtered, so this per-event check is what
        // limits the stream to our stewarded accounts. It also handles a DID
        // purged after a repoint.
        let stewarded = match self.state.store.get(did).await {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(
                    did,
                    error = %format!("{e:#}"),
                    "credential lookup failed; skipping jetstream event"
                );
                return Ok(());
            }
        };
        if !stewarded {
            return Ok(());
        }

        // Discard events at or below the load-time rev floor: their state is
        // already reflected in the loaded records (see `ArbiterCollection::is_newer`).
        if !self.state.arbiters.is_newer(did, rev).await {
            return Ok(());
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
        match load_and_onboard(&self.state, did).await {
            Ok(pds) => {
                tracing::debug!(did, pds = %pds, "reloaded arbiter from jetstream event");
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
        Ok(())
    }

    fn handler_id(&self) -> &str {
        "arbiter-policy-reload"
    }
}

/// Whether a Jetstream record collection is one this server watches.
fn is_watched_collection(collection: &str) -> bool {
    WATCHED_COLLECTIONS.iter().any(|c| c == &collection)
}
