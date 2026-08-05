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

use crate::policy::load_and_onboard;
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
    }
}

/// Connect once and pump events until the stream closes or errors.
///
/// The consumer is deliberately not DID-filtered: it subscribes to every repo,
/// and `ReloadHandler` accepts only events for accounts the server currently
/// stewards. An account created after this subscription is live therefore still
/// gets hot-reload/auto-delete without a reconnect.
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
    let handle = tokio::spawn(async move { consumer.run_background(cancel).await });
    // The consumer runs until the stream closes (returns Ok) or errors. Wait for
    // the task to finish, then return to the reconnect loop (any Err -> backoff).
    match handle.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(anyhow!("jetstream consumer task panicked: {e}")),
    }
}

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

        // The record key this event targets, used for monotonic-rev gating. For a
        // commit this is the record path; for a delete it's the collection/rkey too
        // (so a delete of a watched record is rev-gated identically).
        let path = format!("{collection}/{rkey}");

        // Discard older/duplicate revs.
        if !self.state.arbiters.is_newer(did, &path, rev).await {
            return Ok(());
        }

        // Re-fetch the current PDS state and reapply the lifecycle + policies.
        // This never applies the event payload directly, so reordered/duplicate
        // events cannot regress policy.
        // 
        // TODO: maybe we should try to surgically update instead of refreshing the
        // whole policy by re-loading all the records in the future, but we need to
        // analyze carefully for correctness before doing that.
        match load_and_onboard(&self.state, did).await {
            Ok(pds) => {
                self.state
                    .arbiters
                    .set_rev(did, &path, rev.to_string())
                    .await;
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
