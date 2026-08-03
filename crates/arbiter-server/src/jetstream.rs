//! Jetstream subscription for policy/service-record hot reload + auto-delete
//! (SERVER_PLAN.md §4).
//!
//! Subscribes to ATProto Jetstream using the `atproto-jetstream` consumer
//! library (typed events, WebSocket + parsing handled by the library). The
//! subscription is filtered to the stewarded accounts' repos and the record
//! collections this server cares about:
//!
//! - `town.muni.arbiter.service` (the `self` service record) — §4 lifecycle.
//! - `town.muni.arbiter.policy.root` / `town.muni.arbiter.policy.sub` — policy
//!   hot reload.
//!
//! On every relevant `commit`/`delete` event, the record's `rev` is gated
//! through [`crate::state::ArbiterCollection::is_newer`] (older/duplicate revs
//! are discarded) and, if newer, the arbiter is reloaded via
//! [`crate::policy::load_and_onboard`], which re-fetches the *current* records
//! from the PDS and applies the §4 lifecycle. Because `load_and_onboard` always
//! reads the latest PDS state (never the event payload), a reordered or
//! duplicate event can never regress policy.
//!
//! The library does **not** reconnect automatically — `subscribe` keeps the
//! outer reconnect-with-backoff loop and drives the consumer on each attempt.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use atproto_jetstream::{
    CancellationToken, Consumer, ConsumerTaskConfig, EventHandler, JetstreamEvent,
};
use async_trait::async_trait;

use crate::policy::load_and_onboard;
use crate::{AppState, CONFIG};

/// Collections this server watches on Jetstream.
const WATCHED_COLLECTIONS: &[&str] = &[
    "town.muni.arbiter.service",
    "town.muni.arbiter.policy.root",
    "town.muni.arbiter.policy.sub",
];

/// Subscribe to Jetstream for all stewarded accounts and drive:
///  - `town.muni.arbiter.policy.*` writes -> monotonic-rev reload
///    (`load_and_onboard`, gated by `is_newer`/`set_rev`)
///  - `town.muni.arbiter.service/self` writes/deletes -> auto-delete lifecycle
///    (absent -> offboard; repointed at another server -> offboard + store.remove)
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
async fn run_subscription(state: &Arc<AppState>) -> anyhow::Result<()> {
    let dids = state
        .store
        .list()
        .await
        .map_err(|e| anyhow!("listing stewarded DIDs: {e:#}"))?;
    if dids.is_empty() {
        tracing::info!("no stewarded accounts; jetstream subscription idle until one is added");
        // Nothing to subscribe to; wait and let the outer loop retry so newly
        // bootstrapped arbiters are picked up.
        tokio::time::sleep(Duration::from_secs(60)).await;
        return Ok(());
    }

    let steward_dids: Vec<String> = dids.into_iter().map(|(d, _)| d).collect();

    let host = jetstream_host(&CONFIG.jetstream_url);
    let config = ConsumerTaskConfig {
        user_agent: format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        // TODO(compression): consider enabling Zstandard compression to save on
        // bandwidth. Requires vendoring the Jetstream zstd dictionary file and
        // wiring a config path to it (the library hard-reads
        // `zstd_dictionary_location` at connect time, so a missing/mismatched
        // dictionary fails the whole subscription). Deferred for simplicity.
        compression: false,
        zstd_dictionary_location: String::new(),
        jetstream_hostname: host.to_string(),
        collections: WATCHED_COLLECTIONS.iter().map(|s| s.to_string()).collect(),
        dids: steward_dids.clone(),
        max_message_size_bytes: None,
        cursor: None,
        require_hello: false,
    };

    let consumer = Consumer::new(config);
    let handler = Arc::new(ReloadHandler {
        state: Arc::clone(state),
        dids: steward_dids,
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

/// Derive the `host[:port]` for the Jetstream consumer from the configured URL.
///
/// `CONFIG.jetstream_url` is a full `wss://host[:port]/subscribe` URL; the
/// library builds its own subscribe path from a bare hostname, so we strip the
/// scheme and path.
fn jetstream_host(url: &str) -> &str {
    let trimmed = url.trim_end_matches('/');
    let after_scheme = trimmed
        .strip_prefix("wss://")
        .or_else(|| trimmed.strip_prefix("ws://"))
        .unwrap_or(trimmed);
    after_scheme
        .split('/')
        .next()
        .unwrap_or(after_scheme)
}

/// Handler that reloads arbiters on watched policy/service-record events.
struct ReloadHandler {
    state: Arc<AppState>,
    /// Stewarded DIDs at connect time (guards against a stale server-side filter).
    dids: Vec<String>,
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
        // Jetstream filters server-side via wantedDids, but this guards against a
        // stale filter or a DID purged after a repoint.
        if !self.dids.iter().any(|d| d == did) {
            return Ok(());
        }
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
        match load_and_onboard(&self.state, did).await {
            Ok(pds) => {
                self.state.arbiters.set_rev(did, &path, rev.to_string()).await;
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
    WATCHED_COLLECTIONS
        .iter()
        .any(|c| c == &collection)
}
