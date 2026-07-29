//! Jetstream subscription for policy/service-record hot reload + auto-delete
//! (SERVER_PLAN.md §4).
//!
//! Subscribes to ATProto Jetstream (`CONFIG.jetstream_url`) over a raw
//! WebSocket, filtered to the stewarded accounts' repos and the record
//! collections this server cares about:
//!
//! - `town.muni.arbiter.service` (the `self` service record) — §4 lifecycle.
//! - `town.muni.arbiter.policy.root` / `town.muni.arbiter.policy.sub` — policy
//!   hot reload.
//!
//! On every relevant commit, the per-record `rev` is gated through
//! [`crate::state::ArbiterCollection::is_newer`] (older/duplicate revs are
//! discarded) and, if newer, the arbiter is reloaded via
//! [`crate::policy::load_and_onboard`], which re-fetches the *current* records
//! from the PDS and applies the §4 lifecycle. Because `load_and_onboard` always
//! reads the latest PDS state (never the event payload), a reordered or
//! duplicate event can never regress policy.

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use futures_util::StreamExt;
use serde_json::Value as Json;

use crate::AppState;
use crate::policy::load_and_onboard;

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
/// Runs forever, reconnecting with bounded backoff on disconnect or error.
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

    let url = build_subscribe_url(dids.iter().map(|(d, _)| d.as_str()));
    tracing::info!(%url, "connecting to jetstream");

    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .map_err(|e| anyhow!("jetstream connect failed: {e}"))?;
    tracing::info!("jetstream connected");

    while let Some(msg) = ws.next().await {
        let text = match msg {
            Ok(tokio_tungstenite::tungstenite::Message::Text(t)) => t.to_string(),
            Ok(tokio_tungstenite::tungstenite::Message::Binary(b)) => {
                match String::from_utf8(b.to_vec()) {
                    Ok(s) => s,
                    Err(_) => continue,
                }
            }
            Ok(tokio_tungstenite::tungstenite::Message::Ping(_))
            | Ok(tokio_tungstenite::tungstenite::Message::Pong(_)) => continue,
            Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => {
                tracing::info!("jetstream websocket closed by server");
                return Ok(());
            }
            Ok(tokio_tungstenite::tungstenite::Message::Frame(_)) => continue,
            Err(e) => {
                return Err(anyhow!("jetstream websocket error: {e}"));
            }
        };
        let event = match serde_json::from_str::<Json>(&text) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "jetstream frame is not valid JSON; skipping");
                continue;
            }
        };
        handle_event(state, &event).await;
    }
    Ok(())
}

/// Build a Jetstream subscribe URL filtered to the watched collections and the
/// given stewarded DIDs.
fn build_subscribe_url<'a>(dids: impl IntoIterator<Item = &'a str>) -> String {
    let mut params: Vec<String> = WATCHED_COLLECTIONS
        .iter()
        .map(|c| format!("wantedCollections={c}"))
        .collect();
    for d in dids {
        params.push(format!("wantedDids={d}"));
    }
    format!(
        "{}?{}",
        crate::CONFIG.jetstream_url.trim_end_matches('/'),
        params.join("&")
    )
}

/// Dispatch a single Jetstream event. Only `commit` events for stewarded DIDs
/// with at least one op touching a watched collection are acted upon.
async fn handle_event(state: &Arc<AppState>, event: &Json) {
    let ty = event.get("type").and_then(|v| v.as_str());
    if ty != Some("commit") {
        return;
    }
    let did = match event.get("repo").and_then(|v| v.as_str()) {
        Some(d) => d,
        None => return,
    };
    let rev = match event.get("rev").and_then(|v| v.as_str()) {
        Some(r) => r,
        None => return,
    };
    let ops = match event.get("ops").and_then(|v| v.as_array()) {
        Some(o) => o,
        None => return,
    };

    // Collect the record keys in this commit that touch a watched collection and
    // are strictly newer than the last-applied rev. Only reload if at least one
    // such key exists.
    let mut newer_keys: Vec<String> = Vec::new();
    for op in ops {
        let path = match op.get("path").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => continue,
        };
        if !is_watched_path(path) {
            continue;
        }
        if state.arbiters.is_newer(did, path, rev).await {
            newer_keys.push(path.to_string());
        }
    }
    if newer_keys.is_empty() {
        return;
    }

    // Only process accounts we actually steward (have credentials for). Jetstream
    // filters server-side via wantedDids, but this guards against a stale filter
    // or a DID purged after a repoint.
    let stewarded = match state.store.get(did).await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            tracing::warn!(
                did,
                error = %format!("{e:#}"),
                "credential lookup failed; skipping jetstream event"
            );
            return;
        }
    };
    if !stewarded {
        return;
    }

    // Re-fetch the current PDS state and reapply the lifecycle + policies. This
    // never applies the event payload directly, so reordered/duplicate events
    // cannot regress policy.
    match load_and_onboard(state, did).await {
        Ok(pds) => {
            for k in &newer_keys {
                state.arbiters.set_rev(did, k, rev.to_string()).await;
            }
            tracing::debug!(did, pds = %pds, "reloaded arbiter from jetstream commit");
        }
        Err(e) => {
            // Fail closed: stop serving until the next reload succeeds.
            tracing::warn!(
                did,
                error = %format!("{e:#}"),
                "jetstream-triggered reload failed; offboarding (fail-closed)"
            );
            state.arbiters.offboard(did).await;
        }
    }
}

/// Whether a Jetstream commit op `path` (of the form `<collection>/<rkey>`)
/// belongs to one of the watched collections.
fn is_watched_path(path: &str) -> bool {
    WATCHED_COLLECTIONS
        .iter()
        .any(|c| path.starts_with(&format!("{c}/")))
}
