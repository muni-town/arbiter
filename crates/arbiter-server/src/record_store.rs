//! Global store of PDS records the server reads: `town.muni.arbiter.policy`
//! layers (local + remote), and each stewarded account's `arbiter.service`
//! and `arbiter.config` records.
//!
//! Keyed by canonical `at://` URI, the store memoizes every record read so
//! that a record referenced by many arbiters is fetched once and kept current
//! by Jetstream rather than re-fetched per load:
//!
//! - `get_or_fetch` serves cached entries and fetches only on miss, with
//!   coalescing: concurrent loads of the same URI share one PDS read (a
//!   shared remote layer referenced by thousands of arbiters is otherwise a
//!   guaranteed 429 stampede on the layer's PDS).
//! - `apply_update` / `apply_delete` fold Jetstream commit events into the
//!   store *without fetching*: every watched write fires an event that
//!   carries the record payload, so while the subscription is healthy, loads
//!   never touch the PDS. Application is rev-gated (each entry carries the
//!   repo rev of the write it reflects; only strictly newer events apply), so
//!   reordered or duplicate events can never regress an entry.
//! - `invalidate_all` runs on reconnect: Jetstream does not replay missed
//!   events, so the bulk refresh re-fetches current PDS state (coalesced)
//!   — this preserves the fail-closed argument that a reconnect pass closes
//!   any window where the server would otherwise keep enforcing the
//!   last-loaded policy.
//! - `invalidate` is called by handlers that write records through the
//!   steward session (installPolicy/resetConfig): the store would otherwise
//!   serve the pre-write value until the write's own event lands.
//!
//! Deliberate exclusions:
//!
//! - **Absence is never cached.** A missing service record is the offboard
//!   signal and a missing config is fail-closed, so absence is always
//!   re-checked against the PDS.
//! - **The recovery record is not stored.** `recovery_admin` is the
//!   authorization gate for installPolicy and must not be served from a
//!   cache that can go stale during a disconnect; it re-reads fresh per
//!   install call (one fetch per call, no herd).
//!
//! Entries are evicted only by rev-gated deletes, handler invalidation, and
//! reconnect `invalidate_all` — there is no TTL, because currency is carried
//! by the event stream. Capacity-bounded LRU eviction falls back to
//! fetch-on-miss, which is always safe.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use anyhow::Result;
use atrium_api::types::TryIntoUnknown;
use moka::future::Cache;
use serde_json::Value;

/// A record value loaded from the PDS (or folded in from a Jetstream commit
/// payload).
///
/// `cid` is `None` for event-fed entries: Jetstream delivers record payloads
/// but not their CIDs, and recomputing a DAG-CBOR CID is not worth it here.
/// Callers treat `None` as "no provenance CID" (already supported — see
/// `resolve_layer`'s compile path).
#[derive(Clone)]
pub(crate) struct RecordSource {
    pub(crate) source: atrium_api::types::Unknown,
    /// The record CID at fetch time, when the PDS reports one. Provenance
    /// for pipeline layers + the cache key for compiled layers.
    pub(crate) cid: Option<String>,
}

impl RecordSource {
    /// Read a top-level string field from the record value.
    ///
    /// `Unknown` is an untagged serde enum; materialize it as JSON to read
    /// the field without depending on ipld internals.
    pub(crate) fn field(&self, name: &str) -> Option<String> {
        let json = serde_json::to_value(&self.source).ok()?;
        json.get(name).and_then(|v| v.as_str()).map(String::from)
    }
}

/// What the store holds for one record: the value plus the repo rev of the
/// write it reflects (`None` when produced by a fetch whose rev is unknown —
#[derive(Clone)]
struct RecordEntry {
    record: RecordSource,
    rev: Option<String>,
}

static RECORDS: LazyLock<Cache<String, RecordEntry>> = LazyLock::new(|| {
    Cache::builder()
        // Generous LRU bound: ~4k stewarded accounts x (service + config) plus
        // every shared policy layer comfortably fits; eviction only costs a
        // fetch-on-miss fallback.
        .max_capacity(65_536)
        .build()
});

/// Error shared between concurrent waiters of a coalesced fetch. moka hands
/// errors to waiters as `Arc<E>`, which erases the inner anyhow chain — so
/// the bits the retry loop needs (whether the failure was a 429) and the
/// absent/failed distinction are carried explicitly, with the message
/// capturing the full original chain.
#[derive(Clone, Debug)]
pub(crate) struct FetchError {
    pub(crate) absent: bool,
    pub(crate) rate_limited: bool,
    message: String,
}

impl FetchError {
    fn from_err(context: &str, e: &anyhow::Error) -> Self {
        Self {
            absent: false,
            rate_limited: e.downcast_ref::<crate::policy::RateLimited>().is_some(),
            message: format!("{context}: {e:#}"),
        }
    }

    fn absent(uri: &str) -> Self {
        Self {
            absent: true,
            rate_limited: false,
            message: format!("record not found: {uri}"),
        }
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for FetchError {}

/// Fold a Create/Update Jetstream commit into the store without fetching:
/// the event payload *is* the record's new content.
///
/// Gated: applied only when the event's repo rev is strictly newer than the
/// entry's stamp, so reordered/duplicate/older events can never regress an
/// entry (a fetched entry stamped `None` — rev unknown — accepts any event,
/// which is always safe: the payload either matches or upgrades it).
pub(crate) async fn apply_update(uri: &str, rev: &str, record: RecordSource) {
    // Track the folded rev BEFORE the entry fold: an in-flight fetch must
    // see it and re-read rather than cache a pre-event snapshot, even when
    // this event loses the entry gate (already reflected).
    fold_rev(uri, rev);
    RECORDS
        .entry(uri.to_string())
        .and_upsert_with(|existing| async move {
            match existing {
                Some(entry) if !event_supersedes(entry.value(), rev) => entry.into_value(),
                _ => RecordEntry {
                    record,
                    rev: Some(rev.to_string()),
                },
            }
        })
        .await;
}

/// Fold a Delete commit into the store: evict the entry so the next read
/// re-fetches and observes the absence (the offboard / fail-closed signal).
/// Gated on the entry the same way as `apply_update` — a delete older than
/// the entry's last write is a stale reordered event and must not evict
/// newer content. The folded-rev tracker is updated unconditionally: a
/// delete that lands while a coalesced fetch is in flight (no entry to gate
/// against) must still force that fetch to re-read and observe the absence.
pub(crate) async fn apply_delete(uri: &str, rev: &str) {
    fold_rev(uri, rev);
    let Some(entry) = RECORDS.get(uri).await else {
        return;
    };
    if event_supersedes(&entry, rev) {
        RECORDS.invalidate(uri).await;
    }
}

/// Newest event rev folded into the store per URI (updates AND deletes),
/// tracked beside the cache so an in-flight coalesced fetch can detect that
/// the world moved past its floor and re-read before its snapshot is
/// cached. Without this, `try_get_with` would unconditionally insert a
/// fetch result that can predate a just-folded event — clobbering fresher
/// content or resurrecting a record whose delete event landed mid-fetch.
static FOLDED_REVS: LazyLock<std::sync::RwLock<HashMap<String, String>>> =
    LazyLock::new(|| std::sync::RwLock::new(HashMap::new()));

/// Merge `rev` into the folded-rev tracker (monotonic max).
fn fold_rev(uri: &str, rev: &str) {
    let mut revs = FOLDED_REVS.write().unwrap();
    match revs.get_mut(uri) {
        Some(tracked) if rev > tracked.as_str() => *tracked = rev.to_string(),
        Some(_) => {}
        None => {
            revs.insert(uri.to_string(), rev.to_string());
        }
    }
}

/// Read a record from the store, fetching from the PDS on miss.
///
/// The fetch is coalesced: concurrent callers for the same URI share one PDS
/// read (see module docs). `rev_floor`, when known, is the repo head captured
/// by the caller *before* any record reads — the store stamps the entry with
/// it so that Jetstream events at or below the floor are recognized as
/// already-reflected and skipped (same TID-monotonicity logic as the
/// rev-floor gate on arbiters).
///
/// Freshness: after the fetch, the folded-rev tracker is checked — if an
/// event newer than the floor folded in while the fetch was in flight, the
/// fetch re-runs (bounded) so the cached snapshot cannot predate a known
/// write; a delete folded in mid-flight resolves to absent and is never
/// cached. A floor is a lower bound only: content fetched after it may
/// still reflect a write the store has not seen; a delayed older event can
/// briefly overwrite it until its own event lands — self-correcting, and
/// bounded by reconnect invalidation.
///
/// A missing record (`Ok(None)`) is never cached: every call re-checks the
/// PDS, because absence is a lifecycle signal (offboard / fail-closed), not
/// a value.
pub(crate) async fn get_or_fetch<F, Fut>(
    uri: &str,
    rev_floor: Option<&str>,
    fetch: F,
) -> Result<Option<RecordSource>>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<Option<RecordSource>>>,
{
    match RECORDS
        .try_get_with(uri.to_string(), async {
            // Re-read (bounded) while the store has folded events newer than
            // what our floor proves — each pass consumes one fetch, and the
            // folded rev is monotonic, so this converges in practice.
            let mut record = fetch()
                .await
                .map_err(|e| FetchError::from_err("fetching record", &e))?;
            for _ in 0..2 {
                let folded = FOLDED_REVS.read().unwrap().get(uri).cloned();
                match folded {
                    // No floor to compare against (remote records, or a
                    // failed rev fetch): cannot prove the fetch postdates the
                    // folded write — re-read.
                    Some(rev) if rev_floor.is_none_or(|f| rev.as_str() > f) => {
                        record = fetch()
                            .await
                            .map_err(|e| FetchError::from_err("re-fetching record", &e))?;
                    }
                    _ => break,
                }
            }
            record
                .map(|record| RecordEntry {
                    record,
                    rev: rev_floor.map(str::to_string),
                })
                .ok_or_else(|| FetchError::absent(uri))
        })
        .await
    {
        Ok(entry) => Ok(Some(entry.record)),
        Err(e) => {
            let fetch_error = Arc::unwrap_or_clone(e);
            if fetch_error.absent {
                Ok(None)
            } else {
                Err(anyhow::Error::new(fetch_error))
            }
        }
    }
}

/// Whether an event at repo rev `rev` carries state newer than `entry`
/// reflects. `None` (rev unknown — e.g. a fetch-time entry without a floor)
/// is treated as oldest: any event supersedes it.
fn event_supersedes(entry: &RecordEntry, rev: &str) -> bool {
    entry.rev.as_deref().is_none_or(|entry_rev| rev > entry_rev)
}

/// Drop the entry for `uri`, forcing the next read to fetch from the PDS.
///
/// Called by handlers that write records through the steward session
/// (installPolicy/resetConfig): the write lands on the PDS before its own
/// Jetstream event does, and a reload can run in between, so the handler
/// invalidates what it just wrote.
pub(crate) async fn invalidate(uri: &str) {
    // The handler wrote fresh content; any folded revs for this URI predate
    // the write and must not force spurious re-reads.
    FOLDED_REVS.write().unwrap().remove(uri);
    RECORDS.invalidate(uri).await;
}

/// Drop every entry — called on Jetstream reconnect, before
/// `refresh_all_after_reconnect`. Missed events are invisible to the store
/// (Jetstream does not replay), so a reconnect must not trust cached state:
/// the refresh pass re-fetches each distinct record once (coalesced).
pub(crate) fn invalidate_all() {
    RECORDS.invalidate_all();
    FOLDED_REVS.write().unwrap().clear();
}

/// Build a record value from a Jetstream Create/Update commit payload.
pub(crate) fn from_commit_record(record: &Value) -> Result<RecordSource> {
    Ok(RecordSource {
        source: record.clone().try_into_unknown()?,
        cid: None,
    })
}

/// Whether a record URI is one the store caches. The recovery record is
/// deliberately excluded: `recovery_admin` is the installPolicy authorization
/// gate and must not be served from a cache that can go stale during a
/// disconnect (see `recovery_admin`).
pub(crate) fn is_storeable_collection(collection: &str) -> bool {
    collection == crate::policy::POLICY_COLLECTION
        || collection == crate::policy::SERVICE_COLLECTION
        || collection == crate::policy::CONFIG_COLLECTION
}
