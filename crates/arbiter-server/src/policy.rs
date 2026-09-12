//! Policy loading from PDS records + startup onboarding.
//!
//! The policy model is a **pipeline**: an ordered list of `at://` URIs, each
//! naming a policy record, evaluated in order per request (see
//! `arbiter_core::arbiter::Pipeline` — the first layer that handles or denies
//! wins; falling off the end denies).
//!
//! Records read per stewarded account (via its PDS, resolved through
//! [`crate::AppState`].resolver):
//!
//! - `town.muni.arbiter.service/self` — the arbiter service record. Its `did`
//!   field determines lifecycle: absent -> offboard (keep credentials);
//!   pointing at a different server -> offboard + purge credentials.
//! - `town.muni.arbiter.config/self` — the arbiter config: `trustedScopes`
//!   (NSID prefixes accepted by the scoped `*.arbiter.proxy` endpoints) and
//!   `policyLayers` (the ordered `at://` policy-record URIs).
//! - `town.muni.arbiter.recovery/self` — the recovery-admin designation: THE
//!   authority for who may `installPolicy`. It is re-read on every install
//!   call (see [`recovery_admin`]), so rewriting it rotates the admin.
//! - Every `policyLayers` entry: `at://<did>/<collection>/<rkey>` naming a
//!   `town.muni.arbiter.policy` record — the stewarded account's own repo or
//!   a remote repo both work; other collections are not accepted (see
//!   `validate_config_inputs`). Local entries (the stewarded account's own
//!   repo) are read from the account's PDS; remote entries are read from the
//!   record DID's resolved `#atproto_pds`. Each is compiled as a pipeline
//!   [`Layer`] carrying its provenance (the at:// URI + record CID).
//!
//! Fail-closed lifecycle: an arbiter is online only when the service record
//! exists **and** the config record parses **and** the whole pipeline resolves
//! and compiles. Anything missing or invalid makes [`load_and_onboard`] return
//! `Err`, which every caller (startup, Jetstream, `installPolicy`) treats as
//! "offboarded".
//!
//! Two cross-load caches live here:
//!
//! - [`LAYER_CACHE`] — compiled layers keyed by `(at:// uri, record cid)`, so
//!   a reload of an unchanged record does not recompile Rego.
//! - [`LAYER_REFS`] — reverse index `at:// uri -> stewarded arbiters whose
//!   pipeline references it`, used by the Jetstream handler to reload exactly
//!   the arbiters affected by a policy-record write in *any* repo (see
//!   [`referencing_arbiters`]).
//!
//! Reads are performed with unauthenticated atrium clients: policy/service
//! records are public ATProto records that do not require auth. (The
//! credential store only holds the steward password for *writing* records,
//! not for these reads.)

use crate::record_store::RecordSource;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;

use crate::record_store;
use crate::resolver::IdentityResolverExt;
use crate::{AppState, CONFIG};
use anyhow::{Context, Result, anyhow};
use arbiter_core::arbiter::{Arbiter, Layer, Pipeline};
use atproto_record::aturi::ATURI;
use atrium_api::client::AtpServiceClient;
use atrium_api::com::atproto::repo::get_record;
use atrium_api::types::string::{AtIdentifier, Nsid, RecordKey, Tid};
use atrium_xrpc::error::XrpcErrorKind;
use atrium_xrpc_client::reqwest::ReqwestClient;
use axum::http::StatusCode;
use futures_util::stream::{self, StreamExt};
use moka::future::Cache;
use rand::Rng;

/// Service record collection + rkey (`town.muni.arbiter.service/self`).
pub(crate) const SERVICE_COLLECTION: &str = "town.muni.arbiter.service";
pub(crate) const SERVICE_RKEY: &str = "self";
/// Arbiter config record collection + rkey
/// (`town.muni.arbiter.config/self`): trusted scopes + ordered pipeline.
pub const CONFIG_COLLECTION: &str = "town.muni.arbiter.config";
pub const CONFIG_RKEY: &str = "self";
/// Policy record collection (`town.muni.arbiter.policy/<rkey>`); the rkey is
/// the policy name. Referenced from the config record's `policyLayers` as
/// `at://<did>/town.muni.arbiter.policy/<rkey>`: the record may live in the
/// stewarded repo or a remote (app-owned) repo, but an entry naming any other
/// collection is rejected (see `validate_config_inputs`).
pub const POLICY_COLLECTION: &str = "town.muni.arbiter.policy";

/// Canonical `at://` URI of `did`'s config record (`.../config/self`).
pub(crate) fn config_record_uri(did: &str) -> String {
    format!("at://{did}/{CONFIG_COLLECTION}/{CONFIG_RKEY}")
}

/// Canonical `at://` URI of `did`'s service record (`.../service/self`).
pub(crate) fn service_record_uri(did: &str) -> String {
    format!("at://{did}/{SERVICE_COLLECTION}/{SERVICE_RKEY}")
}

/// Recovery-admin designation record collection + rkey
/// (`town.muni.arbiter.recovery/self`): its `did` field designates the
/// account's recovery admin — THE authority for `installPolicy` (see
/// [`recovery_admin`]), re-read on every install call.
const RECOVERY_COLLECTION: &str = "town.muni.arbiter.recovery";
const RECOVERY_RKEY: &str = "self";

/// Maximum number of `load_and_onboard` attempts per arbiter during a bulk
/// onboarding pass (startup onboarding, post-reconnect refresh). After this
/// many consecutive failures the arbiter is left offboarded (fail-closed) and
/// we move on, so a permanently unreachable PDS cannot spin the pass forever.
/// A subsequent Jetstream event or restart retries.
const STARTUP_MAX_RETRIES: u32 = 2;

/// Maximum arbiters whose `load_and_onboard` runs concurrently during a bulk
/// onboarding pass ([`startup_onboard`], [`refresh_all_after_reconnect`]).
///
/// Each load opens several unauthenticated HTTPS connections to per-DID
/// endpoints (DID resolution, repo rev, service/config records, every
/// pipeline layer), so an unbounded pass at thousands-of-arbiters scale
/// would mean thousands of simultaneous DNS lookups and TLS handshakes plus
/// file-descriptor pressure. The bound keeps concurrent fetches — and open
/// sockets — flat; the pass is background work, so 32-wide throughput is
/// ample.
pub(crate) const ONBOARD_CONCURRENCY: usize = 32;

/// Marker attached to load errors that came back as HTTP 429 from a PDS
/// (or its edge). atrium's XRPC error type discards response headers, so
/// the server's own `Retry-After` value is not visible to us — the retry
/// loop instead applies a dedicated longer window
/// ([`RATE_LIMIT_RETRY_BASE`] / [`RATE_LIMIT_RETRY_MAX`]) as a stand-in.
#[derive(Debug, thiserror::Error)]
#[error("rate limited (HTTP 429)")]
pub(crate) struct RateLimited;

/// Base wait before retrying a rate-limited (429) load — far above the
/// generic 1s backoff, so a retry does not instantly re-trip the same
/// per-IP quota. Grown 4x per consecutive 429 up to
/// [`RATE_LIMIT_RETRY_MAX`], then jittered (see [`jitter`]).
const RATE_LIMIT_RETRY_BASE: Duration = Duration::from_secs(10);

/// Upper bound on a single rate-limit retry wait, so one permanently
/// 429-ing arbiter cannot stall its slot in a bulk pass indefinitely.
const RATE_LIMIT_RETRY_MAX: Duration = Duration::from_secs(60);

/// Maximum rate-limit deferrals per arbiter before giving up. A 429 is the
/// PDS saying "slow down", not a load failure, so it must not consume the
/// generic give-up budget; deferrals get their own cap instead. With the
/// 10s → 60s deferral schedule this bounds one arbiter's rate-limit wait to
/// a few minutes, so the pass still terminates.
const RATE_LIMIT_MAX_DEFERRALS: u32 = 8;

/// Uniformly jitter a retry wait upward by up to 25%, so up to
/// [`ONBOARD_CONCURRENCY`] concurrently failing loads do not all wake and
/// re-fire at the same instant against the same host.
fn jitter(d: Duration) -> Duration {
    d + d.mul_f64(rand::rng().random_range(0.0..0.25))
}

/// Convert an atrium XRPC error into a load-path error, tagging HTTP 429
/// responses with [`RateLimited`] so [`onboard_with_retries`] can back off
/// differently from generic failures.
fn xrpc_load_error<E>(what: &str, e: atrium_xrpc::Error<E>) -> anyhow::Error
where
    E: std::fmt::Display + std::fmt::Debug,
{
    if let atrium_xrpc::Error::XrpcResponse(xrpc_err) = &e
        && xrpc_err.status == StatusCode::TOO_MANY_REQUESTS
    {
        return anyhow::Error::new(RateLimited).context(format!("{what}: {e}"));
    }
    anyhow!("{what}: {e}")
}

/// Whether a load error was an HTTP 429 — either tagged directly
/// ([`RateLimited`]) or carried inside a coalesced store-fetch error, whose
/// moka `Arc` sharing erases the inner anyhow chain.
fn is_rate_limited(e: &anyhow::Error) -> bool {
    e.downcast_ref::<RateLimited>().is_some()
        || e.downcast_ref::<record_store::FetchError>()
            .is_some_and(|f| f.rate_limited)
}

/// Compiled pipeline layers, keyed by `(at:// uri, record cid)`. A `(uri,
/// cid)` pair is content-addressed, so entries never go stale — the TTL only
/// bounds memory; a changed record compiles under a fresh key.
static LAYER_CACHE: LazyLock<Cache<(String, String), Layer>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(4096)
        .time_to_idle(Duration::from_secs(6 * 60 * 60))
        .build()
});
/// Reverse index: `at://<did>/<collection>/<rkey>` policy-record URI → the
/// stewarded arbiters whose loaded pipeline references it.
///
/// Rebuilt (for the loading arbiter) only when an onboard is *applied* — a
/// stale load rejected by `ArbiterCollection::onboard` leaves the winner's
/// backlinks untouched, so the index always mirrors the pipelines actually
/// serving. Entries are deliberately *not* removed on offboard: a stale
/// backlink only causes a redundant `load_and_onboard`, which re-applies the
/// lifecycle (and for a purged DID, purges again) — never incorrect behavior.
static LAYER_REFS: LazyLock<RwLock<HashMap<String, BTreeSet<String>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// The stewarded arbiters whose loaded pipeline references `uri` (used by the
/// Jetstream handler to reload exactly the arbiters a policy-record write
/// affects).
pub fn referencing_arbiters(uri: &str) -> Vec<String> {
    match LAYER_REFS.read() {
        Ok(index) => index
            .get(uri)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Replace `did`'s backlinks in the reverse index with its newly loaded
/// pipeline URIs.
fn index_pipeline(did: &str, uris: &[String]) {
    let mut index = LAYER_REFS.write().expect("layer refs index lock");
    for arbiters in index.values_mut() {
        arbiters.remove(did);
    }
    index.retain(|_, arbiters| !arbiters.is_empty());
    for uri in uris {
        index
            .entry(uri.clone())
            .or_default()
            .insert(did.to_string());
    }
}

/// Unauthenticated client used for public PDS record reads.
pub(crate) type PdsReadClient = AtpServiceClient<ReqwestClient>;

/// Outcome of a [`load_and_onboard`] pass: whether the arbiter was brought
/// online or offboarded. `load_and_onboard` returns `Ok` for both — the
/// lifecycle was applied successfully either way — so callers must branch on
/// this to log accurately (an offboard is not an onboard). Load *failures*
/// (unreachable PDS, missing config, uncompilable pipeline) are `Err` and
/// leave the arbiter fail-closed (offboarded).
pub enum OnboardOutcome {
    /// Config + pipeline loaded and the arbiter is serving.
    Onboarded { pds_endpoint: String },
    /// Lifecycle applied but the arbiter is not serving (service record absent,
    /// malformed, or repointed at another server).
    Offboarded { pds_endpoint: String },
}

/// On startup, load + onboard every arbiter the server holds credentials for.
///
/// Per-arbiter fail-closed is already enforced by `ArbiterCollection::begin_request`
/// returning `ArbiterNotReady` for un-onboarded DIDs; this task just brings them
/// online. Loads run bounded-concurrent (see [`onboard_all`]) and each arbiter
/// retries independently with bounded exponential backoff (see
/// [`onboard_with_retries`]).
pub async fn startup_onboard(state: Arc<AppState>) -> Result<()> {
    let dids = stored_dids(&state).await?;
    if dids.is_empty() {
        tracing::info!("no stewarded accounts to onboard at startup");
        return Ok(());
    }
    let summary = onboard_all(&state, dids, STARTUP_MAX_RETRIES, "startup").await;
    tracing::info!(
        onboarded = summary.onboarded,
        offboarded = summary.offboarded,
        failed = summary.failed,
        "startup onboarding complete"
    );
    Ok(())
}

/// Re-onboard stewarded arbiters after a Jetstream reconnect, tiered by how
/// much the record store can be trusted:
///
/// - `full = true` — an unverified gap: Jetstream could not honor the cursor,
///   so the store was invalidated and nothing cached may be served. The pass
///   re-observes *current* PDS state for every steward, closing the
///   fail-open window where the server would otherwise keep enforcing the
///   last-loaded (possibly revoked/permissive) policy.
/// - `full = false` — a verified cursor replay (or a fresh boot, whose
///   baseline is the just-finished startup onboard): the store is provably
///   current, and replayed events already reloaded every arbiter whose
///   records changed. Loading the non-serving arbiters only — never-onboarded,
///   load-failure-offboarded (fail-closed), or deliberately offboarded
///   accounts — heals them without the full 4k-arbiter pass; serving
///   arbiters would re-onboard to identical pipelines.
///
/// Runs bounded-concurrent (see [`onboard_all`]); each failed load is left
/// fail-closed (offboarded) and retried a bounded number of times. The rev
/// floor captured per load remains the gate baseline for future events.
pub async fn refresh_all_after_reconnect(state: Arc<AppState>, full: bool) {
    if full {
        // Jetstream does not replay missed events, so entries in the record
        // store may be stale after an unverified disconnect. The whole point
        // of this pass is re-observing current PDS state (fail-closed), so
        // nothing cached before the disconnect may be served.
        record_store::invalidate_all();
    }
    let dids = match stored_dids(&state).await {
        Ok(dids) => dids,
        Err(e) => {
            tracing::error!(
                error = %format!("{e:#}"),
                "failed to list credentials for reconnect refresh"
            );
            return;
        }
    };
    if dids.is_empty() {
        return;
    }
    let dids = if full {
        dids
    } else {
        // Heal-only: a verified replay already reloaded every arbiter whose
        // records changed, and serving arbiters would re-onboard to
        // identical pipelines. Load only the ones that are not serving.
        let mut heal = Vec::new();
        for did in &dids {
            if !state.arbiters.is_online(did).await {
                heal.push(did.clone());
            }
        }
        tracing::info!(
            total = dids.len(),
            healing = heal.len(),
            "verified reconnect refresh; healing non-serving arbiters"
        );
        heal
    };
    let summary = onboard_all(&state, dids, STARTUP_MAX_RETRIES, "post-reconnect refresh").await;
    tracing::info!(
        onboarded = summary.onboarded,
        offboarded = summary.offboarded,
        failed = summary.failed,
        "post-reconnect refresh complete"
    );
}

/// The DIDs the server holds credentials for — the bulk-onboarding work list.
async fn stored_dids(state: &AppState) -> Result<Vec<String>> {
    let entries = state
        .store
        .list()
        .await
        .context("listing stored credentials")?;
    Ok(entries.into_iter().map(|(did, _creds)| did).collect())
}

/// Outcome counts of a bulk onboarding pass.
#[derive(Default)]
struct OnboardSummary {
    onboarded: usize,
    offboarded: usize,
    failed: usize,
}

/// Load + onboard every DID in `dids`, at most [`ONBOARD_CONCURRENCY`] loads
/// in flight, returning per-outcome counts.
///
/// Concurrency is bounded because each load opens several unauthenticated
/// HTTPS connections to per-DID endpoints (see [`ONBOARD_CONCURRENCY`]): at
/// thousands-of-arbiters scale an unbounded pass would stampede DNS/PLC and
/// the PDS fleet. Arbiters are independent — one hung PDS only occupies its
/// own slot instead of stalling the pass head-of-line. Record fetches are
/// coalesced globally by the record store, so a shared remote layer is
/// fetched once per pass no matter how many arbiters reference it.
async fn onboard_all(
    state: &AppState,
    dids: Vec<String>,
    max_retries: u32,
    pass: &str,
) -> OnboardSummary {
    let mut summary = OnboardSummary::default();
    let mut loads = stream::iter(dids)
        .map(|did| async move { onboard_with_retries(state, did, max_retries, pass).await })
        .buffer_unordered(ONBOARD_CONCURRENCY);
    while let Some(outcome) = loads.next().await {
        match outcome {
            Ok(OnboardOutcome::Onboarded { .. }) => summary.onboarded += 1,
            Ok(OnboardOutcome::Offboarded { .. }) => summary.offboarded += 1,
            Err(_) => summary.failed += 1, // already logged in `onboard_with_retries`
        }
    }
    summary
}

/// One arbiter's load + onboard with bounded retry: exponential backoff from
/// 1s doubling to 30s for generic failures; 429s defer instead — they do not
/// consume the give-up budget and wait a longer dedicated window
/// ([`RATE_LIMIT_RETRY_BASE`]), capped after [`RATE_LIMIT_MAX_DEFERRALS`].
/// All waits jittered. Giving up is fail-closed (the arbiter stays
/// offboarded), so the pass always terminates.
async fn onboard_with_retries(
    state: &AppState,
    did: String,
    max_retries: u32,
    pass: &str,
) -> Result<OnboardOutcome> {
    let mut attempt: u32 = 0;
    let mut delay = Duration::from_secs(1);
    let mut deferrals: u32 = 0;
    loop {
        match load_and_onboard(state, &did).await {
            Ok(outcome) => {
                match &outcome {
                    OnboardOutcome::Onboarded { pds_endpoint } => {
                        tracing::info!(did = %did, pds = %pds_endpoint, "onboarded arbiter ({pass})");
                    }
                    OnboardOutcome::Offboarded { pds_endpoint } => {
                        tracing::info!(
                            did = %did,
                            pds = %pds_endpoint,
                            "arbiter offboarded during {pass} (service record absent or repointed)"
                        );
                    }
                }
                return Ok(outcome);
            }
            Err(e) if attempt >= max_retries => {
                // Fail closed: leave the arbiter offboarded and move on.
                tracing::error!(
                    did = %did,
                    error = %format!("{e:#}"),
                    "giving up onboarding arbiter after {max_retries} attempts ({pass})"
                );
                return Err(e);
            }
            Err(e) => {
                // A 429 means the PDS's per-IP quota is exhausted: the PDS
                // saying "slow down", not "broken". It must not consume the
                // give-up budget — otherwise `max_retries` retries are
                // exhausted in seconds under a rate limit and the pass
                // leaves most arbiters offline. Deferrals get their own cap
                // ([`RATE_LIMIT_MAX_DEFERRALS`]) so the pass terminates.
                let rate_limited = is_rate_limited(&e);
                if rate_limited {
                    deferrals += 1;
                    if deferrals > RATE_LIMIT_MAX_DEFERRALS {
                        tracing::error!(
                            did = %did,
                            error = %format!("{e:#}"),
                            "giving up onboarding arbiter after {RATE_LIMIT_MAX_DEFERRALS} \
                             rate-limit deferrals ({pass})"
                        );
                        return Err(e);
                    }
                } else {
                    attempt += 1;
                }
                // atrium's XRPC error type drops response headers, so the
                // server's own `Retry-After` value is not visible; wait a
                // dedicated longer window for 429s (4x growth, higher cap),
                // and jitter every wait so concurrent failing loads don't
                // re-sync into one burst against the same host.
                let wait = jitter(if rate_limited {
                    RATE_LIMIT_RETRY_BASE.max(delay)
                } else {
                    delay
                });
                tracing::warn!(
                    did = %did,
                    attempt,
                    deferrals,
                    rate_limited,
                    error = %format!("{e:#}"),
                    "load_and_onboard failed during {pass}; retrying in {wait:?}"
                );
                tokio::time::sleep(wait).await;
                delay = if rate_limited {
                    (delay * 4).min(RATE_LIMIT_RETRY_MAX)
                } else {
                    (delay * 2).min(Duration::from_secs(30))
                };
            }
        }
    }
}

/// Load `did`'s config record + pipeline and onboard (or update) the arbiter.
/// Records are served by the global record store — fetch-on-miss, coalesced,
/// kept current by Jetstream events (see `record_store`).
///
/// Also applies the lifecycle: if `town.muni.arbiter.service/self` is absent
/// -> `state.arbiters.offboard(did)`; if its `did` field != `CONFIG.server_did`
/// -> `offboard` + `state.store.remove(did)`. A missing or malformed config
/// record, or a pipeline that fails to resolve/compile, is a load error
/// (`Err`) — fail-closed, the arbiter stays offline.
///
/// Returns [`OnboardOutcome`] so callers can tell an onboard from an offboard
/// (both are `Ok` — the lifecycle applied successfully).
pub async fn load_and_onboard(state: &AppState, did: &str) -> Result<OnboardOutcome> {
    let pds_endpoint = state
        .resolver
        .resolve_pds_endpoint(did)
        .await
        .map_err(|e| anyhow::anyhow!("resolving PDS endpoint for {did}: {e:#}"))?;

    // Unauthenticated client for public record reads. A bounded timeout keeps a
    // hung PDS from stalling onboarding.
    let api = pds_read_client(&pds_endpoint)?;

    let repo = parse_at_identifier(did)?;

    // Compute the load-time rev floor BEFORE reading the records so the floor
    // provably dominates the records we load: the records are read at or after
    // the moment the floor was captured, so they reflect state at least as new
    // as the floor. (Fetching the floor after the reads would let a concurrent
    // load read stale records and then capture a raised floor, permanently
    // dropping the events it is missing.)
    //
    // A failed floor fetch is retried with short jittered backoff; if it
    // still fails the load FAILS (fail-closed, healable by the retry loop's
    // deferrals) rather than proceeding floor-less — a floor-less onboard is
    // rejected by the gate whenever an entry already exists, which would
    // silently discard a reload that already read correct store values.
    // `Ok(None)` (repo inactive / no rev reported) is a legitimate floor-less
    // load: the gate accepts everything, which only risks redundant reloads
    // — never a missed update.
    let rev_floor = {
        let mut attempt: u32 = 0;
        let mut delay = Duration::from_secs(1);
        loop {
            match fetch_repo_rev(&api, &repo).await {
                Ok(Some(rev)) => break Some(rev.as_str().to_string()),
                Ok(None) => {
                    tracing::warn!(
                        did,
                        "repo inactive or no rev reported; leaving rev floor unset"
                    );
                    break None;
                }
                Err(e) if attempt >= 2 => return Err(e),
                Err(e) => {
                    attempt += 1;
                    let wait = jitter(delay);
                    tracing::warn!(
                        did,
                        attempt,
                        error = %format!("{e:#}"),
                        "repo rev unavailable; retrying in {wait:?}"
                    );
                    tokio::time::sleep(wait).await;
                    delay = (delay * 2).min(Duration::from_secs(8));
                }
            }
        }
    };
    // --- lifecycle: service record ----------------------------------------
    let service =
        record_store::get_or_fetch(&service_record_uri(did), rev_floor.as_deref(), || {
            fetch_record(&api, &repo, SERVICE_COLLECTION, SERVICE_RKEY)
        })
        .await
        .with_context(|| format!("fetching {SERVICE_COLLECTION}/{SERVICE_RKEY}"))?;
    match service {
        None => {
            // Service record absent. If the account is only partially
            // provisioned (its bootstrap records were never fully written),
            // repair it rather than offboard it — otherwise a failed
            // createArbiter leaves an unrecoverable account. A fully
            // provisioned account whose service record disappears is a
            // deliberate offboard (auto-delete) and is NOT repaired.
            let creds = state.store.get(did).await.context("reading credentials")?;
            match creds {
                Some(creds) if !creds.provisioned => {
                    tracing::info!(
                        did,
                        "un-provisioned account missing service record; repairing bootstrap"
                    );
                    crate::handlers::repair_provisioning(state, did, &creds, &pds_endpoint).await?;
                    // Fall through: the records are (re)written; re-run the
                    // service-record fetch so we don't treat it as absent below.
                }
                _ => {
                    // Record absent: stop serving but keep credentials (may re-onboard).
                    tracing::info!(did, "service record absent; offboarding arbiter");
                    state.arbiters.offboard(did).await;
                    return Ok(OnboardOutcome::Offboarded { pds_endpoint });
                }
            }
        }
        Some(rec) => {
            let svc_did = rec.field("did");
            match svc_did.as_deref() {
                None => {
                    // Malformed service record: treat as absent (keep credentials).
                    tracing::warn!(did, "service record missing 'did' field; offboarding");
                    state.arbiters.offboard(did).await;
                    return Ok(OnboardOutcome::Offboarded { pds_endpoint });
                }
                Some(d) if d != CONFIG.server_did => {
                    // Repointed at another server: stop serving + purge credentials.
                    tracing::info!(
                        did,
                        server = %d,
                        own = %CONFIG.server_did,
                        "service record repointed at another arbiter server; offboarding + purging credentials"
                    );
                    state.arbiters.offboard(did).await;
                    if let Err(e) = state.store.remove(did).await {
                        tracing::warn!(did, error = %format!("{e:#}"), "failed to purge credentials");
                    }
                    return Ok(OnboardOutcome::Offboarded { pds_endpoint });
                }
                _ => {
                    // Points at this server: continue loading policies.
                }
            }
        }
    }

    // --- config record ------------------------------------------------------
    // Fail-closed: a missing or malformed config record is a load error, which
    // every caller treats as offboarded.
    let config_rec =
        record_store::get_or_fetch(&config_record_uri(did), rev_floor.as_deref(), || {
            fetch_record(&api, &repo, CONFIG_COLLECTION, CONFIG_RKEY)
        })
        .await
        .with_context(|| format!("fetching {CONFIG_COLLECTION}/{CONFIG_RKEY}"))?
        .ok_or_else(|| {
            anyhow!("config record {CONFIG_COLLECTION}/{CONFIG_RKEY} not found for {did}")
        })?;
    let config = parse_config(&config_rec)
        .with_context(|| format!("parsing {CONFIG_COLLECTION}/{CONFIG_RKEY} for {did}"))?;

    // --- pipeline layers ----------------------------------------------------
    // Resolve every at:// entry to a compiled Layer with provenance. One bad
    // layer keeps the whole arbiter offline (fail-closed).
    let mut remote_clients: HashMap<String, PdsReadClient> = HashMap::new();
    let mut layers = Vec::with_capacity(config.policy_layers.len());
    for uri in &config.policy_layers {
        layers.push(
            resolve_layer(
                state,
                &api,
                did,
                uri,
                &mut remote_clients,
                rev_floor.as_deref(),
            )
            .await
            .with_context(|| format!("resolving pipeline layer {uri}"))?,
        );
    }
    let arbiter = Arbiter::new(Pipeline::from_layers(layers));

    // Onboard first, then index. `onboard` rejects a replacement whose rev
    // floor is older than the current entry's (a concurrent load won the
    // race); indexing before that check would let the losing load rewrite
    // the reverse index to its (stale) pipeline while the winner keeps
    // serving — later writes to records referenced only by the winner's
    // pipeline would find no backlink and hot-reload would be silently
    // skipped. Indexing only when the onboard was applied keeps the reverse
    // index mirroring the pipelines actually serving.
    let applied = state
        .arbiters
        .onboard(
            did.to_string(),
            arbiter,
            pds_endpoint.clone(),
            config.trusted_scopes,
            rev_floor,
        )
        .await;
    if applied {
        // Record which policy records this arbiter's pipeline references so
        // Jetstream events for a record reload exactly the arbiters using it.
        index_pipeline(did, &config.policy_layers);
    }
    Ok(OnboardOutcome::Onboarded { pds_endpoint })
}

/// Parse an `at://<did>/<collection>/<rkey>` pipeline entry.
///
/// Syntax and DID-authority validation are delegated to `atproto-record`'s
/// [`ATURI`] (handles are rejected as authority — pipeline entries are
/// DID-addressed). On top of the crate's rules we require the record-level
/// shape exactly: three path segments, since the crate tolerates trailing
/// segments that would otherwise be silently dropped.
pub(crate) fn parse_at_uri(uri: &str) -> Result<ATURI> {
    let parsed: ATURI = uri
        .parse()
        .map_err(|e| anyhow!("invalid at:// URI `{uri}`: {e}"))?;
    let rest = uri
        .strip_prefix("at://")
        .expect("ATURI parse requires the at:// prefix");
    if rest.split('/').count() != 3 {
        return Err(anyhow!(
            "invalid at:// URI (want at://<did>/<collection>/<rkey>): `{uri}`"
        ));
    }
    Ok(parsed)
}

/// A pipeline entry must reference a `town.muni.arbiter.policy` record.
///
/// The Jetstream reload path dispatches policy-record writes only for that
/// collection, so an entry naming any other collection would load once at
/// onboard and then never hot-reload, silently freezing at its first-loaded
/// version. Enforced at install (`validate_config_inputs`) and defensively at
/// load (`resolve_layer`).
fn require_policy_collection(uri: &str, parsed: &ATURI) -> Result<()> {
    if parsed.collection != POLICY_COLLECTION {
        return Err(anyhow!(
            "pipeline entry `{uri}` must reference a `{POLICY_COLLECTION}` record, not `{}`",
            parsed.collection
        ));
    }
    Ok(())
}

/// An arbiter's parsed config record.
#[derive(Default)]
pub(crate) struct ArbiterConfig {
    /// NSID prefixes accepted by the scoped `*.arbiter.proxy` endpoints.
    pub(crate) trusted_scopes: Vec<String>,
    /// Ordered `at://` URIs of `town.muni.arbiter.policy` records forming the policy layers.
    pub(crate) policy_layers: Vec<String>,
}

/// Parse a `town.muni.arbiter.config/self` record value. Both fields are
/// required by the lexicon; anything missing or malformed is a load failure
/// (fail-closed).
fn parse_config(record: &RecordSource) -> Result<ArbiterConfig> {
    let json = serde_json::to_value(&record.source).context("decoding config record")?;
    let obj = json
        .as_object()
        .ok_or_else(|| anyhow!("config record is not an object"))?;
    let string_list = |field: &str| -> Result<Vec<String>> {
        let value = obj
            .get(field)
            .ok_or_else(|| anyhow!("config record is missing `{field}`"))?;
        value
            .as_array()
            .ok_or_else(|| anyhow!("config record `{field}` is not an array"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow!("config record `{field}` entries must be strings"))
            })
            .collect()
    };
    Ok(ArbiterConfig {
        trusted_scopes: string_list("trustedScopes")?,
        policy_layers: string_list("policyLayers")?,
    })
}

/// Read `repo`'s current `town.muni.arbiter.config/self` record: its trusted
/// scopes + pipeline, or the empty bootstrap config when the record is absent
/// (a first install appends onto nothing). A present-but-malformed record is
/// an error: an append cannot be computed against an unreadable config —
/// that broken state is exactly what the recovery admin's `resetConfig`
/// repairs.
pub(crate) async fn current_config(
    api: &PdsReadClient,
    repo: &AtIdentifier,
) -> Result<ArbiterConfig> {
    match fetch_record(api, repo, CONFIG_COLLECTION, CONFIG_RKEY).await? {
        Some(record) => parse_config(&record),
        None => Ok(ArbiterConfig::default()),
    }
}

/// Resolve one pipeline entry (`at://` URI) to a compiled [`Layer`].
///
/// The record is fetched from its repo's PDS: the stewarded account's own PDS
/// read client for local records, the record DID's resolved `#atproto_pds` for
/// remote ones. Compiled layers are cached by `(uri, cid)`, so an unchanged
/// record is reused without recompiling.
///
/// Record reads go through the global record store — fetch-on-miss, coalesced,
/// kept current by Jetstream (see `record_store`); entries are stamped with
/// the load's rev floor when the caller has one.
///
/// The entry must name a `town.muni.arbiter.policy` record (see
/// `require_policy_collection`): the Jetstream reload path would never deliver
/// writes for a foreign collection, so such a layer could never hot-reload.
async fn resolve_layer(
    state: &AppState,
    local_api: &PdsReadClient,
    steward_did: &str,
    uri: &str,
    remote_clients: &mut HashMap<String, PdsReadClient>,
    rev_floor: Option<&str>,
) -> Result<Layer> {
    let parsed = parse_at_uri(uri)?;
    require_policy_collection(uri, &parsed)?;
    let record_repo = parse_at_identifier(&parsed.authority)?;
    let client = if parsed.authority == steward_did {
        local_api
    } else {
        if !remote_clients.contains_key(&parsed.authority) {
            let pds = state
                .resolver
                .resolve_pds_endpoint(&parsed.authority)
                .await
                .with_context(|| {
                    format!(
                        "resolving PDS for pipeline record repo `{}`",
                        parsed.authority
                    )
                })?;
            remote_clients.insert(parsed.authority.clone(), pds_read_client(&pds)?);
        }
        &remote_clients[&parsed.authority]
    };

    // Stamp the store entry with the load's rev floor ONLY for records in
    // the steward's own repo: the floor is the STEWARD repo's head, and rev
    // streams are per-repo — comparing a remote record's events against it
    // would gate valid updates on an incomparable rev (the same reason
    // `reload` skips the gate for remote-record events). Remote entries are
    // stamped `None`, so their events always apply — the tradeoff there is
    // only a redundant reload, never a missed update.
    let rev_floor = if parsed.authority == steward_did {
        rev_floor
    } else {
        None
    };

    // Serve from the global record store (fetch-on-miss, coalesced, kept
    // current by Jetstream — see `record_store`); the entry is stamped with
    // this load's rev floor so events at or below it are recognized as
    // already-reflected.
    let record = record_store::get_or_fetch(uri, rev_floor, || {
        fetch_record(client, &record_repo, &parsed.collection, &parsed.record_key)
    })
    .await
    .with_context(|| format!("fetching policy record {uri}"))?
    .ok_or_else(|| anyhow!("pipeline policy record not found: {uri}"))?;

    // Cache hit: the record is unchanged since it was last compiled.
    if let Some(cid) = &record.cid {
        if let Some(layer) = LAYER_CACHE.get(&(uri.to_string(), cid.clone())).await {
            return Ok(layer);
        }
    }

    let source =
        rego_source(&record).with_context(|| format!("extracting policy source from {uri}"))?;
    let layer = Layer::compile(&source, uri, record.cid.clone())
        .with_context(|| format!("compiling pipeline layer {uri}"))?;
    if let Some(cid) = record.cid {
        LAYER_CACHE
            .insert((uri.to_string(), cid), layer.clone())
            .await;
    }
    Ok(layer)
}

/// Parse a repo identifier (handle or DID) for the atrium typed client.
fn parse_at_identifier(repo: &str) -> Result<AtIdentifier> {
    repo.parse::<AtIdentifier>()
        .map_err(|e| anyhow!("invalid repo identifier `{repo}`: {e}"))
}

/// Shared HTTP client for every unauthenticated PDS read (service/config/rev
/// fetches, layer records, remote loads). Pooling + keepalive mean repeated
/// reads to the same PDS host reuse the established connection (HTTP/2 where
/// negotiated) instead of redoing TCP+TLS per client, cutting per-request
/// latency and connection churn at the PDS's edge. It does not reduce
/// request *counts*, so request-based rate limits still apply — see
/// [`RateLimited`] handling in [`onboard_with_retries`].
static PDS_READ_HTTP: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(60))
        .build()
        .expect("building shared PDS read HTTP client")
});

/// Build an unauthenticated atrium client for public PDS record reads. The
/// per-request total timeout keeps a hung PDS from stalling the caller; the
/// reqwest client itself is shared ([`PDS_READ_HTTP`]) so connections are
/// pooled across loads instead of rebuilt per call.
pub(crate) fn pds_read_client(pds_endpoint: &str) -> Result<PdsReadClient> {
    let client = atrium_xrpc_client::reqwest::ReqwestClientBuilder::new(pds_endpoint)
        .client(PDS_READ_HTTP.clone())
        .build();
    Ok(AtpServiceClient::new(client))
}

/// Fetch the current repo `rev` (head commit) for `repo` via
/// `com.atproto.sync.getRepoStatus`. This is the load-time monotonic floor for
/// Jetstream gating.
///
/// Returns `Ok(None)` when the repo is inactive or the PDS reports no rev.
async fn fetch_repo_rev(api: &PdsReadClient, repo: &AtIdentifier) -> Result<Option<Tid>> {
    let did = match repo {
        AtIdentifier::Did(did) => did.clone(),
        // Handle-based repo identifiers have no stable DID here; callers always
        AtIdentifier::Handle(_) => return Ok(None),
    };
    let params = atrium_api::com::atproto::sync::get_repo_status::ParametersData { did }.into();
    match api.service.com.atproto.sync.get_repo_status(params).await {
        Ok(output) => Ok(output.data.rev),
        Err(e) => Err(xrpc_load_error("getRepoStatus", e)),
    }
}

/// Fetch the current repo head commit CID for `did` via
/// `com.atproto.sync.getLatestCommit`.
///
/// This is the compare-and-swap token for an `installPolicy` write: passing it
/// as `swap_commit` makes the `putRecord` fail if the repo's head commit
/// changed between the read and the write, so two concurrent policy installs
/// (or any other concurrent repo write) cannot silently clobber each other.
/// Using the repo head rather than a record CID also covers the very first
/// install, when no records exist yet but the repo still has a head to guard.
pub async fn repo_head_cid(state: &AppState, did: &str) -> Result<Option<String>> {
    let pds_endpoint = state
        .resolver
        .resolve_pds_endpoint(did)
        .await
        .map_err(|e| anyhow::anyhow!("resolving PDS endpoint for {did}: {e:#}"))?;
    let api = pds_read_client(&pds_endpoint)?;
    let repo_did = match parse_at_identifier(did)? {
        AtIdentifier::Did(d) => d,
        AtIdentifier::Handle(_) => return Ok(None),
    };
    let params =
        atrium_api::com::atproto::sync::get_latest_commit::ParametersData { did: repo_did }.into();
    match api.service.com.atproto.sync.get_latest_commit(params).await {
        Ok(output) => Ok(Some(output.data.cid.as_ref().to_string())),
        Err(e) => Err(xrpc_load_error("getLatestCommit", e)),
    }
}

/// Fetch a single record via `com.atproto.repo.getRecord`.
///
/// Returns `Ok(None)` when the record does not exist (treated as absent for the
/// lifecycle). Other errors are propagated. The record's CID (when the PDS
/// reports one) is carried alongside the value for layer caching + provenance.
async fn fetch_record(
    api: &PdsReadClient,
    repo: &AtIdentifier,
    collection: &str,
    rkey: &str,
) -> Result<Option<RecordSource>> {
    let params = get_record::ParametersData {
        cid: None,
        collection: parse_nsid(collection)?,
        repo: repo.clone(),
        rkey: parse_record_key(rkey)?,
    }
    .into();
    match api.service.com.atproto.repo.get_record(params).await {
        Ok(output) => Ok(Some(RecordSource {
            source: output.data.value,
            cid: output.data.cid.map(|c| c.as_ref().to_string()),
        })),
        Err(atrium_xrpc::Error::XrpcResponse(xrpc_err)) => {
            if xrpc_err.status == StatusCode::TOO_MANY_REQUESTS {
                Err(xrpc_load_error(
                    &format!("getRecord {collection}/{rkey}"),
                    atrium_xrpc::Error::XrpcResponse(xrpc_err),
                ))
            } else if matches!(
                xrpc_err.error,
                Some(XrpcErrorKind::Custom(get_record::Error::RecordNotFound(_)))
            ) {
                Ok(None)
            } else {
                Err(anyhow!("getRecord {collection}/{rkey}: {xrpc_err}"))
            }
        }
        Err(e) => Err(xrpc_load_error(
            &format!("getRecord {collection}/{rkey}"),
            e,
        )),
    }
}

/// Resolve the recovery admin designated by `did`'s
/// `town.muni.arbiter.recovery/self` record.
///
/// This record is THE authority for `installPolicy`: it is fetched fresh from
/// the account's repo on every install call, so rewriting it rotates the
/// recovery admin with effect on the next call. Returns `Ok(None)` when the
/// record is absent or carries no string `did` field (fail-closed).
pub(crate) async fn recovery_admin(state: &AppState, did: &str) -> Result<Option<String>> {
    let pds_endpoint = state
        .resolver
        .resolve_pds_endpoint(did)
        .await
        .map_err(|e| anyhow!("resolving PDS endpoint for {did}: {e:#}"))?;
    let api = pds_read_client(&pds_endpoint)?;
    let repo = parse_at_identifier(did)?;
    Ok(
        fetch_record(&api, &repo, RECOVERY_COLLECTION, RECOVERY_RKEY)
            .await?
            .and_then(|record| record.field("did")),
    )
}

/// Extract the Rego source string from a policy record's `policy` field.
fn rego_source(record: &RecordSource) -> Result<String> {
    record
        .field("policy")
        .ok_or_else(|| anyhow!("policy record is missing a string 'policy' field"))
}

/// Parse an NSID collection name.
pub(crate) fn parse_nsid(s: &str) -> Result<Nsid> {
    s.parse::<Nsid>()
        .map_err(|e| anyhow!("invalid nsid `{s}`: {e}"))
}

/// Validate the config inputs an installPolicy request carries, before any
/// records are written: every trusted scope must be a valid NSID (it is
/// matched against request NSID prefixes at request time) and every pipeline
/// entry must be a record-level `at://` URI naming a `town.muni.arbiter.policy`
/// record — it is resolved and compiled at onboard, and only that collection
/// hot-reloads (see `require_policy_collection`). Rejecting at install turns a
/// fail-closed onboard failure into an `ErrInvalidPolicy` the installer can
/// act on.
pub(crate) fn validate_config_inputs(trusted_scopes: &[String], pipeline: &[String]) -> Result<()> {
    for scope in trusted_scopes {
        parse_nsid(scope)
            .with_context(|| format!("trusted scope `{scope}` is not a valid NSID"))?;
    }
    for uri in pipeline {
        let parsed = parse_at_uri(uri)
            .with_context(|| format!("pipeline entry `{uri}` is not a valid record URI"))?;
        require_policy_collection(uri, &parsed)?;
    }
    Ok(())
}

/// Verify that every pipeline entry resolves and compiles, before the config
/// write activates the pipeline.
///
/// Runs each entry through [`resolve_layer`] — the exact machinery the
/// re-onboard uses — so a rejection here is exactly a failure the re-onboard
/// would hit: a missing record, a missing or non-string `policy` field, or a
/// source that does not compile (an uncompilable record would otherwise pass
/// install, get CAS-written and activated, and then fail the re-onboard's
/// compile as an undeclared 500 — with the config write's reload event
/// offboarding a previously-serving arbiter). Rejecting at install turns that
/// fail-closed onboard failure into an `ErrInvalidPolicy` the installer can
/// act on.
///
/// Called from `installPolicy` with the referenced policy URI (the caller
/// wrote the record to its repo beforehand) before the config write.
pub(crate) async fn validate_pipeline_records(
    state: &AppState,
    local_api: &PdsReadClient,
    steward_did: &str,
    pipeline: &[String],
) -> Result<()> {
    let mut remote_clients: HashMap<String, PdsReadClient> = HashMap::new();
    for uri in pipeline {
        resolve_layer(
            state,
            local_api,
            steward_did,
            uri,
            &mut remote_clients,
            None,
        )
        .await?;
    }
    Ok(())
}

/// Parse a record key.
fn parse_record_key(s: &str) -> Result<RecordKey> {
    s.parse::<RecordKey>()
        .map_err(|e| anyhow!("invalid rkey `{s}`: {e}"))
}
