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

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;

use crate::resolver::IdentityResolverExt;
use crate::{AppState, CONFIG};
use anyhow::{Context, Result, anyhow};
use arbiter_core::arbiter::{Arbiter, Layer, Pipeline};
use atrium_api::client::AtpServiceClient;
use atrium_api::com::atproto::repo::get_record;
use atrium_api::types::string::{AtIdentifier, Nsid, RecordKey, Tid};
use atrium_xrpc::error::XrpcErrorKind;
use atrium_xrpc_client::reqwest::ReqwestClient;
use atproto_record::aturi::ATURI;
use futures_util::stream::{self, StreamExt};
use moka::future::Cache;

/// Service record collection + rkey (`town.muni.arbiter.service/self`).
const SERVICE_COLLECTION: &str = "town.muni.arbiter.service";
const SERVICE_RKEY: &str = "self";
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
const STARTUP_MAX_RETRIES: u32 = 5;

/// Maximum arbiters whose `load_and_onboard` runs concurrently during a bulk
/// onboarding pass ([`startup_onboard`], [`refresh_all_after_reconnect`]).
///
/// Each load opens several unauthenticated HTTPS connections to per-DID
/// endpoints (DID resolution, repo rev, service/config records, every
/// pipeline layer — each on a fresh client with no pool reuse, see
/// `pds_read_client`), so an unbounded pass at thousands-of-arbiters scale
/// would mean thousands of simultaneous DNS lookups and TLS handshakes plus
/// file-descriptor pressure. The bound keeps concurrent fetches — and open
/// sockets — flat; the pass is background work, so 64-wide throughput is
/// ample.
const ONBOARD_CONCURRENCY: usize = 64;

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
        index.entry(uri.clone()).or_default().insert(did.to_string());
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

/// Re-load + onboard every stewarded arbiter after a Jetstream reconnect.
///
/// A disconnect means the subscription missed any policy/service-record writes
/// that happened while it was down, and `load_and_onboard` re-fetches the
/// *current* PDS state, so this closes the fail-open window where the server
/// would otherwise keep enforcing the last-loaded (possibly revoked/permissive)
/// policy. Runs bounded-concurrent (see [`onboard_all`]); each failed load is
/// left fail-closed (offboarded) and retried a bounded number of times.
pub async fn refresh_all_after_reconnect(state: Arc<AppState>) {
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
/// own slot instead of stalling the pass head-of-line.
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
/// 1s doubling to 30s, giving up after `max_retries` consecutive failures —
/// fail-closed (the arbiter stays offboarded), so the pass always terminates.
async fn onboard_with_retries(
    state: &AppState,
    did: String,
    max_retries: u32,
    pass: &str,
) -> Result<OnboardOutcome> {
    let mut attempt: u32 = 0;
    let mut delay = Duration::from_secs(1);
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
                attempt += 1;
                tracing::warn!(
                    did = %did,
                    attempt,
                    error = %format!("{e:#}"),
                    "load_and_onboard failed during {pass}; retrying in {delay:?}"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            }
        }
    }
}

/// Fetch the config record + pipeline for `did` from the PDS, compile the
/// pipeline layers, and onboard (or update) the arbiter.
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

    // --- lifecycle: service record ----------------------------------------
    let service = fetch_record(&api, &repo, SERVICE_COLLECTION, SERVICE_RKEY)
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
                    tracing::info!(did, "un-provisioned account missing service record; repairing bootstrap");
                    crate::handlers::repair_provisioning(state, did, &creds, &pds_endpoint)
                        .await?;
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

    // Compute the load-time rev floor BEFORE reading the records so the floor
    // provably dominates the records we load: the records are read at or after
    // the moment the floor was captured, so they reflect state at least as new
    // as the floor. (Fetching the floor after the reads would let a concurrent
    // load read stale records and then capture a raised floor, permanently
    // dropping the events it is missing.) If the floor can't be determined we
    // use no floor (accept everything), which only risks redundant reloads —
    // never a missed update.
    let rev_floor = match fetch_repo_rev(&api, &repo).await {
        Ok(Some(rev)) => Some(rev.as_str().to_string()),
        Ok(None) => {
            tracing::warn!(did, "repo inactive or no rev reported; leaving rev floor unset");
            None
        }
        Err(e) => {
            tracing::warn!(
                did,
                error = %format!("{e:#}"),
                "repo rev unavailable; leaving rev floor unset"
            );
            None
        }
    };

    // --- config record ------------------------------------------------------
    // Fail-closed: a missing or malformed config record is a load error, which
    // every caller treats as offboarded.
    let config_rec = fetch_record(&api, &repo, CONFIG_COLLECTION, CONFIG_RKEY)
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
            resolve_layer(state, &api, did, uri, &mut remote_clients)
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
/// The entry must name a `town.muni.arbiter.policy` record (see
/// `require_policy_collection`): the Jetstream reload path would never deliver
/// writes for a foreign collection, so such a layer could never hot-reload.
async fn resolve_layer(
    state: &AppState,
    local_api: &PdsReadClient,
    steward_did: &str,
    uri: &str,
    remote_clients: &mut HashMap<String, PdsReadClient>,
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
                    format!("resolving PDS for pipeline record repo `{}`", parsed.authority)
                })?;
            remote_clients.insert(parsed.authority.clone(), pds_read_client(&pds)?);
        }
        &remote_clients[&parsed.authority]
    };

    let record = fetch_record(client, &record_repo, &parsed.collection, &parsed.record_key)
        .await
        .with_context(|| format!("fetching policy record {uri}"))?
        .ok_or_else(|| anyhow!("pipeline policy record not found: {uri}"))?;

    // Cache hit: the record is unchanged since it was last compiled.
    if let Some(cid) = &record.cid {
        if let Some(layer) = LAYER_CACHE.get(&(uri.to_string(), cid.clone())).await {
            return Ok(layer);
        }
    }

    let source = rego_source(&record).with_context(|| format!("extracting policy source from {uri}"))?;
    let layer = Layer::compile(&source, uri, record.cid.clone())
        .with_context(|| format!("compiling pipeline layer {uri}"))?;
    if let Some(cid) = record.cid {
        LAYER_CACHE.insert((uri.to_string(), cid), layer.clone()).await;
    }
    Ok(layer)
}

/// Parse a repo identifier (handle or DID) for the atrium typed client.
fn parse_at_identifier(repo: &str) -> Result<AtIdentifier> {
    repo.parse::<AtIdentifier>()
        .map_err(|e| anyhow!("invalid repo identifier `{repo}`: {e}"))
}

/// Build an unauthenticated atrium client for public PDS record reads. A bounded
/// timeout keeps a hung PDS from stalling the caller.
pub(crate) fn pds_read_client(pds_endpoint: &str) -> Result<PdsReadClient> {
    let client = atrium_xrpc_client::reqwest::ReqwestClientBuilder::new(pds_endpoint)
        .client(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .context("building HTTP client")?,
        )
        .build();
    Ok(AtpServiceClient::new(client))
}

/// Fetch the current repo `rev` (head commit) for `repo` via
/// `com.atproto.sync.getRepoStatus`. This is the load-time monotonic floor for
/// Jetstream gating.
///
/// Returns `Ok(None)` when the repo is inactive or the PDS reports no rev.
async fn fetch_repo_rev(
    api: &PdsReadClient,
    repo: &AtIdentifier,
) -> Result<Option<Tid>> {
    let did = match repo {
        AtIdentifier::Did(did) => did.clone(),
        // Handle-based repo identifiers have no stable DID here; callers always
        // pass a DID, so this is defensive.
        AtIdentifier::Handle(_) => return Ok(None),
    };
    let params = atrium_api::com::atproto::sync::get_repo_status::ParametersData { did }.into();
    match api.service.com.atproto.sync.get_repo_status(params).await {
        Ok(output) => Ok(output.data.rev),
        Err(e) => Err(anyhow!("getRepoStatus: {e}")),
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
    let params = atrium_api::com::atproto::sync::get_latest_commit::ParametersData { did: repo_did }
        .into();
    match api.service.com.atproto.sync.get_latest_commit(params).await {
        Ok(output) => Ok(Some(output.data.cid.as_ref().to_string())),
        Err(e) => Err(anyhow!("getLatestCommit: {e}")),
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
            if matches!(
                xrpc_err.error,
                Some(XrpcErrorKind::Custom(get_record::Error::RecordNotFound(_)))
            ) {
                Ok(None)
            } else {
                Err(anyhow!("getRecord {collection}/{rkey}: {xrpc_err}"))
            }
        }
        Err(e) => Err(anyhow!("getRecord {collection}/{rkey}: {e}")),
    }
}

/// A record value loaded from the PDS.
struct RecordSource {
    /// The raw record value as an atrium [`Unknown`].
    source: atrium_api::types::Unknown,
    /// The record CID at fetch time, when the PDS reports one. Provenance for
    /// pipeline layers + the cache key for compiled layers.
    cid: Option<String>,
}

impl RecordSource {
    /// Read a top-level string field from the record value.
    ///
    /// `Unknown` is an untagged serde enum; materialize it as JSON to read the
    /// field without depending on ipld internals.
    fn field(&self, name: &str) -> Option<String> {
        let json = serde_json::to_value(&self.source).ok()?;
        json.get(name).and_then(|v| v.as_str()).map(String::from)
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
    Ok(fetch_record(&api, &repo, RECOVERY_COLLECTION, RECOVERY_RKEY)
        .await?
        .and_then(|record| record.field("did")))
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
        resolve_layer(state, local_api, steward_did, uri, &mut remote_clients).await?;
    }
    Ok(())
}

/// Parse a record key.
fn parse_record_key(s: &str) -> Result<RecordKey> {
    s.parse::<RecordKey>()
        .map_err(|e| anyhow!("invalid rkey `{s}`: {e}"))
}