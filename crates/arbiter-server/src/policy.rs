//! Policy loading from PDS records + startup onboarding.
//!
//! Records read from each stewarded account's PDS (resolved via
//! [`crate::AppState`].resolver):
//! - `town.muni.arbiter.service/self` — the arbiter service record. Its `did`
//!   field determines lifecycle: absent -> offboard (keep credentials); pointing
//!   at a different server -> offboard + purge credentials.
//! - `town.muni.arbiter.policy.root/self` — the root Rego policy source.
//! - `town.muni.arbiter.policy.sub/<name>` — named sub-policies (listed via
//!   `com.atproto.repo.listRecords`, keyed by record rkey).
//!
//! Each policy record carries the Rego source in its `policy` string field.
//!
//! Reads are performed with an unauthenticated atrium client: policy/service
//! records are public ATProto records that do not require auth, so no PDS
//! session is established here. (The credential store only holds the steward
//! password for *writing* records during provisioning, not for these reads.)

use std::sync::Arc;
use std::time::Duration;

use crate::resolver::IdentityResolverExt;
use crate::{AppState, CONFIG};
use anyhow::{Context, Result, anyhow};
use arbiter_core::arbiter::{Arbiter, Policies};
use arbiter_core::policy::PolicyVm;
use atrium_api::client::AtpServiceClient;
use atrium_api::com::atproto::repo::get_record;
use atrium_api::types::string::{AtIdentifier, Nsid, RecordKey, Tid};
use atrium_xrpc::error::XrpcErrorKind;
use atrium_xrpc_client::reqwest::ReqwestClientBuilder;
use regorus::Value;

/// Service record collection + rkey (`town.muni.arbiter.service/self`).
const SERVICE_COLLECTION: &str = "town.muni.arbiter.service";
const SERVICE_RKEY: &str = "self";
/// Root policy record collection + rkey (`town.muni.arbiter.policy.root/self`).
pub const ROOT_COLLECTION: &str = "town.muni.arbiter.policy.root";
pub const ROOT_RKEY: &str = "self";
/// Recovery-admin designation record (`town.muni.arbiter.recovery/self`).
pub const RECOVERY_COLLECTION: &str = "town.muni.arbiter.recovery";
pub const RECOVERY_RKEY: &str = "self";
/// Sub-policy record collection (`town.muni.arbiter.policy.sub/<name>`).
const SUB_COLLECTION: &str = "town.muni.arbiter.policy.sub";

/// Async host functions registered on every arbiter policy VM.
const HOST_FNS: &[&str] = &["xrpc", "policy"];
/// Rego entrypoint evaluated to produce a request's result.
const ENTRYPOINT: &str = "data.arbiter.result";

/// Maximum number of `load_and_onboard` attempts per arbiter during startup
/// onboarding. After this many consecutive failures the arbiter is left
/// offboarded (fail-closed) and we move on, so a permanently unreachable PDS
/// cannot spin this task forever. A subsequent Jetstream event or restart
/// retries.
const STARTUP_MAX_RETRIES: u32 = 5;

/// On startup, load + onboard every arbiter the server holds credentials for.
///
/// Per-arbiter fail-closed is already enforced by `ArbiterCollection::begin_request`
/// returning `ArbiterNotReady` for un-onboarded DIDs; this task just brings them
/// online. Retry each load with bounded exponential backoff, giving up after
/// [`STARTUP_MAX_RETRIES`] consecutive failures per arbiter.
pub async fn startup_onboard(state: Arc<AppState>) -> Result<()> {
    let entries = state
        .store
        .list()
        .await
        .context("listing stored credentials")?;
    if entries.is_empty() {
        tracing::info!("no stewarded accounts to onboard at startup");
        return Ok(());
    }
    for (did, _creds) in entries {
        let mut attempt: u32 = 0;
        let mut delay = Duration::from_secs(1);
        loop {
            match load_and_onboard(&state, &did).await {
                Ok(pds_endpoint) => {
                    tracing::info!(did = %did, pds = %pds_endpoint, "onboarded arbiter");
                    break;
                }
                Err(e) if attempt >= STARTUP_MAX_RETRIES => {
                    // Fail closed: leave the arbiter offboarded and move on.
                    tracing::error!(
                        did = %did,
                        error = %format!("{e:#}"),
                        "giving up onboarding arbiter after {STARTUP_MAX_RETRIES} attempts"
                    );
                    break;
                }
                Err(e) => {
                    attempt += 1;
                    tracing::warn!(
                        did = %did,
                        attempt,
                        error = %format!("{e:#}"),
                        "load_and_onboard failed; retrying in {delay:?}"
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(30));
                }
            }
        }
    }
    Ok(())
}

/// Re-load + onboard every stewarded arbiter after a Jetstream reconnect.
///
/// A disconnect means the subscription missed any policy/service-record writes
/// that happened while it was down, and `load_and_onboard` re-fetches the
/// *current* PDS state, so this closes the fail-open window where the server
/// would otherwise keep enforcing the last-loaded (possibly revoked/permissive)
/// policy. Each failed load is left fail-closed (offboarded) and retried a
/// bounded number of times.
pub async fn refresh_all_after_reconnect(state: Arc<AppState>) {
    let entries = match state.store.list().await {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "failed to list credentials for reconnect refresh");
            return;
        }
    };
    for (did, _creds) in entries {
        let mut attempt: u32 = 0;
        let mut delay = Duration::from_secs(1);
        loop {
            match load_and_onboard(&state, &did).await {
                Ok(pds) => {
                    tracing::info!(did = %did, pds = %pds, "refreshed arbiter after reconnect");
                    break;
                }
                Err(e) if attempt >= STARTUP_MAX_RETRIES => {
                    tracing::error!(
                        did = %did,
                        error = %format!("{e:#}"),
                        "giving up refreshing arbiter after reconnect ({STARTUP_MAX_RETRIES} attempts)"
                    );
                    break;
                }
                Err(e) => {
                    attempt += 1;
                    tracing::warn!(
                        did = %did,
                        attempt,
                        error = %format!("{e:#}"),
                        "reconnect refresh failed; retrying in {delay:?}"
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(30));
                }
            }
        }
    }
}

/// Fetch the latest root + sub-policy records and the service record for `did`
/// from its PDS, build `Policies`, and onboard (or update) the arbiter. Returns
/// the resolved PDS endpoint.
///
/// Also applies the lifecycle: if `town.muni.arbiter.service/self` is absent
/// -> `state.arbiters.offboard(did)`; if its `did` field != `CONFIG.server_did`
/// -> `offboard` + `state.store.remove(did)`.
pub async fn load_and_onboard(state: &AppState, did: &str) -> Result<String> {
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
                    return Ok(pds_endpoint);
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
                    return Ok(pds_endpoint);
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
                    return Ok(pds_endpoint);
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

    // --- root policy -------------------------------------------------------
    let root_rec = fetch_record(&api, &repo, ROOT_COLLECTION, ROOT_RKEY)
        .await
        .with_context(|| format!("fetching {ROOT_COLLECTION}/{ROOT_RKEY}"))?
        .ok_or_else(|| {
            anyhow!("root policy record {ROOT_COLLECTION}/{ROOT_RKEY} not found for {did}")
        })?;
    let root_src = rego_source(&root_rec)
        .with_context(|| format!("extracting root policy source for {did}"))?;
    let root = compile_root(&root_src)
        .with_context(|| format!("compiling root policy for {did}"))?;

    // --- sub-policies ------------------------------------------------------
    let sub_records = list_records(&api, &repo, SUB_COLLECTION)
        .await
        .with_context(|| format!("listing {SUB_COLLECTION} records"))?;
    let mut subs = std::collections::HashMap::new();
    for (rkey, rec) in sub_records {
        match rego_source(&rec) {
            Ok(src) => match PolicyVm::new(&src, Value::new_object(), ENTRYPOINT, HOST_FNS) {
                Ok(vm) => {
                    subs.insert(rkey, vm);
                }
                Err(e) => {
                    tracing::warn!(did, rkey = %rkey, error = %format!("{e:#}"), "sub-policy failed to compile; skipping");
                }
            },
            Err(e) => {
                tracing::warn!(did, rkey = %rkey, error = %format!("{e:#}"), "sub-policy record missing source; skipping");
            }
        }
    }

    let policies = Policies::new(root, subs);
    let arbiter = Arbiter::new(policies);

    state
        .arbiters
        .onboard(did.to_string(), arbiter, pds_endpoint.clone(), rev_floor)
        .await;
    Ok(pds_endpoint)
}

/// Parse a repo identifier (handle or DID) for the atrium typed client.
fn parse_at_identifier(repo: &str) -> Result<AtIdentifier> {
    repo.parse::<AtIdentifier>()
        .map_err(|e| anyhow!("invalid repo identifier `{repo}`: {e}"))
}

/// Build an unauthenticated atrium client for public PDS record reads. A bounded
/// timeout keeps a hung PDS from stalling the caller.
fn pds_read_client(pds_endpoint: &str) -> Result<AtpServiceClient<atrium_xrpc_client::reqwest::ReqwestClient>> {
    let client = ReqwestClientBuilder::new(pds_endpoint)
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
    api: &AtpServiceClient<atrium_xrpc_client::reqwest::ReqwestClient>,
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

/// Fetch the designated recovery admin DID from `town.muni.arbiter.recovery/self`
/// on `did`'s PDS, if the record exists and carries a `did` field.
///
/// Returns `Ok(None)` when no recovery admin has been designated.
pub async fn recovery_admin(state: &AppState, did: &str) -> Result<Option<String>> {
    let pds_endpoint = state
        .resolver
        .resolve_pds_endpoint(did)
        .await
        .map_err(|e| anyhow::anyhow!("resolving PDS endpoint for {did}: {e:#}"))?;
    let api = pds_read_client(&pds_endpoint)?;
    let repo = parse_at_identifier(did)?;
    let rec = fetch_record(&api, &repo, RECOVERY_COLLECTION, RECOVERY_RKEY)
        .await
        .with_context(|| format!("fetching {RECOVERY_COLLECTION}/{RECOVERY_RKEY}"))?;
    Ok(rec.and_then(|r| r.field("did")))
}

/// Fetch the current repo head commit CID for `did` via
/// `com.atproto.sync.getLatestCommit`.
///
/// This is the compare-and-swap token for a `resetPolicy` write: passing it as
/// `swap_commit` makes the `putRecord` fail if the repo's head commit changed
/// between the read and the write, so two concurrent policy resets (or any
/// other concurrent repo write) cannot silently clobber each other. Using the
/// repo head rather than the root-policy record CID also covers the very first
/// policy install, when no root policy record exists yet but the repo still has
/// a head commit to guard.
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

/// Compile a root policy from Rego `source`, returning a freshly compiled
/// [`PolicyVm`] (a fresh execution context). Used both by onboarding and by
/// `resetPolicy` to validate + install a replacement root policy.
pub fn compile_root(source: &str) -> Result<PolicyVm> {
    PolicyVm::new(source, Value::new_object(), ENTRYPOINT, HOST_FNS)
}

/// Fetch a single record via `com.atproto.repo.getRecord`.
///
/// Returns `Ok(None)` when the record does not exist (treated as absent for the
/// lifecycle). Other errors are propagated.
async fn fetch_record(
    api: &AtpServiceClient<atrium_xrpc_client::reqwest::ReqwestClient>,
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

/// List records in a collection via `com.atproto.repo.listRecords`, following
/// the `cursor` pagination until every record is fetched. Returns
/// `(rkey, record_value)` pairs, keyed by the record rkey (the segment after the
/// final `/` in each record's `uri`).
async fn list_records(
    api: &AtpServiceClient<atrium_xrpc_client::reqwest::ReqwestClient>,
    repo: &AtIdentifier,
    collection: &str,
) -> Result<Vec<(String, RecordSource)>> {
    let mut cursor: Option<String> = None;
    let mut out = Vec::new();
    loop {
        let params = atrium_api::com::atproto::repo::list_records::ParametersData {
            collection: parse_nsid(collection)?,
            cursor: cursor.clone(),
            limit: Some(atrium_api::types::LimitedNonZeroU8::<100>::MAX),
            repo: repo.clone(),
            reverse: None,
        }
        .into();
        let output = api
            .service
            .com
            .atproto
            .repo
            .list_records(params)
            .await
            .context("listRecords")?;
        for record in output.data.records {
            // at-uri: at://<did>/<collection>/<rkey> -> rkey is the last segment.
            let rkey = record.data.uri.rsplit('/').next().unwrap_or("").to_string();
            out.push((
                rkey,
                RecordSource {
                    source: record.data.value,
                },
            ));
        }
        // Follow the pagination cursor until the server stops returning one.
        cursor = output.data.cursor.clone();
        if cursor.is_none() {
            break;
        }
    }
    Ok(out)
}

/// A record value loaded from the PDS.
struct RecordSource {
    /// The raw record value as an atrium [`Unknown`].
    source: atrium_api::types::Unknown,
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

/// Extract the Rego source string from a policy record's `policy` field.
fn rego_source(record: &RecordSource) -> Result<String> {
    record
        .field("policy")
        .ok_or_else(|| anyhow!("policy record is missing a string 'policy' field"))
}

/// Parse an NSID collection name.
fn parse_nsid(s: &str) -> Result<Nsid> {
    s.parse::<Nsid>()
        .map_err(|e| anyhow!("invalid nsid `{s}`: {e}"))
}

/// Parse a record key.
fn parse_record_key(s: &str) -> Result<RecordKey> {
    s.parse::<RecordKey>()
        .map_err(|e| anyhow!("invalid rkey `{s}`: {e}"))
}
