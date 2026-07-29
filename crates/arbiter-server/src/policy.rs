//! Policy loading from PDS records + startup onboarding (SERVER_PLAN.md §4/§6).
//!
//! Records read from each stewarded account's PDS (resolved via
//! [`crate::AppState`].resolver):
//!   the §4 lifecycle (offboard when absent; offboard + purge credentials when it
//!   points at a different server).
//! - `town.muni.arbiter.policy.root/self` — the root Rego policy source.
//! - `town.muni.arbiter.policy.sub/<name>` — named sub-policies (listed via
//!   `com.atproto.repo.listRecords`, keyed by record rkey).
//!
//! Each policy record carries the Rego source in its `source` string field.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use arbiter_core::arbiter::{Arbiter, Policies};
use arbiter_core::policy::PolicyVm;
use regorus::Value;
use serde_json::Value as Json;
use atproto_identity::traits::IdentityResolver;
use crate::{AppState, CONFIG};
/// Service record collection + rkey (`town.muni.arbiter.service/self`).
const SERVICE_COLLECTION: &str = "town.muni.arbiter.service";
const SERVICE_RKEY: &str = "self";
/// Root policy record collection + rkey (`town.muni.arbiter.policy.root/self`).
const ROOT_COLLECTION: &str = "town.muni.arbiter.policy.root";
const ROOT_RKEY: &str = "self";
/// Sub-policy record collection (`town.muni.arbiter.policy.sub/<name>`).
const SUB_COLLECTION: &str = "town.muni.arbiter.policy.sub";

/// Async host functions registered on every arbiter policy VM.
const HOST_FNS: &[&str] = &["xrpc", "policy"];
/// Rego entrypoint evaluated to produce a request's result.
const ENTRYPOINT: &str = "data.arbiter.result";

/// On startup, load + onboard every arbiter the server holds credentials for.
///
/// Per-arbiter fail-closed is already enforced by `ArbiterCollection::begin_request`
/// returning `ArbiterNotReady` for un-onboarded DIDs; this task just brings them
/// online. Retry each load with exponential backoff until it succeeds.
pub async fn startup_onboard(state: Arc<AppState>) -> Result<()> {
    let entries = state.store.list().await.context("listing stored credentials")?;
    if entries.is_empty() {
        tracing::info!("no stewarded accounts to onboard at startup");
        return Ok(());
    }
    for (did, _creds) in entries {
        let mut delay = Duration::from_secs(1);
        loop {
            match load_and_onboard(&state, &did).await {
                Ok(pds_endpoint) => {
                    tracing::info!(did = %did, pds = %pds_endpoint, "onboarded arbiter");
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        did = %did,
                        error = %format!("{e:#}"),
                        "load_and_onboard failed; retrying in {delay:?}"
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(60));
                }
            }
        }
    }
    Ok(())
}

/// Fetch the latest root + sub-policy records and the service record for `did`
/// from its PDS, build `Policies`, and onboard (or update) the arbiter. Returns
/// the resolved PDS endpoint.
///
/// Also applies the §4 lifecycle: if `town.muni.arbiter.service/self` is absent
/// -> `state.arbiters.offboard(did)`; if its `did` field != `CONFIG.server_did`
/// -> `offboard` + `state.store.remove(did)`.
pub async fn load_and_onboard(state: &AppState, did: &str) -> Result<String> {
    let pds_endpoint = resolve_pds_endpoint(&*state.resolver, did)
        .await
        .with_context(|| format!("resolving PDS endpoint for {did}"))?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;

    // Authenticate as the stewarded account so record reads work on PDSs that
    // require auth. Fall back to unauthenticated reads if no credentials are
    // stored or session creation fails.
    let token = match state.store.get(did).await.context("fetching credentials")? {
        Some(creds) => match pds_session(&client, &pds_endpoint, did, &creds.password).await {
            Ok(Some(t)) => Some(t),
            Ok(None) => {
                tracing::debug!(did, "PDS session creation failed; trying unauthenticated reads");
                None
            }
            Err(e) => {
                tracing::warn!(did, error = %format!("{e:#}"), "PDS session error; trying unauthenticated reads");
                None
            }
        },
        None => None,
    };

    // --- §4 lifecycle: service record --------------------------------------
    let service = get_record(&client, &pds_endpoint, token.as_deref(), did, SERVICE_COLLECTION, SERVICE_RKEY)
        .await
        .with_context(|| format!("fetching {SERVICE_COLLECTION}/{SERVICE_RKEY}"))?;
    match service {
        None => {
            // Record absent: stop serving but keep credentials (may re-onboard).
            tracing::info!(did, "service record absent; offboarding arbiter");
            state.arbiters.offboard(did).await;
            return Ok(pds_endpoint);
        }
        Some(rec) => {
            let svc_did = rec.get("did").and_then(|v| v.as_str());
            match svc_did {
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

    // --- root policy -------------------------------------------------------
    let root_rec = get_record(&client, &pds_endpoint, token.as_deref(), did, ROOT_COLLECTION, ROOT_RKEY)
        .await
        .with_context(|| format!("fetching {ROOT_COLLECTION}/{ROOT_RKEY}"))?
        .ok_or_else(|| {
            anyhow!("root policy record {ROOT_COLLECTION}/{ROOT_RKEY} not found for {did}")
        })?;
    let root_src = rego_source(&root_rec)
        .with_context(|| format!("extracting root policy source for {did}"))?;
    let root = PolicyVm::new(&root_src, Value::new_object(), ENTRYPOINT, HOST_FNS)
        .with_context(|| format!("compiling root policy for {did}"))?;

    // --- sub-policies ------------------------------------------------------
    let sub_records = list_records(&client, &pds_endpoint, token.as_deref(), did, SUB_COLLECTION)
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
        .onboard(did.to_string(), arbiter, pds_endpoint.clone())
        .await;
    Ok(pds_endpoint)
}

/// Resolve `did` -> PDS endpoint via the `#atproto_pds` service in its DID doc.
pub(crate) async fn resolve_pds_endpoint(
    resolver: &dyn IdentityResolver,
    did: &str,
) -> Result<String> {
    let doc = resolver
        .resolve(did)
        .await
        .map_err(|e| anyhow!("identity resolution failed for {did}: {e:#}"))?;
    for svc in &doc.service {
        if svc.id == "#atproto_pds" {
            return Ok(svc.service_endpoint.clone());
        }
    }
    Err(anyhow!("no #atproto_pds service in DID document for {did}"))
}

/// Create a PDS session (`com.atproto.server.createSession`) and return its
/// `accessJwt`. Returns `Ok(None)` if authentication could not be established
/// (caller falls back to unauthenticated reads).
async fn pds_session(
    client: &reqwest::Client,
    pds_url: &str,
    identifier: &str,
    password: &str,
) -> Result<Option<String>> {
    let url = format!(
        "{}/xrpc/com.atproto.server.createSession",
        pds_url.trim_end_matches('/')
    );
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "identifier": identifier, "password": password }))
        .send()
        .await
        .context("createSession request")?;
    let status = resp.status();
    let body = resp.bytes().await.context("createSession body")?;
    if !status.is_success() {
        // Non-success => no token; public reads may still work.
        tracing::debug!(
            pds_url,
            status = %status,
            "createSession failed; proceeding without auth"
        );
        return Ok(None);
    }
    let v: Json = serde_json::from_slice(&body).context("createSession json")?;
    Ok(v.get("accessJwt").and_then(|t| t.as_str()).map(String::from))
}

/// Fetch a single record via `com.atproto.repo.getRecord`.
///
/// Returns `Ok(None)` when the record does not exist (treated as absent for the
/// §4 lifecycle). Other HTTP errors are propagated.
async fn get_record(
    client: &reqwest::Client,
    pds_url: &str,
    token: Option<&str>,
    repo: &str,
    collection: &str,
    rkey: &str,
) -> Result<Option<Json>> {
    let url = format!(
        "{}/xrpc/com.atproto.repo.getRecord",
        pds_url.trim_end_matches('/')
    );
    let mut req = client.get(&url).query(&[
        ("repo", repo),
        ("collection", collection),
        ("rkey", rkey),
    ]);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.context("getRecord request")?;
    let status = resp.status();
    let body = resp.bytes().await.context("getRecord body")?;
    if status.is_success() {
        let v: Json = serde_json::from_slice(&body).context("getRecord json")?;
        let value = v
            .get("value")
            .cloned()
            .ok_or_else(|| anyhow!("getRecord response missing 'value'"))?;
        return Ok(Some(value));
    }
    // Distinguish "record not found" (absent) from real errors.
    let parsed: Option<Json> = serde_json::from_slice(&body).ok();
    if let Some(j) = &parsed {
        if j.get("error").and_then(|e| e.as_str()) == Some("RecordNotFound") {
            return Ok(None);
        }
    }
    if status == reqwest::StatusCode::NOT_FOUND || (status.as_u16() == 400 && parsed.is_none()) {
        return Ok(None);
    }
    Err(anyhow!(
        "getRecord {collection}/{rkey} failed: {status}: {}",
        String::from_utf8_lossy(&body)
    ))
}

/// List records in a collection via `com.atproto.repo.listRecords`. Returns
/// `(rkey, record_value)` pairs, keyed by the record rkey (the segment after the
/// final `/` in each record's `uri`).
async fn list_records(
    client: &reqwest::Client,
    pds_url: &str,
    token: Option<&str>,
    repo: &str,
    collection: &str,
) -> Result<Vec<(String, Json)>> {
    let url = format!(
        "{}/xrpc/com.atproto.repo.listRecords",
        pds_url.trim_end_matches('/')
    );
    let mut req = client.get(&url).query(&[
        ("repo", repo),
        ("collection", collection),
        ("limit", "100"),
    ]);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.context("listRecords request")?;
    let status = resp.status();
    let body = resp.bytes().await.context("listRecords body")?;
    if !status.is_success() {
        return Err(anyhow!(
            "listRecords {collection} failed: {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    let v: Json = serde_json::from_slice(&body).context("listRecords json")?;
    let records = v
        .get("records")
        .and_then(|r| r.as_array())
        .ok_or_else(|| anyhow!("listRecords response missing 'records' array"))?;
    let mut out = Vec::with_capacity(records.len());
    for rec in records {
        let uri = rec
            .get("uri")
            .and_then(|u| u.as_str())
            .ok_or_else(|| anyhow!("listRecords entry missing 'uri'"))?;
        let value = rec
            .get("value")
            .cloned()
            .ok_or_else(|| anyhow!("listRecords entry missing 'value'"))?;
        // at-uri: at://<did>/<collection>/<rkey> -> rkey is the last segment.
        let rkey = uri.rsplit('/').next().unwrap_or("").to_string();
        out.push((rkey, value));
    }
    Ok(out)
}

/// Extract the Rego source string from a policy record's `source` field.
fn rego_source(record: &Json) -> Result<String> {
    record
        .get("source")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| anyhow!("policy record is missing a string 'source' field"))
}