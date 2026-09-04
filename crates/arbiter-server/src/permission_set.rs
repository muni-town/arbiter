//! Layer-1 scope gate: permission-set lexicon resolution.
//!
//! A scoped proxy endpoint's NSID is `<scope>.arbiter.proxy` (e.g.
//! `community.lexicon.authCalendar.arbiter.proxy`), where `<scope>` is the NSID
//! of a published permission-set lexicon. The arbiter's layer-1 gate evaluates
//! a Rego policy embedded *in the permission-set lexicon itself* (locked plan
//! decision 3) as a pure [`ScopePolicy`] predicate, before the community
//! pipeline runs. The policy is a boolean predicate with entrypoint
//! `data.arbiter.allow`: `true` allows the request, while a `false` result, an
//! undefined rule, a non-boolean value, or any evaluation error denies it
//! (fail-closed). Its input is the request core — `{ method, nsid, parameters,
//! body, encoding }` — alone, with no context fields (caller/arbiter DIDs and
//! PDS/XRPC endpoints are not visible to scope policies).
//!
//! # The `x-town-muni-arbiter` embedding convention
//!
//! The embedded policy lives under a custom key inside the permission-set
//! lexicon's `defs.main` definition:
//!
//! ```json
//! {
//!   "lexicon": 1,
//!   "id": "community.lexicon.authCalendar",
//!   "defs": {
//!     "main": {
//!       "type": "permission-set",
//!       "title": "Calendar access",
//!       "permissions": [ ... ],
//!       "x-town-muni-arbiter": {
//!         "policy": "package arbiter\ndefault allow := false\nallow if ..."
//!       }
//!     }
//!   }
//! }
//! ```
//!
//! Lexicon definition objects are plain JSON objects whose consumers ignore
//! keys they do not understand, so the extension rides alongside the standard
//! `permission-set` fields without a schema change. This is a documented
//! arbiter-side convention: `defs.main["x-town-muni-arbiter"]` is an object
//! whose `policy` field is the Rego source of the scope policy (compiled with
//! no host functions; see [`ScopePolicy`]).
//!
//! # Resolution mechanism (atproto lexicon publication spec)
//!
//! Given a scope NSID prefix, the lexicon document is resolved exactly as the
//! atproto lexicon publication spec describes for any NSID:
//!
//! 1. **Authority**: all NSID segments except the final name segment, reversed
//!    (`community.lexicon.authCalendar` → authority `lexicon.community`).
//! 2. **DNS TXT**: query `_lexicon.<authority>` for TXT records; the value
//!    starting with `did=` names the DID authorized to publish under the
//!    authority. Zero records, or several *distinct* `did=` values, is a
//!    resolution failure.
//! 3. **DID → PDS**: resolve the publisher DID document (shared identity
//!    resolver) and take its `#atproto_pds` service endpoint.
//! 4. **Record fetch**: `com.atproto.repo.getRecord` with
//!    `repo=<publisher did>`, `collection=com.atproto.lexicon.schema`,
//!    `rkey=<the full NSID>` — the record *is* the lexicon document, and its
//!    `id` must equal the requested NSID (a defense-in-depth identity check).
//! 5. **Extract + compile**: pull `defs.main["x-town-muni-arbiter"].policy`
//!    and compile it as a [`ScopePolicy`]. A missing embedding or a policy
//!    that fails to compile marks the scope unusable.
//!
//! # Caching
//!
//! Resolved + compiled permission sets are cached by NSID for
//! [`SCOPE_CACHE_TTL`] (24h): a cached compiled policy is trusted for up to 24
//! hours ("stale-usable"), after which the next request re-resolves and
//! recompiles. Resolution or compilation failures are **never** cached — the
//! scope is treated as unusable and every request for it is denied (with the
//! error text) until a fresh resolution succeeds. Fail-closed by design: a
//! permission set that cannot be resolved right now does not grant access.

use std::sync::{Arc, LazyLock};

use crate::resolver::IdentityResolverExt;

use anyhow::{Context, Result};
use arbiter_core::arbiter::ScopePolicy;
use async_trait::async_trait;
use atproto_identity::resolve::HickoryDnsResolver;
use atproto_identity::traits::{DnsResolver, IdentityResolver};
use moka::future::Cache;
use serde_json::Value;

/// Collection holding published lexicon documents. The record key is the
/// lexicon NSID; the record value is the lexicon document itself.
pub const LEXICON_COLLECTION: &str = "com.atproto.lexicon.schema";

/// Custom key under a lexicon's `defs.main` carrying the embedded arbiter
/// scope policy (`{ "policy": "<rego>" }`).
pub const ARBITER_DEF_KEY: &str = "x-town-muni-arbiter";

/// How long a resolved + compiled permission set stays trusted (see the
/// module docs for the caching model).
const SCOPE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Shared DNS resolver for `_lexicon.<authority>` TXT lookups. Handle/identity
/// resolution uses its own resolver; this one exists solely for the lexicon
/// publication chain.
static LEXICON_DNS: LazyLock<Arc<dyn DnsResolver>> =
    LazyLock::new(|| Arc::new(HickoryDnsResolver::create_resolver(&[])));

/// Source of permission-set lexicon documents. Injectable so tests can serve
/// documents from a mock instead of walking DNS + DID resolution.
#[async_trait]
pub trait LexiconSource: Send + Sync {
    /// Fetch the lexicon document for `nsid`. Errors when the document cannot
    /// be resolved (unknown authority, no publisher designated, record absent).
    async fn fetch_lexicon(&self, nsid: &str) -> Result<Value>;
}

/// Resolver turning a scope NSID into a compiled, request-pure
/// [`ScopePolicy`], with a 24h NSID-keyed cache.
pub struct ScopeResolver {
    source: Arc<dyn LexiconSource>,
    cache: Cache<String, Arc<ScopePolicy>>,
}

impl ScopeResolver {
    /// Build a resolver over `source`.
    pub fn new(source: Arc<dyn LexiconSource>) -> Self {
        Self {
            source,
            cache: Cache::builder()
                .max_capacity(1024)
                .time_to_live(SCOPE_CACHE_TTL)
                .build(),
        }
    }

    /// The compiled scope policy for `nsid` (a scope prefix, e.g.
    /// `community.lexicon.authCalendar`).
    ///
    /// Errors describe *why the scope is unusable* — unresolvable lexicon,
    /// missing embedded policy, or a policy that fails to compile. Callers
    /// deny the request (403) with this text; nothing is cached on failure.
    pub async fn scope_policy(&self, nsid: &str) -> Result<Arc<ScopePolicy>> {
        if let Some(policy) = self.cache.get(nsid).await {
            return Ok(policy);
        }
        let doc = self
            .source
            .fetch_lexicon(nsid)
            .await
            .with_context(|| format!("resolving permission-set lexicon for `{nsid}`"))?;
        let source = embedded_policy(&doc)
            .with_context(|| format!("extracting embedded arbiter policy from `{nsid}`"))?;
        let policy = Arc::new(ScopePolicy::new(&source).with_context(|| {
            format!("compiling embedded scope policy for `{nsid}`")
        })?);
        self.cache.insert(nsid.to_string(), policy.clone()).await;
        Ok(policy)
    }
}

/// Production [`LexiconSource`]: walks the lexicon publication chain
/// (authority TXT → publisher DID → PDS → `com.atproto.lexicon.schema`
/// record).
pub struct AtprotoLexiconSource {
    resolver: Arc<dyn IdentityResolver>,
}

impl AtprotoLexiconSource {
    pub fn new(resolver: Arc<dyn IdentityResolver>) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl LexiconSource for AtprotoLexiconSource {
    async fn fetch_lexicon(&self, nsid: &str) -> Result<Value> {
        // 1. Authority: all NSID segments except the final name segment,
        //    reversed. `community.lexicon.authCalendar` -> `lexicon.community`.
        let authority = nsid_authority(nsid)?;

        // 2. The authority's `_lexicon.` TXT record names the publisher DID.
        let txts = LEXICON_DNS
            .resolve_txt(&format!("_lexicon.{authority}"))
            .await
            .context("resolving _lexicon TXT records")?;
        let publisher = publisher_from_txt(&txts)?;

        // 3. Publisher DID -> PDS (`#atproto_pds` from its DID document).
        let pds = self
            .resolver
            .resolve_pds_endpoint(&publisher)
            .await
            .map_err(|e| anyhow::anyhow!("resolving lexicon publisher `{publisher}`: {e:#}"))?;

        // 4. Fetch the lexicon record (rkey = the NSID) from the publisher's
        //    PDS. Unauthenticated: lexicon documents are public records.
        let api = crate::policy::pds_read_client(&pds)?;
        let params = atrium_api::com::atproto::repo::get_record::ParametersData {
            cid: None,
            collection: LEXICON_COLLECTION
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid lexicon collection NSID: {e}"))?,
            repo: publisher
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid lexicon publisher `{publisher}`: {e}"))?,
            rkey: nsid
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid lexicon rkey `{nsid}`: {e}"))?,
        }
        .into();
        let output = api
            .service
            .com
            .atproto
            .repo
            .get_record(params)
            .await
            .with_context(|| format!("fetching lexicon record {LEXICON_COLLECTION}/{nsid}"))?;
        let doc = serde_json::to_value(&output.data.value)
            .context("decoding lexicon record value")?;
        check_lexicon_identity(&doc, nsid)?;
        Ok(doc)
    }
}

/// Defense-in-depth identity check on a fetched lexicon document: it must
/// identify as the requested NSID via its own `id` field, not merely arrive
/// at the right (repo, rkey). Any mismatch is a resolution failure
/// (fail-closed).
fn check_lexicon_identity(doc: &Value, nsid: &str) -> Result<()> {
    if doc.get("id").and_then(Value::as_str) != Some(nsid) {
        anyhow::bail!("lexicon document `id` does not match requested NSID `{nsid}`");
    }
    Ok(())
}

/// The lexicon authority for `nsid`: all segments except the final name
/// segment, reversed.
///
/// `community.lexicon.authCalendar` → `lexicon.community`,
/// `com.example.foo.getBar` → `example.com`. An NSID needs at least three
/// segments (two authority segments + the name) for an authority to exist.
pub fn nsid_authority(nsid: &str) -> Result<String> {
    let segments: Vec<&str> = nsid.split('.').collect();
    if segments.len() < 3 || segments.iter().any(|s| s.is_empty()) {
        return Err(anyhow::anyhow!(
            "invalid lexicon NSID `{nsid}` (need at least three non-empty segments)"
        ));
    }
    let mut authority: Vec<&str> = segments[..segments.len() - 1].to_vec();
    authority.reverse();
    Ok(authority.join("."))
}

/// The publisher DID from `_lexicon.<authority>` TXT records: the single
/// distinct `did=...` value. TXT record ordering is arbitrary, so duplicate
/// identical values collapse regardless of where they appear; zero records,
/// or several *distinct* DIDs, is a resolution failure (per the spec a
/// conformant resolver must not guess).
fn publisher_from_txt(txts: &[String]) -> Result<String> {
    let mut dids: Vec<&str> = txts
        .iter()
        .filter_map(|t| t.strip_prefix("did="))
        .collect();
    // `dedup` only collapses consecutive duplicates and TXT record ordering
    // is arbitrary: sort first so repeated identical values collapse wherever
    // they appear, while distinct DIDs still fail closed.
    dids.sort_unstable();
    dids.dedup();
    match dids.as_slice() {
        [] => Err(anyhow::anyhow!(
            "authority has no `_lexicon` TXT record with a `did=` value"
        )),
        [did] => Ok(did.to_string()),
        _ => Err(anyhow::anyhow!(
            "authority has conflicting `_lexicon` TXT records naming multiple DIDs"
        )),
    }
}

/// Extract the embedded arbiter scope policy source from a lexicon document:
/// `defs.main["x-town-muni-arbiter"].policy` (see the module docs for the
/// convention). Missing or non-string → unusable scope.
fn embedded_policy(doc: &Value) -> Result<String> {
    doc.get("defs")
        .and_then(|defs| defs.get("main"))
        .and_then(|main| main.get(ARBITER_DEF_KEY))
        .and_then(|ext| ext.get("policy"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "lexicon document has no `defs.main.{ARBITER_DEF_KEY}.policy` string"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_is_reverse_dns_of_all_but_last_segment() {
        assert_eq!(
            nsid_authority("community.lexicon.authCalendar").unwrap(),
            "lexicon.community"
        );
        assert_eq!(
            nsid_authority("com.example.foo.getBar").unwrap(),
            "foo.example.com"
        );
        assert_eq!(
            nsid_authority("app.bsky.feed.post").unwrap(),
            "feed.bsky.app"
        );
        // Four-segment authorities reverse fully.
        assert_eq!(nsid_authority("a.b.c.d.name").unwrap(), "d.c.b.a");
    }

    #[test]
    fn authority_requires_three_segments() {
        assert!(nsid_authority("com.example").is_err());
        assert!(nsid_authority("onlyone").is_err());
        assert!(nsid_authority("").is_err());
    }

    #[test]
    fn publisher_from_txt_picks_the_single_did() {
        let txts = vec!["did=did:plc:abc".to_string(), "v=1".to_string()];
        assert_eq!(publisher_from_txt(&txts).unwrap(), "did:plc:abc");
        // Duplicated identical values are fine (multi-string TXT records), and
        // duplicates need not be adjacent — TXT record ordering is arbitrary.
        let dup = vec!["did=did:plc:abc".to_string(), "did=did:plc:abc".to_string()];
        assert_eq!(publisher_from_txt(&dup).unwrap(), "did:plc:abc");
        let non_adjacent = vec![
            "did=did:plc:abc".to_string(),
            "v=1".to_string(),
            "did=did:plc:abc".to_string(),
        ];
        assert_eq!(publisher_from_txt(&non_adjacent).unwrap(), "did:plc:abc");
    }

    #[test]
    fn publisher_from_txt_fails_closed() {
        assert!(publisher_from_txt(&[]).is_err());
        assert!(publisher_from_txt(&["v=1".to_string()]).is_err());
        let conflicting = vec![
            "did=did:plc:abc".to_string(),
            "did=did:plc:def".to_string(),
        ];
        assert!(publisher_from_txt(&conflicting).is_err());
        // Distinct DIDs still conflict even when separated by other records.
        let non_adjacent_conflict = vec![
            "did=did:plc:abc".to_string(),
            "v=1".to_string(),
            "did=did:plc:def".to_string(),
        ];
        assert!(publisher_from_txt(&non_adjacent_conflict).is_err());
    }

    #[test]
    fn embedded_policy_is_read_from_defs_main() {
        let doc = serde_json::json!({
            "lexicon": 1,
            "id": "community.lexicon.authCalendar",
            "defs": {
                "main": {
                    "type": "permission-set",
                    "permissions": [],
                    "x-town-muni-arbiter": {
                        "policy": "package arbiter\ndefault allow := false"
                    },
                }
            }
        });
        assert_eq!(
            embedded_policy(&doc).unwrap(),
            "package arbiter\ndefault allow := false"
        );
    }

    #[test]
    fn embedded_policy_missing_or_malformed_is_unusable() {
        // No extension key at all.
        let bare = serde_json::json!({ "lexicon": 1, "defs": { "main": { "type": "permission-set" } } });
        assert!(embedded_policy(&bare).is_err());
        // Extension present but `policy` not a string.
        let wrong_type = serde_json::json!({
            "defs": { "main": { "x-town-muni-arbiter": { "policy": 7 } } }
        });
        assert!(embedded_policy(&wrong_type).is_err());
    }

    /// A resolved permission set compiles through the pure scope-policy
    /// constructor; malformed Rego marks the scope unusable.
    #[test]
    fn embedded_policy_compiles_as_scope_policy() {
        let doc = serde_json::json!({
            "defs": { "main": { "x-town-muni-arbiter": { "policy":
                "package arbiter\ndefault allow := false\nallow if input.method == \"GET\"",
            } } }
        });
        let src = embedded_policy(&doc).unwrap();
        assert!(ScopePolicy::new(&src).is_ok());
        let broken = embedded_policy(&serde_json::json!({
            "defs": { "main": { "x-town-muni-arbiter": { "policy": "package arbiter\nthis is not rego" } } }
        }))
        .unwrap();
        assert!(ScopePolicy::new(&broken).is_err());
    }

    /// A fetched document whose `id` does not match the requested NSID (or
    /// that lacks one entirely) is rejected before it can be served.
    #[test]
    fn lexicon_identity_check_rejects_mismatched_id() {
        let mismatched = serde_json::json!({
            "lexicon": 1,
            "id": "community.lexicon.other",
            "defs": { "main": {} }
        });
        let err = check_lexicon_identity(&mismatched, "community.lexicon.authCalendar")
            .unwrap_err();
        assert!(err.to_string().contains("does not match requested NSID"));
        // A document without an `id` fails too.
        assert!(check_lexicon_identity(&serde_json::json!({ "lexicon": 1 }), "x.y.z").is_err());
        // The matching document passes.
        let ok = serde_json::json!({ "lexicon": 1, "id": "x.y.z" });
        assert!(check_lexicon_identity(&ok, "x.y.z").is_ok());
    }
}