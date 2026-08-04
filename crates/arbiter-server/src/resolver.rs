//! atproto identity resolution (DID docs).
//!
//! Shared resolver reused by `auth` (PDS signing key) and `policy`/`handlers`
//! (PDS endpoint resolution).

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use atproto_identity::{
    resolve::{HickoryDnsResolver, InnerIdentityResolver, SharedIdentityResolver},
    traits::IdentityResolver,
};
use moka::future::Cache;

use crate::CONFIG;
use crate::error::AppError;

/// Identity resolver
pub static RESOLVER: LazyLock<Arc<dyn IdentityResolver>> = LazyLock::new(|| {
    let resolver_client = reqwest::Client::builder().use_rustls_tls().build().unwrap();
    let dns_resolver = HickoryDnsResolver::create_resolver(&[]);
    let identity_resolver = SharedIdentityResolver(Arc::new(InnerIdentityResolver {
        dns_resolver: Arc::new(dns_resolver),
        http_client: resolver_client,
        plc_hostname: CONFIG.plc_hostname.clone(),
    }));
    Arc::new(identity_resolver)
});

/// Per-DID cache of resolved `#atproto_pds` endpoints, shared by every caller
/// (proxying and policy loading). Short TTL so a DID doc move is picked up
/// within minutes.
static PDS_CACHE: LazyLock<Cache<String, String>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(5 * 60))
        .build()
});

/// Resolve a DID's `#atproto_pds` service endpoint from its DID document, with
/// a short-lived cache.
///
/// Matches the service id in its canonical fragment form (`#atproto_pds`).
/// Returns [`AppError::MissingPdsEndpoint`] when the DID doc declares no such
/// service.
pub async fn resolve_pds_endpoint(
    resolver: &dyn IdentityResolver,
    did: &str,
) -> Result<String, AppError> {
    if let Some(ep) = PDS_CACHE.get(did).await {
        return Ok(ep);
    }
    let doc = resolver
        .resolve(did)
        .await
        .map_err(|e| AppError::Other(anyhow::anyhow!("resolve {did}: {e:#}")))?;
    let ep = doc
        .service
        .iter()
        .find(|s| s.id == "#atproto_pds")
        .map(|s| s.service_endpoint.clone())
        .ok_or_else(|| AppError::MissingPdsEndpoint(did.to_string()))?;
    PDS_CACHE.insert(did.to_string(), ep.clone()).await;
    Ok(ep)
}
