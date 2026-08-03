//! atproto identity resolution (DID docs).
//!
//! Shared resolver reused by `auth` (PDS signing key) and `policy`/`handlers`
//! (PDS endpoint resolution).

use std::sync::{Arc, LazyLock};

use atproto_identity::{
    resolve::{HickoryDnsResolver, InnerIdentityResolver, SharedIdentityResolver},
    traits::IdentityResolver,
};

use crate::CONFIG;

pub static RESOLVER: LazyLock<Arc<dyn IdentityResolver>> = LazyLock::new(|| {
    // Identity resolver
    let resolver_client = reqwest::Client::builder().use_rustls_tls().build().unwrap();
    let dns_resolver = HickoryDnsResolver::create_resolver(&[]);
    let identity_resolver = SharedIdentityResolver(Arc::new(InnerIdentityResolver {
        dns_resolver: Arc::new(dns_resolver),
        http_client: resolver_client,
        plc_hostname: CONFIG.plc_hostname.clone(),
    }));
    Arc::new(identity_resolver)
});