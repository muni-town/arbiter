//! Muni Town Arbiter Server — ATProto XRPC policy proxy.
//!
//! This library crate exposes the server's modules so that integration tests
//! can construct an `AppState` with injected dependencies (e.g. a mock
//! identity resolver) and drive the server end-to-end without real DNS/HTTP.

#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod credstore;
pub mod error;
pub mod handlers;
pub mod jetstream;
pub mod permission_set;
pub mod policy;
pub mod proxy;
pub mod record_store;
pub mod resolver;
pub mod state;
pub mod storage;

use std::sync::{Arc, LazyLock};

use atproto_identity::traits::IdentityResolver;
use clap::Parser;

pub use config::ServerConfig;

/// Parsed server configuration (clap). Available process-wide via `CONFIG`.
pub static CONFIG: LazyLock<ServerConfig> = LazyLock::new(ServerConfig::parse);

/// Shared server state handed to every request handler.
///
/// `resolver` is injected (rather than using the static `RESOLVER`) so that
/// tests can substitute a mock identity resolver. `default_pds` and
/// `invite_code` are injected (rather than read from the static `CONFIG`) so
/// that tests can point provisioning at a mock PDS. `scopes` is injected the
/// same way for permission-set (layer-1 scope gate) resolution.
pub struct AppState {
    pub arbiters: state::ArbiterCollection,
    pub store: Box<dyn credstore::CredentialStore>,
    pub resolver: Arc<dyn IdentityResolver>,
    /// Layer-1 permission-set resolver for scoped endpoints (injectable so
    /// tests can serve lexicon documents from a mock).
    pub scopes: permission_set::ScopeResolver,
    /// Default PDS URL to create new stewarded accounts against.
    pub default_pds: String,
    /// Invite code used to create new stewarded PDS accounts.
    pub invite_code: Option<String>,
}
