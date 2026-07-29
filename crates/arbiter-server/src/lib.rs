//! Muni Town Arbiter Server — ATProto XRPC policy proxy.
//!
//! See `SERVER_PLAN.md` for the full design.
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
pub mod policy;
pub mod proxy;
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
/// tests can substitute a mock identity resolver.
pub struct AppState {
    pub arbiters: state::ArbiterCollection,
    pub store: Box<dyn credstore::CredentialStore>,
    pub resolver: Arc<dyn IdentityResolver>,
}