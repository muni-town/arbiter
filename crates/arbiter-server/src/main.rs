//! Muni Town Arbiter Server — ATProto XRPC policy proxy.
//!
//! See `SERVER_PLAN.md` for the full design and
//! `local://arbiter-server-contract.md` for the implementation contract.

#![forbid(unsafe_code)]

use std::sync::{Arc, LazyLock};

mod auth;
mod config;
mod credstore;
mod error;
mod handlers;
mod jetstream;
mod policy;
mod proxy;
mod resolver;
mod state;
mod storage;

use clap::Parser;
use credstore::{CredentialStore, MemoryCredentialStore};
use state::ArbiterCollection;

pub use config::ServerConfig;

/// Parsed server configuration (clap). Available process-wide via `CONFIG`.
pub static CONFIG: LazyLock<ServerConfig> = LazyLock::new(ServerConfig::parse);

/// Shared server state handed to every request handler.
pub struct AppState {
    pub arbiters: ArbiterCollection,
    pub store: Box<dyn CredentialStore>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    tracing::info!(
        "Starting arbiter server on {} (DID: {})",
        CONFIG.listen,
        CONFIG.server_did
    );

    // Credential store: Turso when configured, else the in-memory/JSON store.
    let store: Box<dyn CredentialStore> = match &CONFIG.turso_url {
        Some(url) => Box::new(storage::TursoCredentialStore::new(url.clone())?),
        None => Box::new(MemoryCredentialStore::new(CONFIG.data_dir.clone())),
    };

    let state = Arc::new(AppState {
        arbiters: ArbiterCollection::new(),
        store,
    });

    // Load + onboard every known arbiter (fail-closed per arbiter; un-onboarded
    // DIDs return 503 from `begin_request` until loaded).
    let loader_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = policy::startup_onboard(loader_state).await {
            tracing::error!("startup onboard failed: {e:#}");
        }
    });

    // Watch policy + service-record changes for hot reload / auto-delete.
    let js_state = state.clone();
    tokio::spawn(async move {
        jetstream::subscribe(js_state).await;
    });

    let app = handlers::router(state.clone());
    let listener = tokio::net::TcpListener::bind(&CONFIG.listen).await?;
    tracing::info!("Listening on {}", CONFIG.listen);
    axum::serve(listener, app).await?;
    Ok(())
}