//! Muni Town Arbiter Server — binary entry point.
//!
//! See `SERVER_PLAN.md` for the full design and `lib.rs` for the library
//! crate (used by integration tests).

#![forbid(unsafe_code)]

use std::sync::Arc;

use arbiter_server::{
    credstore::{CredentialStore, MemoryCredentialStore},
    handlers, jetstream, policy, resolver::RESOLVER, state::ArbiterCollection, storage,
    AppState, CONFIG,
};

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
        resolver: RESOLVER.clone(),
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