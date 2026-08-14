//! Muni Town Arbiter Server — binary entry point.
//!
//! See `lib.rs` for the library crate (used by integration tests).

#![forbid(unsafe_code)]

use std::sync::Arc;

use arbiter_server::{
    AppState, CONFIG, credstore::CredentialStore, handlers, jetstream, policy, resolver::RESOLVER,
    state::ArbiterCollection, storage,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    tracing::info!(
        "Starting arbiter server on {} (DID: {})",
        CONFIG.listen,
        CONFIG.server_did
    );

    // Credential store: Turso (local SQLite file).
    let store: Box<dyn CredentialStore> =
        Box::new(storage::TursoCredentialStore::new(CONFIG.db_file.clone())?);

    let state = Arc::new(AppState {
        arbiters: ArbiterCollection::new(),
        store,
        resolver: RESOLVER.clone(),
        default_pds: CONFIG.default_pds.clone(),
        invite_code: CONFIG.invite_code.clone(),
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
