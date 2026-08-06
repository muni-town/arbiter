/// Durable storage for PDS credentials of accounts the arbiter server has
/// created or imported.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Credentials for acting as a stewarded account against its PDS.
///
/// The PDS endpoint is *not* stored here — it is always resolved from the
/// account's DID document (`#atproto_pds`), so the DID doc is the single
/// authority for where the account lives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdsCredentials {
    pub password: String,
    /// The recovery-admin DID (`town.muni.arbiter.recovery/self`) designated at
    /// provisioning time (the caller). Persisted so a half-provisioned account
    /// can be repaired at startup / on reconnect without the original caller.
    pub recovery_admin: String,
    /// Whether the `service/self` + `recovery/self` bootstrap records were
    /// successfully written. `false` means the account is only partially
    /// provisioned and should be repaired (bootstrap records re-written) at
    /// startup / on reconnect. A `true` account whose service record later
    /// disappears is a deliberate offboard (auto-delete) and is NOT repaired.
    pub provisioned: bool,
}

/// Durable store of per-DID PDS credentials.
///
/// The arbiter server holds credentials for the accounts it created (random
/// password) or imported (app password), so it can authenticate as the
/// stewarded account when proxying XRPC requests and writing policy records.
///
/// The single implementation is [`TursoCredentialStore`](crate::storage::TursoCredentialStore),
/// backed by a local Turso (SQLite) database file. The password field is not
/// encrypted at rest for now (see `storage.rs` module docs for the tradeoff).
#[async_trait]
pub trait CredentialStore: Send + Sync {
    async fn store(&self, did: String, creds: PdsCredentials) -> Result<()>;
    async fn get(&self, did: &str) -> Result<Option<PdsCredentials>>;
    async fn remove(&self, did: &str) -> Result<()>;
    async fn list(&self) -> Result<Vec<(String, PdsCredentials)>>;
    /// Mark an account's bootstrap provisioning as complete (service + recovery
    /// records written).
    async fn mark_provisioned(&self, did: &str) -> Result<()>;
}
