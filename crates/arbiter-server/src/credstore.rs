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
    /// Bootstrap designation of the recovery-admin DID, recorded at
    /// provisioning/import time (the caller). The authoritative recovery admin
    /// is the `did` field of the account's `town.muni.arbiter.recovery/self`
    /// record, which the server re-reads on every `installPolicy` call; this
    /// stored copy exists only so `repair_provisioning` can (re)write that
    /// record for half-provisioned accounts.
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
    /// Insert credentials only if no row exists for `did`. Returns `true` if
    /// the row was inserted, `false` if a row already existed (no-op). Used to
    /// enforce the `ErrArbiterAlreadyExists` contract atomically against
    /// concurrent imports.
    async fn store_if_absent(&self, did: String, creds: PdsCredentials) -> Result<bool>;
    async fn get(&self, did: &str) -> Result<Option<PdsCredentials>>;
    async fn remove(&self, did: &str) -> Result<()>;
    async fn list(&self) -> Result<Vec<(String, PdsCredentials)>>;
    /// Mark an account's bootstrap provisioning as complete (service + recovery
    /// records written).
    async fn mark_provisioned(&self, did: &str) -> Result<()>;
}
