//! Durable storage for PDS credentials of accounts the arbiter server has
//! created or imported (SERVER_PLAN.md §5).

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Credentials for acting as a stewarded account against its PDS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdsCredentials {
    pub pds_url: String,
    pub password: String,
}

/// Durable store of per-DID PDS credentials.
///
/// The arbiter server holds credentials for the accounts it created (random
/// password) or imported (app password), so it can authenticate as the
/// stewarded account when proxying XRPC requests and writing policy records.
///
/// Implementations: [`MemoryCredentialStore`] (dev, JSON-file backed). A Turso
/// backend lives in `storage.rs`. **Encryption at rest is required** for the
/// password field; the in-memory store does not encrypt.
#[async_trait]
pub trait CredentialStore: Send + Sync {
    async fn store(&self, did: String, creds: PdsCredentials) -> Result<()>;
    async fn get(&self, did: &str) -> Result<Option<PdsCredentials>>;
    async fn remove(&self, did: &str) -> Result<()>;
    async fn list(&self) -> Result<Vec<(String, PdsCredentials)>>;
}

/// Simple in-memory store, optionally persisted to a JSON file. No encryption.
pub struct MemoryCredentialStore {
    inner: Mutex<HashMap<String, PdsCredentials>>,
    path: Option<PathBuf>,
}

impl MemoryCredentialStore {
    pub fn new(data_dir: PathBuf) -> Self {
        let path = data_dir.join("credentials.json");
        let inner = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
                Err(_) => HashMap::new(),
            }
        } else {
            HashMap::new()
        };
        Self {
            inner: Mutex::new(inner),
            path: Some(path),
        }
    }

    async fn persist(&self, map: &HashMap<String, PdsCredentials>) -> Result<()> {
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, serde_json::to_string_pretty(map)?)?;
        }
        Ok(())
    }
}

#[async_trait]
impl CredentialStore for MemoryCredentialStore {
    async fn store(&self, did: String, creds: PdsCredentials) -> Result<()> {
        let mut map = self.inner.lock().await;
        map.insert(did, creds);
        self.persist(&map).await
    }

    async fn get(&self, did: &str) -> Result<Option<PdsCredentials>> {
        Ok(self.inner.lock().await.get(did).cloned())
    }

    async fn remove(&self, did: &str) -> Result<()> {
        let mut map = self.inner.lock().await;
        map.remove(did);
        self.persist(&map).await
    }

    async fn list(&self) -> Result<Vec<(String, PdsCredentials)>> {
        Ok(self
            .inner
            .lock()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}