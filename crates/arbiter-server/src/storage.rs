//! Durable credential store backed by Turso (embedded SQLite engine).
//!
//! `TursoCredentialStore` implements [`CredentialStore`](crate::credstore::CredentialStore)
//! against a local Turso database file using the `turso` crate (the successor to `libsql`).
//!
//! ## Local-only, no sync
//!
//! This store is a plain local file database. The `turso` crate's remote/cloud sync
//! (`sync` feature) is deliberately **not** enabled, so nothing is pushed or pulled to
//! Turso Cloud. If you inspect the dependency graph, the sync engine types are absent.
//! The server is single-instance (§5/§11 of SERVER_PLAN.md), so a local replica is the
//! right model — no multi-writer coordination to reason about yet.
//!
//! ## Why `turso` and not the Toasty ORM?
//!
//! The contract prefers the Toasty ORM, but Toasty's query API takes `&mut Db` on every
//! call, which is incompatible with the `&self`-only [`CredentialStore`] trait (it would
//! force a `Mutex` serializing every credential operation). Dropping down to the DB
//! client directly, a single `turso::Connection` (cheaply clonable, `&self` query
//! methods) is shared across all operations.
//!
//! ## No encryption at rest (for now)
//!
//! Passwords are stored **in plaintext** in the `password` column. This is a deliberate
//! trade for debuggability: with no field-level AES-GCM, the DB file is directly
//! inspectable and the `ARBITER_CRED_ENCRYPTION_KEY` env var is unnecessary. The `turso`
//! crate supports whole-database encryption at rest (`Builder::with_encryption`), which
//! would restore confidentiality with less code than field-level encryption — revisit
//! there when the credential store's protection matters more than introspection.

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::sync::OnceCell;

use crate::credstore::{CredentialStore, PdsCredentials};

/// Schema for the credentials table. `password` is stored in plaintext (see module docs).
const SCHEMA_SQL: &str = "CREATE TABLE IF NOT EXISTS arbiter_credentials (\n\
    did       TEXT PRIMARY KEY NOT NULL,\n\
    pds_url   TEXT NOT NULL,\n\
    password  TEXT NOT NULL\n\
);";

/// Upsert a credential row, keyed by DID.
const UPSERT_SQL: &str =
    "INSERT INTO arbiter_credentials (did, pds_url, password) VALUES (?, ?, ?)\n\
     ON CONFLICT(did) DO UPDATE SET pds_url = excluded.pds_url, password = excluded.password";

/// Durable credential store backed by a local Turso database file.
///
/// Construct with [`TursoCredentialStore::new`]; the choice between this and the in-memory
/// store is wired in `main.rs` based on `CONFIG.turso_url`.
pub struct TursoCredentialStore {
    /// Local Turso database file path (e.g. `./data/creds.db`).
    path: String,
    /// Lazily established connection. Open + migrate happens once, on first use.
    conn: OnceCell<turso::Connection>,
}

impl TursoCredentialStore {
    /// Create a store backed by the local Turso database file at `path`.
    ///
    /// The actual open + table migration are deferred to the first credential operation
    /// (they are async and the constructor is sync), so misconfiguration surfaces on
    /// first use.
    pub fn new(path: String) -> Result<Self> {
        Ok(Self {
            path,
            conn: OnceCell::new(),
        })
    }

    /// Lazily open the database file (and run the `CREATE TABLE IF NOT EXISTS` migration)
    /// once, returning the shared connection. Subsequent calls reuse the cached connection.
    async fn conn(&self) -> Result<&turso::Connection> {
        self.conn
            .get_or_try_init(|| {
                let path = self.path.clone();
                async move {
                    let db = turso::Builder::new_local(&path)
                        .build()
                        .await
                        .context("failed to open local Turso database file")?;
                    let conn = db
                        .connect()
                        .context("failed to connect to local Turso database")?;
                    conn.execute(SCHEMA_SQL, ())
                        .await
                        .context("failed to create credentials schema")?;
                    Ok::<_, anyhow::Error>(conn)
                }
            })
            .await
    }
}

#[async_trait]
impl CredentialStore for TursoCredentialStore {
    async fn store(&self, did: String, creds: PdsCredentials) -> Result<()> {
        let conn = self.conn().await?;
        conn.execute(UPSERT_SQL, turso::params![did, creds.pds_url, creds.password])
            .await
            .context("failed to store credentials")?;
        Ok(())
    }

    async fn get(&self, did: &str) -> Result<Option<PdsCredentials>> {
        let conn = self.conn().await?;
        let mut rows = conn
            .query(
                "SELECT pds_url, password FROM arbiter_credentials WHERE did = ?",
                turso::params![did],
            )
            .await
            .context("failed to query credentials")?;
        match rows.next().await? {
            Some(row) => {
                let pds_url: String = row.get(0)?;
                let password: String = row.get(1)?;
                Ok(Some(PdsCredentials { pds_url, password }))
            }
            None => Ok(None),
        }
    }

    async fn remove(&self, did: &str) -> Result<()> {
        let conn = self.conn().await?;
        conn.execute(
            "DELETE FROM arbiter_credentials WHERE did = ?",
            turso::params![did],
        )
        .await
        .context("failed to remove credentials")?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<(String, PdsCredentials)>> {
        let conn = self.conn().await?;
        let mut rows = conn
            .query(
                "SELECT did, pds_url, password FROM arbiter_credentials",
                (),
            )
            .await
            .context("failed to list credentials")?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            let did: String = row.get(0)?;
            let pds_url: String = row.get(1)?;
            let password: String = row.get(2)?;
            out.push((did, PdsCredentials { pds_url, password }));
        }
        Ok(out)
    }
}
