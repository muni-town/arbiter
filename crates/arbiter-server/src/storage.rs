//! Durable credential store backed by Turso (embedded SQLite engine).
//!
//! `TursoCredentialStore` implements [`CredentialStore`](crate::credstore::CredentialStore)
//! against a local Turso database file using the `turso` crate (the successor to `libsql`).
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
/// The PDS endpoint is resolved from the DID doc. `recovery_admin` is the
/// bootstrap designation of the recovery admin (the provisioning caller); the
/// authoritative admin is the `town.muni.arbiter.recovery/self` record, and
/// this value only repairs a half-provisioned account by re-writing it.
/// `provisioned` distinguishes a partially-provisioned account (bootstrap
/// records not yet written) from a fully-provisioned one (whose service record
/// disappearing later is a deliberate auto-delete, not to be repaired).
const SCHEMA_SQL: &str = "CREATE TABLE IF NOT EXISTS arbiter_credentials (\n\
    did              TEXT PRIMARY KEY NOT NULL,\n\
    password         TEXT NOT NULL,\n\
    recovery_admin   TEXT NOT NULL,\n\
    provisioned      INTEGER NOT NULL DEFAULT 0\n\
);";

/// Upsert a credential row, keyed by DID.
const UPSERT_SQL: &str = "INSERT INTO arbiter_credentials (did, password, recovery_admin, provisioned)\n\
     VALUES (?, ?, ?, ?)\n\
     ON CONFLICT(did) DO UPDATE SET\n\
       password = excluded.password,\n\
       recovery_admin = excluded.recovery_admin,\n\
       provisioned = excluded.provisioned";

/// Insert a credential row only if no row exists for the DID.
const INSERT_IF_ABSENT_SQL: &str = "INSERT INTO arbiter_credentials (did, password, recovery_admin, provisioned)\
     VALUES (?, ?, ?, ?)\
     ON CONFLICT(did) DO NOTHING";

/// Mark an account as fully provisioned (bootstrap records written).
const MARK_PROVISIONED_SQL: &str = "UPDATE arbiter_credentials SET provisioned = 1 WHERE did = ?";

/// Durable credential store backed by a local Turso database file.
///
/// Construct with [`TursoCredentialStore::new`]; it is the sole
/// [`CredentialStore`] implementation and is wired in `main.rs` from
/// `CONFIG.turso_url`.
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
        conn.execute(
            UPSERT_SQL,
            turso::params![
                did,
                creds.password,
                creds.recovery_admin,
                creds.provisioned as i64
            ],
        )
        .await
        .context("failed to store credentials")?;
        Ok(())
    }

    async fn store_if_absent(&self, did: String, creds: PdsCredentials) -> Result<bool> {
        let conn = self.conn().await?;
        let affected = conn
            .execute(
                INSERT_IF_ABSENT_SQL,
                turso::params![
                    did,
                    creds.password,
                    creds.recovery_admin,
                    creds.provisioned as i64
                ],
            )
            .await
            .context("failed to insert credentials if absent")?;
        Ok(affected > 0)
    }

    async fn get(&self, did: &str) -> Result<Option<PdsCredentials>> {
        let conn = self.conn().await?;
        let mut rows = conn
            .query(
                "SELECT password, recovery_admin, provisioned FROM arbiter_credentials WHERE did = ?",
                turso::params![did],
            )
            .await
            .context("failed to get credentials")?;
        match rows.next().await? {
            Some(row) => {
                let password: String = row.get(0)?;
                let recovery_admin: String = row.get(1)?;
                let provisioned: i64 = row.get(2)?;
                Ok(Some(PdsCredentials {
                    password,
                    recovery_admin,
                    provisioned: provisioned != 0,
                }))
            }
            None => Ok(None),
        }
    }

    async fn mark_provisioned(&self, did: &str) -> Result<()> {
        let conn = self.conn().await?;
        conn.execute(MARK_PROVISIONED_SQL, turso::params![did])
            .await
            .context("failed to mark provisioned")?;
        Ok(())
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
                "SELECT did, password, recovery_admin, provisioned FROM arbiter_credentials",
                (),
            )
            .await
            .context("failed to list credentials")?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            let did: String = row.get(0)?;
            let password: String = row.get(1)?;
            let recovery_admin: String = row.get(2)?;
            let provisioned: i64 = row.get(3)?;
            out.push((
                did,
                PdsCredentials {
                    password,
                    recovery_admin,
                    provisioned: provisioned != 0,
                },
            ));
        }
        Ok(out)
    }
}
