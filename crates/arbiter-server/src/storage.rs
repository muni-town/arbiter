//! Durable credential store backed by Turso (libSQL).
//!
//! `TursoCredentialStore` implements [`CredentialStore`](crate::credstore::CredentialStore)
//! against a libSQL database — a local file or a remote Turso Cloud database — using the
//! `libsql` crate directly.
//!
//! ## Why `libsql` and not the Toasty ORM?
//!
//! The contract prefers the Toasty ORM, but Toasty's query API takes `&mut Db` on every
//! call, which is incompatible with the `&self`-only [`CredentialStore`] trait (it would
//! force a `Mutex` serializing every credential operation). The contract explicitly allows
//! dropping down to the `libsql` client directly, so we do: a single `libsql::Connection`
//! (cheaply clonable, `&self` query methods) is shared across all operations. The result is
//! the same durable Turso storage with a cleaner fit for the trait.
//!
//! ## Encryption at rest
//!
//! The `password` column is **never** stored in plaintext. Each value is encrypted with
//! AES-256-GCM (authenticated) before being written, and decrypted on read. A fresh random
//! 96-bit nonce is generated per encryption and stored prefixed to the ciphertext (both are
//! base64-encoded into a single TEXT column).
//!
//! The symmetric key is **not** derived or stored here; it is supplied out-of-band via the
//! `ARBITER_CRED_ENCRYPTION_KEY` environment variable, which must hold the *base64* encoding
//! of 32 raw bytes (a 256-bit AES key). Generate one with:
//!
//! ```sh
//! openssl rand -base64 32
//! ```
//!
//! The key is required whenever the Turso store is selected (i.e. when `TURSO_URL` is set);
//! constructing the store without it fails fast. For remote Turso Cloud databases, the auth
//! token is read from `TURSO_AUTH_TOKEN`.

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use tokio::sync::OnceCell;

use aes_gcm::{
    aead::{Aead, Generate, Key, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;

use crate::credstore::{CredentialStore, PdsCredentials};

/// Environment variable holding the base64-encoded 32-byte AES-256 key used to encrypt
/// credentials at rest.
const ENCRYPTION_KEY_ENV: &str = "ARBITER_CRED_ENCRYPTION_KEY";

/// Environment variable holding the Turso Cloud auth token (only needed for `libsql://`
/// remote URLs).
const TURSO_AUTH_TOKEN_ENV: &str = "TURSO_AUTH_TOKEN";

/// AES-GCM nonce length (96 bits / 12 bytes).
const NONCE_LEN: usize = 12;

/// Schema for the credentials table. `password` holds
/// `base64(nonce || ciphertext_with_tag)` — never plaintext.
const SCHEMA_SQL: &str = "CREATE TABLE IF NOT EXISTS arbiter_credentials (\n\
    did       TEXT PRIMARY KEY NOT NULL,\n\
    pds_url   TEXT NOT NULL,\n\
    password  TEXT NOT NULL\n\
);";

/// Upsert a credential row, keyed by DID.
const UPSERT_SQL: &str =
    "INSERT INTO arbiter_credentials (did, pds_url, password) VALUES (?, ?, ?)\n\
     ON CONFLICT(did) DO UPDATE SET pds_url = excluded.pds_url, password = excluded.password";

/// Durable, encrypted-at-rest credential store backed by a Turso/libSQL database.
///
/// Construct with [`TursoCredentialStore::new`]; the choice between this and the in-memory
/// store is wired in `main.rs` based on `CONFIG.turso_url`.
pub struct TursoCredentialStore {
    /// libSQL database URL. A local file path (e.g. `./data/creds.db`) or a remote scheme
    /// (`libsql://`, `https://`, `http://`).
    url: String,
    /// Turso Cloud auth token, read from `TURSO_AUTH_TOKEN`. Only used for remote URLs.
    token: Option<String>,
    /// AES-256-GCM cipher used to encrypt/decrypt the `password` field at rest.
    cipher: Aes256Gcm,
    /// Lazily established connection. Connect + migrate happens once, on first use.
    conn: OnceCell<libsql::Connection>,
}

impl TursoCredentialStore {
    /// Create a store backed by the libSQL database at `url`.
    ///
    /// Reads the encryption key from `ARBITER_CRED_ENCRYPTION_KEY` (base64 of 32 bytes) and,
    /// for remote Turso URLs, the auth token from `TURSO_AUTH_TOKEN`. The actual connection
    /// and table migration are deferred to the first credential operation (they are async and
    /// the constructor is sync), so misconfiguration surfaces on first use.
    pub fn new(url: String) -> Result<Self> {
        let key_bytes = load_encryption_key()?;
        if key_bytes.len() != 32 {
            bail!(
                "`{ENCRYPTION_KEY_ENV}` must decode to exactly 32 bytes (AES-256); got {} \
                 bytes. Generate one with `openssl rand -base64 32`.",
                key_bytes.len()
            );
        }
        #[allow(deprecated)] // hybrid_array's TryFrom replacement targets refs; from_slice is simplest for an owned key schedule.
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

        let token = std::env::var(TURSO_AUTH_TOKEN_ENV).ok();

        Ok(Self {
            url,
            token,
            cipher,
            conn: OnceCell::new(),
        })
    }

    /// Lazily connect (and run the `CREATE TABLE IF NOT EXISTS` migration) once, returning the
    /// shared connection. Subsequent calls reuse the cached connection.
    async fn conn(&self) -> Result<&libsql::Connection> {
        self.conn
            .get_or_try_init(|| {
                let url = self.url.clone();
                let token = self.token.clone();
                async move {
                    let db = if is_remote_url(&url) {
                        libsql::Builder::new_remote(url, token.unwrap_or_default())
                            .build()
                            .await
                            .context("failed to connect to remote Turso database")?
                    } else {
                        libsql::Builder::new_local(url)
                            .build()
                            .await
                            .context("failed to open local libSQL database file")?
                    };
                    let conn = db.connect()?;
                    conn.execute(SCHEMA_SQL, ())
                        .await
                        .context("failed to create credentials schema")?;
                    Ok::<_, anyhow::Error>(conn)
                }
            })
            .await
    }

    /// Encrypt `plaintext` into `nonce || ciphertext+tag`, returned as a single byte vector.
    fn seal(&self, plaintext: &str) -> Result<Vec<u8>> {
        let nonce = Nonce::generate();
        let ct = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow!("aes-gcm encrypt failed: {e}"))?;
        let mut out = nonce.as_slice().to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a `nonce || ciphertext+tag` blob (as produced by [`Self::seal`]).
    fn open(&self, blob: &[u8]) -> Result<String> {
        if blob.len() < NONCE_LEN {
            bail!("encrypted password blob is too short to contain a nonce");
        }
        #[allow(deprecated)] // see note on the key construction above.
        let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
        let pt = self
            .cipher
            .decrypt(nonce, &blob[NONCE_LEN..])
            .map_err(|e| anyhow!("aes-gcm decrypt failed: {e}"))?;
        String::from_utf8(pt).context("decrypted password is not valid UTF-8")
    }
}

#[async_trait]
impl CredentialStore for TursoCredentialStore {
    async fn store(&self, did: String, creds: PdsCredentials) -> Result<()> {
        let conn = self.conn().await?;
        let sealed = self.seal(&creds.password)?;
        let password = base64::engine::general_purpose::STANDARD.encode(&sealed);
        conn.execute(UPSERT_SQL, libsql::params![did, creds.pds_url, password])
            .await
            .context("failed to store credentials")?;
        Ok(())
    }

    async fn get(&self, did: &str) -> Result<Option<PdsCredentials>> {
        let conn = self.conn().await?;
        let mut rows = conn
            .query(
                "SELECT pds_url, password FROM arbiter_credentials WHERE did = ?",
                libsql::params![did],
            )
            .await
            .context("failed to query credentials")?;
        match rows.next().await? {
            Some(row) => {
                let pds_url: String = row.get(0)?;
                let password_b64: String = row.get(1)?;
                let sealed = base64::engine::general_purpose::STANDARD
                    .decode(password_b64)
                    .context("stored password is not valid base64")?;
                let password = self.open(&sealed)?;
                Ok(Some(PdsCredentials { pds_url, password }))
            }
            None => Ok(None),
        }
    }

    async fn remove(&self, did: &str) -> Result<()> {
        let conn = self.conn().await?;
        conn.execute(
            "DELETE FROM arbiter_credentials WHERE did = ?",
            libsql::params![did],
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
            let password_b64: String = row.get(2)?;
            let sealed = base64::engine::general_purpose::STANDARD
                .decode(password_b64)
                .context("stored password is not valid base64")?;
            let password = self.open(&sealed)?;
            out.push((did, PdsCredentials { pds_url, password }));
        }
        Ok(out)
    }
}

/// Load and base64-decode the encryption key from `ARBITER_CRED_ENCRYPTION_KEY`.
fn load_encryption_key() -> Result<Vec<u8>> {
    let raw = std::env::var(ENCRYPTION_KEY_ENV).with_context(|| {
        format!(
            "credential encryption key is required when using the Turso store: set the \
             `{ENCRYPTION_KEY_ENV}` env var to the base64 encoding of 32 random bytes \
             (`openssl rand -base64 32`)"
        )
    })?;
    base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .with_context(|| format!("`{ENCRYPTION_KEY_ENV}` is not valid base64"))
}

/// Treat `libsql://`, `https://`, and `http://` URLs as remote Turso databases; anything else
/// is a local libSQL file path.
fn is_remote_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("libsql://")
        || lower.starts_with("https://")
        || lower.starts_with("http://")
}