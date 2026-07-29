//! CLI / environment configuration (clap).

use clap::Parser;

/// Muni Town Arbiter Server — ATProto XRPC policy proxy.
#[derive(Parser, Debug, Clone)]
#[command(name = "arbiter-server", version, about)]
pub struct ServerConfig {
    /// Listen address.
    #[arg(short, long = "listen", env = "LISTEN", default_value = "0.0.0.0:8203")]
    pub listen: String,

    /// This arbiter server's own DID (the `aud` serviceAuth tokens must match).
    #[arg(short, long = "server-did", env = "DID", default_value = "did:web:localhost:8203")]
    pub server_did: String,

    /// Jetstream endpoint (wss) to subscribe to for policy/service-record hot
    /// reload and auto-delete.
    #[arg(long = "jetstream-url", env = "JETSTREAM_URL", default_value = "wss://jetstream.atproto.tools/subscribe")]
    pub jetstream_url: String,

    /// Default PDS URL to create new stewarded accounts against.
    #[arg(long = "default-pds", env = "DEFAULT_PDS", default_value = "http://localhost:8082")]
    pub default_pds: String,

    /// Invite code used to create new stewarded PDS accounts.
    #[arg(long = "invite-code", env = "INVITE_CODE")]
    pub invite_code: Option<String>,

    /// PLC directory hostname for DID resolution.
    #[arg(long = "plc-hostname", env = "PLC_HOSTNAME", default_value = "plc.directory")]
    pub plc_hostname: String,

    /// Data directory for the in-memory/JSON credential store fallback.
    #[arg(long = "data-dir", env = "DATA_DIR", default_value = "./data/arbiters")]
    pub data_dir: std::path::PathBuf,

    /// Turso (libSQL) database URL. If set, the Turso credential store is used;
    /// otherwise the in-memory/JSON store is used.
    #[arg(long = "turso-url", env = "TURSO_URL")]
    pub turso_url: Option<String>,

    /// Handle domain suffix for newly created stewarded accounts
    /// (e.g. `.muni.town` → handle `arbiter-<random>.muni.town`).
    #[arg(long = "handle-suffix", env = "HANDLE_SUFFIX", default_value = ".muni.town")]
    pub handle_suffix: String,
}