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
    #[arg(
        short,
        long = "server-did",
        env = "DID",
        default_value = "did:web:localhost:8203"
    )]
    pub server_did: String,

    /// Jetstream hostname (host[:port]) to subscribe to for policy/service-record
    /// hot reload and auto-delete.
    #[arg(
        long = "jetstream-host",
        env = "JETSTREAM_HOST",
        default_value = "jetstream.atproto.tools"
    )]
    pub jetstream_host: String,

    /// Default PDS URL to create new stewarded accounts against.
    #[arg(
        long = "default-pds",
        env = "DEFAULT_PDS",
        default_value = "http://localhost:8082"
    )]
    pub default_pds: String,

    /// Invite code used to create new stewarded PDS accounts.
    #[arg(long = "invite-code", env = "INVITE_CODE")]
    pub invite_code: Option<String>,

    /// PLC directory hostname for DID resolution.
    #[arg(
        long = "plc-hostname",
        env = "PLC_HOSTNAME",
        default_value = "plc.directory"
    )]
    pub plc_hostname: String,

    /// Local Turso database file for the credential store (e.g. `./data/arbiter-server.db`).
    #[arg(
        long = "db-file",
        env = "DB_FILE",
        default_value = "./data/arbiter-server.db"
    )]
    pub db_file: String,

    /// Handle domain suffix for newly created stewarded accounts
    /// (e.g. `.muni.town` → handle `arbiter-<random>.muni.town`).
    #[arg(
        long = "handle-suffix",
        env = "HANDLE_SUFFIX",
        default_value = ".muni.town"
    )]
    pub handle_suffix: String,

    /// Max `createArbiter` calls allowed per caller per window. Set to 0 to
    /// disallow account creation entirely. This is deliberately aggressive by
    /// default (bulk arbiter creation is not allowed unless the admin raises
    /// it explicitly).
    #[arg(
        long = "create-arbiter-rate-limit",
        env = "CREATE_ARBITER_RATE_LIMIT",
        default_value_t = 1
    )]
    pub create_arbiter_rate_limit: u64,

    /// The rate-limit window for `createArbiter` (seconds).
    #[arg(
        long = "create-arbiter-rate-window-secs",
        env = "CREATE_ARBITER_RATE_WINDOW_SECS",
        default_value_t = 60
    )]
    pub create_arbiter_rate_window_secs: u64,
}
