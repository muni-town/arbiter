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
        long = "turso-url",
        env = "TURSO_URL",
        default_value = "./data/arbiter-server.db"
    )]
    pub turso_url: String,

    /// Handle domain suffix for newly created stewarded accounts
    /// (e.g. `.muni.town` → handle `arbiter-<random>.muni.town`).
    #[arg(
        long = "handle-suffix",
        env = "HANDLE_SUFFIX",
        default_value = ".muni.town"
    )]
    pub handle_suffix: String,
}
