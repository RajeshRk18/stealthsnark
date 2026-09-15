//! EMSM server binary.
//!
//! reads configuration from the environment, validate it, load
//! credentials, then hand off to [`stealthsnark::protocol::server::serve`], which
//! owns both listeners, the sweeper, and graceful shutdown.

use stealthsnark::protocol::auth::AuthStore;
use stealthsnark::protocol::config::ServerConfig;
use stealthsnark::protocol::server::{serve, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = ServerConfig::from_env()?;
    config.validate()?;

    let auth = match (&config.auth_file, config.auth_mode.is_enabled()) {
        (Some(path), _) => AuthStore::from_file(path, config.auth_mode)?,
        (None, false) => AuthStore::disabled(),
        // validate already rejects this anyway
        (None, true) => anyhow::bail!("authentication is enabled but no auth file is configured"),
    };

    serve(AppState::with_auth(config, auth)).await
}

/// JSON logs when `STEALTHSNARK_LOG_FORMAT=json`, human-readable otherwise.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("STEALTHSNARK_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let json = std::env::var("STEALTHSNARK_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}
