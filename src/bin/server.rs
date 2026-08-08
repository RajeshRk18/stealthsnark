//! EMSM server binary.
//!
//! Thin wrapper: read configuration from the environment, validate it, load
//! credentials, then hand off to [`stealthsnark::protocol::server::serve`], which
//! owns both listeners, the sweeper, and graceful shutdown.

use stealthsnark::protocol::auth::AuthStore;
use stealthsnark::protocol::config::ServerConfig;
use stealthsnark::protocol::server::{serve, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    // A bad environment variable fails startup here, rather than showing up later
    // as odd behaviour under load.
    let config = ServerConfig::from_env()?;
    config.validate()?;

    // Credentials load before the listener binds, so a malformed auth file never
    // leaves a port open with nothing behind it.
    let auth = match (&config.auth_file, config.auth_mode.is_enabled()) {
        (Some(path), _) => AuthStore::from_file(path, config.auth_mode)?,
        (None, false) => AuthStore::disabled(),
        // `validate` already rejects this pair; kept as a guard, not a fallback.
        (None, true) => anyhow::bail!("authentication is enabled but no auth file is configured"),
    };

    // `?` rather than `.expect()`: a port clash should print one clear line, not
    // a panic backtrace.
    serve(AppState::with_auth(config, auth)).await
}

/// JSON logs when `STEALTHSNARK_LOG_FORMAT=json`, human-readable otherwise.
///
/// Structured output matters because the handlers emit tracing *fields*
/// (`principal`, `session`, `elapsed_ms`) rather than interpolating values into
/// the message. Fields are queryable; interpolated strings are not.
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
