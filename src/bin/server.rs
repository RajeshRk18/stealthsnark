//! EMSM server binary.
//!
//! Thin wrapper: read configuration from the environment, validate it, hand off
//! to [`stealthsnark::protocol::server::serve`], which owns binding, the session
//! sweeper, and graceful shutdown.

use stealthsnark::protocol::config::ServerConfig;
use stealthsnark::protocol::server::{serve, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    // A bad env var fails startup here rather than surfacing later as odd
    // behaviour under load.
    let config = ServerConfig::from_env()?;
    config.validate()?;

    // `?` rather than `.expect()`: a port clash should print one clear line, not
    // a panic backtrace.
    serve(AppState::new(config)).await
}

/// JSON logs when `STEALTHSNARK_LOG_FORMAT=json`, human-readable otherwise.
///
/// Structured output matters because the handlers emit tracing *fields*
/// (`session`, `elapsed_ms`, `resident_mib`) rather than interpolating values
/// into the message. Fields are queryable; interpolated strings are not.
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
