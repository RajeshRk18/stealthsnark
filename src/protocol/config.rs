//! Runtime configuration for the EMSM server.
//!
//! Everything an operator might need to change per-deployment is read from the
//! environment at startup rather than hardcoded, so one binary serves a test
//! harness, a laptop, and a box behind a reverse proxy without a rebuild.
//! Parsing is strict: a typo in an env var fails startup loudly instead of
//! silently falling back to a default that hides the mistake.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

/// Default cap on a single request body.
///
/// This is the setting that decides which circuits the service can actually
/// serve. `/setup` uploads every generator for all five MSMs in one body: a
/// compressed G1 point is 32 bytes and a G2 point 64, so a circuit needing 2^20
/// generators per MSM lands around 192 MiB.
///
/// It is a real tradeoff, not a free knob — the body is buffered in memory
/// before decoding, so worst-case footprint is about
/// `max_body_bytes * max_concurrent_msm`. [`ServerConfig::peak_body_bytes`]
/// reports that product so an operator can see it at startup.
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Configuration for [`crate::protocol::server`].
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Address to bind. Defaults to loopback rather than `0.0.0.0` so an
    /// unauthenticated service is never exposed to the network by accident.
    pub bind_addr: SocketAddr,

    /// Maximum accepted request body. See [`DEFAULT_MAX_BODY_BYTES`].
    pub max_body_bytes: usize,

    /// Maximum number of live sessions. Each session pins its generators in
    /// memory, so without a cap any client can grow the process without bound.
    pub max_sessions: usize,

    /// Idle timeout after which a session is evicted and its generators freed.
    pub session_ttl: Duration,

    /// How often the background sweeper looks for expired sessions. Sessions are
    /// also checked lazily on lookup; the sweeper exists so that an *idle*
    /// server still releases memory.
    pub sweep_interval: Duration,

    /// Maximum number of MSM evaluations running at once.
    ///
    /// Deliberately small. An arkworks MSM is already internally parallel via
    /// rayon, so it saturates the machine on its own; admitting many at once
    /// does not raise throughput, it just multiplies peak memory and makes every
    /// request slower. Excess requests wait up to `admission_wait`, then get a
    /// 503 — far kinder to a client than an eventual timeout.
    pub max_concurrent_msm: usize,

    /// How long a request waits for an MSM slot before being shed with 503.
    pub admission_wait: Duration,

    /// Per-request wall-clock ceiling. Generous by default, because a large
    /// honest MSM legitimately takes minutes.
    pub request_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_sessions: 64,
            session_ttl: Duration::from_secs(30 * 60),
            sweep_interval: Duration::from_secs(60),
            max_concurrent_msm: default_concurrency(),
            admission_wait: Duration::from_secs(30),
            request_timeout: Duration::from_secs(600),
        }
    }
}

/// Half the available cores, clamped to `[1, 4]`.
///
/// Not one-per-core: each MSM fans out over rayon internally, so the useful
/// range for *concurrent* MSMs is small, and the upper clamp keeps peak memory
/// predictable on a many-core box.
fn default_concurrency() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    (cores / 2).clamp(1, 4)
}

impl ServerConfig {
    /// Read configuration from the environment, falling back to [`Default`].
    ///
    /// Every variable is prefixed `STEALTHSNARK_`. A malformed value is an
    /// error, never a silent default.
    pub fn from_env() -> anyhow::Result<Self> {
        let d = Self::default();
        Ok(Self {
            bind_addr: env_or("STEALTHSNARK_BIND", d.bind_addr)?,
            max_body_bytes: env_or("STEALTHSNARK_MAX_BODY_BYTES", d.max_body_bytes)?,
            max_sessions: env_or("STEALTHSNARK_MAX_SESSIONS", d.max_sessions)?,
            session_ttl: env_secs("STEALTHSNARK_SESSION_TTL_SECS", d.session_ttl)?,
            sweep_interval: env_secs("STEALTHSNARK_SWEEP_INTERVAL_SECS", d.sweep_interval)?,
            max_concurrent_msm: env_or("STEALTHSNARK_MAX_CONCURRENT_MSM", d.max_concurrent_msm)?,
            admission_wait: env_secs("STEALTHSNARK_ADMISSION_WAIT_SECS", d.admission_wait)?,
            request_timeout: env_secs("STEALTHSNARK_REQUEST_TIMEOUT_SECS", d.request_timeout)?,
        })
    }

    /// Reject configurations that are unusable.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_concurrent_msm == 0 {
            anyhow::bail!("STEALTHSNARK_MAX_CONCURRENT_MSM must be >= 1");
        }
        if self.max_sessions == 0 {
            anyhow::bail!("STEALTHSNARK_MAX_SESSIONS must be >= 1");
        }
        if self.max_body_bytes == 0 {
            anyhow::bail!("STEALTHSNARK_MAX_BODY_BYTES must be >= 1");
        }
        if self.session_ttl.is_zero() {
            anyhow::bail!("STEALTHSNARK_SESSION_TTL_SECS must be >= 1");
        }
        Ok(())
    }

    /// Worst-case resident bytes from in-flight request bodies alone. Logged at
    /// startup so an operator sees the memory envelope they just configured.
    pub fn peak_body_bytes(&self) -> usize {
        self.max_body_bytes.saturating_mul(self.max_concurrent_msm)
    }
}

fn env_or<T>(key: &str, default: T) -> anyhow::Result<T>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => raw
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("{key}: cannot parse {raw:?}: {e}")),
    }
}

fn env_secs(key: &str, default: Duration) -> anyhow::Result<Duration> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => {
            let secs: u64 = raw
                .trim()
                .parse()
                .map_err(|e| anyhow::anyhow!("{key}: cannot parse {raw:?} as seconds: {e}"))?;
            Ok(Duration::from_secs(secs))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid_and_loopback_only() {
        let c = ServerConfig::default();
        c.validate().unwrap();
        // Binding 0.0.0.0 by default would expose an unauthenticated service.
        assert!(c.bind_addr.ip().is_loopback());
    }

    #[test]
    fn body_limit_admits_a_realistic_circuit() {
        // 2^20 generators per MSM: 4 sets of G1 (32B) + 1 set of G2 (64B).
        let per_set_g1 = (1usize << 20) * 32;
        let per_set_g2 = (1usize << 20) * 64;
        let total = 4 * per_set_g1 + per_set_g2;
        assert!(
            DEFAULT_MAX_BODY_BYTES >= total,
            "default body limit {DEFAULT_MAX_BODY_BYTES} rejects a 2^20 circuit needing {total}"
        );
    }

    #[test]
    fn zero_values_are_rejected() {
        let mutations: [fn(&mut ServerConfig); 4] = [
            |c| c.max_concurrent_msm = 0,
            |c| c.max_sessions = 0,
            |c| c.max_body_bytes = 0,
            |c| c.session_ttl = Duration::ZERO,
        ];
        for mutate in mutations {
            let mut c = ServerConfig::default();
            mutate(&mut c);
            assert!(c.validate().is_err());
        }
    }

    #[test]
    fn default_concurrency_is_in_range() {
        assert!((1..=4).contains(&default_concurrency()));
    }
}
