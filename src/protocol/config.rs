//! Runtime configuration for the EMSM server.
//!
//! Everything an operator might need to change per-deployment is read from the
//! environment at startup rather than hardcoded, so one binary serves a test
//! harness, a laptop, and a box behind a reverse proxy without a rebuild.
//! Parsing is strict: a typo in an env var fails startup loudly instead of
//! silently falling back to a default that hides the mistake.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use super::auth::AuthMode;

/// Paths to the PEM material for the TLS listener.
///
/// Defined here rather than in [`super::tls`] so that configuration parses and
/// validates identically whether or not the `tls` feature is compiled in. With
/// the feature off, a configured TLS path is a startup error rather than a
/// silent downgrade to plain HTTP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsPaths {
    /// Server certificate chain, leaf first.
    pub cert: PathBuf,
    /// Server private key: PKCS#8, PKCS#1, or SEC1.
    pub key: PathBuf,
    /// CA that signs client certificates. Required for mTLS.
    pub client_ca: Option<PathBuf>,
}

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

    /// Which client credentials the data plane accepts.
    pub auth_mode: AuthMode,

    /// JSON credential file. Required unless `auth_mode` is
    /// [`AuthMode::Disabled`].
    pub auth_file: Option<PathBuf>,

    /// TLS material. `None` serves plain HTTP, which is only sensible on
    /// loopback or behind a proxy that terminates TLS.
    pub tls: Option<TlsPaths>,

    /// Address for the admin plane: `/livez`, `/readyz`, `/metrics`.
    ///
    /// A second listener rather than routes on the main port, because those
    /// endpoints have opposite requirements to the data plane. They must stay
    /// reachable without a credential so a probe can work, and they must not be
    /// reachable from outside, because `/metrics` reports internal state. A
    /// separate loopback listener gives both; one port cannot.
    pub admin_bind_addr: SocketAddr,

    /// Idle time after which a principal's rate-limit bucket is forgotten.
    pub quota_bucket_idle: Duration,
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
            // Off by default so that `cargo run --bin server` still works on a
            // developer machine. It is safe only because `validate` refuses this
            // combination on any non-loopback bind address.
            auth_mode: AuthMode::Disabled,
            auth_file: None,
            tls: None,
            admin_bind_addr: SocketAddr::from(([127, 0, 0, 1], 3001)),
            quota_bucket_idle: Duration::from_secs(600),
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
            auth_mode: env_or("STEALTHSNARK_AUTH", d.auth_mode)?,
            auth_file: env_path("STEALTHSNARK_AUTH_FILE")?,
            tls: tls_from_env()?,
            admin_bind_addr: env_or("STEALTHSNARK_ADMIN_BIND", d.admin_bind_addr)?,
            quota_bucket_idle: env_secs(
                "STEALTHSNARK_QUOTA_BUCKET_IDLE_SECS",
                d.quota_bucket_idle,
            )?,
        })
    }

    /// Reject configurations that are unusable or unsafe.
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
        if self.quota_bucket_idle.is_zero() {
            anyhow::bail!("STEALTHSNARK_QUOTA_BUCKET_IDLE_SECS must be >= 1");
        }

        // The safety interlock. Unauthenticated on loopback is a convenience for
        // development. Unauthenticated on a routable address is an open service,
        // and that is never worth inferring from a missing variable.
        if !self.auth_mode.is_enabled() && !self.bind_addr.ip().is_loopback() {
            anyhow::bail!(
                "refusing to bind {} with authentication disabled; \
                 set STEALTHSNARK_AUTH=apikey|mtls|any and STEALTHSNARK_AUTH_FILE",
                self.bind_addr
            );
        }
        if self.auth_mode.is_enabled() && self.auth_file.is_none() {
            anyhow::bail!(
                "STEALTHSNARK_AUTH={:?} needs STEALTHSNARK_AUTH_FILE",
                self.auth_mode
            );
        }

        // mTLS identity comes from the TLS handshake, so it cannot work without
        // TLS. Accepting this silently would leave the service unauthenticated.
        if self.auth_mode.accepts_client_cert() && self.auth_mode.requires_client_cert() {
            match &self.tls {
                None => anyhow::bail!("STEALTHSNARK_AUTH=mtls requires TLS to be configured"),
                Some(t) if t.client_ca.is_none() => {
                    anyhow::bail!("STEALTHSNARK_AUTH=mtls requires STEALTHSNARK_TLS_CLIENT_CA")
                }
                Some(_) => {}
            }
        }

        // A TLS configuration that cannot be honoured must stop startup rather
        // than serve plain HTTP on the port an operator believes is encrypted.
        #[cfg(not(feature = "tls"))]
        if self.tls.is_some() {
            anyhow::bail!("TLS is configured but this binary was built without the `tls` feature");
        }

        if self.bind_addr == self.admin_bind_addr {
            anyhow::bail!(
                "STEALTHSNARK_BIND and STEALTHSNARK_ADMIN_BIND must differ; \
                 the admin plane is unauthenticated and must not share the data port"
            );
        }
        if !self.admin_bind_addr.ip().is_loopback() {
            anyhow::bail!(
                "refusing to expose the admin plane on {}; /metrics reports internal state",
                self.admin_bind_addr
            );
        }
        Ok(())
    }

    /// Whether the data plane will serve TLS.
    pub fn tls_enabled(&self) -> bool {
        self.tls.is_some()
    }

    /// URL scheme the data plane will speak, for logging and client hints.
    pub fn scheme(&self) -> &'static str {
        if self.tls_enabled() {
            "https"
        } else {
            "http"
        }
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

fn env_path(key: &str) -> anyhow::Result<Option<PathBuf>> {
    match std::env::var(key) {
        Err(_) => Ok(None),
        Ok(raw) if raw.trim().is_empty() => Ok(None),
        Ok(raw) => {
            let path = PathBuf::from(raw.trim());
            // Fail here rather than on the first request that needs the file.
            if !path.exists() {
                anyhow::bail!("{key}: {} does not exist", path.display());
            }
            Ok(Some(path))
        }
    }
}

/// Read the TLS paths. Certificate and key must be given together.
fn tls_from_env() -> anyhow::Result<Option<TlsPaths>> {
    let cert = env_path("STEALTHSNARK_TLS_CERT")?;
    let key = env_path("STEALTHSNARK_TLS_KEY")?;
    let client_ca = env_path("STEALTHSNARK_TLS_CLIENT_CA")?;

    match (cert, key) {
        (Some(cert), Some(key)) => Ok(Some(TlsPaths {
            cert,
            key,
            client_ca,
        })),
        (None, None) => {
            if client_ca.is_some() {
                anyhow::bail!(
                    "STEALTHSNARK_TLS_CLIENT_CA is set but STEALTHSNARK_TLS_CERT and \
                     STEALTHSNARK_TLS_KEY are not; a client CA has no effect without TLS"
                );
            }
            Ok(None)
        }
        _ => anyhow::bail!("STEALTHSNARK_TLS_CERT and STEALTHSNARK_TLS_KEY must be set together"),
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

    fn authed(mode: AuthMode) -> ServerConfig {
        ServerConfig {
            auth_mode: mode,
            // `validate` only checks that a path was supplied.
            auth_file: Some(PathBuf::from("/dev/null")),
            ..ServerConfig::default()
        }
    }

    #[test]
    fn unauthenticated_service_may_not_bind_a_routable_address() {
        // The interlock that matters most: no missing variable can produce an
        // open service on a network interface.
        let open = ServerConfig {
            bind_addr: "0.0.0.0:3000".parse().unwrap(),
            auth_mode: AuthMode::Disabled,
            ..ServerConfig::default()
        };
        let err = open.validate().unwrap_err();
        assert!(err.to_string().contains("authentication disabled"), "{err}");

        // Loopback with auth off stays allowed, for development.
        assert!(ServerConfig::default().validate().is_ok());

        // A routable address is fine once auth is on.
        let closed = ServerConfig {
            bind_addr: "0.0.0.0:3000".parse().unwrap(),
            ..authed(AuthMode::ApiKey)
        };
        assert!(closed.validate().is_ok());
    }

    #[test]
    fn enabled_auth_requires_a_credential_file() {
        let c = ServerConfig {
            auth_mode: AuthMode::ApiKey,
            auth_file: None,
            ..ServerConfig::default()
        };
        assert!(c.validate().unwrap_err().to_string().contains("AUTH_FILE"));
    }

    #[test]
    fn mtls_requires_tls_and_a_client_ca() {
        // No TLS at all.
        let no_tls = authed(AuthMode::MutualTls);
        let err = no_tls.validate().unwrap_err();
        assert!(err.to_string().contains("requires TLS"), "{err}");

        // TLS, but no client CA to verify certificates against.
        let no_ca = ServerConfig {
            tls: Some(TlsPaths {
                cert: PathBuf::from("/dev/null"),
                key: PathBuf::from("/dev/null"),
                client_ca: None,
            }),
            ..authed(AuthMode::MutualTls)
        };
        let err = no_ca.validate().unwrap_err();
        assert!(err.to_string().contains("CLIENT_CA"), "{err}");

        // Complete configuration. Only valid when the `tls` feature is compiled
        // in; without it, `validate` must refuse rather than serve plain HTTP on
        // a port the operator believes is encrypted.
        let complete = ServerConfig {
            tls: Some(TlsPaths {
                cert: PathBuf::from("/dev/null"),
                key: PathBuf::from("/dev/null"),
                client_ca: Some(PathBuf::from("/dev/null")),
            }),
            ..authed(AuthMode::MutualTls)
        };
        #[cfg(feature = "tls")]
        assert!(complete.validate().is_ok());
        #[cfg(not(feature = "tls"))]
        {
            let err = complete.validate().unwrap_err();
            assert!(
                err.to_string().contains("without the `tls` feature"),
                "{err}"
            );
        }
    }

    #[cfg(not(feature = "tls"))]
    #[test]
    fn configured_tls_without_the_feature_is_refused() {
        let c = ServerConfig {
            tls: Some(TlsPaths {
                cert: PathBuf::from("/dev/null"),
                key: PathBuf::from("/dev/null"),
                client_ca: None,
            }),
            ..ServerConfig::default()
        };
        assert!(c.validate().is_err(), "must not silently serve plain HTTP");
    }

    #[test]
    fn any_mode_does_not_require_tls() {
        // `Any` accepts an API key, so it must work over plain HTTP behind a
        // proxy that terminates TLS.
        assert!(authed(AuthMode::Any).validate().is_ok());
    }

    #[test]
    fn admin_plane_stays_private_and_separate() {
        let shared = ServerConfig {
            admin_bind_addr: ServerConfig::default().bind_addr,
            ..ServerConfig::default()
        };
        let err = shared.validate().unwrap_err();
        assert!(err.to_string().contains("must differ"), "{err}");

        let exposed = ServerConfig {
            admin_bind_addr: "0.0.0.0:3001".parse().unwrap(),
            ..ServerConfig::default()
        };
        let err = exposed.validate().unwrap_err();
        assert!(err.to_string().contains("admin plane"), "{err}");
    }

    #[test]
    fn scheme_follows_the_tls_setting() {
        assert_eq!(ServerConfig::default().scheme(), "http");
        let tls = ServerConfig {
            tls: Some(TlsPaths {
                cert: PathBuf::from("/dev/null"),
                key: PathBuf::from("/dev/null"),
                client_ca: None,
            }),
            ..ServerConfig::default()
        };
        assert_eq!(tls.scheme(), "https");
        assert!(tls.tls_enabled());
    }
}
