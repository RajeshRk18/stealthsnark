//! Client authentication and the tier model.
//!
//! # Two-layer credential model
//!
//! A request carries up to two independent credentials:
//!
//! 1. A **client credential** that says *who you are* — an API key, or a TLS
//!    client certificate under mTLS. It is required on every `/v1` endpoint.
//! 2. A **session token** that says *which stored generators you mean*. It is
//!    issued by `/v1/setup` and required on `/v1/prove` and `/v1/session`.
//!
//! The layers are deliberately separate. A session records the principal that
//! created it, so a stolen session token is useless without that principal's
//! client credential, and one principal can never operate on another's session
//! even if it learns the token. A single combined credential could not express
//! either property.
//!
//! # API key format
//!
//! `ssk_<key_id>_<secret>`, where `key_id` is 16 hex characters and `secret` is
//! 64. The key id makes lookup a single map probe instead of a scan over every
//! record, which matters because a scan would compare the secret against each
//! stored digest in turn. Only `SHA-256(secret)` is stored, so the auth file
//! never holds a usable credential.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use super::error::ApiError;
use super::secret::{constant_time_eq, hex_decode, random_hex, sha256_hex};

/// Prefix on every API key. Makes a leaked key greppable in logs and scanners.
pub const API_KEY_PREFIX: &str = "ssk";

const KEY_ID_BYTES: usize = 8; // 16 hex characters
const KEY_SECRET_BYTES: usize = 32; // 64 hex characters, 256 bits

/// Which credentials the server accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMode {
    /// No client credential required. Every caller becomes the `anonymous`
    /// principal on the default tier.
    ///
    /// This must be selected explicitly, and
    /// [`crate::protocol::config::ServerConfig::validate`] refuses it on a
    /// non-loopback bind address. An unauthenticated service reachable from a
    /// network is almost never the intent.
    Disabled,
    /// API key only.
    ApiKey,
    /// TLS client certificate only. Requires the `tls` feature and a configured
    /// client CA.
    MutualTls,
    /// Either an API key or a client certificate.
    Any,
}

impl AuthMode {
    pub fn accepts_api_key(self) -> bool {
        matches!(self, Self::ApiKey | Self::Any)
    }

    pub fn accepts_client_cert(self) -> bool {
        matches!(self, Self::MutualTls | Self::Any)
    }

    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Whether the TLS layer must demand a certificate from the client.
    ///
    /// `Any` requests one but tolerates its absence, because such a caller may
    /// instead present an API key.
    pub fn requires_client_cert(self) -> bool {
        matches!(self, Self::MutualTls)
    }
}

impl std::str::FromStr for AuthMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "disabled" | "off" | "none" => Ok(Self::Disabled),
            "apikey" | "api_key" | "api-key" => Ok(Self::ApiKey),
            "mtls" | "mutual_tls" | "mutual-tls" => Ok(Self::MutualTls),
            "any" | "both" => Ok(Self::Any),
            other => anyhow::bail!(
                "unknown auth mode {other:?} (expected disabled, apikey, mtls, or any)"
            ),
        }
    }
}

/// Resource limits attached to a principal.
///
/// Quota lives on the tier rather than on the principal so that limits are
/// declared once and shared, which is how a plan behaves in practice.
#[derive(Clone, Debug, PartialEq)]
pub struct Tier {
    pub name: String,
    /// Concurrent sessions this principal may hold.
    pub max_sessions: usize,
    /// Largest request body this principal may upload.
    pub max_body_bytes: usize,
    /// Sustained request rate, requests per second.
    pub requests_per_sec: f64,
    /// Requests available in a burst after an idle period.
    pub burst: u32,
}

impl Tier {
    /// Conservative limits for the built-in default tier.
    pub fn default_tier() -> Self {
        Self {
            name: "default".to_string(),
            max_sessions: 4,
            max_body_bytes: super::config::DEFAULT_MAX_BODY_BYTES,
            requests_per_sec: 2.0,
            burst: 10,
        }
    }

    /// Limits that never bind. Used only for the anonymous principal.
    ///
    /// A per-principal quota exists to stop one client starving the others. When
    /// authentication is off, every caller shares one identity, so the same quota
    /// would instead act as a second server-wide limit — and a surprising one,
    /// because a tier's `max_sessions` of 4 would silently override an operator's
    /// `STEALTHSNARK_MAX_SESSIONS=64`. The server-wide limits in
    /// [`crate::protocol::config`] are the honest control in that mode.
    ///
    /// The rate is a large finite number rather than infinity: the token bucket
    /// multiplies the rate by elapsed time, and `f64::INFINITY * 0.0` is `NaN`.
    pub fn unlimited() -> Self {
        Self {
            name: "unlimited".to_string(),
            max_sessions: usize::MAX,
            max_body_bytes: usize::MAX,
            requests_per_sec: f64::from(u32::MAX),
            burst: u32::MAX,
        }
    }
}

/// How a principal proved its identity on this request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    ApiKey,
    MutualTls,
    /// Authentication is disabled. Never produced when [`AuthMode::is_enabled`].
    Anonymous,
}

impl AuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::MutualTls => "mutual_tls",
            Self::Anonymous => "anonymous",
        }
    }
}

/// An authenticated caller.
#[derive(Clone, Debug)]
pub struct Principal {
    /// Stable, non-secret identifier. Safe to log and to use as a metric label.
    pub id: String,
    pub tier: Tier,
    pub method: AuthMethod,
}

impl Principal {
    fn anonymous() -> Self {
        Self {
            id: "anonymous".to_string(),
            tier: Tier::unlimited(),
            method: AuthMethod::Anonymous,
        }
    }
}

/// One credential record.
#[derive(Clone, Debug)]
struct Record {
    principal_id: String,
    tier: String,
    /// Hex SHA-256 of the API key secret.
    api_key_sha256: Option<String>,
}

/// Credential store: API keys by key id, principals by client-certificate digest.
#[derive(Debug)]
pub struct AuthStore {
    mode: AuthMode,
    tiers: HashMap<String, Tier>,
    /// key id -> record. A map and not a list, so verification never compares
    /// the presented secret against unrelated digests.
    by_key_id: HashMap<String, Record>,
    /// Hex SHA-256 of the client certificate DER -> principal id and tier.
    by_cert_digest: HashMap<String, Record>,
}

impl AuthStore {
    /// A store that authenticates nothing. Only valid with [`AuthMode::Disabled`].
    pub fn disabled() -> Self {
        Self {
            mode: AuthMode::Disabled,
            tiers: HashMap::new(),
            by_key_id: HashMap::new(),
            by_cert_digest: HashMap::new(),
        }
    }

    pub fn mode(&self) -> AuthMode {
        self.mode
    }

    pub fn principal_count(&self) -> usize {
        let mut ids: Vec<&str> = self
            .by_key_id
            .values()
            .chain(self.by_cert_digest.values())
            .map(|r| r.principal_id.as_str())
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    }

    pub fn api_key_count(&self) -> usize {
        self.by_key_id.len()
    }

    pub fn client_cert_count(&self) -> usize {
        self.by_cert_digest.len()
    }

    /// Load credentials from a JSON file. See [`AuthFile`] for the shape.
    pub fn from_file(path: impl AsRef<Path>, mode: AuthMode) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read auth file {}: {e}", path.display()))?;
        let parsed: AuthFile = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("cannot parse auth file {}: {e}", path.display()))?;
        Self::from_spec(parsed, mode)
    }

    pub fn from_spec(spec: AuthFile, mode: AuthMode) -> anyhow::Result<Self> {
        let mut tiers: HashMap<String, Tier> = HashMap::new();
        tiers.insert("default".to_string(), Tier::default_tier());

        for (name, t) in spec.tiers {
            if t.requests_per_sec <= 0.0 || !t.requests_per_sec.is_finite() {
                anyhow::bail!("tier {name:?}: requests_per_sec must be a positive number");
            }
            if t.burst == 0 {
                anyhow::bail!("tier {name:?}: burst must be >= 1");
            }
            if t.max_body_bytes == 0 {
                anyhow::bail!("tier {name:?}: max_body_bytes must be >= 1");
            }
            tiers.insert(
                name.clone(),
                Tier {
                    name,
                    max_sessions: t.max_sessions,
                    max_body_bytes: t.max_body_bytes,
                    requests_per_sec: t.requests_per_sec,
                    burst: t.burst,
                },
            );
        }

        let mut by_key_id = HashMap::new();
        let mut by_cert_digest = HashMap::new();

        for p in spec.principals {
            let tier = p.tier.unwrap_or_else(|| "default".to_string());
            if !tiers.contains_key(&tier) {
                anyhow::bail!("principal {:?} references unknown tier {tier:?}", p.id);
            }
            let record = Record {
                principal_id: p.id.clone(),
                tier,
                api_key_sha256: p.api_key_sha256.clone(),
            };

            match (&p.api_key_id, &p.api_key_sha256) {
                (Some(id), Some(digest)) => {
                    validate_hex(id, KEY_ID_BYTES * 2, "api_key_id", &p.id)?;
                    validate_hex(digest, 64, "api_key_sha256", &p.id)?;
                    if by_key_id.insert(id.clone(), record.clone()).is_some() {
                        anyhow::bail!("duplicate api_key_id {id:?}");
                    }
                }
                (None, None) => {}
                _ => anyhow::bail!(
                    "principal {:?}: api_key_id and api_key_sha256 must be given together",
                    p.id
                ),
            }

            if let Some(digest) = &p.tls_cert_sha256 {
                validate_hex(digest, 64, "tls_cert_sha256", &p.id)?;
                let normalised = digest.to_ascii_lowercase();
                if by_cert_digest.insert(normalised, record).is_some() {
                    anyhow::bail!("duplicate tls_cert_sha256 {digest:?}");
                }
            }
        }

        if mode.is_enabled() && by_key_id.is_empty() && by_cert_digest.is_empty() {
            anyhow::bail!(
                "auth mode {mode:?} is enabled but no credentials are configured; \
                 run `cargo run --bin keygen` to mint one"
            );
        }
        if mode == AuthMode::ApiKey && by_key_id.is_empty() {
            anyhow::bail!("auth mode apikey requires at least one api_key_id record");
        }
        if mode == AuthMode::MutualTls && by_cert_digest.is_empty() {
            anyhow::bail!("auth mode mtls requires at least one tls_cert_sha256 record");
        }

        Ok(Self {
            mode,
            tiers,
            by_key_id,
            by_cert_digest,
        })
    }

    /// Resolve a caller to a principal.
    ///
    /// `presented_key` is the `Authorization: Bearer` value; `cert_digest` is the
    /// hex SHA-256 of the peer certificate, when the connection supplied one.
    pub fn authenticate(
        &self,
        presented_key: Option<&str>,
        cert_digest: Option<&str>,
    ) -> Result<Principal, ApiError> {
        if !self.mode.is_enabled() {
            return Ok(Principal::anonymous());
        }

        // A certificate is checked first: it is bound to the connection, so it
        // cannot be replayed from a captured header.
        if self.mode.accepts_client_cert() {
            if let Some(digest) = cert_digest {
                let normalised = digest.to_ascii_lowercase();
                if let Some(record) = self.by_cert_digest.get(&normalised) {
                    return Ok(self.principal_from(record, AuthMethod::MutualTls));
                }
                // A presented certificate that is unknown is a hard failure under
                // mTLS-only: it means the CA trusts a client this service does not.
                if self.mode == AuthMode::MutualTls {
                    return Err(ApiError::Unauthenticated(
                        "client certificate is not registered".to_string(),
                    ));
                }
            } else if self.mode == AuthMode::MutualTls {
                return Err(ApiError::Unauthenticated(
                    "no client certificate presented".to_string(),
                ));
            }
        }

        if self.mode.accepts_api_key() {
            let key = presented_key
                .ok_or_else(|| ApiError::Unauthenticated("no API key presented".to_string()))?;
            return self.verify_api_key(key);
        }

        Err(ApiError::Unauthenticated(
            "no acceptable credential presented".to_string(),
        ))
    }

    fn verify_api_key(&self, presented: &str) -> Result<Principal, ApiError> {
        let (key_id, secret) = parse_api_key(presented)
            .ok_or_else(|| ApiError::Unauthenticated("malformed API key".to_string()))?;

        // Deliberately the same message for "no such key id" and "wrong secret".
        // Distinguishing them would tell an attacker which key ids exist.
        let invalid = || ApiError::Unauthenticated("invalid API key".to_string());

        let record = self.by_key_id.get(&key_id).ok_or_else(invalid)?;
        let expected = record.api_key_sha256.as_deref().ok_or_else(invalid)?;

        if !constant_time_eq(&sha256_hex(secret.as_bytes()), expected) {
            return Err(invalid());
        }
        Ok(self.principal_from(record, AuthMethod::ApiKey))
    }

    fn principal_from(&self, record: &Record, method: AuthMethod) -> Principal {
        let tier = self
            .tiers
            .get(&record.tier)
            .cloned()
            // Unreachable: from_spec rejects unknown tier names.
            .unwrap_or_else(Tier::default_tier);
        Principal {
            id: record.principal_id.clone(),
            tier,
            method,
        }
    }

    /// Largest `max_body_bytes` over all tiers.
    ///
    /// The transport body limit is global, so it is set from this value and the
    /// per-tier limit is enforced afterwards. A tier therefore cannot exceed the
    /// transport ceiling, but a smaller tier still gets its own smaller cap.
    pub fn max_body_bytes_over_tiers(&self) -> usize {
        self.tiers
            .values()
            .map(|t| t.max_body_bytes)
            .max()
            .unwrap_or_else(|| Tier::default_tier().max_body_bytes)
    }
}

/// JSON shape of the auth file.
///
/// ```json
/// {
///   "tiers": {
///     "standard": {"max_sessions": 4, "max_body_bytes": 268435456,
///                  "requests_per_sec": 2.0, "burst": 10}
///   },
///   "principals": [
///     {"id": "alice", "tier": "standard",
///      "api_key_id": "0123456789abcdef",
///      "api_key_sha256": "<64 hex>",
///      "tls_cert_sha256": "<64 hex>"}
///   ]
/// }
/// ```
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthFile {
    #[serde(default)]
    pub tiers: HashMap<String, TierSpec>,
    #[serde(default)]
    pub principals: Vec<PrincipalSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierSpec {
    pub max_sessions: usize,
    pub max_body_bytes: usize,
    pub requests_per_sec: f64,
    pub burst: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalSpec {
    pub id: String,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub api_key_id: Option<String>,
    #[serde(default)]
    pub api_key_sha256: Option<String>,
    #[serde(default)]
    pub tls_cert_sha256: Option<String>,
}

/// A newly minted API key. The secret exists only in this value.
#[derive(Debug)]
pub struct GeneratedKey {
    /// Full credential to hand to the client. Shown once and never stored.
    pub key: String,
    /// Lookup id to record in the auth file.
    pub key_id: String,
    /// Digest to record in the auth file.
    pub sha256: String,
}

/// Mint an API key.
pub fn generate_api_key() -> GeneratedKey {
    let key_id = random_hex(KEY_ID_BYTES);
    let secret = random_hex(KEY_SECRET_BYTES);
    let sha256 = sha256_hex(secret.as_bytes());
    GeneratedKey {
        key: format!("{API_KEY_PREFIX}_{key_id}_{secret}"),
        key_id,
        sha256,
    }
}

/// Split `ssk_<key_id>_<secret>`. Returns `None` on any deviation.
fn parse_api_key(presented: &str) -> Option<(String, String)> {
    let mut parts = presented.trim().split('_');
    if parts.next()? != API_KEY_PREFIX {
        return None;
    }
    let key_id = parts.next()?;
    let secret = parts.next()?;
    if parts.next().is_some() {
        return None; // extra separator: not our format
    }
    if key_id.len() != KEY_ID_BYTES * 2 || secret.len() != KEY_SECRET_BYTES * 2 {
        return None;
    }
    hex_decode(key_id)?;
    hex_decode(secret)?;
    Some((key_id.to_string(), secret.to_string()))
}

fn validate_hex(value: &str, want_len: usize, field: &str, owner: &str) -> anyhow::Result<()> {
    if value.len() != want_len || hex_decode(value).is_none() {
        anyhow::bail!("principal {owner:?}: {field} must be {want_len} hex characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with_one_key(mode: AuthMode) -> (AuthStore, String) {
        let generated = generate_api_key();
        let spec = AuthFile {
            tiers: HashMap::new(),
            principals: vec![PrincipalSpec {
                id: "alice".to_string(),
                tier: None,
                api_key_id: Some(generated.key_id.clone()),
                api_key_sha256: Some(generated.sha256.clone()),
                tls_cert_sha256: None,
            }],
        };
        (AuthStore::from_spec(spec, mode).unwrap(), generated.key)
    }

    #[test]
    fn a_valid_api_key_authenticates() {
        let (store, key) = store_with_one_key(AuthMode::ApiKey);
        let p = store.authenticate(Some(&key), None).unwrap();
        assert_eq!(p.id, "alice");
        assert_eq!(p.method, AuthMethod::ApiKey);
        assert_eq!(p.tier.name, "default");
    }

    #[test]
    fn a_wrong_secret_is_refused_and_does_not_say_why() {
        let (store, key) = store_with_one_key(AuthMode::ApiKey);

        // Same key id, flipped last character of the secret.
        let mut tampered: Vec<char> = key.chars().collect();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == '0' { '1' } else { '0' };
        let tampered: String = tampered.into_iter().collect();

        let wrong_secret = store.authenticate(Some(&tampered), None).unwrap_err();
        let unknown_id = store
            .authenticate(
                Some(&format!("ssk_{}_{}", "aa".repeat(8), "bb".repeat(32))),
                None,
            )
            .unwrap_err();

        // Identical messages: an attacker must not learn which key ids exist.
        assert_eq!(wrong_secret.to_string(), unknown_id.to_string());
        assert_eq!(wrong_secret.code(), "unauthenticated");
    }

    #[test]
    fn malformed_keys_are_refused() {
        let (store, _) = store_with_one_key(AuthMode::ApiKey);
        for bad in [
            "",
            "nonsense",
            "ssk_short_short",
            "wrongprefix_0123456789abcdef_0",
            "ssk_0123456789abcdef",       // no secret
            "ssk_0123456789abcdef_zz",    // non-hex secret
            "ssk_0123456789abcdef_aa_bb", // extra separator
        ] {
            assert_eq!(
                store.authenticate(Some(bad), None).unwrap_err().code(),
                "unauthenticated",
                "accepted malformed key {bad:?}"
            );
        }
    }

    #[test]
    fn a_missing_credential_is_refused_when_auth_is_on() {
        let (store, _) = store_with_one_key(AuthMode::ApiKey);
        assert_eq!(
            store.authenticate(None, None).unwrap_err().code(),
            "unauthenticated"
        );
    }

    #[test]
    fn disabled_auth_yields_an_unmetered_anonymous_principal() {
        let store = AuthStore::disabled();
        let p = store.authenticate(None, None).unwrap();
        assert_eq!(p.id, "anonymous");
        assert_eq!(p.method, AuthMethod::Anonymous);

        // The quota must not bind: with one shared identity it would act as a
        // second server-wide limit and silently override STEALTHSNARK_MAX_SESSIONS.
        assert_eq!(p.tier.max_sessions, usize::MAX);
        assert_eq!(p.tier.max_body_bytes, usize::MAX);
        // Finite, so the token bucket's `rate * elapsed` cannot produce NaN.
        assert!(p.tier.requests_per_sec.is_finite());
        assert!(p.tier.requests_per_sec > 1e6);
    }

    #[test]
    fn the_unlimited_tier_never_refuses() {
        use super::super::quota::QuotaEnforcer;
        let q = QuotaEnforcer::new();
        let p = Principal::anonymous();
        let now = std::time::Instant::now();

        // Many requests at one instant: a finite-rate bucket must still admit
        // them, which is what the u32::MAX burst is for.
        for i in 0..10_000 {
            assert!(
                q.check_rate_at(&p, now).is_ok(),
                "unlimited tier refused request {i}"
            );
        }
        assert!(q.check_body_size(&p, Some(u64::MAX)).is_ok());
        assert!(q.check_session_allowance(&p, 1_000_000).is_ok());
    }

    #[test]
    fn client_certificate_digest_authenticates_under_mtls() {
        let digest = "ab".repeat(32);
        let spec = AuthFile {
            tiers: HashMap::new(),
            principals: vec![PrincipalSpec {
                id: "bob".to_string(),
                tier: None,
                api_key_id: None,
                api_key_sha256: None,
                tls_cert_sha256: Some(digest.clone()),
            }],
        };
        let store = AuthStore::from_spec(spec, AuthMode::MutualTls).unwrap();

        let p = store.authenticate(None, Some(&digest)).unwrap();
        assert_eq!(p.id, "bob");
        assert_eq!(p.method, AuthMethod::MutualTls);

        // Case-insensitive, because hex casing is not semantic.
        assert!(store
            .authenticate(None, Some(&digest.to_uppercase()))
            .is_ok());

        // A certificate the CA signed but this service does not know.
        let unknown = store
            .authenticate(None, Some(&"cd".repeat(32)))
            .unwrap_err();
        assert_eq!(unknown.code(), "unauthenticated");

        // No certificate at all under mTLS-only.
        assert_eq!(
            store.authenticate(None, None).unwrap_err().code(),
            "unauthenticated"
        );
    }

    #[test]
    fn any_mode_accepts_either_credential() {
        let generated = generate_api_key();
        let digest = "ef".repeat(32);
        let spec = AuthFile {
            tiers: HashMap::new(),
            principals: vec![
                PrincipalSpec {
                    id: "keyed".to_string(),
                    tier: None,
                    api_key_id: Some(generated.key_id.clone()),
                    api_key_sha256: Some(generated.sha256.clone()),
                    tls_cert_sha256: None,
                },
                PrincipalSpec {
                    id: "certed".to_string(),
                    tier: None,
                    api_key_id: None,
                    api_key_sha256: None,
                    tls_cert_sha256: Some(digest.clone()),
                },
            ],
        };
        let store = AuthStore::from_spec(spec, AuthMode::Any).unwrap();

        assert_eq!(
            store.authenticate(Some(&generated.key), None).unwrap().id,
            "keyed"
        );
        assert_eq!(
            store.authenticate(None, Some(&digest)).unwrap().id,
            "certed"
        );
        // An unrecognised certificate falls through to the API key under `Any`.
        assert_eq!(
            store
                .authenticate(Some(&generated.key), Some(&"11".repeat(32)))
                .unwrap()
                .id,
            "keyed"
        );
    }

    #[test]
    fn tiers_are_resolved_and_bound_the_transport_limit() {
        let mut tiers = HashMap::new();
        tiers.insert(
            "small".to_string(),
            TierSpec {
                max_sessions: 1,
                max_body_bytes: 1024,
                requests_per_sec: 1.0,
                burst: 1,
            },
        );
        tiers.insert(
            "large".to_string(),
            TierSpec {
                max_sessions: 32,
                max_body_bytes: 8192,
                requests_per_sec: 50.0,
                burst: 100,
            },
        );
        let generated = generate_api_key();
        let spec = AuthFile {
            tiers,
            principals: vec![PrincipalSpec {
                id: "small-fry".to_string(),
                tier: Some("small".to_string()),
                api_key_id: Some(generated.key_id.clone()),
                api_key_sha256: Some(generated.sha256.clone()),
                tls_cert_sha256: None,
            }],
        };
        let store = AuthStore::from_spec(spec, AuthMode::ApiKey).unwrap();

        let p = store.authenticate(Some(&generated.key), None).unwrap();
        assert_eq!(p.tier.name, "small");
        assert_eq!(p.tier.max_sessions, 1);
        assert_eq!(p.tier.max_body_bytes, 1024);

        // The global transport limit must admit the most generous tier, including
        // the built-in default that is always present.
        assert!(store.max_body_bytes_over_tiers() >= 8192);
    }

    #[test]
    fn malformed_specs_are_rejected() {
        let generated = generate_api_key();
        let principal = |api_key_id, sha| PrincipalSpec {
            id: "x".to_string(),
            tier: None,
            api_key_id,
            api_key_sha256: sha,
            tls_cert_sha256: None,
        };

        // Half a credential.
        let spec = AuthFile {
            tiers: HashMap::new(),
            principals: vec![principal(Some(generated.key_id.clone()), None)],
        };
        assert!(AuthStore::from_spec(spec, AuthMode::ApiKey).is_err());

        // Digest of the wrong width.
        let spec = AuthFile {
            tiers: HashMap::new(),
            principals: vec![principal(
                Some(generated.key_id.clone()),
                Some("abc".to_string()),
            )],
        };
        assert!(AuthStore::from_spec(spec, AuthMode::ApiKey).is_err());

        // Unknown tier name.
        let spec = AuthFile {
            tiers: HashMap::new(),
            principals: vec![PrincipalSpec {
                id: "x".to_string(),
                tier: Some("gold".to_string()),
                api_key_id: Some(generated.key_id.clone()),
                api_key_sha256: Some(generated.sha256.clone()),
                tls_cert_sha256: None,
            }],
        };
        assert!(AuthStore::from_spec(spec, AuthMode::ApiKey).is_err());

        // Auth on, but nothing to authenticate against.
        let empty = AuthFile::default();
        assert!(AuthStore::from_spec(empty, AuthMode::ApiKey).is_err());
        // The same file is fine when auth is off.
        assert!(AuthStore::from_spec(AuthFile::default(), AuthMode::Disabled).is_ok());
    }

    #[test]
    fn duplicate_credentials_are_rejected() {
        let generated = generate_api_key();
        let one = |id: &str| PrincipalSpec {
            id: id.to_string(),
            tier: None,
            api_key_id: Some(generated.key_id.clone()),
            api_key_sha256: Some(generated.sha256.clone()),
            tls_cert_sha256: None,
        };
        let spec = AuthFile {
            tiers: HashMap::new(),
            principals: vec![one("a"), one("b")],
        };
        let err = AuthStore::from_spec(spec, AuthMode::ApiKey).unwrap_err();
        assert!(err.to_string().contains("duplicate api_key_id"));
    }

    #[test]
    fn generated_keys_are_unique_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let g = generate_api_key();
            assert!(g.key.starts_with("ssk_"));
            assert_eq!(g.key_id.len(), 16);
            assert_eq!(g.sha256.len(), 64);
            // The stored digest must not reveal the secret.
            assert!(!g.key.contains(&g.sha256));
            let (id, secret) = parse_api_key(&g.key).expect("own key must parse");
            assert_eq!(id, g.key_id);
            assert_eq!(sha256_hex(secret.as_bytes()), g.sha256);
            assert!(seen.insert(g.key), "generated a duplicate key");
        }
    }

    #[test]
    fn auth_mode_parsing() {
        use std::str::FromStr;
        assert_eq!(AuthMode::from_str("disabled").unwrap(), AuthMode::Disabled);
        assert_eq!(AuthMode::from_str("apikey").unwrap(), AuthMode::ApiKey);
        assert_eq!(AuthMode::from_str("MTLS").unwrap(), AuthMode::MutualTls);
        assert_eq!(AuthMode::from_str(" any ").unwrap(), AuthMode::Any);
        assert!(AuthMode::from_str("sortof").is_err());

        assert!(AuthMode::MutualTls.requires_client_cert());
        // `Any` must not demand a certificate: such a caller may use an API key.
        assert!(!AuthMode::Any.requires_client_cert());
        assert!(AuthMode::Any.accepts_api_key());
        assert!(AuthMode::Any.accepts_client_cert());
    }
}
