//! HTTP client for the EMSM server.
//!
//! # Credentials
//!
//! Two independent things, in two headers, matching the server:
//!
//! - The **client credential** goes in `Authorization: Bearer <api key>`, or is
//!   supplied by a TLS client certificate under mTLS. It says who you are.
//! - The **session token** goes in `x-stealthsnark-session`, is issued by
//!   `/v1/setup`, and is held here. It says which stored generators you mean.
//!
//! `send_prove` refuses to run without a session, so "forgot to set up" is a
//! local error rather than a puzzling 401 from the server.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use super::messages::{
    ProveRequest, ProveResponse, SetupRequest, SetupResponse, PROTOCOL_VERSION, SESSION_HEADER,
    VERSION_HEADER,
};

/// Default per-request ceiling.
///
/// Generous because a large honest MSM legitimately takes minutes; the point is
/// to have a bound, since `reqwest::Client::new()` has none and a stalled server
/// would otherwise hang a client for ever.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

/// Connect timeout. Short, because a TCP connection that will not establish does
/// not improve after ten minutes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How to authenticate to the server.
#[derive(Clone, Debug, Default)]
pub enum Credential {
    /// Send no credential. Only works against a server with auth disabled.
    #[default]
    None,
    /// Send `Authorization: Bearer <key>`.
    ApiKey(String),
    /// Authenticate with a TLS client certificate. The identity travels in the
    /// handshake, so no header is added.
    ClientCertificate,
}

/// Builder for [`EmsmClient`].
///
/// A builder rather than a widening list of `new` arguments, because TLS trust,
/// client certificates, and timeouts are independent choices.
#[derive(Debug)]
pub struct EmsmClientBuilder {
    base_url: String,
    request_timeout: Duration,
    credential: Credential,
    root_certificate_pem: Option<Vec<u8>>,
    client_identity_pem: Option<Vec<u8>>,
    accept_invalid_certs: bool,
}

impl EmsmClientBuilder {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            credential: Credential::None,
            root_certificate_pem: None,
            client_identity_pem: None,
            accept_invalid_certs: false,
        }
    }

    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Authenticate with an API key.
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.credential = Credential::ApiKey(key.into());
        self
    }

    /// Trust a private CA in addition to the built-in roots.
    ///
    /// Needed whenever the server certificate is not signed by a public CA, which
    /// is the normal case for an internal service.
    pub fn root_certificate_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.root_certificate_pem = Some(pem.into());
        self
    }

    pub fn root_certificate_file(self, path: impl AsRef<Path>) -> Result<Self> {
        let pem = std::fs::read(path.as_ref())
            .map_err(|e| anyhow::anyhow!("cannot read CA file {}: {e}", path.as_ref().display()))?;
        Ok(self.root_certificate_pem(pem))
    }

    /// Present a client certificate for mTLS.
    ///
    /// `pem` must hold both the certificate and its private key.
    pub fn client_identity_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.client_identity_pem = Some(pem.into());
        self.credential = Credential::ClientCertificate;
        self
    }

    pub fn client_identity_file(self, path: impl AsRef<Path>) -> Result<Self> {
        let pem = std::fs::read(path.as_ref()).map_err(|e| {
            anyhow::anyhow!("cannot read identity file {}: {e}", path.as_ref().display())
        })?;
        Ok(self.client_identity_pem(pem))
    }

    /// Skip server certificate verification.
    ///
    /// Only for a local test against a self-signed certificate. It removes the
    /// guarantee that you are talking to the intended server, so prefer
    /// [`Self::root_certificate_pem`] in every other case.
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.accept_invalid_certs = accept;
        self
    }

    pub fn build(self) -> Result<EmsmClient> {
        let mut builder = reqwest::Client::builder()
            .timeout(self.request_timeout)
            .connect_timeout(CONNECT_TIMEOUT)
            .use_rustls_tls();

        if let Some(pem) = &self.root_certificate_pem {
            // A CA bundle may hold several certificates; add all of them.
            let certs = reqwest::Certificate::from_pem_bundle(pem)?;
            // An unparseable bundle yields an empty list rather than an error, so
            // without this check the client would quietly keep only the public
            // roots and then fail verification with a misleading message.
            if certs.is_empty() {
                anyhow::bail!("no certificates found in the supplied CA bundle");
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        if let Some(pem) = &self.client_identity_pem {
            builder = builder.identity(reqwest::Identity::from_pem(pem)?);
        }
        if self.accept_invalid_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }

        Ok(EmsmClient {
            base_url: self.base_url,
            client: builder.build()?,
            credential: self.credential,
            session_token: None,
            session_label: None,
        })
    }
}

/// A client bound to one server-issued session.
pub struct EmsmClient {
    base_url: String,
    client: reqwest::Client,
    credential: Credential,
    /// Set by [`EmsmClient::send_setup`]. `None` until then.
    session_token: Option<String>,
    session_label: Option<String>,
}

/// Hand-written so that neither the API key nor the session token can reach a log
/// through a `{:?}` of a struct that happens to contain this one.
impl std::fmt::Debug for EmsmClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let credential = match &self.credential {
            Credential::None => "none",
            Credential::ApiKey(_) => "api_key(redacted)",
            Credential::ClientCertificate => "client_certificate",
        };
        f.debug_struct("EmsmClient")
            .field("base_url", &self.base_url)
            .field("credential", &credential)
            .field("session_label", &self.session_label)
            .field("has_session", &self.has_session())
            .finish()
    }
}

impl EmsmClient {
    pub fn builder(base_url: &str) -> EmsmClientBuilder {
        EmsmClientBuilder::new(base_url)
    }

    /// Client with no credential and the default timeout. For a server with
    /// authentication disabled.
    pub fn new(base_url: &str) -> Result<Self> {
        EmsmClientBuilder::new(base_url).build()
    }

    pub fn with_timeout(base_url: &str, request_timeout: Duration) -> Result<Self> {
        EmsmClientBuilder::new(base_url)
            .request_timeout(request_timeout)
            .build()
    }

    /// The server's non-secret label for this session, for log correlation.
    pub fn session_label(&self) -> Option<&str> {
        self.session_label.as_deref()
    }

    pub fn has_session(&self) -> bool {
        self.session_token.is_some()
    }

    /// `POST /v1/setup` — upload generators and store the returned token.
    pub async fn send_setup(&mut self, request: &SetupRequest) -> Result<()> {
        let body = bincode::serialize(request)?;
        let resp = self
            .request(reqwest::Method::POST, "/v1/setup")
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        let bytes = read_success(resp, "setup").await?;
        let parsed: SetupResponse = bincode::deserialize(&bytes)?;
        self.session_token = Some(parsed.session_token);
        self.session_label = Some(parsed.session_label);
        Ok(())
    }

    /// `POST /v1/prove` — send masked vectors, receive the five MSM results.
    pub async fn send_prove(&self, request: &ProveRequest) -> Result<ProveResponse> {
        let body = bincode::serialize(request)?;
        let resp = self
            .request(reqwest::Method::POST, "/v1/prove")
            .header("Content-Type", "application/octet-stream")
            .header(SESSION_HEADER, self.token()?)
            .body(body)
            .send()
            .await?;

        let bytes = read_success(resp, "prove").await?;
        Ok(bincode::deserialize(&bytes)?)
    }

    /// `DELETE /v1/session` — free the server's copy of the generators now,
    /// instead of leaving them pinned until the idle TTL expires.
    pub async fn release(&self) -> Result<()> {
        let resp = self
            .request(reqwest::Method::DELETE, "/v1/session")
            .header(SESSION_HEADER, self.token()?)
            .send()
            .await?;
        read_success(resp, "release").await?;
        Ok(())
    }

    /// Start a request with the version header and the client credential applied.
    ///
    /// Every call goes through here, so no endpoint can forget either one.
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let builder = self
            .client
            .request(method, format!("{}{path}", self.base_url))
            .header(VERSION_HEADER, PROTOCOL_VERSION.to_string());

        match &self.credential {
            Credential::ApiKey(key) => builder.bearer_auth(key),
            // The certificate travels in the TLS handshake; nothing to add.
            Credential::ClientCertificate | Credential::None => builder,
        }
    }

    fn token(&self) -> Result<&str> {
        self.session_token
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no session: call send_setup first"))
    }
}

/// Turn a non-2xx response into an error carrying the server's structured
/// `{code, message}` body, so a caller sees why it failed rather than only a
/// status number.
async fn read_success(resp: reqwest::Response, op: &str) -> Result<Vec<u8>> {
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = resp.bytes().await.unwrap_or_default();

    if status.is_success() {
        return Ok(body.to_vec());
    }

    let detail = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            let code = v.get("code")?.as_str()?.to_string();
            let message = v.get("message")?.as_str()?.to_string();
            Some(format!("{code}: {message}"))
        })
        .unwrap_or_else(|| String::from_utf8_lossy(&body).trim().to_string());

    // Surface Retry-After, so a caller can honour it without re-reading headers.
    let hint = match retry_after {
        Some(secs) if is_retryable_status(status) => format!(", retry after {secs}s"),
        _ => String::new(),
    };

    if detail.is_empty() {
        anyhow::bail!("{op} failed with status {status}{hint}");
    }
    anyhow::bail!("{op} failed with status {status} ({detail}){hint}");
}

/// Whether a failed request is worth retrying unchanged.
///
/// The server sets `Retry-After` on exactly these.
pub fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status.as_u16(),
        429 | 503 // rate limit / session quota / overloaded / shutting down
    )
}

/// Map a server error code to a semantic category, for callers that branch on the
/// reason rather than parse prose.
pub fn classify(code: &str) -> Option<&'static str> {
    Some(match code {
        "malformed_body" | "invalid_input" | "unsupported_version" | "body_too_large" => {
            "client_error"
        }
        "unauthenticated" | "missing_token" | "unknown_session" => "auth_error",
        "forbidden" => "permission_error",
        "session_limit"
        | "session_quota_exceeded"
        | "rate_limited"
        | "overloaded"
        | "shutting_down" => "transient",
        "internal" => "server_error",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_without_setup_fails_locally() {
        let c = EmsmClient::new("http://127.0.0.1:1").unwrap();
        assert!(!c.has_session());
        let err = c.token().unwrap_err().to_string();
        assert!(err.contains("call send_setup first"), "got: {err}");
    }

    #[test]
    fn base_url_trailing_slash_is_normalised() {
        let c = EmsmClient::new("http://example.com/").unwrap();
        assert_eq!(c.base_url, "http://example.com");
    }

    #[test]
    fn only_transient_statuses_are_retryable() {
        use reqwest::StatusCode as S;
        assert!(is_retryable_status(S::SERVICE_UNAVAILABLE));
        assert!(is_retryable_status(S::TOO_MANY_REQUESTS));
        assert!(!is_retryable_status(S::BAD_REQUEST));
        assert!(!is_retryable_status(S::UNAUTHORIZED));
        assert!(!is_retryable_status(S::FORBIDDEN));
        assert!(!is_retryable_status(S::PAYLOAD_TOO_LARGE));
    }

    #[test]
    fn every_server_error_code_is_classified() {
        for e in crate::protocol::error::tests::every_variant() {
            assert!(
                classify(e.code()).is_some(),
                "unclassified error code: {}",
                e.code()
            );
        }
        assert_eq!(classify("nonsense"), None);
    }

    #[test]
    fn auth_and_permission_errors_are_distinct_categories() {
        // A wrong credential and a session that belongs to someone else need
        // different handling, so they must not collapse to one category.
        assert_eq!(classify("unauthenticated"), Some("auth_error"));
        assert_eq!(classify("forbidden"), Some("permission_error"));
        assert_eq!(classify("rate_limited"), Some("transient"));
        assert_eq!(classify("body_too_large"), Some("client_error"));
    }

    #[test]
    fn builder_selects_the_credential_kind() {
        let keyed = EmsmClient::builder("http://x").api_key("ssk_a_b");
        assert!(matches!(keyed.credential, Credential::ApiKey(_)));

        let plain = EmsmClient::builder("http://x");
        assert!(matches!(plain.credential, Credential::None));
    }

    #[test]
    fn a_client_with_no_credential_adds_no_authorization_header() {
        let c = EmsmClient::new("http://127.0.0.1:1").unwrap();
        let req = c
            .request(reqwest::Method::POST, "/v1/setup")
            .build()
            .unwrap();
        assert!(req.headers().get(reqwest::header::AUTHORIZATION).is_none());
        // The version header is never optional.
        assert_eq!(
            req.headers().get(VERSION_HEADER).unwrap(),
            &PROTOCOL_VERSION.to_string()
        );
    }

    #[test]
    fn an_api_key_client_sends_a_bearer_header() {
        let c = EmsmClient::builder("http://127.0.0.1:1")
            .api_key("ssk_0123456789abcdef_secret")
            .build()
            .unwrap();
        let req = c
            .request(reqwest::Method::POST, "/v1/prove")
            .build()
            .unwrap();
        let auth = req
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(auth, "Bearer ssk_0123456789abcdef_secret");
    }

    #[test]
    fn a_bad_ca_bundle_is_reported_at_build_time() {
        let err = EmsmClient::builder("https://x")
            .root_certificate_pem(b"not a certificate".to_vec())
            .build()
            .unwrap_err();
        assert!(!err.to_string().is_empty());
    }
}
