//! HTTP client for the EMSM server.
//!
//! # Credentials
//!
//! - client credential goes in `Authorization: Bearer <api key>`, or is
//!   supplied by a TLS client certificate under mTLS.
//! - The session token goes in `x-stealthsnark-session`.
//!

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use ark_bn254::{G1Affine, G2Affine};
use rand::Rng;

use crate::groth16::server_aided::{
    MaliciousEncryptedRequest, MaliciousServerResponse, ServerResponse,
};

use super::messages::{
    ark_from_bytes,
    wire_decode, wire_encode, ProveRequest, ProveResponse, ReleaseAllResponse, SetupRequest,
    SetupResponse, PROTOCOL_VERSION, SESSION_HEADER, VERSION_HEADER,
};

/// Default per-request ceiling.
///
/// Generous because a large honest MSM may takes minutes
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
#[derive(Debug)]
pub struct EmsmClientBuilder {
    base_url: String,
    request_timeout: Duration,
    credential: Credential,
    root_certificate_pem: Option<Vec<u8>>,
    client_identity_pem: Option<Vec<u8>>,
}

impl EmsmClientBuilder {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            credential: Credential::None,
            root_certificate_pem: None,
            client_identity_pem: None,
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

    pub fn build(self) -> Result<EmsmClient> {
        let mut builder = reqwest::Client::builder()
            .timeout(self.request_timeout)
            .connect_timeout(CONNECT_TIMEOUT)
            .use_rustls_tls();

        if let Some(pem) = &self.root_certificate_pem {
            let certs = reqwest::Certificate::from_pem_bundle(pem)?;

            // Invalid/empty custom bundle returns an empty list.
            // With this, we return early with a config error rather than a network error later.
            // The connection can be still successful if the server uses public root certificates as most servers do.
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

        Ok(EmsmClient {
            base_url: self.base_url,
            client: builder.build()?,
            credential: self.credential,
            session_token: None,
            session_label: None,
        })
    }
}

/// A client bound to a server-issued session.
pub struct EmsmClient {
    base_url: String,
    client: reqwest::Client,
    credential: Credential,
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

    /// `POST /v1/setup` upload generators and store the returned token.
    pub async fn send_setup(&mut self, request: &SetupRequest<'_>) -> Result<()> {
        let body = wire_encode(request)?;
        let resp = self
            .request(reqwest::Method::POST, "/v1/setup")
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        let bytes = read_success(resp, "setup").await?;
        let parsed: SetupResponse = wire_decode(&bytes)?;
        self.session_token = Some(parsed.session_token);
        self.session_label = Some(parsed.session_label);
        Ok(())
    }

    /// `POST /v1/prove` send masked vectors and receive the five MSM results.
    pub async fn send_prove(&self, request: &ProveRequest<'_>) -> Result<ProveResponse> {
        let body = wire_encode(request)?;
        let resp = self
            .request(reqwest::Method::POST, "/v1/prove")
            .header("Content-Type", "application/octet-stream")
            .header(SESSION_HEADER, self.token()?)
            .body(body)
            .send()
            .await?;

        let bytes = read_success(resp, "prove").await?;
        wire_decode(&bytes)
    }

    /// Malicious-secure prove: the main query and the check query go as two
    /// `/v1/prove` calls on this session, in random order, so the server cannot
    /// tell which one is the check. Pass the result to
    /// [`crate::groth16::server_aided::malicious_client_decrypt`], which detects a
    /// server that cheated on either call.
    pub async fn send_prove_malicious<R: Rng>(
        &self,
        request: &MaliciousEncryptedRequest,
        rng: &mut R,
    ) -> Result<MaliciousServerResponse> {
        let r = request;
        let main = ProveRequest::encode(
            &r.h.masked,
            &r.l.masked,
            &r.a.masked,
            &r.b_g1.masked,
            &r.b_g2.masked,
        )?;
        let check = ProveRequest::encode(
            &r.h.masked_check,
            &r.l.masked_check,
            &r.a.masked_check,
            &r.b_g1.masked_check,
            &r.b_g2.masked_check,
        )?;

        let check_first: bool = rng.gen();
        let (first, second) = if check_first { (&check, &main) } else { (&main, &check) };
        let first = decode_prove_response(&self.send_prove(first).await?)?;
        let second = decode_prove_response(&self.send_prove(second).await?)?;
        let (m, c) = if check_first { (second, first) } else { (first, second) };

        Ok(MaliciousServerResponse {
            em_h: m.em_h,
            em_h_ck: c.em_h,
            em_l: m.em_l,
            em_l_ck: c.em_l,
            em_a: m.em_a,
            em_a_ck: c.em_a,
            em_b_g1: m.em_b_g1,
            em_b_g1_ck: c.em_b_g1,
            em_b_g2: m.em_b_g2,
            em_b_g2_ck: c.em_b_g2,
        })
    }

    /// `DELETE /v1/session` free the server's copy of the generators
    ///
    /// Rationale behind this API:
    ///     - Client actively makes a request to clear its session data in the server. 
    ///       This is just an "optimization" and not the only way to clear session data.
    ///       Server releases once TTL/idle timeout expires anyway.
    /// Clears the local token on success. The token is released from the server, so
    /// keeping it would turn the next call into a 401.
    pub async fn release(&mut self) -> Result<()> {
        let resp = self
            .request(reqwest::Method::DELETE, "/v1/session")
            .header(SESSION_HEADER, self.token()?)
            .send()
            .await?;
        read_success(resp, "release").await?;
        self.forget_session();
        Ok(())
    }

    /// `DELETE /v1/sessions` release every session this client owns on the
    /// server. Returns how many were released.
    ///
    /// Needs no session token, only the client credential. Use it after a restart:
    /// the sessions from the previous run still count against this client's quota,
    /// and their tokens died with the old process.
    pub async fn release_all(&mut self) -> Result<u32> {
        let resp = self
            .request(reqwest::Method::DELETE, "/v1/sessions")
            .send()
            .await?;
        let bytes = read_success(resp, "release_all").await?;
        let parsed: ReleaseAllResponse = wire_decode(&bytes)?;
        self.forget_session();
        Ok(parsed.released)
    }

    fn forget_session(&mut self) {
        self.session_token = None;
        self.session_label = None;
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
            // The certificate travels in the TLS handshake.
            Credential::ClientCertificate | Credential::None => builder,
        }
    }

    fn token(&self) -> Result<&str> {
        self.session_token
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no session yet. call send_setup first"))
    }
}

/// Decode the five MSM results of a `/v1/prove` response.
pub fn decode_prove_response(pr: &ProveResponse) -> Result<ServerResponse> {
    Ok(ServerResponse {
        em_h: ark_from_bytes::<G1Affine>(&pr.em_h)?.into(),
        em_l: ark_from_bytes::<G1Affine>(&pr.em_l)?.into(),
        em_a: ark_from_bytes::<G1Affine>(&pr.em_a)?.into(),
        em_b_g1: ark_from_bytes::<G1Affine>(&pr.em_b_g1)?.into(),
        em_b_g2: ark_from_bytes::<G2Affine>(&pr.em_b_g2)?.into(),
    })
}

/// Turn a non-2xx response into an error carrying the server's structured
/// `{code, message}` body, so a caller can see why it failed rather than only a
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
        | "inflight_limit"
        | "rate_limited"
        | "overloaded"
        | "shutting_down" => "transient",
        "internal" | "timeout" => "server_error",
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
    fn builder_selects_the_credential_kind_and_tls_options() {
        let keyed = EmsmClient::builder("http://x").api_key("ssk_a_b");
        assert!(matches!(keyed.credential, Credential::ApiKey(_)));

        let plain = EmsmClient::builder("http://x");
        assert!(matches!(plain.credential, Credential::None));

        // Supplying an identity implies the certificate is the credential.
        let certed = EmsmClient::builder("http://x").client_identity_pem(b"pem".to_vec());
        assert!(matches!(certed.credential, Credential::ClientCertificate));
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
