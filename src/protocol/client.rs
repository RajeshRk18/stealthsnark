//! HTTP client for the EMSM server.
//!
//! The session token is obtained from `/v1/setup` and held here; callers never
//! construct one. `send_prove` refuses to run without it, so "forgot to set up"
//! is a local error rather than a confusing 401 from the server.

use std::time::Duration;

use anyhow::Result;

use super::error::ApiError;
use super::messages::{
    ProveRequest, ProveResponse, SetupRequest, SetupResponse, PROTOCOL_VERSION, VERSION_HEADER,
};

/// Default per-request ceiling.
///
/// Generous because a large honest MSM legitimately takes minutes; the point is
/// to have *a* bound, since `reqwest::Client::new()` has none and a stalled
/// server would otherwise hang a client forever with no way to recover.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

/// Connect timeout. Short — failing to establish a TCP connection is not
/// something that gets better by waiting ten minutes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A client bound to one server-issued session.
pub struct EmsmClient {
    base_url: String,
    client: reqwest::Client,
    /// Set by [`EmsmClient::send_setup`]. `None` until then.
    session_token: Option<String>,
    session_label: Option<String>,
}

impl EmsmClient {
    /// Create a client with [`DEFAULT_REQUEST_TIMEOUT`].
    pub fn new(base_url: &str) -> Result<Self> {
        Self::with_timeout(base_url, DEFAULT_REQUEST_TIMEOUT)
    }

    pub fn with_timeout(base_url: &str, request_timeout: Duration) -> Result<Self> {
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(request_timeout)
                .connect_timeout(CONNECT_TIMEOUT)
                .build()?,
            session_token: None,
            session_label: None,
        })
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
            .client
            .post(format!("{}/v1/setup", self.base_url))
            .header("Content-Type", "application/octet-stream")
            .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
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
        let token = self.token()?;
        let body = bincode::serialize(request)?;
        let resp = self
            .client
            .post(format!("{}/v1/prove", self.base_url))
            .header("Content-Type", "application/octet-stream")
            .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
            .bearer_auth(token)
            .body(body)
            .send()
            .await?;

        let bytes = read_success(resp, "prove").await?;
        Ok(bincode::deserialize(&bytes)?)
    }

    /// `DELETE /v1/session` — free the server's copy of the generators now
    /// instead of leaving them pinned until the idle TTL expires.
    pub async fn release(&self) -> Result<()> {
        let token = self.token()?;
        let resp = self
            .client
            .delete(format!("{}/v1/session", self.base_url))
            .header(VERSION_HEADER, PROTOCOL_VERSION.to_string())
            .bearer_auth(token)
            .send()
            .await?;
        read_success(resp, "release").await?;
        Ok(())
    }

    fn token(&self) -> Result<&str> {
        self.session_token
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no session: call send_setup first"))
    }
}

/// Turn a non-2xx response into an error carrying the server's structured
/// `{code, message}` body, so a caller sees *why* it failed rather than just a
/// status number.
async fn read_success(resp: reqwest::Response, op: &str) -> Result<Vec<u8>> {
    let status = resp.status();
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

    if detail.is_empty() {
        anyhow::bail!("{op} failed with status {status}");
    }
    anyhow::bail!("{op} failed with status {status} ({detail})");
}

/// Whether a failed request is worth retrying unchanged.
///
/// Exposed so callers can back off on load-shedding rather than treating a 503
/// as fatal; the server sets `Retry-After` on exactly these.
pub fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status.as_u16(),
        429 | 503 // ApiError::SessionLimit | Overloaded / ShuttingDown
    )
}

/// Map a server error code back to the semantic category, for callers that want
/// to branch on the reason rather than parse prose.
pub fn classify(code: &str) -> Option<&'static str> {
    Some(match code {
        "malformed_body" | "invalid_input" | "unsupported_version" => "client_error",
        "missing_token" | "unknown_session" => "auth_error",
        "session_limit" | "overloaded" | "shutting_down" => "transient",
        "internal" => "server_error",
        _ => return None,
    })
}

/// Compile-time reminder that [`classify`] covers every [`ApiError`] code.
#[allow(dead_code)]
fn _classify_is_exhaustive(e: &ApiError) -> &'static str {
    classify(e.code()).expect("every ApiError code must be classified")
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
        assert!(!is_retryable_status(S::PAYLOAD_TOO_LARGE));
    }

    #[test]
    fn every_server_error_code_is_classified() {
        for e in [
            ApiError::MalformedBody(String::new()),
            ApiError::UnsupportedVersion { got: "9".into() },
            ApiError::MissingToken,
            ApiError::UnknownSession,
            ApiError::InvalidInput(String::new()),
            ApiError::SessionLimit,
            ApiError::Overloaded,
            ApiError::ShuttingDown,
            ApiError::Internal(String::new()),
        ] {
            assert!(
                classify(e.code()).is_some(),
                "unclassified error code: {}",
                e.code()
            );
        }
        assert_eq!(classify("nonsense"), None);
    }
}
