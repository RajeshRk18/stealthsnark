//! Typed API errors.
//!
//! The previous handlers returned a bare `StatusCode` for every failure, so a
//! client could not tell "scalar/generator length mismatch" from "bad point
//! encoding" from "corrupt bincode" — three problems with three different fixes,
//! one indistinguishable response. Each variant here carries a stable
//! machine-readable `code` that clients can branch on, plus prose for humans.

use axum::http::{header::RETRY_AFTER, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use super::messages::PROTOCOL_VERSION;

/// An error returned by any `/v1` endpoint.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("malformed request body: {0}")]
    MalformedBody(String),

    #[error("unsupported protocol version {got}, server speaks {PROTOCOL_VERSION}")]
    UnsupportedVersion { got: String },

    #[error("missing or malformed Authorization header (expected `Bearer <token>`)")]
    MissingToken,

    #[error("unknown or expired session")]
    UnknownSession,

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("too many active sessions; retry later or release an existing session")]
    SessionLimit,

    #[error("server at capacity, retry shortly")]
    Overloaded,

    #[error("server is shutting down")]
    ShuttingDown,

    /// The detail is logged server-side and never sent to the caller.
    #[error("internal server error")]
    Internal(String),
}

impl ApiError {
    /// Stable machine-readable code. Clients branch on this, not on prose, so it
    /// must not change without a protocol version bump.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MalformedBody(_) => "malformed_body",
            Self::UnsupportedVersion { .. } => "unsupported_version",
            Self::MissingToken => "missing_token",
            Self::UnknownSession => "unknown_session",
            Self::InvalidInput(_) => "invalid_input",
            Self::SessionLimit => "session_limit",
            Self::Overloaded => "overloaded",
            Self::ShuttingDown => "shutting_down",
            Self::Internal(_) => "internal",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::MalformedBody(_) | Self::InvalidInput(_) | Self::UnsupportedVersion { .. } => {
                StatusCode::BAD_REQUEST
            }
            // An unknown session is an auth failure, not a precondition failure:
            // the caller presented no valid credential for the resource.
            Self::MissingToken | Self::UnknownSession => StatusCode::UNAUTHORIZED,
            Self::SessionLimit => StatusCode::TOO_MANY_REQUESTS,
            Self::Overloaded | Self::ShuttingDown => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Whether a client may safely retry the same request unchanged.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Overloaded | Self::SessionLimit)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Log internal detail; never leak server internals to an untrusted caller.
        if let Self::Internal(detail) = &self {
            tracing::error!(error = %detail, "internal error");
        }

        let body = json!({ "code": self.code(), "message": self.to_string() });
        let mut resp = (self.status(), Json(body)).into_response();

        if self.is_retryable() {
            resp.headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static("5"));
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_distinct() {
        let all = [
            ApiError::MalformedBody(String::new()),
            ApiError::UnsupportedVersion { got: "9".into() },
            ApiError::MissingToken,
            ApiError::UnknownSession,
            ApiError::InvalidInput(String::new()),
            ApiError::SessionLimit,
            ApiError::Overloaded,
            ApiError::ShuttingDown,
            ApiError::Internal(String::new()),
        ];
        let mut codes: Vec<&str> = all.iter().map(|e| e.code()).collect();
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n, "duplicate machine-readable error codes");
    }

    #[test]
    fn internal_detail_is_not_in_the_client_message() {
        let e = ApiError::Internal("secret path /etc/key".into());
        assert!(!e.to_string().contains("secret path"));
    }

    #[test]
    fn auth_failures_are_401_not_412() {
        assert_eq!(ApiError::UnknownSession.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(ApiError::MissingToken.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn only_transient_failures_are_retryable() {
        assert!(ApiError::Overloaded.is_retryable());
        assert!(ApiError::SessionLimit.is_retryable());
        assert!(!ApiError::UnknownSession.is_retryable());
        assert!(!ApiError::MalformedBody(String::new()).is_retryable());
    }
}
