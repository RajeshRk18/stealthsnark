//! Typed API errors.
//!
//! The previous handlers returned a bare `StatusCode` for every failure, so a
//! client could not tell "scalar/generator length mismatch" from "bad point
//! encoding" from "corrupt bincode" — three problems with three different fixes,
//! one indistinguishable response. Each variant here carries a stable
//! machine-readable `code` that clients can branch on, plus prose for humans.

use axum::http::{
    header::{RETRY_AFTER, WWW_AUTHENTICATE},
    HeaderValue, StatusCode,
};
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

    /// No usable client credential. The detail is deliberately coarse — it never
    /// says which key ids exist or which certificates are registered.
    #[error("authentication failed: {0}")]
    Unauthenticated(String),

    /// Authenticated, but not permitted to touch this resource. Distinct from
    /// [`Self::Unauthenticated`]: retrying with the same credential is pointless.
    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("rate limit exceeded, retry in {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("session quota exceeded: this client may hold at most {limit} sessions")]
    SessionQuotaExceeded { limit: usize },

    #[error(
        "request body of {got_bytes} bytes exceeds the {limit_bytes} byte limit for this client"
    )]
    BodyTooLarge { limit_bytes: u64, got_bytes: u64 },

    #[error(
        "missing or malformed session token (expected the `{}` header)",
        super::messages::SESSION_HEADER
    )]
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
            Self::Unauthenticated(_) => "unauthenticated",
            Self::Forbidden(_) => "forbidden",
            Self::RateLimited { .. } => "rate_limited",
            Self::SessionQuotaExceeded { .. } => "session_quota_exceeded",
            Self::BodyTooLarge { .. } => "body_too_large",
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
            // 401: no acceptable credential. An unknown session token is also an
            // auth failure, not a precondition failure.
            Self::Unauthenticated(_) | Self::MissingToken | Self::UnknownSession => {
                StatusCode::UNAUTHORIZED
            }
            // 403: the credential is valid but does not reach this resource.
            // Retrying unchanged cannot help, which is why it is not a 401.
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::BodyTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::SessionLimit | Self::RateLimited { .. } | Self::SessionQuotaExceeded { .. } => {
                StatusCode::TOO_MANY_REQUESTS
            }
            Self::Overloaded | Self::ShuttingDown => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Whether a client may safely retry the same request unchanged.
    ///
    /// Quota and load-shedding failures clear with time. A bad credential, a bad
    /// body, or a forbidden resource never do.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Overloaded
                | Self::SessionLimit
                | Self::RateLimited { .. }
                | Self::SessionQuotaExceeded { .. }
        )
    }

    /// Seconds to advertise in `Retry-After`, when the error carries a useful hint.
    fn retry_after_secs(&self) -> Option<u64> {
        match self {
            Self::RateLimited { retry_after_secs } => Some(*retry_after_secs),
            Self::Overloaded | Self::SessionLimit | Self::SessionQuotaExceeded { .. } => Some(5),
            _ => None,
        }
    }

    /// Whether the response must carry a `WWW-Authenticate` challenge.
    ///
    /// Required by RFC 9110 for a 401, and it is what tells a client which
    /// credential to present rather than making it guess.
    fn needs_auth_challenge(&self) -> bool {
        matches!(self, Self::Unauthenticated(_))
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

        if let Some(secs) = self.retry_after_secs() {
            if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert(RETRY_AFTER, value);
            }
        }
        if self.needs_auth_challenge() {
            resp.headers_mut().insert(
                WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"stealthsnark\""),
            );
        }
        resp
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Every variant, so the checks below cannot silently miss a new one.
    ///
    /// Shared with `client::tests`, which asserts that every code it may receive
    /// is classified. A new variant therefore fails that test until it is handled.
    pub(crate) fn every_variant() -> Vec<ApiError> {
        vec![
            ApiError::MalformedBody(String::new()),
            ApiError::UnsupportedVersion { got: "9".into() },
            ApiError::Unauthenticated("nope".into()),
            ApiError::Forbidden("not yours".into()),
            ApiError::RateLimited {
                retry_after_secs: 7,
            },
            ApiError::SessionQuotaExceeded { limit: 4 },
            ApiError::BodyTooLarge {
                limit_bytes: 10,
                got_bytes: 11,
            },
            ApiError::MissingToken,
            ApiError::UnknownSession,
            ApiError::InvalidInput(String::new()),
            ApiError::SessionLimit,
            ApiError::Overloaded,
            ApiError::ShuttingDown,
            ApiError::Internal(String::new()),
        ]
    }

    #[test]
    fn codes_are_distinct() {
        let all = every_variant();
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
    fn authentication_and_authorization_are_distinguished() {
        // 401: the credential is missing or wrong; a different one may work.
        assert_eq!(
            ApiError::Unauthenticated("x".into()).status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(ApiError::UnknownSession.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(ApiError::MissingToken.status(), StatusCode::UNAUTHORIZED);

        // 403: the credential is fine but does not reach this resource.
        assert_eq!(
            ApiError::Forbidden("x".into()).status(),
            StatusCode::FORBIDDEN
        );
        assert!(
            !ApiError::Forbidden("x".into()).is_retryable(),
            "retrying a forbidden request unchanged cannot help"
        );
    }

    #[test]
    fn quota_failures_are_429_and_retryable() {
        for e in [
            ApiError::RateLimited {
                retry_after_secs: 3,
            },
            ApiError::SessionQuotaExceeded { limit: 2 },
            ApiError::SessionLimit,
        ] {
            assert_eq!(e.status(), StatusCode::TOO_MANY_REQUESTS, "{e}");
            assert!(e.is_retryable(), "{e}");
            assert!(
                e.retry_after_secs().is_some(),
                "{e} must hint a retry delay"
            );
        }
    }

    #[test]
    fn oversize_body_is_413_and_not_retryable() {
        let e = ApiError::BodyTooLarge {
            limit_bytes: 1024,
            got_bytes: 2048,
        };
        assert_eq!(e.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!e.is_retryable(), "the same body will not fit next time");
        // The client needs the limit to adapt, so it must be in the message.
        assert!(e.to_string().contains("1024"));
    }

    #[test]
    fn rate_limit_advertises_its_own_delay() {
        let e = ApiError::RateLimited {
            retry_after_secs: 42,
        };
        assert_eq!(e.retry_after_secs(), Some(42));
    }

    #[test]
    fn only_unauthenticated_carries_a_challenge() {
        for e in every_variant() {
            let expected = e.code() == "unauthenticated";
            assert_eq!(
                e.needs_auth_challenge(),
                expected,
                "wrong challenge decision for {}",
                e.code()
            );
        }
    }

    #[test]
    fn only_transient_failures_are_retryable() {
        assert!(ApiError::Overloaded.is_retryable());
        assert!(ApiError::SessionLimit.is_retryable());
        assert!(!ApiError::UnknownSession.is_retryable());
        assert!(!ApiError::MalformedBody(String::new()).is_retryable());
        assert!(!ApiError::Unauthenticated("x".into()).is_retryable());
    }
}
