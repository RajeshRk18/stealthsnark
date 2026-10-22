//! Request middleware and extractors for the data plane.
//!
//!
//! Authentication runs once as a middleware layer over the whole `/v1`
//! router, and a handler states its requirements in its own signature:
//!
//! ```ignore
//! async fn handle_prove(
//!     ApiVersion: ApiVersion,      // version
//!     Caller(principal): Caller,   // authenticated
//!     session: OwnedSession,       // authorised for this session
//!     body: Bytes,
//! ) -> Result<Bytes, ApiError>
//! ```

use std::sync::Arc;

use axum::extract::{FromRequest, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{header::AUTHORIZATION, HeaderMap};
use axum::middleware::Next;
use axum::response::Response;
use axum::body::Bytes;
use tokio::sync::OwnedSemaphorePermit;

use super::auth::Principal;
use super::error::ApiError;
use super::messages::{PROTOCOL_VERSION, SESSION_HEADER, VERSION_HEADER};
use super::server::AppState;
use super::session::Session;

#[derive(Clone, Copy, Debug)]
pub struct ApiVersion;

/// The authenticated caller.
#[derive(Clone, Debug)]
pub struct Caller(pub Arc<Principal>);

/// A request body read under the caller's own tier limit.
///
/// `DefaultBodyLimit` can only apply one global ceiling, and the
/// `Content-Length` check in [`authenticate`] is skipped entirely by a chunked
/// or HTTP/2 sender that declares no length. This reads the body itself and
/// stops at `min(tier, transport)`
///
/// It takes an upload slot before it reads, so body memory is bounded by
/// `max_concurrent_uploads`, not by the number of connections. Hold the permit
/// for as long as the body is alive.
pub struct TieredBody(pub Bytes, pub OwnedSemaphorePermit);

impl FromRequest<AppState> for TieredBody {
    type Rejection = ApiError;

    async fn from_request(req: Request, app: &AppState) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();
        let Caller(principal) = Caller::from_request_parts(&mut parts, app).await?;
        let limit = principal.tier.max_body_bytes.min(app.config.max_body_bytes);
        let upload = app
            .acquire_slot(&app.upload_slots)
            .await
            .map_err(|e| app.reject(e))?;

        let bytes = axum::body::to_bytes(body, limit).await.map_err(|_| {
            app.reject(ApiError::BodyTooLarge {
                limit_bytes: limit as u64,
            })
        })?;
        Ok(TieredBody(bytes, upload))
    }
}

/// A session the caller is proven to own.
///
/// No `Debug` because it holds the session token which is a credential, and
/// also `Session` holds millions of curve points.
#[derive(Clone)]
pub struct OwnedSession {
    pub token: String,
    pub session: Arc<Session>,
}

pub async fn authenticate(
    State(app): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    require_version(request.headers())?;

    // A client certificate is inserted by the TLS listener when the handshake supplied one.
    #[cfg(feature = "tls")]
    let cert_digest = request
        .extensions()
        .get::<super::tls::PeerCertDigest>()
        .map(|d| d.0.clone());
    #[cfg(not(feature = "tls"))]
    let cert_digest: Option<String> = None;

    let presented_key = bearer_credential(request.headers());

    let principal = app
        .auth
        .authenticate(presented_key.as_deref(), cert_digest.as_deref())
        .map_err(|e| app.reject(e))?;

    app.quota
        .check_rate(&principal)
        .map_err(|e| app.reject(e))?;

    app.quota
        .check_body_size(&principal, content_length(request.headers()))
        .map_err(|e| app.reject(e))?;

    tracing::Span::current().record("principal", tracing::field::display(&principal.id));

    request.extensions_mut().insert(Arc::new(principal));
    Ok(next.run(request).await)
}

impl<S: Send + Sync> FromRequestParts<S> for ApiVersion {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        require_version(&parts.headers)?;
        Ok(Self)
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Arc<Principal>>()
            .cloned()
            .map(Caller)
            // Only reachable if a route is mounted outside the authenticate
            // layer. Treated as an internal fault, never as an open door.
            .ok_or_else(|| {
                ApiError::Internal("route is not covered by the authenticate layer".to_string())
            })
    }
}

impl FromRequestParts<AppState> for OwnedSession {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        app: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Caller(principal) = Caller::from_request_parts(parts, app).await?;
        let token = session_token(&parts.headers).map_err(|e| app.reject(e))?;
        let session = app
            .sessions
            .get_owned(&token, &principal.id)
            .map_err(|e| app.reject(e))?;
        Ok(Self { token, session })
    }
}

/// Reject a caller that does not speak this protocol version.
///
/// postcard is not self-describing, so a message struct that changed shape decodes
/// as something rather than failing. This turns that into a clean 400.
pub fn require_version(headers: &HeaderMap) -> Result<(), ApiError> {
    let raw = headers
        .get(VERSION_HEADER)
        .ok_or_else(|| ApiError::UnsupportedVersion {
            got: "<missing>".to_string(),
        })?;
    let text = raw.to_str().map_err(|_| ApiError::UnsupportedVersion {
        got: "<non-ascii>".to_string(),
    })?;
    match text.trim().parse::<u32>() {
        Ok(v) if v == PROTOCOL_VERSION => Ok(()),
        _ => Err(ApiError::UnsupportedVersion {
            got: text.trim().to_string(),
        }),
    }
}

/// Read `Authorization: Bearer <value>`. `None` when absent or not a bearer.
///
/// Absence is not an error here: under mTLS the credential is the certificate,
/// and the auth store decides what is acceptable.
fn bearer_credential(headers: &HeaderMap) -> Option<String> {
    let text = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let value = text
        .strip_prefix("Bearer ")
        .or_else(|| text.strip_prefix("bearer "))?
        .trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// Read the session token header.
pub fn session_token(headers: &HeaderMap) -> Result<String, ApiError> {
    let raw = headers.get(SESSION_HEADER).ok_or(ApiError::MissingToken)?;
    let text = raw.to_str().map_err(|_| ApiError::MissingToken)?.trim();
    if text.is_empty() {
        return Err(ApiError::MissingToken);
    }
    Ok(text.to_string())
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(axum::http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn version_must_match_exactly() {
        let ok = headers(&[(VERSION_HEADER, &PROTOCOL_VERSION.to_string())]);
        assert!(require_version(&ok).is_ok());

        let missing = require_version(&HeaderMap::new()).unwrap_err();
        assert_eq!(missing.code(), "unsupported_version");
        assert!(missing.to_string().contains("<missing>"));

        // Version 1 sent the session token in Authorization, so accepting it
        // would mean reading a session token as an API key. Version 2 used
        // bincode bodies, which do not decode as postcard.
        for bad in ["1", "2", "0", "4", "banana", ""] {
            let e = require_version(&headers(&[(VERSION_HEADER, bad)])).unwrap_err();
            assert_eq!(e.code(), "unsupported_version", "accepted version {bad:?}");
        }
    }

    #[test]
    fn bearer_credential_parsing() {
        assert_eq!(
            bearer_credential(&headers(&[("authorization", "Bearer ssk_a_b")])).as_deref(),
            Some("ssk_a_b")
        );
        // Lowercase scheme is tolerated.
        assert_eq!(
            bearer_credential(&headers(&[("authorization", "bearer x")])).as_deref(),
            Some("x")
        );
        // Absent or not a bearer: not an error, because mTLS may supply identity.
        assert!(bearer_credential(&HeaderMap::new()).is_none());
        for bad in ["x", "Basic abc", "Bearer ", "Bearer    "] {
            assert!(
                bearer_credential(&headers(&[("authorization", bad)])).is_none(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn session_token_comes_from_its_own_header() {
        let h = headers(&[(SESSION_HEADER, "deadbeef")]);
        assert_eq!(session_token(&h).unwrap(), "deadbeef");

        // A token in Authorization must not be accepted: that slot is the API key.
        let wrong_slot = headers(&[("authorization", "Bearer deadbeef")]);
        assert_eq!(
            session_token(&wrong_slot).unwrap_err().code(),
            "missing_token"
        );

        for bad in ["", "   "] {
            assert_eq!(
                session_token(&headers(&[(SESSION_HEADER, bad)]))
                    .unwrap_err()
                    .code(),
                "missing_token"
            );
        }
        assert_eq!(
            session_token(&HeaderMap::new()).unwrap_err().code(),
            "missing_token"
        );
    }

    #[test]
    fn content_length_is_read_when_sane() {
        assert_eq!(
            content_length(&headers(&[("content-length", "4096")])),
            Some(4096)
        );
        assert_eq!(content_length(&HeaderMap::new()), None);
        // Unparseable means "unknown", so the transport limit takes over.
        assert_eq!(content_length(&headers(&[("content-length", "big")])), None);
        assert_eq!(content_length(&headers(&[("content-length", "-1")])), None);
    }
}
