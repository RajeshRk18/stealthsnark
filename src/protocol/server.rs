//! HTTP server for the EMSM protocol.
//!
//! Endpoints (all request/response bodies are bincode, `application/octet-stream`):
//!
//! | Method | Path           | Auth   | Purpose                                  |
//! |--------|----------------|--------|------------------------------------------|
//! | POST   | `/v1/setup`    | none   | upload generators, receive session token |
//! | POST   | `/v1/prove`    | bearer | evaluate the five MSMs                   |
//! | DELETE | `/v1/session`  | bearer | release generators early                 |
//! | GET    | `/livez`       | none   | process is up                            |
//! | GET    | `/readyz`      | none   | process can accept work                  |
//! | GET    | `/metrics`     | none   | Prometheus text format                   |
//!
//! Two structural properties are worth stating up front, because they are the
//! difference between this and the previous version.
//!
//! **No CPU work runs on the async runtime.** Both point deserialization (which
//! performs on-curve and subgroup checks per point) and MSM evaluation are
//! multi-second-to-multi-minute synchronous workloads. Running them in an `async
//! fn` blocks a tokio worker thread, and enough concurrent requests starve the
//! whole runtime — including the health endpoints, so an orchestrator cannot even
//! tell the process is wedged. Everything expensive happens inside
//! [`tokio::task::spawn_blocking`].
//!
//! **Locks are never held across expensive work.** `/prove` takes a read lock
//! only long enough to clone an `Arc<Session>`. The previous version held the
//! lock across all five MSMs, so no `/setup` could land while any proof was in
//! flight.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ark_bn254::{Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::CurveGroup;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::Router;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use super::config::ServerConfig;
use super::error::ApiError;
use super::messages::*;
use super::metrics::Metrics;
use super::session::{Generators, Session, SessionStore};

/// Shared server state. Cheap to clone — every field is behind an `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ServerConfig>,
    pub sessions: Arc<SessionStore>,
    pub metrics: Arc<Metrics>,
    /// Admission control for MSM evaluation. See
    /// [`ServerConfig::max_concurrent_msm`] for why the bound is small.
    pub msm_slots: Arc<Semaphore>,
    pub shutting_down: Arc<AtomicBool>,
}

impl AppState {
    pub fn new(config: ServerConfig) -> Self {
        let sessions = Arc::new(SessionStore::new(config.max_sessions, config.session_ttl));
        let msm_slots = Arc::new(Semaphore::new(config.max_concurrent_msm));
        Self {
            config: Arc::new(config),
            sessions,
            metrics: Arc::new(Metrics::default()),
            msm_slots,
            shutting_down: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Wait a bounded time for an MSM slot.
    ///
    /// Shedding with 503 + `Retry-After` beats queueing indefinitely: a client
    /// learns immediately that it should back off, rather than discovering it
    /// after a timeout it cannot distinguish from a crash.
    async fn acquire_msm_slot(&self) -> Result<OwnedSemaphorePermit, ApiError> {
        if self.shutting_down.load(Ordering::Relaxed) {
            return Err(ApiError::ShuttingDown);
        }
        let slots = self.msm_slots.clone();
        match tokio::time::timeout(self.config.admission_wait, slots.acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            // Semaphore closed — only happens if the process is tearing down.
            Ok(Err(_)) => Err(ApiError::ShuttingDown),
            Err(_elapsed) => Err(ApiError::Overloaded),
        }
    }

    fn reject(&self, err: ApiError) -> ApiError {
        self.metrics.record_rejection(&err);
        err
    }
}

/// Build the router. Exposed separately from [`serve`] so tests can drive the
/// app without binding a well-known port.
pub fn create_router(state: AppState) -> Router {
    let cfg = state.config.clone();

    Router::new()
        .route("/v1/setup", post(handle_setup))
        .route("/v1/prove", post(handle_prove))
        .route("/v1/session", delete(handle_release))
        .route("/livez", get(handle_livez))
        .route("/readyz", get(handle_readyz))
        .route("/metrics", get(handle_metrics))
        // The single most consequential line in this file: axum's default body
        // limit is 2 MiB, which rejects any circuit needing more than ~16k
        // generators per MSM — i.e. every circuit worth outsourcing.
        .layer(DefaultBodyLimit::max(cfg.max_body_bytes))
        // Outermost first: a panic in a handler becomes one 500 rather than a
        // dead process, and a wedged request cannot occupy a connection forever.
        .layer(CatchPanicLayer::new())
        // 503, not the default 408: a timed-out MSM means the server could not
        // finish in time, which is a server-side condition the client may retry.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            cfg.request_timeout,
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(TraceLayer::new_for_http())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .with_state(state)
}

/// Bind, serve, and drain on SIGINT/SIGTERM.
pub async fn serve(state: AppState) -> anyhow::Result<()> {
    let cfg = state.config.clone();

    tokio::spawn(sweeper(state.clone()));

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await?;
    let local = listener.local_addr()?;
    tracing::info!(
        addr = %local,
        max_body_mib = cfg.max_body_bytes / (1024 * 1024),
        max_sessions = cfg.max_sessions,
        max_concurrent_msm = cfg.max_concurrent_msm,
        session_ttl_secs = cfg.session_ttl.as_secs(),
        peak_body_mib = cfg.peak_body_bytes() / (1024 * 1024),
        "StealthSnark server listening"
    );

    axum::serve(listener, create_router(state.clone()))
        .with_graceful_shutdown(shutdown_signal(state))
        .await?;

    tracing::info!("server stopped cleanly");
    Ok(())
}

/// Resolve when the process is asked to stop, then mark the server unready.
///
/// Failing `/readyz` before the listener closes lets a load balancer drain
/// traffic while in-flight proofs finish. Killing a proof mid-flight is the most
/// expensive thing that can be thrown away here: the client already paid for a
/// trusted setup and a multi-hundred-MiB upload.
async fn shutdown_signal(state: AppState) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => tracing::warn!(error = %e, "cannot listen for SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    state.shutting_down.store(true, Ordering::Relaxed);
    tracing::info!(
        active_sessions = state.sessions.len(),
        "shutdown signal received; draining in-flight requests"
    );
}

/// Periodically release generators held by abandoned sessions.
async fn sweeper(state: AppState) {
    let mut ticker = tokio::time::interval(state.config.sweep_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if state.shutting_down.load(Ordering::Relaxed) {
            return;
        }
        let dropped = state.sessions.sweep();
        if dropped > 0 {
            state
                .metrics
                .sessions_evicted
                .fetch_add(dropped as u64, Ordering::Relaxed);
            tracing::info!(
                evicted = dropped,
                remaining = state.sessions.len(),
                resident_mib = state.sessions.resident_bytes() / (1024 * 1024),
                "swept idle sessions"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_livez() -> StatusCode {
    StatusCode::OK
}

/// Readiness, as distinct from liveness: the process is fine, but it should not
/// receive more work right now.
async fn handle_readyz(State(app): State<AppState>) -> Result<&'static str, ApiError> {
    if app.shutting_down.load(Ordering::Relaxed) {
        return Err(ApiError::ShuttingDown);
    }
    if app.msm_slots.available_permits() == 0 {
        return Err(ApiError::Overloaded);
    }
    Ok("ready")
}

async fn handle_metrics(State(app): State<AppState>) -> impl IntoResponse {
    // Keep the store's own eviction counter authoritative.
    app.metrics
        .sessions_evicted
        .store(app.sessions.evicted_total(), Ordering::Relaxed);

    let body = app
        .metrics
        .render(app.sessions.len(), app.msm_slots.available_permits());

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

/// `POST /v1/setup` — store generators, return a server-issued session token.
async fn handle_setup(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Bytes, ApiError> {
    require_version(&headers)?;

    // Decoding generators is heavy (subgroup checks per point), so it consumes an
    // admission slot just as proving does.
    let permit = app.acquire_msm_slot().await.map_err(|e| {
        app.metrics.setup_err.fetch_add(1, Ordering::Relaxed);
        app.reject(e)
    })?;

    let started = Instant::now();
    let decoded = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        decode_generators(&body)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("setup task panicked or was cancelled: {e}")))?;

    let generators = match decoded {
        Ok(g) => g,
        Err(e) => {
            app.metrics.setup_err.fetch_add(1, Ordering::Relaxed);
            return Err(app.reject(e));
        }
    };

    let counts = generators.counts();
    let resident = generators.resident_bytes();

    let (token, label) = match app.sessions.insert(generators) {
        Ok(pair) => pair,
        Err(e) => {
            app.metrics.setup_err.fetch_add(1, Ordering::Relaxed);
            return Err(app.reject(e));
        }
    };

    app.metrics.setup_ok.fetch_add(1, Ordering::Relaxed);
    // `label`, never `token`: the token is a bearer credential.
    tracing::info!(
        session = %label,
        h = counts[0], l = counts[1], a = counts[2],
        b_g1 = counts[3], b_g2 = counts[4],
        resident_mib = resident / (1024 * 1024),
        elapsed_ms = started.elapsed().as_millis() as u64,
        active_sessions = app.sessions.len(),
        "session established"
    );

    let response = SetupResponse {
        session_token: token,
        session_label: label,
    };
    Ok(Bytes::from(encode(&response)?))
}

/// `POST /v1/prove` — evaluate the five MSMs for an authenticated session.
async fn handle_prove(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Bytes, ApiError> {
    require_version(&headers)?;
    let token = bearer_token(&headers).map_err(|e| {
        app.metrics.prove_err.fetch_add(1, Ordering::Relaxed);
        app.reject(e)
    })?;

    // Short read lock: clone an Arc and release. Never held across the MSMs.
    let session = match app.sessions.get(&token) {
        Some(s) => s,
        None => {
            app.metrics.prove_err.fetch_add(1, Ordering::Relaxed);
            return Err(app.reject(ApiError::UnknownSession));
        }
    };

    let permit = app.acquire_msm_slot().await.map_err(|e| {
        app.metrics.prove_err.fetch_add(1, Ordering::Relaxed);
        app.reject(e)
    })?;

    let label = session.label.clone();
    let started = Instant::now();

    let computed = tokio::task::spawn_blocking(move || {
        let _permit = permit; // released when the MSMs finish
        evaluate_msms(&session, &body)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("prove task panicked or was cancelled: {e}")))?;

    let bytes = match computed {
        Ok(b) => b,
        Err(e) => {
            app.metrics.prove_err.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(session = %label, error = %e, "prove failed");
            return Err(app.reject(e));
        }
    };

    let elapsed = started.elapsed();
    app.metrics.record_prove_ok(elapsed);
    tracing::info!(
        session = %label,
        elapsed_ms = elapsed.as_millis() as u64,
        "evaluated 5 MSMs"
    );

    Ok(Bytes::from(bytes))
}

/// `DELETE /v1/session` — release generators without waiting for the TTL.
async fn handle_release(
    State(app): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    require_version(&headers)?;
    let token = bearer_token(&headers)?;

    match app.sessions.remove(&token) {
        Some(s) => {
            tracing::info!(
                session = %s.label,
                freed_mib = s.resident_bytes / (1024 * 1024),
                "session released"
            );
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(app.reject(ApiError::UnknownSession)),
    }
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

/// Reject a client that does not speak this protocol version.
///
/// bincode is not self-describing, so a struct that gained a field decodes as
/// *something* rather than failing. Without this check that is silent corruption;
/// with it, it is a clear 400.
fn require_version(headers: &HeaderMap) -> Result<(), ApiError> {
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
            got: text.to_string(),
        }),
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<String, ApiError> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(ApiError::MissingToken)?;
    let text = raw.to_str().map_err(|_| ApiError::MissingToken)?;
    let token = text
        .strip_prefix("Bearer ")
        .or_else(|| text.strip_prefix("bearer "))
        .ok_or(ApiError::MissingToken)?
        .trim();
    if token.is_empty() {
        return Err(ApiError::MissingToken);
    }
    Ok(token.to_string())
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ApiError> {
    bincode::serialize(value)
        .map_err(|e| ApiError::Internal(format!("response encode failed: {e}")))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    bincode::deserialize(bytes).map_err(|e| ApiError::MalformedBody(e.to_string()))
}

// ---------------------------------------------------------------------------
// Blocking compute — runs on the blocking pool, never the async runtime
// ---------------------------------------------------------------------------

/// Decode all five generator sets and build the commitment keys.
fn decode_generators(body: &[u8]) -> Result<Generators, ApiError> {
    let req: SetupRequest = decode(body)?;
    let points = |field: &str, raw: &[u8]| -> Result<Vec<G1Affine>, ApiError> {
        ark_vec_from_bytes(raw).map_err(|e| ApiError::InvalidInput(format!("{field}: {e}")))
    };

    let h = points("h_generators", &req.h_generators)?;
    let l = points("l_generators", &req.l_generators)?;
    let a = points("a_generators", &req.a_generators)?;
    let b_g1 = points("b_g1_generators", &req.b_g1_generators)?;
    let b_g2: Vec<G2Affine> = ark_vec_from_bytes(&req.b_g2_generators)
        .map_err(|e| ApiError::InvalidInput(format!("b_g2_generators: {e}")))?;

    Ok(Generators::from_points(h, l, a, b_g1, b_g2))
}

/// Decode the masked scalar vectors and evaluate the five MSMs.
fn evaluate_msms(session: &Session, body: &[u8]) -> Result<Vec<u8>, ApiError> {
    let req: ProveRequest = decode(body)?;

    let scalars = |field: &str, raw: &[u8]| -> Result<Vec<Fr>, ApiError> {
        ark_vec_from_bytes(raw).map_err(|e| ApiError::InvalidInput(format!("{field}: {e}")))
    };

    let v_h = scalars("v_h", &req.v_h)?;
    let v_l = scalars("v_l", &req.v_l)?;
    let v_a = scalars("v_a", &req.v_a)?;
    let v_b_g1 = scalars("v_b_g1", &req.v_b_g1)?;
    let v_b_g2 = scalars("v_b_g2", &req.v_b_g2)?;

    let g = &session.generators;
    let commit_g1 = |field: &str, ped: &crate::emsm::pedersen::Pedersen<G1>, v: &[Fr]| {
        ped.commit(v)
            .map_err(|e| ApiError::InvalidInput(format!("{field}: {e}")))
    };

    let em_h = commit_g1("v_h", &g.ped_h, &v_h)?;
    let em_l = commit_g1("v_l", &g.ped_l, &v_l)?;
    let em_a = commit_g1("v_a", &g.ped_a, &v_a)?;
    let em_b_g1 = commit_g1("v_b_g1", &g.ped_b_g1, &v_b_g1)?;
    let em_b_g2: G2 = g
        .ped_b_g2
        .commit(&v_b_g2)
        .map_err(|e| ApiError::InvalidInput(format!("v_b_g2: {e}")))?;

    let to_bytes = |field: &str, v: &dyn Fn() -> Result<Vec<u8>, anyhow::Error>| {
        v().map_err(|e| ApiError::Internal(format!("{field}: {e}")))
    };

    let response = ProveResponse {
        em_h: to_bytes("em_h", &|| ark_to_bytes(&em_h.into_affine()))?,
        em_l: to_bytes("em_l", &|| ark_to_bytes(&em_l.into_affine()))?,
        em_a: to_bytes("em_a", &|| ark_to_bytes(&em_a.into_affine()))?,
        em_b_g1: to_bytes("em_b_g1", &|| ark_to_bytes(&em_b_g1.into_affine()))?,
        em_b_g2: to_bytes("em_b_g2", &|| ark_to_bytes(&em_b_g2.into_affine()))?,
    };

    encode(&response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
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
    fn version_header_is_required_and_checked() {
        assert!(require_version(&headers_with(&[(VERSION_HEADER, "1")])).is_ok());

        let missing = require_version(&HeaderMap::new()).unwrap_err();
        assert_eq!(missing.code(), "unsupported_version");
        assert!(missing.to_string().contains("<missing>"));

        for bad in ["0", "2", "abc", ""] {
            let e = require_version(&headers_with(&[(VERSION_HEADER, bad)])).unwrap_err();
            assert_eq!(e.code(), "unsupported_version", "accepted version {bad:?}");
        }
    }

    #[test]
    fn bearer_token_parsing() {
        let ok = headers_with(&[("authorization", "Bearer deadbeef")]);
        assert_eq!(bearer_token(&ok).unwrap(), "deadbeef");

        // Lowercase scheme is tolerated; anything else is not a credential.
        let lower = headers_with(&[("authorization", "bearer deadbeef")]);
        assert_eq!(bearer_token(&lower).unwrap(), "deadbeef");

        for bad in ["deadbeef", "Basic deadbeef", "Bearer ", "Bearer    "] {
            let h = headers_with(&[("authorization", bad)]);
            assert_eq!(
                bearer_token(&h).unwrap_err().code(),
                "missing_token",
                "accepted {bad:?} as a token"
            );
        }
        assert_eq!(
            bearer_token(&HeaderMap::new()).unwrap_err().code(),
            "missing_token"
        );
    }

    #[test]
    fn malformed_setup_body_is_a_400_not_a_panic() {
        // `.err()` rather than `unwrap_err()`: Generators holds millions of curve
        // points in production and deliberately does not implement Debug.
        let e = decode_generators(&[0xff; 16])
            .err()
            .expect("garbage bytes must not decode");
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn admission_sheds_load_instead_of_queueing() {
        let app = AppState::new(ServerConfig {
            max_concurrent_msm: 1,
            admission_wait: std::time::Duration::from_millis(50),
            ..ServerConfig::default()
        });

        let held = app.acquire_msm_slot().await.unwrap();
        // Second request finds no slot and is shed rather than parked forever.
        let err = app.acquire_msm_slot().await.unwrap_err();
        assert_eq!(err.code(), "overloaded");
        assert!(err.is_retryable());

        drop(held);
        assert!(app.acquire_msm_slot().await.is_ok());
    }

    #[tokio::test]
    async fn shutdown_stops_admitting_work() {
        let app = AppState::new(ServerConfig::default());
        app.shutting_down.store(true, Ordering::Relaxed);
        assert_eq!(
            app.acquire_msm_slot().await.unwrap_err().code(),
            "shutting_down"
        );
        assert!(handle_readyz(State(app)).await.is_err());
    }

    #[tokio::test]
    async fn readyz_fails_when_saturated_but_livez_still_answers() {
        let app = AppState::new(ServerConfig {
            max_concurrent_msm: 1,
            ..ServerConfig::default()
        });

        assert!(handle_readyz(State(app.clone())).await.is_ok());
        let _held = app.acquire_msm_slot().await.unwrap();

        // Saturated: not ready, but definitely alive.
        let err = handle_readyz(State(app.clone())).await.unwrap_err();
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(handle_livez().await, StatusCode::OK);
    }
}
