//! HTTP server for the EMSM protocol.
//!
//! # Two listeners
//!
//! | Plane | Bind | Transport | Credential | Paths |
//! |---|---|---|---|---|
//! | Data | `STEALTHSNARK_BIND` | TLS when configured | API key or client certificate | `/v1/*` |
//! | Admin | loopback only | plain HTTP | none | `/livez`, `/readyz`, `/metrics` |
//!
//! The split is deliberate. A health probe must work without a credential, and
//! `/metrics` reports internal state that must not leave the host. One port
//! cannot satisfy both; two ports satisfy both without any conditional
//! authentication rule that could be got wrong.
//!
//! # Data plane endpoints
//!
//! Bodies are bincode over `application/octet-stream`. Every request carries
//! `x-stealthsnark-version`. `/v1/prove` and `/v1/session` also carry
//! `x-stealthsnark-session`.
//!
//! | Method | Path | Purpose |
//! |---|---|---|
//! | POST | `/v1/setup` | Upload generators, receive a session token |
//! | POST | `/v1/prove` | Evaluate the five MSMs |
//! | DELETE | `/v1/session` | Release generators early |
//!
//! # Two structural properties
//!
//! **No CPU work runs on the async runtime.** Point deserialization performs
//! on-curve and subgroup checks per point, and MSM evaluation takes seconds to
//! minutes. Both in an `async fn` block a tokio worker, and enough concurrent
//! requests starve the runtime — including the health endpoints, so an
//! orchestrator cannot tell the process is wedged. Everything expensive runs in
//! [`tokio::task::spawn_blocking`].
//!
//! **Locks are never held across expensive work.** `/v1/prove` takes a read lock
//! only long enough to clone an `Arc<Session>`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ark_bn254::{Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::CurveGroup;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::Router;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use super::auth::AuthStore;
use super::config::ServerConfig;
use super::error::ApiError;
use super::extract::{ApiVersion, Caller, OwnedSession};
use super::messages::*;
use super::metrics::Metrics;
use super::quota::QuotaEnforcer;
use super::session::{Generators, Session, SessionStore};

/// Shared server state. Cheap to clone — every field is behind an `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ServerConfig>,
    pub auth: Arc<AuthStore>,
    pub quota: Arc<QuotaEnforcer>,
    pub sessions: Arc<SessionStore>,
    pub metrics: Arc<Metrics>,
    /// Admission control for MSM evaluation. See
    /// [`ServerConfig::max_concurrent_msm`] for why the bound is small.
    pub msm_slots: Arc<Semaphore>,
    pub shutting_down: Arc<AtomicBool>,
}

impl AppState {
    /// State with authentication disabled. For tests and loopback development.
    pub fn new(config: ServerConfig) -> Self {
        Self::with_auth(config, AuthStore::disabled())
    }

    pub fn with_auth(config: ServerConfig, auth: AuthStore) -> Self {
        let sessions = Arc::new(SessionStore::new(config.max_sessions, config.session_ttl));
        let msm_slots = Arc::new(Semaphore::new(config.max_concurrent_msm));
        Self {
            config: Arc::new(config),
            auth: Arc::new(auth),
            quota: Arc::new(QuotaEnforcer::new()),
            sessions,
            metrics: Arc::new(Metrics::default()),
            msm_slots,
            shutting_down: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Wait a bounded time for an MSM slot.
    ///
    /// Shedding with 503 and `Retry-After` beats queueing without limit: a client
    /// learns at once that it should back off, rather than after a timeout it
    /// cannot tell apart from a crash.
    async fn acquire_msm_slot(&self) -> Result<OwnedSemaphorePermit, ApiError> {
        if self.shutting_down.load(Ordering::Relaxed) {
            return Err(ApiError::ShuttingDown);
        }
        let slots = self.msm_slots.clone();
        match tokio::time::timeout(self.config.admission_wait, slots.acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            // The semaphore closes only while the process tears down.
            Ok(Err(_)) => Err(ApiError::ShuttingDown),
            Err(_elapsed) => Err(ApiError::Overloaded),
        }
    }

    /// Count a refusal, then return it unchanged.
    pub(crate) fn reject(&self, err: ApiError) -> ApiError {
        self.metrics.record_rejection(&err);
        err
    }
}

/// Build the data-plane router: `/v1/*`, authenticated.
pub fn create_router(state: AppState) -> Router {
    let cfg = state.config.clone();

    // The server-wide limit is the hard ceiling; a tier can only be more
    // restrictive. The quota middleware applies each principal's own smaller
    // limit afterwards, so a small tier still gets a small cap. `serve` warns if
    // a tier is configured above this value, because that part of it is
    // unreachable.
    let transport_limit = cfg.max_body_bytes;

    let routes = Router::new()
        .route("/v1/setup", post(handle_setup))
        .route("/v1/prove", post(handle_prove))
        .route("/v1/session", delete(handle_release))
        // Authentication, rate limit, and body-size quota run once for every
        // route below, so no route can be added without them.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            super::extract::authenticate,
        ))
        // axum's default body limit is 2 MiB, which rejects any circuit needing
        // more than roughly 16k generators per MSM — every circuit worth
        // outsourcing.
        .layer(DefaultBodyLimit::max(transport_limit));

    with_common_layers(routes, &cfg).with_state(state)
}

/// Build the admin-plane router: health and metrics, no credential.
pub fn create_admin_router(state: AppState) -> Router {
    let cfg = state.config.clone();
    let routes = Router::new()
        .route("/livez", get(handle_livez))
        .route("/readyz", get(handle_readyz))
        .route("/metrics", get(handle_metrics));

    with_common_layers(routes, &cfg).with_state(state)
}

/// Apply the middleware shared by both planes.
///
/// Outermost first: a panicking handler becomes one 500 rather than a dead
/// process, and a wedged request cannot hold a connection for ever. The request
/// id is set before `TraceLayer` so that every log line for a request correlates.
fn with_common_layers<S>(router: Router<S>, cfg: &ServerConfig) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .layer(CatchPanicLayer::new())
        // 503 rather than the default 408: a timed-out MSM is a server-side
        // condition, and the client may retry it.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            cfg.request_timeout,
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(TraceLayer::new_for_http())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}

/// Bind both planes, serve, and drain on SIGINT or SIGTERM.
pub async fn serve(state: AppState) -> anyhow::Result<()> {
    let cfg = state.config.clone();

    tokio::spawn(sweeper(state.clone()));

    let admin = tokio::net::TcpListener::bind(cfg.admin_bind_addr).await?;
    let admin_addr = admin.local_addr()?;

    tracing::info!(
        data_addr = %cfg.bind_addr,
        admin_addr = %admin_addr,
        scheme = cfg.scheme(),
        auth_mode = ?cfg.auth_mode,
        mutual_tls = cfg
            .tls
            .as_ref()
            .map(|t| t.client_ca.is_some())
            .unwrap_or(false),
        principals = state.auth.principal_count(),
        api_keys = state.auth.api_key_count(),
        client_certs = state.auth.client_cert_count(),
        max_body_mib = cfg.max_body_bytes / (1024 * 1024),
        max_sessions = cfg.max_sessions,
        max_concurrent_msm = cfg.max_concurrent_msm,
        session_ttl_secs = cfg.session_ttl.as_secs(),
        peak_body_mib = cfg.peak_body_bytes() / (1024 * 1024),
        "StealthSnark server listening"
    );

    if !cfg.auth_mode.is_enabled() {
        // Loud, because `validate` only permits this on loopback and an operator
        // who did not intend it should see it immediately.
        tracing::warn!("authentication is DISABLED; every caller is the `anonymous` principal");
    }
    if !cfg.tls_enabled() {
        tracing::warn!(
            "TLS is not configured; the data plane serves plain HTTP and expects a \
             proxy to terminate TLS"
        );
    }

    // A tier above the transport ceiling is not an error, but the operator should
    // know that the extra allowance can never be used.
    let widest_tier = state.auth.max_body_bytes_over_tiers();
    if widest_tier > cfg.max_body_bytes {
        tracing::warn!(
            tier_max_body_bytes = widest_tier,
            transport_max_body_bytes = cfg.max_body_bytes,
            "a tier allows a larger body than STEALTHSNARK_MAX_BODY_BYTES; \
             the transport limit binds first"
        );
    }

    let shutdown = shutdown_signal(state.clone());
    let admin_server = axum::serve(admin, create_admin_router(state.clone()))
        .with_graceful_shutdown(shutdown_flag(state.clone()));

    let data_server = serve_data_plane(state.clone());

    // The admin plane must stay up while the data plane drains, so that a probe
    // keeps answering during shutdown.
    let (data_result, admin_result, ()) = tokio::join!(data_server, admin_server, shutdown);
    admin_result?;
    data_result?;

    tracing::info!("server stopped cleanly");
    Ok(())
}

/// Serve the data plane, with TLS when configured.
async fn serve_data_plane(state: AppState) -> anyhow::Result<()> {
    let cfg = state.config.clone();
    let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await?;

    match &cfg.tls {
        None => {
            axum::serve(listener, create_router(state.clone()))
                .with_graceful_shutdown(shutdown_flag(state))
                .await?;
            Ok(())
        }
        Some(paths) => {
            #[cfg(feature = "tls")]
            {
                let require_cert = cfg.auth_mode.requires_client_cert();
                let tls_config = super::tls::server_config(paths, require_cert)?;
                serve_tls(listener, state, tls_config).await
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = paths;
                // `validate` refuses this configuration, so reaching here means a
                // caller bypassed it.
                anyhow::bail!("TLS configured but the `tls` feature is not compiled in")
            }
        }
    }
}

/// TLS accept loop.
///
/// Hand-rolled because `axum::serve` cannot expose the peer certificate, and mTLS
/// identity is useless if the handler cannot see who connected. Each accepted
/// connection completes its handshake, the peer certificate digest goes into the
/// request extensions, and hyper serves the connection from there.
#[cfg(feature = "tls")]
async fn serve_tls(
    listener: tokio::net::TcpListener,
    state: AppState,
    tls_config: rustls::ServerConfig,
) -> anyhow::Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as ConnBuilder;
    use tower::Service;

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let router = create_router(state.clone());
    let connections = Arc::new(tokio::sync::Semaphore::new(1024));

    loop {
        // Stop accepting as soon as shutdown begins, but let live connections
        // finish on their own.
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    // A single failed accept must not end the listener.
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            },
            () = wait_for_shutdown(state.clone()) => break,
        };

        let acceptor = acceptor.clone();
        let router = router.clone();
        // Bounds the number of half-open TLS handshakes, so a handshake flood
        // cannot exhaust memory.
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "connection limit reached; dropping");
            continue;
        };

        tokio::spawn(async move {
            let _permit = permit;

            // A handshake timeout is essential: a client that opens a socket and
            // sends nothing would otherwise hold the slot for ever.
            let handshake =
                tokio::time::timeout(std::time::Duration::from_secs(15), acceptor.accept(stream));
            let tls_stream = match handshake.await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    // `warn`, not `debug`. Under mTLS a rejected handshake means a
                    // client cannot connect at all, and it is the single most
                    // likely misconfiguration — a client certificate without the
                    // `clientAuth` extended key usage, which rustls requires. At
                    // debug level the operator sees an unreachable service and a
                    // silent server.
                    tracing::warn!(%peer, error = %e, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::warn!(%peer, "TLS handshake timed out");
                    return;
                }
            };

            // rustls has verified the chain against the configured client CA by
            // this point. The digest only maps a verified certificate to a
            // principal; it is not itself the trust decision.
            let cert_digest = super::tls::peer_digest(tls_stream.get_ref().1);

            let io = TokioIo::new(tls_stream);
            let service = hyper::service::service_fn(move |mut request: axum::http::Request<_>| {
                if let Some(digest) = cert_digest.clone() {
                    request
                        .extensions_mut()
                        .insert(super::tls::PeerCertDigest(digest));
                }
                router.clone().call(request)
            });

            if let Err(e) = ConnBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
            {
                tracing::debug!(%peer, error = %e, "connection closed with error");
            }
        });
    }

    tracing::info!("TLS listener stopped accepting new connections");
    Ok(())
}

/// Resolve once shutdown has been requested.
async fn wait_for_shutdown(state: AppState) {
    loop {
        if state.shutting_down.load(Ordering::Relaxed) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Graceful-shutdown future for an `axum::serve` call.
async fn shutdown_flag(state: AppState) {
    wait_for_shutdown(state).await;
}

/// Wait for a stop signal, then mark the server unready.
///
/// `/readyz` fails before the listener closes, so a load balancer drains traffic
/// while in-flight proofs finish. Cutting a proof short is the most expensive
/// thing that can be discarded here: the client has already paid for a trusted
/// setup and a large upload.
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

/// Release generators held by abandoned sessions, and forget idle rate buckets.
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

        // Without this the bucket map grows once per distinct principal and never
        // shrinks.
        let forgotten = state.quota.sweep(state.config.quota_bucket_idle);
        if forgotten > 0 {
            tracing::debug!(forgotten, "forgot idle rate-limit buckets");
        }
    }
}

// ---------------------------------------------------------------------------
// Admin handlers
// ---------------------------------------------------------------------------

async fn handle_livez() -> StatusCode {
    StatusCode::OK
}

/// Readiness, as distinct from liveness: the process is healthy, but it should
/// not receive more work now.
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

    let body = app.metrics.render(
        app.sessions.len(),
        app.msm_slots.available_permits(),
        app.quota.tracked_principals(),
    );

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

// ---------------------------------------------------------------------------
// Data-plane handlers
// ---------------------------------------------------------------------------

/// `POST /v1/setup` — store generators, return a session token.
async fn handle_setup(
    State(app): State<AppState>,
    _version: ApiVersion,
    Caller(principal): Caller,
    body: Bytes,
) -> Result<Bytes, ApiError> {
    // Charge the session quota before decoding, so an over-quota caller does not
    // get megabytes of point validation done for free.
    let held = app.sessions.count_for(&principal.id);
    if let Err(e) = app.quota.check_session_allowance(&principal, held) {
        app.metrics.setup_err.fetch_add(1, Ordering::Relaxed);
        return Err(app.reject(e));
    }

    // Decoding generators is heavy (subgroup checks per point), so it takes an
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

    let (token, label) = match app.sessions.insert(&principal.id, generators) {
        Ok(pair) => pair,
        Err(e) => {
            app.metrics.setup_err.fetch_add(1, Ordering::Relaxed);
            return Err(app.reject(e));
        }
    };

    app.metrics.setup_ok.fetch_add(1, Ordering::Relaxed);
    // `label`, never `token`: the token is a credential.
    tracing::info!(
        principal = %principal.id,
        tier = %principal.tier.name,
        auth = principal.method.as_str(),
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

/// `POST /v1/prove` — evaluate the five MSMs for an owned session.
async fn handle_prove(
    State(app): State<AppState>,
    _version: ApiVersion,
    Caller(principal): Caller,
    owned: OwnedSession,
    body: Bytes,
) -> Result<Bytes, ApiError> {
    let permit = app.acquire_msm_slot().await.map_err(|e| {
        app.metrics.prove_err.fetch_add(1, Ordering::Relaxed);
        app.reject(e)
    })?;

    let session = owned.session;
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
            tracing::warn!(principal = %principal.id, session = %label, error = %e, "prove failed");
            return Err(app.reject(e));
        }
    };

    let elapsed = started.elapsed();
    app.metrics.record_prove_ok(elapsed);
    tracing::info!(
        principal = %principal.id,
        session = %label,
        elapsed_ms = elapsed.as_millis() as u64,
        "evaluated 5 MSMs"
    );

    Ok(Bytes::from(bytes))
}

/// `DELETE /v1/session` — release generators without waiting for the TTL.
async fn handle_release(
    State(app): State<AppState>,
    _version: ApiVersion,
    Caller(principal): Caller,
    owned: OwnedSession,
) -> Result<StatusCode, ApiError> {
    let released = app
        .sessions
        .remove_owned(&owned.token, &principal.id)
        .map_err(|e| app.reject(e))?;

    tracing::info!(
        principal = %principal.id,
        session = %released.label,
        freed_mib = released.resident_bytes / (1024 * 1024),
        "session released"
    );
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

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
        // A second request finds no slot and is shed rather than parked for ever.
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

        // Saturated: not ready, but certainly alive.
        let err = handle_readyz(State(app.clone())).await.unwrap_err();
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(handle_livez().await, StatusCode::OK);
    }
}
