use std::collections::HashMap;
use std::sync::Arc;

use ark_bn254::{Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::CurveGroup;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use tokio::sync::RwLock;

use super::messages::*;
use crate::emsm::pedersen::Pedersen;

/// Per-session state: generators received during setup.
struct SessionState {
    h_generators: Vec<G1Affine>,
    l_generators: Vec<G1Affine>,
    a_generators: Vec<G1Affine>,
    b_g1_generators: Vec<G1Affine>,
    b_g2_generators: Vec<G2Affine>,
}

/// Server state: stores per-session generator sets.
#[derive(Default)]
pub struct ServerState {
    sessions: HashMap<String, SessionState>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}

pub type SharedState = Arc<RwLock<ServerState>>;

/// Create the axum router with /setup and /prove endpoints.
pub fn create_router(state: SharedState) -> Router {
    Router::new()
        .route("/setup", post(handle_setup))
        .route("/prove", post(handle_prove))
        .with_state(state)
}

/// Setup request with session ID.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SetupEnvelope {
    pub session_id: String,
    pub request: Vec<u8>, // bincode-serialized SetupRequest
}

/// Prove request with session ID.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ProveEnvelope {
    pub session_id: String,
    pub request: Vec<u8>, // bincode-serialized ProveRequest
}

/// POST /setup: receive and store generators for a session.
async fn handle_setup(
    State(state): State<SharedState>,
    body: axum::body::Bytes,
) -> StatusCode {
    let envelope: SetupEnvelope = match bincode::deserialize(&body) {
        Ok(r) => r,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    let request: SetupRequest = match bincode::deserialize(&envelope.request) {
        Ok(r) => r,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    let h_gens: Vec<G1Affine> = match ark_vec_from_bytes(&request.h_generators) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let l_gens: Vec<G1Affine> = match ark_vec_from_bytes(&request.l_generators) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let a_gens: Vec<G1Affine> = match ark_vec_from_bytes(&request.a_generators) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let b_g1_gens: Vec<G1Affine> = match ark_vec_from_bytes(&request.b_g1_generators) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let b_g2_gens: Vec<G2Affine> = match ark_vec_from_bytes(&request.b_g2_generators) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    tracing::info!(
        "Setup [session={}]: h={}, l={}, a={}, b_g1={}, b_g2={}",
        envelope.session_id,
        h_gens.len(),
        l_gens.len(),
        a_gens.len(),
        b_g1_gens.len(),
        b_g2_gens.len()
    );

    let session = SessionState {
        h_generators: h_gens,
        l_generators: l_gens,
        a_generators: a_gens,
        b_g1_generators: b_g1_gens,
        b_g2_generators: b_g2_gens,
    };

    let mut state = state.write().await;
    state.sessions.insert(envelope.session_id, session);

    StatusCode::OK
}

/// POST /prove: evaluate 5 MSMs on masked vectors for a session.
async fn handle_prove(
    State(state): State<SharedState>,
    body: axum::body::Bytes,
) -> Result<axum::body::Bytes, StatusCode> {
    let envelope: ProveEnvelope =
        bincode::deserialize(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let request: ProveRequest =
        bincode::deserialize(&envelope.request).map_err(|_| StatusCode::BAD_REQUEST)?;

    let state = state.read().await;
    let session = state
        .sessions
        .get(&envelope.session_id)
        .ok_or(StatusCode::PRECONDITION_FAILED)?;

    // Deserialize masked scalars (fallible)
    let v_h: Vec<Fr> = ark_vec_from_bytes(&request.v_h).map_err(|_| StatusCode::BAD_REQUEST)?;
    let v_l: Vec<Fr> = ark_vec_from_bytes(&request.v_l).map_err(|_| StatusCode::BAD_REQUEST)?;
    let v_a: Vec<Fr> = ark_vec_from_bytes(&request.v_a).map_err(|_| StatusCode::BAD_REQUEST)?;
    let v_b_g1: Vec<Fr> =
        ark_vec_from_bytes(&request.v_b_g1).map_err(|_| StatusCode::BAD_REQUEST)?;
    let v_b_g2: Vec<Fr> =
        ark_vec_from_bytes(&request.v_b_g2).map_err(|_| StatusCode::BAD_REQUEST)?;

    tracing::info!("Prove [session={}]: computing 5 MSMs", envelope.session_id);

    // Compute MSMs (fallible — length mismatch returns 400 instead of panic)
    let em_h = Pedersen::<G1>::from_generators(session.h_generators.clone())
        .commit(&v_h)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let em_l = Pedersen::<G1>::from_generators(session.l_generators.clone())
        .commit(&v_l)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let em_a = Pedersen::<G1>::from_generators(session.a_generators.clone())
        .commit(&v_a)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let em_b_g1 = Pedersen::<G1>::from_generators(session.b_g1_generators.clone())
        .commit(&v_b_g1)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let em_b_g2 = Pedersen::<G2>::from_generators(session.b_g2_generators.clone())
        .commit(&v_b_g2)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let response = ProveResponse {
        em_h: ark_to_bytes(&em_h.into_affine()),
        em_l: ark_to_bytes(&em_l.into_affine()),
        em_a: ark_to_bytes(&em_a.into_affine()),
        em_b_g1: ark_to_bytes(&em_b_g1.into_affine()),
        em_b_g2: ark_to_bytes(&em_b_g2.into_affine()),
    };

    let bytes = bincode::serialize(&response).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(axum::body::Bytes::from(bytes))
}
