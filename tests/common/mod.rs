//! Shared helpers for the protocol integration suites.
//!
//! Included separately into each test binary, so any helper a given binary does
//! not use looks dead to that compilation unit.
#![allow(dead_code)]

use ark_bn254::{G1Affine, G2Affine};

use stealthsnark::groth16::server_aided::{
    EncryptedRequest, ServerAidedProvingKey, ServerResponse,
};
use stealthsnark::protocol::config::ServerConfig;
use stealthsnark::protocol::messages::*;
use stealthsnark::protocol::server::{create_router, AppState};

/// Spawn the app on an ephemeral port. Returns the base URL and the shared state
/// so a test can inspect session bookkeeping directly.
pub async fn spawn_server_with(cfg: ServerConfig) -> (String, AppState) {
    let state = AppState::new(cfg);
    let app = create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind failed");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

pub async fn spawn_server() -> (String, AppState) {
    spawn_server_with(ServerConfig::default()).await
}

pub fn setup_request(sapk: &ServerAidedProvingKey) -> SetupRequest {
    SetupRequest::encode::<G1Affine, G2Affine>(
        &sapk.emsm_h.generators,
        &sapk.emsm_l.generators,
        &sapk.emsm_a.generators,
        &sapk.emsm_b_g1.generators,
        &sapk.emsm_b_g2.generators,
    )
    .expect("encoding generators must not fail")
}

pub fn prove_request(req: &EncryptedRequest) -> ProveRequest {
    ProveRequest::encode(&req.v_h, &req.v_l, &req.v_a, &req.v_b_g1, &req.v_b_g2)
        .expect("encoding masked vectors must not fail")
}

pub fn decode_response(pr: &ProveResponse) -> ServerResponse {
    ServerResponse {
        em_h: ark_from_bytes::<G1Affine>(&pr.em_h).unwrap().into(),
        em_l: ark_from_bytes::<G1Affine>(&pr.em_l).unwrap().into(),
        em_a: ark_from_bytes::<G1Affine>(&pr.em_a).unwrap().into(),
        em_b_g1: ark_from_bytes::<G1Affine>(&pr.em_b_g1).unwrap().into(),
        em_b_g2: ark_from_bytes::<G2Affine>(&pr.em_b_g2).unwrap().into(),
    }
}
