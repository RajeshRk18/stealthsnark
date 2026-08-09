//! Shared helpers for the protocol integration suites.
//!
//! Included separately into each test binary, so any helper a given binary does
//! not use looks dead to that compilation unit.
#![allow(dead_code)]

use std::collections::HashMap;

use ark_bn254::{G1Affine, G2Affine};

use stealthsnark::groth16::server_aided::{
    EncryptedRequest, ServerAidedProvingKey, ServerResponse,
};
use stealthsnark::protocol::auth::{
    generate_api_key, AuthFile, AuthMode, AuthStore, GeneratedKey, PrincipalSpec, TierSpec,
};
use stealthsnark::protocol::config::ServerConfig;
use stealthsnark::protocol::messages::*;
use stealthsnark::protocol::server::{create_admin_router, create_router, AppState};

/// Spawn the data plane on an ephemeral port with authentication disabled.
///
/// Returns the base URL and the shared state, so a test can inspect session
/// bookkeeping directly.
pub async fn spawn_server_with(cfg: ServerConfig) -> (String, AppState) {
    spawn_with_auth(cfg, AuthStore::disabled()).await
}

pub async fn spawn_server() -> (String, AppState) {
    spawn_server_with(ServerConfig::default()).await
}

/// Spawn the data plane with a specific credential store.
pub async fn spawn_with_auth(cfg: ServerConfig, auth: AuthStore) -> (String, AppState) {
    let state = AppState::with_auth(cfg, auth);
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

/// Spawn the admin plane for an existing state, so health and metrics are
/// scraped the same way an operator would scrape them.
pub async fn spawn_admin(state: AppState) -> String {
    let app = create_admin_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind failed");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// A credential store with one API-key principal per supplied id.
///
/// Returns the store and the minted keys in the same order as `ids`.
pub fn auth_store_with_keys(
    ids: &[&str],
    tier: Option<&str>,
    tiers: HashMap<String, TierSpec>,
    mode: AuthMode,
) -> (AuthStore, Vec<GeneratedKey>) {
    let mut generated = Vec::new();
    let mut principals = Vec::new();

    for id in ids {
        let g = generate_api_key();
        principals.push(PrincipalSpec {
            id: (*id).to_string(),
            tier: tier.map(str::to_string),
            api_key_id: Some(g.key_id.clone()),
            api_key_sha256: Some(g.sha256.clone()),
            tls_cert_sha256: None,
        });
        generated.push(g);
    }

    let store = AuthStore::from_spec(AuthFile { tiers, principals }, mode)
        .expect("test auth spec must be valid");
    (store, generated)
}

/// One tier by name, for quota tests.
pub fn tier(
    name: &str,
    max_sessions: usize,
    max_body_bytes: usize,
    requests_per_sec: f64,
    burst: u32,
) -> HashMap<String, TierSpec> {
    let mut t = HashMap::new();
    t.insert(
        name.to_string(),
        TierSpec {
            max_sessions,
            max_body_bytes,
            requests_per_sec,
            burst,
        },
    );
    t
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

/// Send a raw request with the correct version header, and optionally a client
/// credential and a session token.
///
/// Used by tests that must bypass [`stealthsnark::protocol::client::EmsmClient`]
/// to send something the client would never send.
pub fn raw(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: String,
    api_key: Option<&str>,
    session_token: Option<&str>,
) -> reqwest::RequestBuilder {
    let mut req = client
        .request(method, url)
        .header(VERSION_HEADER, PROTOCOL_VERSION.to_string());
    if let Some(key) = api_key {
        req = req.bearer_auth(key);
    }
    if let Some(token) = session_token {
        req = req.header(SESSION_HEADER, token);
    }
    req
}

/// Read the machine-readable `code` from an error response body.
pub async fn error_code(resp: reqwest::Response) -> String {
    let bytes = resp.bytes().await.unwrap();
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("code")?.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("<unparseable: {}>", String::from_utf8_lossy(&bytes)))
}
