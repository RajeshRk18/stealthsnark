//! Concurrency stress test for per-session isolation.
//!
//! The server stores each client's generators in a `RwLock<HashMap>` keyed by
//! session id. The existing integration test checks isolation sequentially; this
//! test hammers `/setup` and `/prove` from many concurrent clients to surface
//! races and cross-session clobbering (a "selective failure" where one session's
//! generators leak into another's proving).
//!
//! Detection mechanism: we build two *distinct* proving keys and round-robin
//! sessions across them. A session's proof can only verify under its own
//! verifying key, so if the server ever mixes generators between two sessions
//! that chose different setups, that session's proof fails to verify and the
//! test fails.

use std::sync::Arc;

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::{Groth16, VerifyingKey};
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tokio::sync::RwLock;

use stealthsnark::groth16::circuit::CubeCircuit;
use stealthsnark::groth16::server_aided::{
    client_decrypt, client_encrypt, ServerAidedProvingKey, ServerResponse,
};
use stealthsnark::protocol::client::EmsmClient;
use stealthsnark::protocol::messages::*;
use stealthsnark::protocol::server::{create_router, ServerState};

fn setup_request(sapk: &ServerAidedProvingKey) -> SetupRequest {
    SetupRequest {
        h_generators: ark_vec_to_bytes(&sapk.emsm_h.generators),
        l_generators: ark_vec_to_bytes(&sapk.emsm_l.generators),
        a_generators: ark_vec_to_bytes(&sapk.emsm_a.generators),
        b_g1_generators: ark_vec_to_bytes(&sapk.emsm_b_g1.generators),
        b_g2_generators: ark_vec_to_bytes::<G2Affine>(&sapk.emsm_b_g2.generators),
    }
}

fn prove_request(req: &stealthsnark::groth16::server_aided::EncryptedRequest) -> ProveRequest {
    ProveRequest {
        v_h: ark_vec_to_bytes(&req.v_h),
        v_l: ark_vec_to_bytes(&req.v_l),
        v_a: ark_vec_to_bytes(&req.v_a),
        v_b_g1: ark_vec_to_bytes(&req.v_b_g1),
        v_b_g2: ark_vec_to_bytes(&req.v_b_g2),
    }
}

fn decode_response(pr: &ProveResponse) -> ServerResponse {
    ServerResponse {
        em_h: ark_from_bytes::<G1Affine>(&pr.em_h).unwrap().into(),
        em_l: ark_from_bytes::<G1Affine>(&pr.em_l).unwrap().into(),
        em_a: ark_from_bytes::<G1Affine>(&pr.em_a).unwrap().into(),
        em_b_g1: ark_from_bytes::<G1Affine>(&pr.em_b_g1).unwrap().into(),
        em_b_g2: ark_from_bytes::<G2Affine>(&pr.em_b_g2).unwrap().into(),
    }
}

async fn spawn_server() -> String {
    let state = Arc::new(RwLock::new(ServerState::new()));
    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_sessions_stay_isolated() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5E55);

    // Two distinct proving keys. A proof made under one cannot verify under the
    // other, so any cross-session generator clobber shows up as a verify failure.
    let mut setups: Vec<(Arc<ServerAidedProvingKey>, VerifyingKey<Bn254>)> = Vec::new();
    for _ in 0..2 {
        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(CubeCircuit::<Fr> { x: None }, &mut rng)
                .unwrap();
        let sapk = ServerAidedProvingKey::setup(pk, &mut rng);
        setups.push((Arc::new(sapk), vk));
    }
    let setups = Arc::new(setups);

    let server_url = spawn_server().await;

    // Fan out many concurrent honest sessions, round-robined across the two keys.
    const SESSIONS: usize = 24;
    let mut handles = Vec::new();
    for i in 0..SESSIONS {
        let setups = setups.clone();
        let url = server_url.clone();
        handles.push(tokio::spawn(async move {
            let (sapk, vk) = &setups[i % setups.len()];
            let session_id = format!("sess-{i}");
            let client = EmsmClient::new(&url, session_id);

            client.send_setup(&setup_request(sapk)).await.map_err(|e| format!("setup: {e}"))?;

            // Encryption is synchronous; give each session its own rng.
            let mut local_rng = ChaCha20Rng::seed_from_u64(1000 + i as u64);
            let circuit = CubeCircuit { x: Some(Fr::from(3u64)) };
            let (req, state) =
                client_encrypt::<LibsnarkReduction, _, _>(sapk.as_ref(), circuit, &mut local_rng)
                    .map_err(|e| format!("encrypt: {e}"))?;

            let resp = client
                .send_prove(&prove_request(&req))
                .await
                .map_err(|e| format!("prove: {e}"))?;
            let proof = client_decrypt(sapk.as_ref(), &decode_response(&resp), &state);

            if !Groth16::<Bn254>::verify(vk, &[Fr::from(35u64)], &proof).unwrap() {
                return Err(format!("session {i} proof failed to verify (possible cross-session clobber)"));
            }
            Ok::<(), String>(())
        }));
    }

    // Concurrently, sessions that never ran /setup must be refused.
    let mut unknown_handles = Vec::new();
    for i in 0..6 {
        let setups = setups.clone();
        let url = server_url.clone();
        unknown_handles.push(tokio::spawn(async move {
            let (sapk, _vk) = &setups[0];
            let client = EmsmClient::new(&url, format!("never-setup-{i}"));
            let mut local_rng = ChaCha20Rng::seed_from_u64(9000 + i as u64);
            let circuit = CubeCircuit { x: Some(Fr::from(3u64)) };
            let (req, _state) =
                client_encrypt::<LibsnarkReduction, _, _>(sapk.as_ref(), circuit, &mut local_rng)
                    .unwrap();
            client.send_prove(&prove_request(&req)).await.is_err()
        }));
    }

    for h in handles {
        h.await.unwrap().expect("a concurrent session failed");
    }
    for h in unknown_handles {
        assert!(
            h.await.unwrap(),
            "prove against a never-setup session should have been refused"
        );
    }
}
