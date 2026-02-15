use std::sync::Arc;
use tokio::sync::RwLock;

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use stealthsnark::groth16::circuit::CubeCircuit;
use stealthsnark::groth16::server_aided::{
    client_decrypt, client_encrypt, ServerAidedProvingKey,
};
use stealthsnark::protocol::client::EmsmClient;
use stealthsnark::protocol::messages::*;
use stealthsnark::protocol::server::{create_router, ServerState};

/// Full integration test: spawn axum server in-process, run client flow, verify proof.
#[tokio::test]
async fn test_integration_e2e() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    // Spawn server in-process on a random port
    let state = Arc::new(RwLock::new(ServerState::new()));
    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind failed");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let server_url = format!("http://{addr}");
    let session_id = "test-session-42".to_string();

    // Groth16 setup
    let circuit_for_setup = CubeCircuit::<Fr> { x: None };
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(circuit_for_setup, &mut rng).unwrap();

    // Server-aided proving key
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

    // Send generators
    let http_client = EmsmClient::new(&server_url, session_id);
    let setup_request = SetupRequest {
        h_generators: ark_vec_to_bytes(&sapk.emsm_h.generators),
        l_generators: ark_vec_to_bytes(&sapk.emsm_l.generators),
        a_generators: ark_vec_to_bytes(&sapk.emsm_a.generators),
        b_g1_generators: ark_vec_to_bytes(&sapk.emsm_b_g1.generators),
        b_g2_generators: ark_vec_to_bytes::<G2Affine>(&sapk.emsm_b_g2.generators),
    };
    http_client
        .send_setup(&setup_request)
        .await
        .expect("setup failed");

    // Encrypt
    let circuit = CubeCircuit { x: Some(Fr::from(3u64)) };
    let (request, state) =
        client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng).unwrap();

    // Prove via server
    let prove_request = ProveRequest {
        v_h: ark_vec_to_bytes(&request.v_h),
        v_l: ark_vec_to_bytes(&request.v_l),
        v_a: ark_vec_to_bytes(&request.v_a),
        v_b_g1: ark_vec_to_bytes(&request.v_b_g1),
        v_b_g2: ark_vec_to_bytes(&request.v_b_g2),
    };
    let prove_response = http_client
        .send_prove(&prove_request)
        .await
        .expect("prove failed");

    // Decode response
    let server_response = stealthsnark::groth16::server_aided::ServerResponse {
        em_h: ark_from_bytes::<G1Affine>(&prove_response.em_h)
            .unwrap()
            .into(),
        em_l: ark_from_bytes::<G1Affine>(&prove_response.em_l)
            .unwrap()
            .into(),
        em_a: ark_from_bytes::<G1Affine>(&prove_response.em_a)
            .unwrap()
            .into(),
        em_b_g1: ark_from_bytes::<G1Affine>(&prove_response.em_b_g1)
            .unwrap()
            .into(),
        em_b_g2: ark_from_bytes::<G2Affine>(&prove_response.em_b_g2)
            .unwrap()
            .into(),
    };

    // Decrypt and verify
    let proof = client_decrypt(&sapk, &server_response, &state);

    let public_inputs = vec![Fr::from(35u64)];
    let valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();
    assert!(valid, "Integration test: proof should verify!");
}

/// Test that multiple sessions are isolated from each other.
#[tokio::test]
async fn test_session_isolation() {
    let mut rng = ChaCha20Rng::seed_from_u64(99);

    let state = Arc::new(RwLock::new(ServerState::new()));
    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind failed");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let server_url = format!("http://{addr}");

    // Setup session A
    let circuit_for_setup = CubeCircuit::<Fr> { x: None };
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(circuit_for_setup, &mut rng).unwrap();
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

    let client_a = EmsmClient::new(&server_url, "session-a".to_string());
    let setup_req = SetupRequest {
        h_generators: ark_vec_to_bytes(&sapk.emsm_h.generators),
        l_generators: ark_vec_to_bytes(&sapk.emsm_l.generators),
        a_generators: ark_vec_to_bytes(&sapk.emsm_a.generators),
        b_g1_generators: ark_vec_to_bytes(&sapk.emsm_b_g1.generators),
        b_g2_generators: ark_vec_to_bytes::<G2Affine>(&sapk.emsm_b_g2.generators),
    };
    client_a.send_setup(&setup_req).await.unwrap();

    // Client B tries to prove against session-b which was never set up
    let client_b = EmsmClient::new(&server_url, "session-b".to_string());
    let circuit = CubeCircuit { x: Some(Fr::from(3u64)) };
    let (request, _state) =
        client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng).unwrap();
    let prove_req = ProveRequest {
        v_h: ark_vec_to_bytes(&request.v_h),
        v_l: ark_vec_to_bytes(&request.v_l),
        v_a: ark_vec_to_bytes(&request.v_a),
        v_b_g1: ark_vec_to_bytes(&request.v_b_g1),
        v_b_g2: ark_vec_to_bytes(&request.v_b_g2),
    };

    let result = client_b.send_prove(&prove_req).await;
    assert!(result.is_err(), "Prove against unknown session should fail");

    // Client A should still work
    let circuit2 = CubeCircuit { x: Some(Fr::from(3u64)) };
    let (request2, state2) =
        client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit2, &mut rng).unwrap();
    let prove_req2 = ProveRequest {
        v_h: ark_vec_to_bytes(&request2.v_h),
        v_l: ark_vec_to_bytes(&request2.v_l),
        v_a: ark_vec_to_bytes(&request2.v_a),
        v_b_g1: ark_vec_to_bytes(&request2.v_b_g1),
        v_b_g2: ark_vec_to_bytes(&request2.v_b_g2),
    };
    let prove_resp = client_a.send_prove(&prove_req2).await.unwrap();

    let server_response = stealthsnark::groth16::server_aided::ServerResponse {
        em_h: ark_from_bytes::<G1Affine>(&prove_resp.em_h).unwrap().into(),
        em_l: ark_from_bytes::<G1Affine>(&prove_resp.em_l).unwrap().into(),
        em_a: ark_from_bytes::<G1Affine>(&prove_resp.em_a).unwrap().into(),
        em_b_g1: ark_from_bytes::<G1Affine>(&prove_resp.em_b_g1).unwrap().into(),
        em_b_g2: ark_from_bytes::<G2Affine>(&prove_resp.em_b_g2).unwrap().into(),
    };
    let proof = client_decrypt(&sapk, &server_response, &state2);
    let valid = Groth16::<Bn254>::verify(&vk, &[Fr::from(35u64)], &proof).unwrap();
    assert!(valid, "Session A should still produce valid proofs");
}
