mod common;

use ark_bn254::{Bn254, Fr};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use common::{decode_response, prove_request, setup_request, spawn_server};
use stealthsnark::groth16::circuit::CubeCircuit;
use stealthsnark::groth16::server_aided::{client_decrypt, client_encrypt, ServerAidedProvingKey};
use stealthsnark::protocol::client::EmsmClient;

/// Full integration test: spawn axum server in-process, run client flow, verify proof.
#[tokio::test]
async fn test_integration_e2e() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (server_url, state) = spawn_server().await;

    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(CubeCircuit::<Fr> { x: None }, &mut rng).unwrap();
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

    // The client obtains its session token from the server; it does not choose one.
    let mut http_client = EmsmClient::new(&server_url).unwrap();
    assert!(!http_client.has_session());
    http_client
        .send_setup(&setup_request(&sapk))
        .await
        .expect("setup failed");
    assert!(http_client.has_session());
    assert!(http_client.session_label().is_some());
    assert_eq!(state.sessions.len(), 1);

    let circuit = CubeCircuit {
        x: Some(Fr::from(3u64)),
    };
    let (request, enc_state) =
        client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng).unwrap();

    let prove_response = http_client
        .send_prove(&prove_request(&request))
        .await
        .expect("prove failed");

    let proof = client_decrypt(&sapk, &decode_response(&prove_response), &enc_state);
    let valid = Groth16::<Bn254>::verify(&vk, &[Fr::from(35u64)], &proof).unwrap();
    assert!(valid, "Integration test: proof should verify!");

    // Explicit release must free the generators immediately.
    http_client.release().await.expect("release failed");
    assert_eq!(state.sessions.len(), 0);
}

/// Two concurrent clients get independent sessions, and neither can act on the
/// other's. This is the property the old client-chosen `session_id` did not have.
#[tokio::test]
async fn test_session_isolation() {
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let (server_url, state) = spawn_server().await;

    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(CubeCircuit::<Fr> { x: None }, &mut rng).unwrap();
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

    let mut client_a = EmsmClient::new(&server_url).unwrap();
    client_a.send_setup(&setup_request(&sapk)).await.unwrap();

    let mut client_b = EmsmClient::new(&server_url).unwrap();
    client_b.send_setup(&setup_request(&sapk)).await.unwrap();

    // Distinct sessions, not one overwriting the other.
    assert_eq!(state.sessions.len(), 2);
    assert_ne!(client_a.session_label(), client_b.session_label());

    // A client that never set up cannot prove at all.
    let client_c = EmsmClient::new(&server_url).unwrap();
    let circuit = CubeCircuit {
        x: Some(Fr::from(3u64)),
    };
    let (request, _) = client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng).unwrap();
    let err = client_c
        .send_prove(&prove_request(&request))
        .await
        .expect_err("prove without a session must fail");
    assert!(
        err.to_string().contains("send_setup"),
        "expected a local no-session error, got: {err}"
    );

    // Releasing B must not disturb A.
    client_b.release().await.unwrap();
    assert_eq!(state.sessions.len(), 1);

    let circuit2 = CubeCircuit {
        x: Some(Fr::from(3u64)),
    };
    let (request2, state2) =
        client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit2, &mut rng).unwrap();
    let prove_resp = client_a
        .send_prove(&prove_request(&request2))
        .await
        .unwrap();
    let proof = client_decrypt(&sapk, &decode_response(&prove_resp), &state2);
    assert!(
        Groth16::<Bn254>::verify(&vk, &[Fr::from(35u64)], &proof).unwrap(),
        "Session A should still produce valid proofs"
    );

    // A released session's token is no longer accepted.
    let stale = client_b.send_prove(&prove_request(&request2)).await;
    assert!(stale.is_err(), "released session must not still prove");
}

#[tokio::test]
async fn malicious_secure_proof_over_the_wire_verifies() {
    use stealthsnark::groth16::server_aided::{malicious_client_decrypt, malicious_client_encrypt};

    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (server_url, state) = spawn_server().await;
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(CubeCircuit::<Fr> { x: None }, &mut rng).unwrap();
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

    let mut client = EmsmClient::new(&server_url).unwrap();
    client.send_setup(&setup_request(&sapk)).await.unwrap();

    let circuit = CubeCircuit { x: Some(Fr::from(3u64)) };
    let (request, enc_state) =
        malicious_client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng).unwrap();
    let response = client.send_prove_malicious(&request, &mut rng).await.unwrap();

    let proof = malicious_client_decrypt(&sapk, &response, &enc_state)
        .expect("an honest server passes the consistency check");
    assert!(Groth16::<Bn254>::verify(&vk, &[Fr::from(35u64)], &proof).unwrap());
    // Both queries went to the same session as two /v1/prove calls.
    assert_eq!(state.metrics.prove_ok.load(std::sync::atomic::Ordering::Relaxed), 2);
}

/// A server that returns well-formed but wrong MSM results is caught.
#[tokio::test]
async fn malicious_secure_mode_detects_a_cheating_server() {
    use ark_ec::AffineRepr;
    use axum::routing::post;
    use stealthsnark::groth16::server_aided::{malicious_client_decrypt, malicious_client_encrypt};
    use stealthsnark::protocol::messages::{ark_to_bytes, wire_encode, ProveResponse, SetupResponse};

    // Answers every prove with the identity point, whatever the input.
    let cheat = axum::Router::new()
        .route(
            "/v1/setup",
            post(|| async {
                wire_encode(&SetupResponse {
                    session_token: "t".into(),
                    session_label: "l".into(),
                })
                .unwrap()
            }),
        )
        .route(
            "/v1/prove",
            post(|| async {
                let g1 = ark_to_bytes(&ark_bn254::G1Affine::zero()).unwrap();
                let g2 = ark_to_bytes(&ark_bn254::G2Affine::zero()).unwrap();
                wire_encode(&ProveResponse {
                    em_h: g1.clone(),
                    em_l: g1.clone(),
                    em_a: g1.clone(),
                    em_b_g1: g1,
                    em_b_g2: g2,
                })
                .unwrap()
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, cheat).await });

    let mut rng = ChaCha20Rng::seed_from_u64(8);
    let (pk, _vk) =
        Groth16::<Bn254>::circuit_specific_setup(CubeCircuit::<Fr> { x: None }, &mut rng).unwrap();
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);
    let mut client = EmsmClient::new(&url).unwrap();
    client.send_setup(&setup_request(&sapk)).await.unwrap();

    let circuit = CubeCircuit { x: Some(Fr::from(3u64)) };
    let (request, enc_state) =
        malicious_client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng).unwrap();
    let response = client.send_prove_malicious(&request, &mut rng).await.unwrap();

    assert!(matches!(
        malicious_client_decrypt(&sapk, &response, &enc_state),
        Err(stealthsnark::emsm::malicious::MaliciousError::ConsistencyCheckFailed)
    ));
}
