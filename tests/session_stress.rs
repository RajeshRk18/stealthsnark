//! Concurrency stress test for per-session isolation.
//!
//! The server stores each client's generators in a token-keyed map. This test
//! hammers `/v1/setup` and `/v1/prove` from many concurrent clients to surface
//! races and cross-session clobbering (a "selective failure" where one session's
//! generators leak into another's proving).
//!
//! Detection mechanism: we build two *distinct* proving keys and round-robin
//! sessions across them. A session's proof can only verify under its own
//! verifying key, so if the server ever mixes generators between two sessions
//! that chose different setups, that session's proof fails to verify and the
//! test fails.

mod common;

use std::sync::Arc;

use ark_bn254::{Bn254, Fr};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::{Groth16, VerifyingKey};
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use common::{decode_response, prove_request, setup_request, spawn_server_with};
use stealthsnark::groth16::circuit::CubeCircuit;
use stealthsnark::groth16::server_aided::{client_decrypt, client_encrypt, ServerAidedProvingKey};
use stealthsnark::protocol::client::EmsmClient;
use stealthsnark::protocol::config::ServerConfig;

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

    const SESSIONS: usize = 24;

    // Headroom above the session count so the cap is not what this test measures,
    // and enough MSM slots that admission control does not serialise everything.
    let cfg = ServerConfig {
        max_sessions: SESSIONS * 2,
        max_concurrent_msm: 4,
        ..ServerConfig::default()
    };
    let (server_url, state) = spawn_server_with(cfg).await;

    let mut handles = Vec::new();
    for i in 0..SESSIONS {
        let setups = setups.clone();
        let url = server_url.clone();
        handles.push(tokio::spawn(async move {
            let (sapk, vk) = &setups[i % setups.len()];
            let mut client = EmsmClient::new(&url).map_err(|e| format!("client: {e}"))?;

            client
                .send_setup(&setup_request(sapk))
                .await
                .map_err(|e| format!("setup: {e}"))?;

            // Encryption is synchronous; give each session its own rng.
            let mut local_rng = ChaCha20Rng::seed_from_u64(1000 + i as u64);
            let circuit = CubeCircuit {
                x: Some(Fr::from(3u64)),
            };
            let (req, enc_state) =
                client_encrypt::<LibsnarkReduction, _, _>(sapk.as_ref(), circuit, &mut local_rng)
                    .map_err(|e| format!("encrypt: {e}"))?;

            let resp = client
                .send_prove(&prove_request(&req))
                .await
                .map_err(|e| format!("prove: {e}"))?;
            let proof = client_decrypt(sapk.as_ref(), &decode_response(&resp), &enc_state);

            if !Groth16::<Bn254>::verify(vk, &[Fr::from(35u64)], &proof).unwrap() {
                return Err(format!(
                    "session {i} proof failed to verify (possible cross-session clobber)"
                ));
            }

            client
                .release()
                .await
                .map_err(|e| format!("release: {e}"))?;
            Ok::<(), String>(())
        }));
    }

    // Concurrently, forged tokens must be refused.
    let mut forged_handles = Vec::new();
    for i in 0..6 {
        let setups = setups.clone();
        let url = server_url.clone();
        forged_handles.push(tokio::spawn(async move {
            let (sapk, _vk) = &setups[0];
            let mut local_rng = ChaCha20Rng::seed_from_u64(9000 + i as u64);
            let circuit = CubeCircuit {
                x: Some(Fr::from(3u64)),
            };
            let (req, _) =
                client_encrypt::<LibsnarkReduction, _, _>(sapk.as_ref(), circuit, &mut local_rng)
                    .unwrap();

            // A plausible-looking but never-issued token.
            let forged = format!("{:064x}", i);
            let body = bincode::serialize(&prove_request(&req)).unwrap();
            let resp = reqwest::Client::new()
                .post(format!("{url}/v1/prove"))
                .header(
                    stealthsnark::protocol::messages::VERSION_HEADER,
                    stealthsnark::protocol::messages::PROTOCOL_VERSION.to_string(),
                )
                .bearer_auth(forged)
                .body(body)
                .send()
                .await
                .unwrap();
            resp.status().as_u16()
        }));
    }

    for h in handles {
        h.await.unwrap().expect("a concurrent session failed");
    }
    for h in forged_handles {
        assert_eq!(
            h.await.unwrap(),
            401,
            "a forged session token must be rejected with 401"
        );
    }

    // Every session released itself; nothing should be left pinned.
    assert_eq!(
        state.sessions.len(),
        0,
        "sessions leaked after all clients released"
    );
}
