//! Demo client: proves a Circom `multiplier2` circuit through the server-aided
//! Groth16 protocol and verifies the resulting proof locally.

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_circom::CircomReduction;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand::rngs::OsRng;

use stealthsnark::groth16::circom::{build_circuit, circom_setup, get_public_inputs};
use stealthsnark::groth16::server_aided::{client_decrypt, client_encrypt, ServerAidedProvingKey};
use stealthsnark::protocol::client::EmsmClient;
use stealthsnark::protocol::messages::*;

const MULTIPLIER2_WASM: &str = "circuits/build/multiplier2_js/multiplier2.wasm";
const MULTIPLIER2_R1CS: &str = "circuits/build/multiplier2.r1cs";
const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:3000";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let mut rng = OsRng;
    let server_url =
        std::env::var("STEALTHSNARK_SERVER_URL").unwrap_or_else(|_| DEFAULT_SERVER_URL.to_string());

    println!("=== StealthSnark Client (Circom multiplier2) ===");
    println!("Server: {server_url}");

    // Step 1: Groth16 setup with Circom circuit
    println!("[1/6] Running Groth16 trusted setup (Circom multiplier2)...");
    let (pk, vk) = circom_setup(MULTIPLIER2_WASM, MULTIPLIER2_R1CS, &mut rng)?;

    // Step 2: Create server-aided proving key (EMSM preprocessing)
    println!("[2/6] Creating server-aided proving key (EMSM preprocessing)...");
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

    // Step 3: Send generators to server. The session token comes back from the
    // server; the client does not pick its own identifier.
    println!("[3/6] Sending generators to server...");
    let mut http_client = build_client(&server_url)?;
    let setup_request = SetupRequest::encode::<G1Affine, G2Affine>(
        &sapk.emsm_h.generators,
        &sapk.emsm_l.generators,
        &sapk.emsm_a.generators,
        &sapk.emsm_b_g1.generators,
        &sapk.emsm_b_g2.generators,
    )?;
    http_client.send_setup(&setup_request).await?;
    println!(
        "      session established (label {})",
        http_client.session_label().unwrap_or("?")
    );

    // Step 4: Build Circom circuit and encrypt
    println!("[4/6] Building Circom circuit (a=3, b=11) and encrypting...");
    let circuit = build_circuit(
        MULTIPLIER2_WASM,
        MULTIPLIER2_R1CS,
        &[("a", 3.into()), ("b", 11.into())],
    )?;
    let public_inputs = get_public_inputs(&circuit).expect("no public inputs");
    let (request, state) = client_encrypt::<CircomReduction, _, _>(&sapk, circuit, &mut rng)?;

    // Step 5: Send masked vectors to server, receive MSM results
    println!("[5/6] Delegating MSM computation to server...");
    let prove_request = ProveRequest::encode(
        &request.v_h,
        &request.v_l,
        &request.v_a,
        &request.v_b_g1,
        &request.v_b_g2,
    )?;
    let prove_response = http_client.send_prove(&prove_request).await?;

    // Decode server response back to group elements
    let server_response = stealthsnark::groth16::server_aided::ServerResponse {
        em_h: ark_from_bytes::<G1Affine>(&prove_response.em_h)?.into(),
        em_l: ark_from_bytes::<G1Affine>(&prove_response.em_l)?.into(),
        em_a: ark_from_bytes::<G1Affine>(&prove_response.em_a)?.into(),
        em_b_g1: ark_from_bytes::<G1Affine>(&prove_response.em_b_g1)?.into(),
        em_b_g2: ark_from_bytes::<G2Affine>(&prove_response.em_b_g2)?.into(),
    };

    // Step 6: Decrypt and verify
    println!("[6/6] Decrypting proof and verifying...");
    let proof = client_decrypt(&sapk, &server_response, &state);
    let valid = Groth16::<Bn254, CircomReduction>::verify(&vk, &public_inputs, &proof)?;

    // Free the server's copy of the generators rather than leaving them pinned
    // until the idle TTL expires. Best-effort: a failure here does not
    // invalidate a proof we already verified.
    if let Err(e) = http_client.release().await {
        tracing::warn!(error = %e, "failed to release session; it will expire on its own");
    }

    if valid {
        println!("SUCCESS: Server-aided Groth16 proof verified! (3 * 11 = 33)");
        Ok(())
    } else {
        // Exit non-zero so a scripted caller notices.
        anyhow::bail!("proof verification failed")
    }
}

/// Assemble the client from the environment.
///
/// Credentials and TLS trust come from the environment rather than from flags, so
/// the demo can reach a secured server without a rebuild, and so a key never
/// appears in shell history or a process listing.
fn build_client(server_url: &str) -> anyhow::Result<EmsmClient> {
    let mut builder = EmsmClient::builder(server_url);

    // Verify the server against a private CA. Needed for any internal service,
    // whose certificate no public CA has signed.
    if let Ok(path) = std::env::var("STEALTHSNARK_CA_CERT") {
        builder = builder.root_certificate_file(&path)?;
        println!("      trusting CA from {path}");
    }

    // mTLS: certificate and key in one PEM file. Checked before the API key,
    // because a certificate identifies the connection itself.
    if let Ok(path) = std::env::var("STEALTHSNARK_CLIENT_IDENTITY") {
        builder = builder.client_identity_file(&path)?;
        println!("      presenting client certificate from {path}");
    } else if let Ok(key) = std::env::var("STEALTHSNARK_API_KEY") {
        builder = builder.api_key(key);
        println!("      authenticating with an API key");
    } else {
        println!("      no credential set; the server must have auth disabled");
    }

    builder.build()
}
