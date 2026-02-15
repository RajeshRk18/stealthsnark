use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_circom::CircomReduction;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand::rngs::OsRng;

use stealthsnark::groth16::circom::{build_circuit, circom_setup, get_public_inputs};
use stealthsnark::groth16::server_aided::{
    client_decrypt, client_encrypt, ServerAidedProvingKey,
};
use stealthsnark::protocol::client::EmsmClient;
use stealthsnark::protocol::messages::*;

const MULTIPLIER2_WASM: &str = "circuits/build/multiplier2_js/multiplier2.wasm";
const MULTIPLIER2_R1CS: &str = "circuits/build/multiplier2.r1cs";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let mut rng = OsRng;
    let server_url = "http://127.0.0.1:3000";
    let session_id = format!("{:016x}", rand::random::<u64>());

    println!("=== StealthSnark Client (Circom multiplier2) ===");
    println!("Session: {session_id}");

    // Step 1: Groth16 setup with Circom circuit
    println!("[1/6] Running Groth16 trusted setup (Circom multiplier2)...");
    let (pk, vk) = circom_setup(MULTIPLIER2_WASM, MULTIPLIER2_R1CS, &mut rng)?;

    // Step 2: Create server-aided proving key (EMSM preprocessing)
    println!("[2/6] Creating server-aided proving key (EMSM preprocessing)...");
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

    // Step 3: Send generators to server
    println!("[3/6] Sending generators to server...");
    let http_client = EmsmClient::new(server_url, session_id);
    let setup_request = SetupRequest {
        h_generators: ark_vec_to_bytes(&sapk.emsm_h.generators),
        l_generators: ark_vec_to_bytes(&sapk.emsm_l.generators),
        a_generators: ark_vec_to_bytes(&sapk.emsm_a.generators),
        b_g1_generators: ark_vec_to_bytes(&sapk.emsm_b_g1.generators),
        b_g2_generators: ark_vec_to_bytes::<G2Affine>(&sapk.emsm_b_g2.generators),
    };
    http_client.send_setup(&setup_request).await?;

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
    let prove_request = ProveRequest {
        v_h: ark_vec_to_bytes(&request.v_h),
        v_l: ark_vec_to_bytes(&request.v_l),
        v_a: ark_vec_to_bytes(&request.v_a),
        v_b_g1: ark_vec_to_bytes(&request.v_b_g1),
        v_b_g2: ark_vec_to_bytes(&request.v_b_g2),
    };
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

    if valid {
        println!("SUCCESS: Server-aided Groth16 proof verified! (3 * 11 = 33)");
    } else {
        println!("FAILURE: Proof verification failed!");
    }

    Ok(())
}
