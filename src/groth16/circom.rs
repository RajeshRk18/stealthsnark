use std::path::Path;

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig, CircomReduction};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, Rng};
use num_bigint::BigInt;

/// Run Groth16 trusted setup for a Circom circuit using `CircomReduction`.
pub fn circom_setup<R: Rng + CryptoRng>(
    wasm: impl AsRef<Path>,
    r1cs: impl AsRef<Path>,
    rng: &mut R,
) -> anyhow::Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    let cfg = CircomConfig::<Fr>::new(wasm, r1cs).map_err(|e| anyhow::anyhow!("{e}"))?;
    let builder = CircomBuilder::new(cfg);
    let setup_circuit = builder.setup();
    let (pk, vk) = Groth16::<Bn254, CircomReduction>::circuit_specific_setup(setup_circuit, rng)?;
    Ok((pk, vk))
}

/// Build a Circom circuit with witness from the given inputs.
///
/// Each input is `(name, value)`. For array inputs, push multiple times with
/// the same name (the builder accumulates them).
pub fn build_circuit(
    wasm: impl AsRef<Path>,
    r1cs: impl AsRef<Path>,
    inputs: &[(&str, BigInt)],
) -> anyhow::Result<CircomCircuit<Fr>> {
    let cfg = CircomConfig::<Fr>::new(wasm, r1cs).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut builder = CircomBuilder::new(cfg);
    for (name, val) in inputs {
        builder.push_input(*name, val.clone());
    }
    let circuit = builder.build().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(circuit)
}

/// Extract public inputs from a built circuit (with witness).
pub fn get_public_inputs(circuit: &CircomCircuit<Fr>) -> Option<Vec<Fr>> {
    circuit.get_public_inputs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groth16::server_aided::*;
    use ark_circom::CircomReduction;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const MULTIPLIER2_WASM: &str = "circuits/build/multiplier2_js/multiplier2.wasm";
    const MULTIPLIER2_R1CS: &str = "circuits/build/multiplier2.r1cs";
    const RANGE_CHECK_WASM: &str = "circuits/build/range_check_js/range_check.wasm";
    const RANGE_CHECK_R1CS: &str = "circuits/build/range_check.r1cs";

    fn skip_if_missing(path: &str) -> bool {
        if !Path::new(path).exists() {
            eprintln!(
                "Skipping: circuit artifact not found at {path}. Run ./circuits/compile.sh first."
            );
            true
        } else {
            false
        }
    }

    #[tokio::test]
    async fn test_circom_multiplier2_server_aided() {
        if skip_if_missing(MULTIPLIER2_WASM) || skip_if_missing(MULTIPLIER2_R1CS) {
            return;
        }
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        // Setup
        let (pk, vk) = circom_setup(MULTIPLIER2_WASM, MULTIPLIER2_R1CS, &mut rng)
            .expect("circom setup failed");

        let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

        // Build circuit with witness: a=3, b=11 → c=33
        let circuit = build_circuit(
            MULTIPLIER2_WASM,
            MULTIPLIER2_R1CS,
            &[("a", 3.into()), ("b", 11.into())],
        )
        .expect("build circuit failed");

        let public_inputs = get_public_inputs(&circuit).expect("no public inputs");

        // Encrypt → server evaluate → decrypt
        let (request, state) =
            client_encrypt::<CircomReduction, _, _>(&sapk, circuit, &mut rng)
                .expect("encrypt failed");
        let response = server_evaluate(&sapk, &request).expect("server evaluate failed");
        let proof = client_decrypt(&sapk, &response, &state);

        // Verify
        let valid = Groth16::<Bn254, CircomReduction>::verify(&vk, &public_inputs, &proof)
            .expect("verification failed");
        assert!(valid, "multiplier2 proof should verify (3*11=33)");
    }

    #[tokio::test]
    async fn test_circom_range_check_server_aided() {
        if skip_if_missing(RANGE_CHECK_WASM) || skip_if_missing(RANGE_CHECK_R1CS) {
            return;
        }
        let mut rng = ChaCha20Rng::seed_from_u64(99);

        // Setup
        let (pk, vk) = circom_setup(RANGE_CHECK_WASM, RANGE_CHECK_R1CS, &mut rng)
            .expect("circom setup failed");

        let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

        // Build circuit with witness: value=200 (fits in 8 bits, 0..255)
        let circuit = build_circuit(
            RANGE_CHECK_WASM,
            RANGE_CHECK_R1CS,
            &[("value", 200.into())],
        )
        .expect("build circuit failed");

        let public_inputs = get_public_inputs(&circuit).expect("no public inputs");

        // Encrypt → server evaluate → decrypt
        let (request, state) =
            client_encrypt::<CircomReduction, _, _>(&sapk, circuit, &mut rng)
                .expect("encrypt failed");
        let response = server_evaluate(&sapk, &request).expect("server evaluate failed");
        let proof = client_decrypt(&sapk, &response, &state);

        // Verify
        let valid = Groth16::<Bn254, CircomReduction>::verify(&vk, &public_inputs, &proof)
            .expect("verification failed");
        assert!(valid, "range_check proof should verify (200 fits in 8 bits)");
    }
}
