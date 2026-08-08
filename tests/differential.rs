//! Differential tests: the server-aided proving protocol must produce proofs
//! that are *valid Groth16 proofs* — indistinguishable in validity from proofs
//! produced by the stock `ark-groth16` prover for the same circuit and witness.
//!
//! `ark-groth16` is an independent oracle (it is the reference implementation we
//! are outsourcing, not the code under test), so this is the strongest cheap
//! correctness check we have. We assert both directions:
//!   * positive — vanilla proof and server-aided proof both verify, for the
//!     semi-honest and malicious-secure paths;
//!   * negative — a server-aided proof must NOT verify against a *different*
//!     public input (a soundness-flavoured smoke test).

use ark_bn254::{Bn254, Fr};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::{Groth16, Proof};
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use stealthsnark::groth16::circuit::CubeCircuit;
use stealthsnark::groth16::server_aided::{
    client_decrypt, client_encrypt, malicious_client_decrypt, malicious_client_encrypt,
    malicious_server_evaluate_groth16, server_evaluate, ServerAidedProvingKey,
};

/// y = x^3 + x + 5 (the public output of CubeCircuit).
fn expected_output(x: u64) -> Fr {
    let x = Fr::from(x);
    x * x * x + x + Fr::from(5u64)
}

/// Build a server-aided proving key and matching verifying key for CubeCircuit.
fn setup(rng: &mut ChaCha20Rng) -> (ServerAidedProvingKey, ark_groth16::VerifyingKey<Bn254>) {
    let circuit_for_setup = CubeCircuit::<Fr> { x: None };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit_for_setup, rng)
        .expect("groth16 setup failed");
    let sapk = ServerAidedProvingKey::setup(pk, rng);
    (sapk, vk)
}

/// Run the full semi-honest server-aided flow and return the assembled proof.
fn prove_semi_honest(sapk: &ServerAidedProvingKey, x: u64, rng: &mut ChaCha20Rng) -> Proof<Bn254> {
    let circuit = CubeCircuit {
        x: Some(Fr::from(x)),
    };
    let (request, state) =
        client_encrypt::<LibsnarkReduction, _, _>(sapk, circuit, rng).expect("encrypt failed");
    let response = server_evaluate(sapk, &request).expect("server evaluate failed");
    client_decrypt(sapk, &response, &state)
}

/// Run the full malicious-secure server-aided flow and return the assembled proof.
fn prove_malicious(sapk: &ServerAidedProvingKey, x: u64, rng: &mut ChaCha20Rng) -> Proof<Bn254> {
    let circuit = CubeCircuit {
        x: Some(Fr::from(x)),
    };
    let (request, state) = malicious_client_encrypt::<LibsnarkReduction, _, _>(sapk, circuit, rng)
        .expect("malicious encrypt failed");
    let response =
        malicious_server_evaluate_groth16(sapk, &request).expect("malicious evaluate failed");
    malicious_client_decrypt(sapk, &response, &state)
        .expect("consistency check should pass for honest server")
}

#[test]
fn server_aided_proof_matches_vanilla_groth16() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xD1FF);
    let (sapk, vk) = setup(&mut rng);

    // Exercise several witnesses to avoid an accidental pass on one lucky value.
    for x in [2u64, 3, 5, 7, 11, 100, 12345] {
        let public = vec![expected_output(x)];

        // Reference oracle: the stock ark-groth16 prover, using the *same* pk.
        let vanilla = Groth16::<Bn254>::prove(
            &sapk.pk,
            CubeCircuit {
                x: Some(Fr::from(x)),
            },
            &mut rng,
        )
        .expect("vanilla groth16 prove failed");
        assert!(
            Groth16::<Bn254>::verify(&vk, &public, &vanilla).unwrap(),
            "sanity: vanilla groth16 proof must verify (x={x})"
        );

        // System under test: semi-honest server-aided proof must also verify.
        let sa = prove_semi_honest(&sapk, x, &mut rng);
        assert!(
            Groth16::<Bn254>::verify(&vk, &public, &sa).unwrap(),
            "semi-honest server-aided proof must verify (x={x})"
        );

        // System under test: malicious-secure server-aided proof must also verify.
        let mal = prove_malicious(&sapk, x, &mut rng);
        assert!(
            Groth16::<Bn254>::verify(&vk, &public, &mal).unwrap(),
            "malicious-secure server-aided proof must verify (x={x})"
        );
    }
}

#[test]
fn server_aided_proof_rejects_wrong_public_input() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xBADC0DE);
    let (sapk, vk) = setup(&mut rng);

    let x = 3u64;
    let correct = vec![expected_output(x)]; // 35
    let wrong = vec![expected_output(x) + Fr::from(1u64)]; // 36

    let proof = prove_semi_honest(&sapk, x, &mut rng);
    assert!(
        Groth16::<Bn254>::verify(&vk, &correct, &proof).unwrap(),
        "proof must verify against the correct public input"
    );
    assert!(
        !Groth16::<Bn254>::verify(&vk, &wrong, &proof).unwrap(),
        "proof must NOT verify against a different public input"
    );

    let mal = prove_malicious(&sapk, x, &mut rng);
    assert!(Groth16::<Bn254>::verify(&vk, &correct, &mal).unwrap());
    assert!(
        !Groth16::<Bn254>::verify(&vk, &wrong, &mal).unwrap(),
        "malicious-secure proof must NOT verify against a different public input"
    );
}

#[test]
fn distinct_witnesses_yield_distinct_proofs() {
    // Two different witnesses for the same statement shape must give proofs that
    // each verify against their *own* public input and not the other's. This
    // catches a class of bug where the witness fails to bind into the proof.
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EED);
    let (sapk, vk) = setup(&mut rng);

    let (x0, x1) = (3u64, 9u64);
    let p0 = prove_semi_honest(&sapk, x0, &mut rng);
    let p1 = prove_semi_honest(&sapk, x1, &mut rng);

    assert!(Groth16::<Bn254>::verify(&vk, &[expected_output(x0)], &p0).unwrap());
    assert!(Groth16::<Bn254>::verify(&vk, &[expected_output(x1)], &p1).unwrap());
    assert!(!Groth16::<Bn254>::verify(&vk, &[expected_output(x1)], &p0).unwrap());
    assert!(!Groth16::<Bn254>::verify(&vk, &[expected_output(x0)], &p1).unwrap());
}
