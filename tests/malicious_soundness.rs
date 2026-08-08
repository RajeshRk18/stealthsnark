//! Adversarial soundness tests for the malicious-secure path.
//!
//! The whole point of the double-query consistency check is that a server which
//! tampers with *any* of the ten MSM results is caught with overwhelming
//! probability. The existing suite tampers a single component once; here we:
//!
//!   * deterministically tamper each of the ten components in isolation and
//!     require detection (every component must be covered by the check);
//!   * fuzz arbitrary *combinations* of tampered components with random offsets
//!     via proptest — every non-empty combination must be rejected outright
//!     (random offsets slip the check only with probability ~2^-254, so a hard
//!     assert cannot flake);
//!   * assert soundness of the honest path: an untampered response must decrypt
//!     to a proof that verifies for the correct public input and fails for a
//!     different one.
//!
//! Groth16 setup is expensive, so it is built once and shared across cases.

use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr, G1Projective as G1, G2Projective as G2};
use ark_ff::{UniformRand, Zero};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::{Groth16, VerifyingKey};
use ark_snark::SNARK;
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use stealthsnark::groth16::circuit::CubeCircuit;
use stealthsnark::groth16::server_aided::{
    malicious_client_decrypt, malicious_client_encrypt, malicious_server_evaluate_groth16,
    MaliciousServerResponse, ServerAidedProvingKey,
};

const X: u64 = 3;
fn correct_public() -> Vec<Fr> {
    vec![Fr::from(35u64)] // 3^3 + 3 + 5
}

/// Expensive Groth16 + server-aided setup, built once.
fn cached() -> &'static (ServerAidedProvingKey, VerifyingKey<Bn254>) {
    static CELL: OnceLock<(ServerAidedProvingKey, VerifyingKey<Bn254>)> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut rng = ChaCha20Rng::seed_from_u64(0xA11CE);
        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(CubeCircuit::<Fr> { x: None }, &mut rng)
                .expect("setup failed");
        let sapk = ServerAidedProvingKey::setup(pk, &mut rng);
        (sapk, vk)
    })
}

/// A non-identity G1 offset.
fn nonzero_g1(rng: &mut ChaCha20Rng) -> G1 {
    loop {
        let p = G1::rand(rng);
        if !p.is_zero() {
            return p;
        }
    }
}

/// A non-identity G2 offset.
fn nonzero_g2(rng: &mut ChaCha20Rng) -> G2 {
    loop {
        let p = G2::rand(rng);
        if !p.is_zero() {
            return p;
        }
    }
}

/// Apply tampering to the components selected by `mask` (bits 0..10). Returns the
/// number of components actually perturbed.
fn tamper(resp: &mut MaliciousServerResponse, mask: u16, rng: &mut ChaCha20Rng) -> u32 {
    let mut changed = 0;
    let bit = |i: u32| -> bool { (mask >> i) & 1 == 1 };
    if bit(0) {
        resp.em_h += nonzero_g1(rng);
        changed += 1;
    }
    if bit(1) {
        resp.em_h_ck += nonzero_g1(rng);
        changed += 1;
    }
    if bit(2) {
        resp.em_l += nonzero_g1(rng);
        changed += 1;
    }
    if bit(3) {
        resp.em_l_ck += nonzero_g1(rng);
        changed += 1;
    }
    if bit(4) {
        resp.em_a += nonzero_g1(rng);
        changed += 1;
    }
    if bit(5) {
        resp.em_a_ck += nonzero_g1(rng);
        changed += 1;
    }
    if bit(6) {
        resp.em_b_g1 += nonzero_g1(rng);
        changed += 1;
    }
    if bit(7) {
        resp.em_b_g1_ck += nonzero_g1(rng);
        changed += 1;
    }
    if bit(8) {
        resp.em_b_g2 += nonzero_g2(rng);
        changed += 1;
    }
    if bit(9) {
        resp.em_b_g2_ck += nonzero_g2(rng);
        changed += 1;
    }
    changed
}

/// Produce a fresh encrypt + honest response for one case.
fn honest_round(
    sapk: &ServerAidedProvingKey,
    rng: &mut ChaCha20Rng,
) -> (
    MaliciousServerResponse,
    stealthsnark::groth16::server_aided::MaliciousClientState,
) {
    let circuit = CubeCircuit {
        x: Some(Fr::from(X)),
    };
    let (req, state) =
        malicious_client_encrypt::<LibsnarkReduction, _, _>(sapk, circuit, rng).unwrap();
    let resp = malicious_server_evaluate_groth16(sapk, &req).unwrap();
    (resp, state)
}

#[test]
fn honest_response_verifies_and_is_sound() {
    let (sapk, vk) = cached();
    let mut rng = ChaCha20Rng::seed_from_u64(100);
    let (resp, state) = honest_round(sapk, &mut rng);

    let proof =
        malicious_client_decrypt(sapk, &resp, &state).expect("honest response must decrypt");
    assert!(
        Groth16::<Bn254>::verify(vk, &correct_public(), &proof).unwrap(),
        "honest proof must verify for the correct input"
    );
    assert!(
        !Groth16::<Bn254>::verify(vk, &[Fr::from(36u64)], &proof).unwrap(),
        "honest proof must not verify for a wrong input"
    );
}

#[test]
fn each_single_component_tamper_is_detected() {
    let (sapk, _vk) = cached();
    // Tamper exactly one component at a time; every one must be caught.
    for i in 0..10u32 {
        let mut rng = ChaCha20Rng::seed_from_u64(200 + i as u64);
        let (mut resp, state) = honest_round(sapk, &mut rng);
        let changed = tamper(&mut resp, 1 << i, &mut rng);
        assert_eq!(changed, 1);
        let result = malicious_client_decrypt(sapk, &resp, &state);
        assert!(
            result.is_err(),
            "tampering component {i} alone was NOT detected"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Any non-empty combination of tampered components must be rejected; the
    /// empty combination must yield a sound, verifying proof.
    #[test]
    fn random_tamper_combinations(mask in 0u16..1024, seed in any::<u64>()) {
        let (sapk, vk) = cached();
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (mut resp, state) = honest_round(sapk, &mut rng);

        let changed = tamper(&mut resp, mask, &mut rng);
        let result = malicious_client_decrypt(sapk, &resp, &state);

        if changed == 0 {
            // Untampered: must decrypt to a sound proof.
            let proof = result.expect("untampered response must decrypt");
            prop_assert!(Groth16::<Bn254>::verify(vk, &correct_public(), &proof).unwrap());
            prop_assert!(!Groth16::<Bn254>::verify(vk, &[Fr::from(36u64)], &proof).unwrap());
        } else {
            // Tampered: the consistency check must reject, full stop. Random
            // offsets pass the check only if they satisfy a relation involving
            // the client's secret per-query scalar (probability ~2^-254), so a
            // hard assert cannot flake — and anything weaker would silently
            // tolerate detection regressions (e.g. tampering only `_ck`
            // components never enters proof assembly, so a broken check would
            // still hand back a verifying proof).
            prop_assert!(
                result.is_err(),
                "tampering {changed} component(s) (mask {mask:#012b}) was NOT detected"
            );
        }
    }
}
