//! Soundness fuzzer for the malicious-secure path.
//!
//! A cheating server returns a tampered set of MSM results. The double-query
//! consistency check must catch this. The invariant enforced here:
//!
//!   * untampered response => decrypt Ok, proof verifies (and is bound to the
//!     correct public input);
//!   * any tampered response => decrypt must reject. Random offsets pass the
//!     check only with probability ~2^-254, so an Ok on tampered input is a
//!     detection bug, not bad luck — the fuzzer hunts for check-bypassing
//!     inputs directly.
//!
//! Setup is built once; each run copies the honest response, applies fuzz-driven
//! tampering, and re-runs decryption — so iterations are cheap (no MSMs).
#![no_main]

use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr, G1Projective as G1, G2Projective as G2};
use ark_ff::{UniformRand, Zero};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::{Groth16, VerifyingKey};
use ark_snark::SNARK;
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use stealthsnark::groth16::circuit::CubeCircuit;
use stealthsnark::groth16::server_aided::{
    malicious_client_decrypt, malicious_client_encrypt, malicious_server_evaluate_groth16,
    MaliciousClientState, MaliciousServerResponse, ServerAidedProvingKey,
};

struct Fixture {
    sapk: ServerAidedProvingKey,
    vk: VerifyingKey<Bn254>,
    base: MaliciousServerResponse,
    state: MaliciousClientState,
}

fn fixture() -> &'static Fixture {
    static CELL: OnceLock<Fixture> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut rng = ChaCha20Rng::seed_from_u64(0xF1ED);
        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(CubeCircuit::<Fr> { x: None }, &mut rng)
                .expect("setup");
        let sapk = ServerAidedProvingKey::setup(pk, &mut rng);
        let circuit = CubeCircuit { x: Some(Fr::from(3u64)) };
        let (req, state) =
            malicious_client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng)
                .expect("encrypt");
        let base = malicious_server_evaluate_groth16(&sapk, &req).expect("evaluate");
        Fixture { sapk, vk, base, state }
    })
}

fn copy_response(b: &MaliciousServerResponse) -> MaliciousServerResponse {
    MaliciousServerResponse {
        em_h: b.em_h,
        em_h_ck: b.em_h_ck,
        em_l: b.em_l,
        em_l_ck: b.em_l_ck,
        em_a: b.em_a,
        em_a_ck: b.em_a_ck,
        em_b_g1: b.em_b_g1,
        em_b_g1_ck: b.em_b_g1_ck,
        em_b_g2: b.em_b_g2,
        em_b_g2_ck: b.em_b_g2_ck,
    }
}

fn nonzero_g1(rng: &mut ChaCha20Rng) -> G1 {
    loop {
        let p = G1::rand(rng);
        if !p.is_zero() {
            return p;
        }
    }
}
fn nonzero_g2(rng: &mut ChaCha20Rng) -> G2 {
    loop {
        let p = G2::rand(rng);
        if !p.is_zero() {
            return p;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();

    // Derive a tamper mask (bits 0..10) and an offset RNG from the fuzz input.
    let mask: u16 = if data.len() >= 2 {
        u16::from_le_bytes([data[0], data[1]]) & 0x03ff
    } else {
        0
    };
    let mut seed = [0u8; 32];
    for (i, b) in data.iter().take(32).enumerate() {
        seed[i] = *b;
    }
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut resp = copy_response(&f.base);
    let mut changed = 0u32;
    let bit = |i: u32| (mask >> i) & 1 == 1;
    if bit(0) { resp.em_h += nonzero_g1(&mut rng); changed += 1; }
    if bit(1) { resp.em_h_ck += nonzero_g1(&mut rng); changed += 1; }
    if bit(2) { resp.em_l += nonzero_g1(&mut rng); changed += 1; }
    if bit(3) { resp.em_l_ck += nonzero_g1(&mut rng); changed += 1; }
    if bit(4) { resp.em_a += nonzero_g1(&mut rng); changed += 1; }
    if bit(5) { resp.em_a_ck += nonzero_g1(&mut rng); changed += 1; }
    if bit(6) { resp.em_b_g1 += nonzero_g1(&mut rng); changed += 1; }
    if bit(7) { resp.em_b_g1_ck += nonzero_g1(&mut rng); changed += 1; }
    if bit(8) { resp.em_b_g2 += nonzero_g2(&mut rng); changed += 1; }
    if bit(9) { resp.em_b_g2_ck += nonzero_g2(&mut rng); changed += 1; }

    let result = malicious_client_decrypt(&f.sapk, &resp, &f.state);
    let correct = [Fr::from(35u64)];
    let wrong = [Fr::from(36u64)];

    match (changed, result) {
        (0, Ok(proof)) => {
            assert!(Groth16::<Bn254>::verify(&f.vk, &correct, &proof).unwrap());
            assert!(!Groth16::<Bn254>::verify(&f.vk, &wrong, &proof).unwrap());
        }
        (0, Err(e)) => panic!("untampered response rejected: {e:?}"),
        (n, Ok(_)) => {
            // Random offsets pass the consistency check only with probability
            // ~2^-254, so any Ok here is a detection bug — including tampers
            // that would still yield a verifying proof (e.g. `_ck`-only
            // components, which never enter proof assembly).
            panic!("tampering {n} component(s) (mask {mask:#012b}) was NOT detected");
        }
        (_, Err(_)) => { /* expected: tampering detected */ }
    }
});
