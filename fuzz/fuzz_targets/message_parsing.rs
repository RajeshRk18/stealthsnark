//! Fuzz the full server-side request-parsing pipeline with arbitrary bytes,
//! mirroring what `handle_setup` / `handle_prove` do before touching any state.
//!
//! Invariant: no input can make the parsing path panic — every malformed
//! envelope, inner request, or generator/scalar blob must fail gracefully.
#![no_main]

use ark_bn254::{Fr, G1Affine, G2Affine};
use libfuzzer_sys::fuzz_target;
use stealthsnark::protocol::messages::{ark_vec_from_bytes, ProveRequest, SetupRequest};
use stealthsnark::protocol::server::{ProveEnvelope, SetupEnvelope};

fuzz_target!(|data: &[u8]| {
    // /setup pipeline: envelope -> SetupRequest -> generator vectors.
    if let Ok(env) = bincode::deserialize::<SetupEnvelope>(data) {
        if let Ok(req) = bincode::deserialize::<SetupRequest>(&env.request) {
            let _ = ark_vec_from_bytes::<G1Affine>(&req.h_generators);
            let _ = ark_vec_from_bytes::<G1Affine>(&req.l_generators);
            let _ = ark_vec_from_bytes::<G1Affine>(&req.a_generators);
            let _ = ark_vec_from_bytes::<G1Affine>(&req.b_g1_generators);
            let _ = ark_vec_from_bytes::<G2Affine>(&req.b_g2_generators);
        }
    }

    // /prove pipeline: envelope -> ProveRequest -> masked scalar vectors.
    if let Ok(env) = bincode::deserialize::<ProveEnvelope>(data) {
        if let Ok(req) = bincode::deserialize::<ProveRequest>(&env.request) {
            let _ = ark_vec_from_bytes::<Fr>(&req.v_h);
            let _ = ark_vec_from_bytes::<Fr>(&req.v_l);
            let _ = ark_vec_from_bytes::<Fr>(&req.v_a);
            let _ = ark_vec_from_bytes::<Fr>(&req.v_b_g1);
            let _ = ark_vec_from_bytes::<Fr>(&req.v_b_g2);
        }
    }
});
