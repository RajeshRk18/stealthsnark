//! Fuzz the full server-side request-parsing pipeline with arbitrary bytes,
//!
//! INVARIANT: no input can make the parsing path panic. Every malformed request
//! or generator/scalar blob must fail gracefully.

#![no_main]

use ark_bn254::{Fr, G1Affine, G2Affine};
use libfuzzer_sys::fuzz_target;
use stealthsnark::protocol::messages::{ark_vec_from_bytes, ProveRequest, SetupRequest};

fuzz_target!(|data: &[u8]| {
    // /v1/setup pipeline: body -> SetupRequest -> generator vectors.
    if let Ok(req) = stealthsnark::protocol::messages::wire_decode::<SetupRequest>(data) {
        let _ = ark_vec_from_bytes::<G1Affine>(&req.h_generators);
        let _ = ark_vec_from_bytes::<G1Affine>(&req.l_generators);
        let _ = ark_vec_from_bytes::<G1Affine>(&req.a_generators);
        let _ = ark_vec_from_bytes::<G1Affine>(&req.b_g1_generators);
        let _ = ark_vec_from_bytes::<G2Affine>(&req.b_g2_generators);
    }

    // /v1/prove pipeline: body -> ProveRequest -> masked scalar vectors.
    if let Ok(req) = stealthsnark::protocol::messages::wire_decode::<ProveRequest>(data) {
        let _ = ark_vec_from_bytes::<Fr>(&req.v_h);
        let _ = ark_vec_from_bytes::<Fr>(&req.v_l);
        let _ = ark_vec_from_bytes::<Fr>(&req.v_a);
        let _ = ark_vec_from_bytes::<Fr>(&req.v_b_g1);
        let _ = ark_vec_from_bytes::<Fr>(&req.v_b_g2);
    }
});
