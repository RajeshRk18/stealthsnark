//! Fuzz the wire-deserialization primitives against arbitrary attacker bytes.
//!
//! Invariant: deserialization must never panic, never OOM, never hang — only
//! return `Ok` or `Err`. The `MAX_VEC_LEN` cap is what prevents the length
//! prefix from driving an unbounded allocation; this target exercises that and
//! all the arkworks decode paths reachable from the network.
#![no_main]

use ark_bn254::{Fr, G1Affine, G2Affine};
use libfuzzer_sys::fuzz_target;
use stealthsnark::protocol::messages::{ark_from_bytes, ark_vec_from_bytes};

fuzz_target!(|data: &[u8]| {
    let _ = ark_vec_from_bytes::<Fr>(data);
    let _ = ark_vec_from_bytes::<G1Affine>(data);
    let _ = ark_vec_from_bytes::<G2Affine>(data);
    let _ = ark_from_bytes::<Fr>(data);
    let _ = ark_from_bytes::<G1Affine>(data);
    let _ = ark_from_bytes::<G2Affine>(data);
});
