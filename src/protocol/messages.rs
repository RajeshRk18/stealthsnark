use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

/// Maximum number of elements allowed in a deserialized vector.
/// Prevents unbounded allocation from attacker-controlled length prefixes.
/// 2^24 elements is the largest LPN parameter table entry.
const MAX_VEC_LEN: u64 = 1 << 24;

/// Maximum number of elements pre-allocated before any element has decoded.
/// The allocation for a `Vec<T>` is `count * size_of::<T>()`, so deriving the
/// capacity from untrusted byte counts still amplifies attacker bytes by
/// `size_of::<T>()` (~136x for G2Affine). Beyond this bound the Vec grows
/// amortized, which is negligible next to element deserialization.
const MAX_PREALLOC_ELEMS: usize = 1024;

/// Serialize an arkworks type to bytes.
pub fn ark_to_bytes<T: CanonicalSerialize>(val: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    val.serialize_compressed(&mut buf)
        .expect("serialization failed");
    buf
}

/// Deserialize an arkworks type from bytes.
/// Returns an error instead of panicking on malformed input.
pub fn ark_from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, anyhow::Error> {
    T::deserialize_compressed(bytes).map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))
}

/// Serialize a vector of arkworks types to bytes.
pub fn ark_vec_to_bytes<T: CanonicalSerialize>(vals: &[T]) -> Vec<u8> {
    let mut buf = Vec::new();
    let len = vals.len() as u64;
    len.serialize_compressed(&mut buf).unwrap();
    for v in vals {
        v.serialize_compressed(&mut buf).unwrap();
    }
    buf
}

/// Deserialize a vector of arkworks types from bytes.
/// Returns an error on malformed input or if the length exceeds MAX_VEC_LEN.
pub fn ark_vec_from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<Vec<T>, anyhow::Error> {
    let mut cursor = bytes;
    let len: u64 = CanonicalDeserialize::deserialize_compressed(&mut cursor)
        .map_err(|e| anyhow::anyhow!("failed to read vec length: {e}"))?;
    if len > MAX_VEC_LEN {
        anyhow::bail!("vec length {len} exceeds maximum {MAX_VEC_LEN}");
    }
    // Do NOT pre-allocate based on untrusted input: the length prefix is
    // attacker-controlled, and even the remaining byte count is a bad bound
    // because the allocation is `count * size_of::<T>()` — for G2Affine that
    // is ~136 bytes per *input byte*, letting a few-MB body force a
    // hundreds-of-MB allocation before the first decode fails
    // (memory-amplification DoS). Cap the initial capacity at a small constant
    // and let the Vec grow amortized as elements actually decode; the growth
    // cost is negligible next to point decompression.
    let cap = (len as usize).min(cursor.len()).min(MAX_PREALLOC_ELEMS);
    let mut vals = Vec::with_capacity(cap);
    for i in 0..len {
        let val = T::deserialize_compressed(&mut cursor)
            .map_err(|e| anyhow::anyhow!("failed to deserialize element {i}: {e}"))?;
        vals.push(val);
    }
    Ok(vals)
}

/// Setup request: generator points for each of the 5 MSMs.
#[derive(Serialize, Deserialize)]
pub struct SetupRequest {
    pub h_generators: Vec<u8>,
    pub l_generators: Vec<u8>,
    pub a_generators: Vec<u8>,
    pub b_g1_generators: Vec<u8>,
    pub b_g2_generators: Vec<u8>,
}

/// Prove request: 5 masked scalar vectors.
#[derive(Serialize, Deserialize)]
pub struct ProveRequest {
    pub v_h: Vec<u8>,
    pub v_l: Vec<u8>,
    pub v_a: Vec<u8>,
    pub v_b_g1: Vec<u8>,
    pub v_b_g2: Vec<u8>,
}

/// Prove response: 5 MSM results (group elements).
#[derive(Serialize, Deserialize)]
pub struct ProveResponse {
    pub em_h: Vec<u8>,
    pub em_l: Vec<u8>,
    pub em_a: Vec<u8>,
    pub em_b_g1: Vec<u8>,
    pub em_b_g2: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Affine, G1Projective as G1};
    use ark_ec::CurveGroup;
    use ark_std::test_rng;
    use ark_std::UniformRand;

    #[test]
    fn test_scalar_roundtrip() {
        let mut rng = test_rng();
        let scalars: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let bytes = ark_vec_to_bytes(&scalars);
        let recovered: Vec<Fr> = ark_vec_from_bytes(&bytes).unwrap();
        assert_eq!(scalars, recovered);
    }

    #[test]
    fn test_point_roundtrip() {
        let mut rng = test_rng();
        let points: Vec<G1Affine> = (0..5).map(|_| G1::rand(&mut rng).into_affine()).collect();
        let bytes = ark_vec_to_bytes(&points);
        let recovered: Vec<G1Affine> = ark_vec_from_bytes(&bytes).unwrap();
        assert_eq!(points, recovered);
    }

    #[test]
    fn test_malformed_bytes_return_error() {
        let result: Result<Vec<Fr>, _> = ark_vec_from_bytes(&[0xff, 0xff]);
        assert!(result.is_err());
    }

    #[test]
    fn test_huge_length_prefix_tiny_body_does_not_overallocate() {
        // Regression for an OOM found by the `vec_deser` fuzzer: a length prefix
        // at the maximum (2^24) with an empty body must fail fast WITHOUT
        // pre-allocating gigabytes. We assert it returns an error quickly; if the
        // capacity were driven by `len` alone this would attempt a ~1.5 GB
        // allocation for G2Affine.
        let mut buf = Vec::new();
        let huge_len: u64 = MAX_VEC_LEN; // within the cap, but no elements follow
        ark_serialize::CanonicalSerialize::serialize_compressed(&huge_len, &mut buf).unwrap();
        let r1: Result<Vec<Fr>, _> = ark_vec_from_bytes(&buf);
        assert!(r1.is_err());
        let r2: Result<Vec<G1Affine>, _> = ark_vec_from_bytes(&buf);
        assert!(r2.is_err());

        // Variant: a multi-KB junk body. Bounding the capacity by the remaining
        // *byte* count alone would still allocate body_len * size_of::<T>()
        // (~136x amplification for G2Affine); the MAX_PREALLOC_ELEMS cap keeps
        // the upfront allocation constant regardless of body size.
        buf.extend(std::iter::repeat_n(0xAAu8, 64 * 1024));
        let r3: Result<Vec<G1Affine>, _> = ark_vec_from_bytes(&buf);
        assert!(r3.is_err());
    }

    #[test]
    fn test_oversized_length_rejected() {
        // Craft bytes with a huge length prefix
        let mut buf = Vec::new();
        let huge_len: u64 = MAX_VEC_LEN + 1;
        ark_serialize::CanonicalSerialize::serialize_compressed(&huge_len, &mut buf).unwrap();
        let result: Result<Vec<Fr>, _> = ark_vec_from_bytes(&buf);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }
}
