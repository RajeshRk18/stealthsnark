use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

/// Wire protocol version, sent in the [`VERSION_HEADER`] on every `/v1` request.
///
/// bincode is not self-describing: if a message struct gains a field, an older
/// peer decodes the bytes as *something* rather than failing. An explicit version
/// turns that silent corruption into a clean rejection. Bump this whenever any
/// type in this module changes shape, or whenever a header changes meaning.
///
/// Version 2 moved the session token out of `Authorization` and into
/// [`SESSION_HEADER`], because `Authorization` now carries the client credential.
/// A version 1 client therefore sends its session token where the server expects
/// an API key; the version check turns that into a clear rejection instead of a
/// confusing authentication failure.
pub const PROTOCOL_VERSION: u32 = 2;

/// Header carrying [`PROTOCOL_VERSION`].
pub const VERSION_HEADER: &str = "x-stealthsnark-version";

/// Header carrying the session token issued by `/v1/setup`.
///
/// Separate from `Authorization` on purpose. `Authorization` says *who you are*
/// (an API key, or a TLS client certificate); this says *which stored generators
/// you mean*. Keeping them apart is what lets the server bind a session to its
/// owner, so a stolen session token is useless without the owner's credential.
pub const SESSION_HEADER: &str = "x-stealthsnark-session";

/// Maximum number of elements allowed in a deserialized vector.
/// Prevents unbounded allocation from attacker-controlled length prefixes.
/// 2^24 elements is the largest LPN parameter table entry.
///
/// Note this is a *structural* bound, not the effective one: a request also has
/// to fit under [`crate::protocol::config::ServerConfig::max_body_bytes`], which
/// is what actually decides the largest servable circuit.
const MAX_VEC_LEN: u64 = 1 << 24;

/// Maximum number of elements pre-allocated before any element has decoded.
/// The allocation for a `Vec<T>` is `count * size_of::<T>()`, so deriving the
/// capacity from untrusted byte counts still amplifies attacker bytes by
/// `size_of::<T>()` (~136x for G2Affine). Beyond this bound the Vec grows
/// amortized, which is negligible next to element deserialization.
const MAX_PREALLOC_ELEMS: usize = 1024;

/// Serialize an arkworks type to bytes.
///
/// Fallible for the same reason the deserializers are: this runs on the server's
/// response path, and a library function that aborts the process on an
/// unexpected input is the wrong failure mode even when the input is our own.
pub fn ark_to_bytes<T: CanonicalSerialize>(val: &T) -> Result<Vec<u8>, anyhow::Error> {
    let mut buf = Vec::new();
    val.serialize_compressed(&mut buf)
        .map_err(|e| anyhow::anyhow!("serialization failed: {e}"))?;
    Ok(buf)
}

/// Deserialize an arkworks type from bytes.
/// Returns an error instead of panicking on malformed input.
pub fn ark_from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, anyhow::Error> {
    T::deserialize_compressed(bytes).map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))
}

/// Serialize a vector of arkworks types to bytes.
///
/// Fallible for the same reason as [`ark_to_bytes`].
pub fn ark_vec_to_bytes<T: CanonicalSerialize>(vals: &[T]) -> Result<Vec<u8>, anyhow::Error> {
    let mut buf = Vec::new();
    let len = vals.len() as u64;
    len.serialize_compressed(&mut buf)
        .map_err(|e| anyhow::anyhow!("failed to write vec length: {e}"))?;
    for (i, v) in vals.iter().enumerate() {
        v.serialize_compressed(&mut buf)
            .map_err(|e| anyhow::anyhow!("failed to serialize element {i}: {e}"))?;
    }
    Ok(buf)
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

/// Setup response: the server-issued session credential.
///
/// The client does not choose its session identifier. When it did, a second
/// `/setup` reusing an id silently replaced the first client's generators, so
/// anyone who could guess or observe an id could make a victim's `/prove` run
/// against attacker-supplied bases.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetupResponse {
    /// Bearer credential for `/v1/prove` and `/v1/session`. Treat as a secret:
    /// do not log it, and do not persist it beyond the session.
    pub session_token: String,
    /// Short non-secret id that the server also logs, so a client and an operator
    /// can correlate a request without the token ever reaching a log sink.
    pub session_label: String,
}

/// Setup request: generator points for each of the 5 MSMs.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetupRequest {
    pub h_generators: Vec<u8>,
    pub l_generators: Vec<u8>,
    pub a_generators: Vec<u8>,
    pub b_g1_generators: Vec<u8>,
    pub b_g2_generators: Vec<u8>,
}

impl SetupRequest {
    /// Encode the five generator sets.
    ///
    /// Exists so that the fallibility introduced by [`ark_vec_to_bytes`] is
    /// handled once here rather than five times at every call site.
    pub fn encode<P1, P2>(
        h: &[P1],
        l: &[P1],
        a: &[P1],
        b_g1: &[P1],
        b_g2: &[P2],
    ) -> Result<Self, anyhow::Error>
    where
        P1: CanonicalSerialize,
        P2: CanonicalSerialize,
    {
        Ok(Self {
            h_generators: ark_vec_to_bytes(h)?,
            l_generators: ark_vec_to_bytes(l)?,
            a_generators: ark_vec_to_bytes(a)?,
            b_g1_generators: ark_vec_to_bytes(b_g1)?,
            b_g2_generators: ark_vec_to_bytes(b_g2)?,
        })
    }
}

/// Prove request: 5 masked scalar vectors.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProveRequest {
    pub v_h: Vec<u8>,
    pub v_l: Vec<u8>,
    pub v_a: Vec<u8>,
    pub v_b_g1: Vec<u8>,
    pub v_b_g2: Vec<u8>,
}

impl ProveRequest {
    /// Encode the five masked scalar vectors.
    pub fn encode<F: CanonicalSerialize>(
        v_h: &[F],
        v_l: &[F],
        v_a: &[F],
        v_b_g1: &[F],
        v_b_g2: &[F],
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            v_h: ark_vec_to_bytes(v_h)?,
            v_l: ark_vec_to_bytes(v_l)?,
            v_a: ark_vec_to_bytes(v_a)?,
            v_b_g1: ark_vec_to_bytes(v_b_g1)?,
            v_b_g2: ark_vec_to_bytes(v_b_g2)?,
        })
    }
}

/// Prove response: 5 MSM results (group elements).
#[derive(Debug, Serialize, Deserialize)]
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
        let bytes = ark_vec_to_bytes(&scalars).unwrap();
        let recovered: Vec<Fr> = ark_vec_from_bytes(&bytes).unwrap();
        assert_eq!(scalars, recovered);
    }

    #[test]
    fn test_point_roundtrip() {
        let mut rng = test_rng();
        let points: Vec<G1Affine> = (0..5).map(|_| G1::rand(&mut rng).into_affine()).collect();
        let bytes = ark_vec_to_bytes(&points).unwrap();
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
