use std::borrow::Cow;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

/// Wire protocol version, sent in the [`VERSION_HEADER`] on every `/v1` request.
pub const PROTOCOL_VERSION: u32 = 3;

/// Header carrying [`PROTOCOL_VERSION`].
pub const VERSION_HEADER: &str = "x-stealthsnark-version";

/// Header carrying the session token issued by `/v1/setup`.
pub const SESSION_HEADER: &str = "x-stealthsnark-session";

/// Maximum number of elements allowed in a deserialized vector.
/// Prevents unbounded allocation from attacker-controlled length prefixes.
/// 
/// Note this is a structural bound and not the effective one because a request also has
/// to fit under [`crate::protocol::config::ServerConfig::max_body_bytes`], which
/// is what actually decides the largest servable circuit.
const MAX_VEC_LEN: u64 = 1 << 24;

/// Maximum number of elements pre-allocated before any element has decoded.
/// The allocation for a `Vec<T>` is `count * size_of::<T>()`, so deriving the
/// capacity from untrusted byte counts still amplifies attacker bytes by
/// `size_of::<T>()` (~136x for G2Affine). 
/// Beyond this bound, the Vec grows amortized, which is negligible compared to deserialization.
const MAX_PREALLOC_ELEMS: usize = 1024;

/// Encode a message body. postcard is not self-describing, so the version header
/// is what keeps a changed message shape from decoding as something else.
pub fn wire_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, anyhow::Error> {
    postcard::to_allocvec(value).map_err(|e| anyhow::anyhow!("encode failed: {e}"))
}

/// Decode a message body. Bytes after the message are an error, not ignored.
pub fn wire_decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, anyhow::Error> {
    let (value, rest) =
        postcard::take_from_bytes(bytes).map_err(|e| anyhow::anyhow!("decode failed: {e}"))?;
    if !rest.is_empty() {
        anyhow::bail!("{} trailing bytes after the message", rest.len());
    }
    Ok(value)
}

/// Serialize an arkworks type to bytes.
pub fn ark_to_bytes<T: CanonicalSerialize>(val: &T) -> Result<Vec<u8>, anyhow::Error> {
    let mut buf = Vec::new();
    val.serialize_compressed(&mut buf)
        .map_err(|e| anyhow::anyhow!("serialization failed: {e}"))?;
    Ok(buf)
}

/// Deserialize an arkworks type from bytes.
pub fn ark_from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, anyhow::Error> {
    T::deserialize_compressed(bytes).map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))
}

/// Serialize a vector of arkworks types to bytes.
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
    /// Bearer credential for `/v1/prove` and `/v1/session`.
    pub session_token: String,
    /// Short non-secret id that the server also logs, so a client and an operator
    /// can correlate a request.
    pub session_label: String,
}

/// Response to `DELETE /v1/sessions`: how many sessions were released.
///
/// A new type rather than an empty 204, because the count is the only way a client
/// that lost its tokens learns whether it had anything to reclaim.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReleaseAllResponse {
    pub released: u32,
}

/// Setup request: generator points for each of the 5 MSMs.
///
/// The fields borrow from the request body when decoded, so the server does not
/// copy hundreds of MiB of points before it parses them.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetupRequest<'a> {
    #[serde(borrow)]
    pub h_generators: Cow<'a, [u8]>,
    #[serde(borrow)]
    pub l_generators: Cow<'a, [u8]>,
    #[serde(borrow)]
    pub a_generators: Cow<'a, [u8]>,
    #[serde(borrow)]
    pub b_g1_generators: Cow<'a, [u8]>,
    #[serde(borrow)]
    pub b_g2_generators: Cow<'a, [u8]>,
}

impl SetupRequest<'static> {
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
            h_generators: ark_vec_to_bytes(h)?.into(),
            l_generators: ark_vec_to_bytes(l)?.into(),
            a_generators: ark_vec_to_bytes(a)?.into(),
            b_g1_generators: ark_vec_to_bytes(b_g1)?.into(),
            b_g2_generators: ark_vec_to_bytes(b_g2)?.into(),
        })
    }
}

/// Prove request: 5 masked scalar vectors. Borrows from the body when decoded.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProveRequest<'a> {
    #[serde(borrow)]
    pub v_h: Cow<'a, [u8]>,
    #[serde(borrow)]
    pub v_l: Cow<'a, [u8]>,
    #[serde(borrow)]
    pub v_a: Cow<'a, [u8]>,
    #[serde(borrow)]
    pub v_b_g1: Cow<'a, [u8]>,
    #[serde(borrow)]
    pub v_b_g2: Cow<'a, [u8]>,
}

impl ProveRequest<'static> {
    /// Encode the five masked scalar vectors.
    pub fn encode<F: CanonicalSerialize>(
        v_h: &[F],
        v_l: &[F],
        v_a: &[F],
        v_b_g1: &[F],
        v_b_g2: &[F],
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            v_h: ark_vec_to_bytes(v_h)?.into(),
            v_l: ark_vec_to_bytes(v_l)?.into(),
            v_a: ark_vec_to_bytes(v_a)?.into(),
            v_b_g1: ark_vec_to_bytes(v_b_g1)?.into(),
            v_b_g2: ark_vec_to_bytes(v_b_g2)?.into(),
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

    // Regression test for the memory amplification DoS found by `vec_deser`
    #[test]
    fn test_huge_length_prefix_tiny_body_does_not_overallocate() {
        // a length prefix at the maximum (2^24) with an empty body 
        // must fail fast WITHOUT pre-allocating gigabytes. 
        let mut buf = Vec::new();
        let huge_len: u64 = MAX_VEC_LEN; // within the cap, but no elements follow
        ark_serialize::CanonicalSerialize::serialize_compressed(&huge_len, &mut buf).unwrap();
        let r1: Result<Vec<Fr>, _> = ark_vec_from_bytes(&buf);
        assert!(r1.is_err());
        let r2: Result<Vec<G1Affine>, _> = ark_vec_from_bytes(&buf);
        assert!(r2.is_err());

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

    #[test]
    fn decoded_requests_borrow_the_body() {
        let bytes = wire_encode(&ProveRequest::encode::<Fr>(&[], &[], &[], &[], &[]).unwrap()).unwrap();
        let req: ProveRequest = wire_decode(&bytes).unwrap();
        assert!(matches!(req.v_h, Cow::Borrowed(_)));
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = wire_encode(&ReleaseAllResponse { released: 2 }).unwrap();
        assert_eq!(wire_decode::<ReleaseAllResponse>(&bytes).unwrap().released, 2);
        bytes.push(0);
        assert!(wire_decode::<ReleaseAllResponse>(&bytes).is_err());
    }

}
