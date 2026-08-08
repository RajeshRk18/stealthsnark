//! Primitives for handling secrets: random generation, hex coding, digests, and
//! constant-time comparison.
//!
//! Collected in one place so that every credential in the service is generated
//! and compared the same way. Session tokens and API keys both depend on this.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Generate `n_bytes` from the OS CSPRNG and return them hex-encoded.
///
/// `OsRng` and not a seeded generator: these values are credentials, and a
/// reproducible credential is not a credential.
pub fn random_hex(n_bytes: usize) -> String {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut raw = vec![0u8; n_bytes];
    OsRng.fill_bytes(&mut raw);
    hex_encode(&raw)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode lowercase or uppercase hex. Returns `None` on odd length or a
/// non-hex digit.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// SHA-256 of `bytes`, hex-encoded.
///
/// One unsalted digest round is the right choice for a high-entropy random API
/// key: there is no dictionary to attack, so a slow password hash would only add
/// latency to every request. A user-chosen password would need Argon2 instead.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_encode(&digest)
}

/// Compare two hex strings in constant time with respect to their contents.
///
/// The length comparison is not constant-time, which is intended: the length of
/// a digest is public. What must not leak is *where* two digests first differ,
/// because that turns key recovery into a byte-at-a-time search.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_hex_has_the_requested_width_and_varies() {
        let a = random_hex(32);
        let b = random_hex(32);
        assert_eq!(a.len(), 64);
        assert_eq!(b.len(), 64);
        assert_ne!(a, b, "two draws must not collide");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hex_round_trips() {
        let raw = [0x00u8, 0x0f, 0x10, 0xff, 0xa5];
        let text = hex_encode(&raw);
        assert_eq!(text, "000f10ffa5");
        assert_eq!(hex_decode(&text).unwrap(), raw);
        // Uppercase is accepted too.
        assert_eq!(hex_decode("000F10FFA5").unwrap(), raw);
    }

    #[test]
    fn hex_decode_rejects_malformed_input() {
        assert!(hex_decode("abc").is_none(), "odd length");
        assert!(hex_decode("zz").is_none(), "non-hex digit");
        assert!(hex_decode("00 11").is_none(), "embedded space");
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn sha256_matches_the_known_answer() {
        // Standard test vector for the empty input.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn constant_time_eq_agrees_with_equality() {
        assert!(constant_time_eq("deadbeef", "deadbeef"));
        assert!(!constant_time_eq("deadbeef", "deadbeee"));
        assert!(!constant_time_eq("deadbeef", "deadbee"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }
}
