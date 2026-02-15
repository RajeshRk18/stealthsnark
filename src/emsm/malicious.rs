use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use thiserror::Error;

use super::dual_lpn::DualLPNInstance;
use super::emsm::{decrypt, encrypt, EmsmPublicParams, PreprocessedCommitments};

#[derive(Debug, Error)]
pub enum MaliciousError {
    #[error("server cheated: consistency check failed")]
    ConsistencyCheckFailed,
}

/// Encrypted data for the malicious-secure variant.
/// Contains two masked vectors: one for the actual computation and one for the check.
pub struct MaliciousEncrypted<F: PrimeField> {
    /// v = z + r (masked witness)
    pub masked: Vec<F>,
    /// v_ck = c * z + r' (check vector)
    pub masked_check: Vec<F>,
}

/// Client-side decryption state for the malicious variant.
pub struct MaliciousDecryptState<F: PrimeField> {
    /// Random challenge scalar
    pub challenge: F,
    /// LPN instance for the main query
    pub lpn: DualLPNInstance<F>,
    /// LPN instance for the check query
    pub lpn_check: DualLPNInstance<F>,
}

/// Encrypt for malicious-secure EMSM.
/// Sends two queries: v = z + r and v_ck = c*z + r' with independent LPN noise.
pub fn malicious_encrypt<G: CurveGroup, R: Rng>(
    params: &EmsmPublicParams<G>,
    witness: &[G::ScalarField],
    rng: &mut R,
) -> (
    MaliciousEncrypted<G::ScalarField>,
    MaliciousDecryptState<G::ScalarField>,
) {
    // Sample random challenge
    let challenge = G::ScalarField::rand(rng);

    // First query: v = z + r
    let (masked, lpn) = encrypt(params, witness, rng);

    // Second query: v_ck = c*z + r'
    let c_witness: Vec<G::ScalarField> = witness.iter().map(|zi| challenge * *zi).collect();
    let (masked_check, lpn_check) = encrypt(params, &c_witness, rng);

    let encrypted = MaliciousEncrypted {
        masked,
        masked_check,
    };

    let state = MaliciousDecryptState {
        challenge,
        lpn,
        lpn_check,
    };

    (encrypted, state)
}

/// Server evaluates both queries (server doesn't know which is which).
pub fn malicious_server_evaluate<G: CurveGroup>(
    params: &EmsmPublicParams<G>,
    encrypted: &MaliciousEncrypted<G::ScalarField>,
) -> Result<(G, G), crate::emsm::pedersen::PedersenError> {
    let em = params.server_computation(&encrypted.masked)?;
    let em_ck = params.server_computation(&encrypted.masked_check)?;
    Ok((em, em_ck))
}

/// Decrypt and verify consistency: dm_ck should equal c * dm.
/// If the server cheated on either query, the check fails with overwhelming probability.
pub fn malicious_decrypt<G: CurveGroup>(
    server_result: G,
    server_result_check: G,
    state: &MaliciousDecryptState<G::ScalarField>,
    preprocessed: &PreprocessedCommitments<G>,
) -> Result<G, MaliciousError> {
    let dm = decrypt(server_result, &state.lpn, preprocessed);
    let dm_ck = decrypt(server_result_check, &state.lpn_check, preprocessed);

    // Check: dm_ck == c * dm
    let expected_ck = dm * state.challenge;
    if dm_ck != expected_ck {
        return Err(MaliciousError::ConsistencyCheckFailed);
    }

    Ok(dm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective as G1};
    use ark_std::test_rng;

    #[test]
    fn test_malicious_honest_server() {
        let mut rng = test_rng();
        let n = 64;

        let generators: Vec<<G1 as CurveGroup>::Affine> =
            (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();
        let witness: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        let params = EmsmPublicParams::<G1>::new(generators.clone(), &mut rng);
        let preprocessed = params.preprocess();

        // Encrypt (malicious variant)
        let (encrypted, state) = malicious_encrypt(&params, &witness, &mut rng);

        // Honest server evaluates both
        let (em, em_ck) = malicious_server_evaluate(&params, &encrypted).unwrap();

        // Decrypt and verify
        let result = malicious_decrypt(em, em_ck, &state, &preprocessed);
        assert!(result.is_ok());

        // Check correctness
        let ped = super::super::pedersen::Pedersen::<G1>::from_generators(generators);
        let expected = ped.commit(&witness).unwrap();
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn test_malicious_cheating_server_detected() {
        let mut rng = test_rng();
        let n = 64;

        let generators: Vec<<G1 as CurveGroup>::Affine> =
            (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();
        let witness: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        let params = EmsmPublicParams::<G1>::new(generators, &mut rng);
        let preprocessed = params.preprocess();

        let (encrypted, state) = malicious_encrypt(&params, &witness, &mut rng);

        // Honest server evaluates both
        let (em, em_ck) = malicious_server_evaluate(&params, &encrypted).unwrap();

        // Tamper with one result (cheating server)
        let tampered_em = em + G1::rand(&mut rng);

        let result = malicious_decrypt(tampered_em, em_ck, &state, &preprocessed);
        assert!(result.is_err());
    }
}
