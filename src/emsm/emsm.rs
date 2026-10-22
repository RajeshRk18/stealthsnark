use ark_ec::CurveGroup;
use ark_std::rand::Rng;

use super::dual_lpn::DualLPNInstance;
use super::params::get_lpn_params;
use super::pedersen::Pedersen;
use super::raa_code::TOperator;

/// Public parameters for EMSM
#[derive(Clone, Debug)]
pub struct EmsmPublicParams<G: CurveGroup> {
    /// The TOperator for masking
    pub t_operator: TOperator,
    /// Original generators 
    pub generators: Vec<G::Affine>,
    /// LPN sparsity parameter
    pub t: usize,
}

/// Preprocessed commitments h = G^T * g, with h[i] = sum over j of G^T[i][j] * generators[j].
/// These are computed once during setup and stored by the client.
/// Used during decryption to remove the noise contribution.
#[derive(Clone, Debug)]
pub struct PreprocessedCommitments<G: CurveGroup> {
    /// Pedersen instance over the preprocessed generators h, in affine form.
    pub pedersen_h: Pedersen<G>,
}

impl<G: CurveGroup> EmsmPublicParams<G> {
    /// Create EMSM public parameters from generators.
    pub fn new<R: Rng>(generators: Vec<G::Affine>, rng: &mut R) -> Self {
        let n = generators.len();
        let params = get_lpn_params(n);
        let t_operator = TOperator::rand(n, rng);
        Self {
            t_operator,
            generators,
            t: params.t,
        }
    }

    /// Compute G^T * g (expand generators through transpose of RAA code).
    /// h has dimension N = 4n. Used by client to remove noise during decryption.
    pub fn preprocess(&self) -> PreprocessedCommitments<G> {
        let h: Vec<G> = self
            .t_operator
            .multiply_transpose_group::<G>(&self.generators);

        // One field inversion for the whole batch instead of one per point.
        let pedersen_h = Pedersen::from_generators(G::normalize_batch(&h));

        PreprocessedCommitments { pedersen_h }
    }

    /// Computes MSM(masked_scalars, generators).
    /// From server side, it is just a plain MSM on the masked vector.
    pub fn server_computation(
        &self,
        masked_scalars: &[G::ScalarField],
    ) -> Result<G, crate::emsm::pedersen::PedersenError> {
        let ped = Pedersen::<G>::from_generators(self.generators.clone());
        ped.commit(masked_scalars)
    }
}

/// Encrypt(mask) a witness vector and return the masked vector + decryption material.
pub fn encrypt<G: CurveGroup, R: Rng>(
    params: &EmsmPublicParams<G>,
    witness: &[G::ScalarField],
    rng: &mut R,
) -> (Vec<G::ScalarField>, DualLPNInstance<G::ScalarField>) {
    let lpn = DualLPNInstance::sample(&params.t_operator, params.t, rng);
    let masked = lpn.mask_witness(witness);
    (masked, lpn)
}

/// Decrypt(unmask) the server's MSM result.
/// removes noise contribution.
pub fn decrypt<G: CurveGroup>(
    server_result: G,
    lpn: &DualLPNInstance<G::ScalarField>,
    preprocessed: &PreprocessedCommitments<G>,
) -> G {
    // Compute <e, h> = sparse MSM of noise against preprocessed generators
    let noise_contribution = preprocessed.pedersen_h.commit_sparse(&lpn.noise);
    server_result - noise_contribution
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective as G1};
    use ark_std::test_rng;
    use ark_std::UniformRand;

    #[test]
    fn test_emsm_roundtrip() {
        // This is the critical correctness test:
        // encrypt -> server MSM -> decrypt should equal plaintext MSM
        let mut rng = test_rng();
        let n = 64;

        // Random generators (simulating proving key points)
        let generators: Vec<<G1 as CurveGroup>::Affine> =
            (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();

        // Random witness
        let witness: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        // Setup EMSM
        let params = EmsmPublicParams::<G1>::new(generators.clone(), &mut rng);
        let preprocessed = params.preprocess();

        // Plaintext MSM (ground truth)
        let ped = Pedersen::<G1>::from_generators(generators);
        let expected = ped.commit(&witness).unwrap();

        // Encrypt
        let (masked, lpn) = encrypt(&params, &witness, &mut rng);

        // Server computes MSM on masked data
        let server_result = params.server_computation(&masked).unwrap();

        // Decrypt
        let actual = decrypt(server_result, &lpn, &preprocessed);

        assert_eq!(actual, expected, "EMSM roundtrip failed!");
    }

    #[test]
    fn test_emsm_different_witnesses() {
        let mut rng = test_rng();
        let n = 32;

        let generators: Vec<<G1 as CurveGroup>::Affine> =
            (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();

        let params = EmsmPublicParams::<G1>::new(generators.clone(), &mut rng);
        let preprocessed = params.preprocess();
        let ped = Pedersen::<G1>::from_generators(generators);

        // Test with multiple different witnesses
        for _ in 0..3 {
            let witness: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let expected = ped.commit(&witness).unwrap();

            let (masked, lpn) = encrypt(&params, &witness, &mut rng);
            let server_result = params.server_computation(&masked).unwrap();
            let actual = decrypt(server_result, &lpn, &preprocessed);

            assert_eq!(actual, expected);
        }
    }
}
