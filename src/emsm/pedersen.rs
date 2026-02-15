use ark_ec::CurveGroup;
use ark_std::rand::Rng;

use super::sparse_vec::SparseVector;

/// Pedersen-style commitment scheme: MSM wrapper over generators.
#[derive(Clone, Debug)]
pub struct Pedersen<G: CurveGroup> {
    pub generators: Vec<G::Affine>,
}

impl<G: CurveGroup> Pedersen<G> {
    /// Create Pedersen instance from existing generators.
    pub fn from_generators(generators: Vec<G::Affine>) -> Self {
        Self { generators }
    }

    /// Create Pedersen instance with random generators.
    pub fn rand<R: Rng>(n: usize, rng: &mut R) -> Self {
        let generators: Vec<G::Affine> = (0..n).map(|_| G::rand(rng).into_affine()).collect();
        Self { generators }
    }

    /// Compute MSM: sum(scalars[i] * generators[i]).
    /// Returns an error if lengths don't match.
    pub fn commit(&self, scalars: &[G::ScalarField]) -> Result<G, PedersenError> {
        if scalars.len() != self.generators.len() {
            return Err(PedersenError::LengthMismatch {
                scalars: scalars.len(),
                generators: self.generators.len(),
            });
        }
        G::msm(&self.generators, scalars).map_err(|_| PedersenError::MsmFailed)
    }

    /// Compute sparse MSM: sum over nonzero entries only.
    pub fn commit_sparse(&self, sparse: &SparseVector<G::ScalarField>) -> G {
        assert!(sparse.size <= self.generators.len());
        if sparse.entries.is_empty() {
            return G::zero();
        }

        let (indices, values): (Vec<_>, Vec<_>) = sparse.entries.iter().cloned().unzip();
        let bases: Vec<G::Affine> = indices.iter().map(|&i| self.generators[i]).collect();
        G::msm(&bases, &values).expect("sparse MSM failed")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PedersenError {
    #[error("scalar/generator length mismatch: {scalars} scalars vs {generators} generators")]
    LengthMismatch { scalars: usize, generators: usize },
    #[error("MSM computation failed")]
    MsmFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective as G1};
    use ark_std::test_rng;
    use ark_std::Zero;

    #[test]
    fn test_commit_zero() {
        let mut rng = test_rng();
        let ped = Pedersen::<G1>::rand(8, &mut rng);
        let scalars = vec![Fr::zero(); 8];
        let result = ped.commit(&scalars).unwrap();
        assert_eq!(result, G1::zero());
    }

    #[test]
    fn test_commit_sparse_matches_dense() {
        let mut rng = test_rng();
        let n = 16;
        let ped = Pedersen::<G1>::rand(n, &mut rng);

        // Create a sparse vector
        let sparse = SparseVector::new(n, vec![(2, Fr::from(5u64)), (7, Fr::from(3u64))]);
        let sparse_result = ped.commit_sparse(&sparse);

        // Compare with dense
        let dense = sparse.into_dense();
        let dense_result = ped.commit(&dense).unwrap();

        assert_eq!(sparse_result, dense_result);
    }

    #[test]
    fn test_commit_length_mismatch_returns_error() {
        let mut rng = test_rng();
        let ped = Pedersen::<G1>::rand(8, &mut rng);
        let scalars = vec![Fr::zero(); 5]; // wrong length
        let result = ped.commit(&scalars);
        assert!(result.is_err());
    }
}
