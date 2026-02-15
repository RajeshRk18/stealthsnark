use ark_ff::Field;
use ark_std::rand::Rng;

use super::raa_code::TOperator;
use super::sparse_vec::SparseVector;

/// A Dual-LPN instance: noise vector e (sparse) and mask vector r = T * e (dense).
/// Used to mask witness vectors: v = z + r, where the server sees v but not z.
#[derive(Clone, Debug)]
pub struct DualLPNInstance<F: Field> {
    /// Sparse noise vector e of dimension N = 4n
    pub noise: SparseVector<F>,
    /// Dense mask vector r = T * e of dimension n
    pub lpn_vector: Vec<F>,
}

impl<F: Field> DualLPNInstance<F> {
    /// Sample a fresh Dual-LPN instance:
    /// 1. Sample sparse e with t nonzero entries across N-dimensional space
    /// 2. Compute r = T * e (dense n-dimensional vector)
    pub fn sample<R: Rng>(t_operator: &TOperator, t: usize, rng: &mut R) -> Self {
        let noise = SparseVector::error_vec(t_operator.big_n, t, rng);
        let lpn_vector = t_operator.multiply_sparse(&noise.entries);
        Self { noise, lpn_vector }
    }

    /// Mask a witness vector z: returns v = z + r
    pub fn mask_witness(&self, z: &[F]) -> Vec<F> {
        assert_eq!(z.len(), self.lpn_vector.len(), "z must have same length as lpn_vector");
        z.iter()
            .zip(self.lpn_vector.iter())
            .map(|(zi, ri)| *zi + *ri)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::test_rng;

    #[test]
    fn test_dual_lpn_dimensions() {
        let mut rng = test_rng();
        let n = 64;
        let t_op = TOperator::rand(n, &mut rng);
        let t = 8;

        let instance = DualLPNInstance::<Fr>::sample(&t_op, t, &mut rng);
        assert_eq!(instance.noise.size, 4 * n);
        assert_eq!(instance.noise.entries.len(), t);
        assert_eq!(instance.lpn_vector.len(), n);
    }

    #[test]
    fn test_mask_witness() {
        let mut rng = test_rng();
        let n = 32;
        let t_op = TOperator::rand(n, &mut rng);
        let instance = DualLPNInstance::<Fr>::sample(&t_op, 4, &mut rng);

        let z: Vec<Fr> = (0..n).map(|i| Fr::from(i as u64)).collect();
        let v = instance.mask_witness(&z);
        assert_eq!(v.len(), n);

        // v - r should equal z
        for i in 0..n {
            assert_eq!(v[i] - instance.lpn_vector[i], z[i]);
        }
    }
}
