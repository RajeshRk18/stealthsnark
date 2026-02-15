use ark_ff::Field;
use ark_std::rand::Rng;

/// Sparse vector: stores (index, value) pairs over a field F.
#[derive(Clone, Debug)]
pub struct SparseVector<F: Field> {
    pub size: usize,
    pub entries: Vec<(usize, F)>,
}

impl<F: Field> SparseVector<F> {
    pub fn new(size: usize, entries: Vec<(usize, F)>) -> Self {
        debug_assert!(entries.iter().all(|(i, _)| *i < size));
        Self { size, entries }
    }

    /// Convert to dense vector of length `size`.
    pub fn into_dense(&self) -> Vec<F> {
        let mut dense = vec![F::zero(); self.size];
        for &(i, ref v) in &self.entries {
            dense[i] += *v;
        }
        dense
    }

    /// Generate a sparse error vector for LPN.
    /// Splits [0, size) into size/t chunks, picks one random index per chunk
    /// with a random nonzero field element.
    pub fn error_vec<R: Rng>(size: usize, t: usize, rng: &mut R) -> Self {
        if t == 0 || size == 0 {
            return Self { size, entries: Vec::new() };
        }
        assert!(size >= t, "need size >= t, got size={size}, t={t}");
        let chunk_size = size / t;
        let mut entries = Vec::with_capacity(t);

        for chunk_idx in 0..t {
            let base = chunk_idx * chunk_size;
            let offset = rng.gen_range(0..chunk_size);
            let val = F::rand(rng);
            entries.push((base + offset, val));
        }

        Self { size, entries }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::Zero;
    use ark_std::test_rng;

    #[test]
    fn test_sparse_to_dense() {
        let sv = SparseVector::<Fr>::new(5, vec![(0, Fr::from(3u64)), (3, Fr::from(7u64))]);
        let dense = sv.into_dense();
        assert_eq!(dense.len(), 5);
        assert_eq!(dense[0], Fr::from(3u64));
        assert_eq!(dense[3], Fr::from(7u64));
        assert_eq!(dense[1], Fr::zero());
    }

    #[test]
    fn test_error_vec_structure() {
        let mut rng = test_rng();
        let size = 1024;
        let t = 16;
        let ev = SparseVector::<Fr>::error_vec(size, t, &mut rng);
        assert_eq!(ev.size, size);
        assert_eq!(ev.entries.len(), t);

        // Each entry should be in its own chunk
        let chunk_size = size / t;
        for (i, &(idx, _)) in ev.entries.iter().enumerate() {
            assert!(idx >= i * chunk_size && idx < (i + 1) * chunk_size);
        }
    }
}
