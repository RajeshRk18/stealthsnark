use ark_ff::Field;
use ark_std::rand::Rng;
use rayon::prelude::*;

const PARALLEL_THRESHOLD: usize = 1 << 16;

/// TOperator implements the RAA (Random Accumulate and Add) code.
/// G = F_r * M_p * A * M_q * A
/// where A = accumulate (suffix-sum), M_p/M_q = permute, F_r = fold (4:1).
///
/// Maps N-dimensional sparse vectors to n-dimensional dense vectors,
/// where N = 4n (rate R = 1/4).
#[derive(Clone, Debug)]
pub struct TOperator {
    /// Permutation p of size N
    pub perm_p: Vec<usize>,
    /// Permutation q of size N
    pub perm_q: Vec<usize>,
    /// Inverse of perm_p
    pub inv_perm_p: Vec<usize>,
    /// Inverse of perm_q
    pub inv_perm_q: Vec<usize>,
    /// N = 4n (expanded dimension)
    pub big_n: usize,
    /// n (original dimension)
    pub n: usize,
}

impl TOperator {
    /// Create a new TOperator with random permutations.
    pub fn rand<R: Rng>(n: usize, rng: &mut R) -> Self {
        let big_n = 4 * n;
        let perm_p = random_permutation(big_n, rng);
        let perm_q = random_permutation(big_n, rng);
        let inv_perm_p = inverse_permutation(&perm_p);
        let inv_perm_q = inverse_permutation(&perm_q);
        Self {
            perm_p,
            perm_q,
            inv_perm_p,
            inv_perm_q,
            big_n,
            n,
        }
    }

    /// Multiply a sparse vector by the TOperator: G * e.
    /// Computes F_r * M_p * A * M_q * A * e in O(N) additions.
    pub fn multiply_sparse<F: Field>(&self, sparse_entries: &[(usize, F)]) -> Vec<F> {
        // Start with dense representation of sparse input
        let mut v = vec![F::zero(); self.big_n];
        for &(i, ref val) in sparse_entries {
            v[i] += *val;
        }

        // Step 1: A (accumulate / suffix-sum)
        accumulate_inplace(&mut v);

        // Step 2: M_q (permute by q)
        v = permute_safe(&v, &self.perm_q);

        // Step 3: A (accumulate again)
        accumulate_inplace(&mut v);

        // Step 4: M_p (permute by p)
        v = permute_safe(&v, &self.perm_p);

        // Step 5: F_r (fold: sum groups of 4 to go from N -> n)
        apply_f_fold(&v)
    }

    /// Apply the transpose G^T to a vector of group elements.
    /// G^T = A^T * M_q^T * A^T * M_p^T * F_r^T
    /// Used in EMSM preprocessing: h = G^T * g
    pub fn multiply_transpose_group<G: ark_ec::CurveGroup>(&self, g: &[G::Affine]) -> Vec<G> {
        assert_eq!(g.len(), self.n, "input must have length n");

        // F_r^T: expand n -> N by placing each element at positions [4i, 4i+1, 4i+2, 4i+3]
        let mut v: Vec<G> = vec![G::zero(); self.big_n];
        for (i, gi) in g.iter().enumerate() {
            let gi_proj: G = (*gi).into();
            for k in 0..4 {
                v[4 * i + k] = gi_proj;
            }
        }

        // M_p^T = M_{p^{-1}}: permute by inverse of p
        v = permute_safe_group::<G>(&v, &self.inv_perm_p);

        // A^T = prefix-sum
        prefix_sum_inplace_group::<G>(&mut v);

        // M_q^T = M_{q^{-1}}: permute by inverse of q
        v = permute_safe_group::<G>(&v, &self.inv_perm_q);

        // A^T = prefix-sum
        prefix_sum_inplace_group::<G>(&mut v);

        v
    }
}

/// Compute suffix-sum in-place: v[i] = sum(v[i..N])
fn accumulate_inplace<F: Field>(v: &mut [F]) {
    let n = v.len();
    if n <= 1 {
        return;
    }

    if n >= PARALLEL_THRESHOLD {
        // Parallel: chunk-wise suffix sums then fix up
        let num_chunks = rayon::current_num_threads().min(n / 1024).max(1);
        let chunk_size = n.div_ceil(num_chunks);

        // Phase 1: local suffix sums within each chunk
        let chunk_sums: Vec<F> = v
            .par_chunks_mut(chunk_size)
            .map(|chunk| {
                let mut sum = F::zero();
                for elem in chunk.iter_mut().rev() {
                    sum += *elem;
                    *elem = sum;
                }
                sum
            })
            .collect();

        // Phase 2: compute suffix sums of chunk totals
        let mut corrections = vec![F::zero(); num_chunks];
        let mut running = F::zero();
        for i in (0..chunk_sums.len()).rev() {
            if i + 1 < chunk_sums.len() {
                corrections[i] = running;
            }
            running += chunk_sums[i];
        }
        // corrections[0] should be sum of chunk_sums[1..], etc.
        // Recalculate properly
        let mut suffix = F::zero();
        for i in (0..num_chunks).rev() {
            corrections[i] = suffix;
            suffix += chunk_sums[i];
        }

        // Phase 3: add corrections to each chunk
        v.par_chunks_mut(chunk_size)
            .enumerate()
            .for_each(|(idx, chunk)| {
                let c = corrections[idx];
                if !c.is_zero() {
                    for elem in chunk.iter_mut() {
                        *elem += c;
                    }
                }
            });
    } else {
        // Sequential suffix-sum
        let mut sum = F::zero();
        for i in (0..n).rev() {
            sum += v[i];
            v[i] = sum;
        }
    }
}

/// Apply permutation: out[i] = v[perm[i]]
fn permute_safe<F: Clone + Send + Sync>(v: &[F], perm: &[usize]) -> Vec<F> {
    assert_eq!(v.len(), perm.len());
    if v.len() >= PARALLEL_THRESHOLD {
        perm.par_iter().map(|&p| v[p].clone()).collect()
    } else {
        perm.iter().map(|&p| v[p].clone()).collect()
    }
}

/// Permute group elements: out[i] = v[perm[i]]
fn permute_safe_group<G: ark_ec::CurveGroup>(v: &[G], perm: &[usize]) -> Vec<G> {
    assert_eq!(v.len(), perm.len());
    perm.iter().map(|&p| v[p]).collect()
}

/// Prefix-sum in-place on group elements: v[i] = sum(v[0..=i])
fn prefix_sum_inplace_group<G: ark_ec::CurveGroup>(v: &mut [G]) {
    for i in 1..v.len() {
        v[i] = v[i - 1] + v[i];
    }
}

/// Fold: sum groups of 4 to reduce from N=4n to n.
fn apply_f_fold<F: Field>(v: &[F]) -> Vec<F> {
    assert!(v.len().is_multiple_of(4));
    let n = v.len() / 4;
    if n >= PARALLEL_THRESHOLD / 4 {
        (0..n)
            .into_par_iter()
            .map(|i| v[4 * i] + v[4 * i + 1] + v[4 * i + 2] + v[4 * i + 3])
            .collect()
    } else {
        (0..n)
            .map(|i| v[4 * i] + v[4 * i + 1] + v[4 * i + 2] + v[4 * i + 3])
            .collect()
    }
}

/// Compute inverse of a permutation.
pub fn inverse_permutation(perm: &[usize]) -> Vec<usize> {
    let mut inv = vec![0; perm.len()];
    for (i, &p) in perm.iter().enumerate() {
        inv[p] = i;
    }
    inv
}

/// Generate a random permutation using Fisher-Yates.
fn random_permutation<R: Rng>(n: usize, rng: &mut R) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = rng.gen_range(0..=i);
        perm.swap(i, j);
    }
    perm
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::Zero;
    use ark_std::test_rng;

    #[test]
    fn test_suffix_sum() {
        let mut v = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        accumulate_inplace(&mut v);
        assert_eq!(v[0], Fr::from(10u64)); // 1+2+3+4
        assert_eq!(v[1], Fr::from(9u64));  // 2+3+4
        assert_eq!(v[2], Fr::from(7u64));  // 3+4
        assert_eq!(v[3], Fr::from(4u64));  // 4
    }

    #[test]
    fn test_permutation_inverse() {
        let perm = vec![2, 0, 3, 1];
        let inv = inverse_permutation(&perm);
        // perm[0]=2, so inv[2]=0
        assert_eq!(inv, vec![1, 3, 0, 2]);

        // Composing perm and inv should give identity
        for i in 0..4 {
            assert_eq!(inv[perm[i]], i);
        }
    }

    #[test]
    fn test_fold() {
        let v = vec![
            Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64),
            Fr::from(5u64), Fr::from(6u64), Fr::from(7u64), Fr::from(8u64),
        ];
        let folded = apply_f_fold(&v);
        assert_eq!(folded.len(), 2);
        assert_eq!(folded[0], Fr::from(10u64)); // 1+2+3+4
        assert_eq!(folded[1], Fr::from(26u64)); // 5+6+7+8
    }

    #[test]
    fn test_toperator_multiply_sparse() {
        let mut rng = test_rng();
        let n = 64;
        let t_op = TOperator::rand(n, &mut rng);

        // Create a sparse vector with a single entry
        let sparse = vec![(10usize, Fr::from(5u64))];
        let result = t_op.multiply_sparse::<Fr>(&sparse);
        assert_eq!(result.len(), n);

        // Result should be nonzero (overwhelmingly likely)
        let is_nonzero = result.iter().any(|x| !x.is_zero());
        assert!(is_nonzero, "TOperator output should be nonzero for nonzero input");
    }

    #[test]
    fn test_toperator_linearity() {
        let mut rng = test_rng();
        let n = 32;
        let t_op = TOperator::rand(n, &mut rng);

        // T(e1 + e2) == T(e1) + T(e2)
        let e1 = vec![(5usize, Fr::from(3u64))];
        let e2 = vec![(20usize, Fr::from(7u64))];
        let e_combined = vec![(5usize, Fr::from(3u64)), (20usize, Fr::from(7u64))];

        let r1 = t_op.multiply_sparse::<Fr>(&e1);
        let r2 = t_op.multiply_sparse::<Fr>(&e2);
        let r_combined = t_op.multiply_sparse::<Fr>(&e_combined);

        for i in 0..n {
            assert_eq!(r1[i] + r2[i], r_combined[i], "linearity failed at index {i}");
        }
    }
}
