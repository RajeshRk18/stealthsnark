use ark_ff::Field;
use ark_std::rand::Rng;
// Rayon (and the threshold that switches to it) is only used in the parallel
// branches, which are gated out under `cargo kani` — see `accumulate_inplace`.
#[cfg(not(kani))]
use rayon::prelude::*;

#[cfg_attr(kani, allow(dead_code))]
const PARALLEL_THRESHOLD: usize = 1 << 16;

/// Minimal additive-monoid interface the RAA suffix-sum / fold kernels actually
/// need: an identity, in-place addition, and an identity test. Decoupling the
/// kernels from the full `Field` trait lets the Kani proofs (see the `kani_proofs`
/// module) instantiate them with a tiny, model-checkable type instead of 254-bit
/// BN254 arithmetic — while production still runs the *same* kernels on real
/// field elements via the blanket impl below.
///
/// Every operation here is that of a commutative monoid (associative,
/// commutative `+` with identity `0`), so any reordering identity proved for one
/// such type (e.g. wrapping `u64` = ℤ/2⁶⁴) holds for every field too. That is
/// what makes the Kani results transfer to the real code.
pub(crate) trait Additive: Copy + Send + Sync {
    fn azero() -> Self;
    fn aadd_assign(&mut self, rhs: &Self);
    fn ais_zero(&self) -> bool;
}

impl<F: Field> Additive for F {
    #[inline]
    fn azero() -> Self {
        F::zero()
    }
    #[inline]
    fn aadd_assign(&mut self, rhs: &Self) {
        *self += *rhs;
    }
    #[inline]
    fn ais_zero(&self) -> bool {
        self.is_zero()
    }
}

/// Phase-1 kernel (also the whole sequential path): rewrite `chunk` in place
/// with its suffix sums — `chunk[i] = Σ chunk[i..]` — and return the chunk
/// total. Shared verbatim by `accumulate_inplace` and the Kani model, so the
/// logic Kani proves IS the logic production runs.
#[inline]
pub(crate) fn chunk_suffix_sum_inplace<T: Additive>(chunk: &mut [T]) -> T {
    let mut sum = T::azero();
    for elem in chunk.iter_mut().rev() {
        sum.aadd_assign(elem);
        *elem = sum;
    }
    sum
}

/// Phase-2 kernel: exclusive suffix sums of the per-chunk totals.
/// `corrections[i] = Σ chunk_sums[i+1..]`, with `corrections[last] = 0`. This is
/// the off-by-one-prone step that previously harboured dead code; it is proved
/// against its specification directly in `kani_proofs::exclusive_suffix_sums_correct`.
#[inline]
pub(crate) fn exclusive_suffix_sums<T: Additive>(chunk_sums: &[T]) -> Vec<T> {
    let num = chunk_sums.len();
    let mut corrections = vec![T::azero(); num];
    let mut suffix = T::azero();
    for i in (0..num).rev() {
        corrections[i] = suffix;
        suffix.aadd_assign(&chunk_sums[i]);
    }
    corrections
}

/// Fold kernel: sum one group of four, `Σ v[4i..4i+4]`. Shared by both branches
/// of `apply_f_fold` and proved in `kani_proofs::fold_quad_correct`.
#[inline]
pub(crate) fn fold_quad<T: Additive>(v: &[T], i: usize) -> T {
    let mut acc = v[4 * i];
    acc.aadd_assign(&v[4 * i + 1]);
    acc.aadd_assign(&v[4 * i + 2]);
    acc.aadd_assign(&v[4 * i + 3]);
    acc
}

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

/// Compute suffix-sum in-place: v[i] = sum(v[i..N]).
///
/// Both branches are built from `chunk_suffix_sum_inplace` and
/// `exclusive_suffix_sums`; the parallel branch only changes the *execution
/// order* of independent per-chunk work (rayon), which is irrelevant to the
/// result. The kernels' correctness — including their equivalence under
/// chunking — is machine-checked in `kani_proofs`.
fn accumulate_inplace<T: Additive>(v: &mut [T]) {
    let n = v.len();
    if n <= 1 {
        return;
    }

    // The rayon branch is gated out under `cargo kani`: monomorphising rayon's
    // worker-thread machinery balloons the CBMC model even though the branch is
    // unreachable at the proof's small sizes. Its *logic* is verified rayon-free
    // by `kani_proofs::chunked_suffix_sum_equals_naive` (a faithful sequential
    // mirror). Production keeps both branches.
    #[cfg(not(kani))]
    if n >= PARALLEL_THRESHOLD {
        // Parallel: chunk-wise suffix sums, then fix up with chunk corrections.
        let num_chunks = rayon::current_num_threads().min(n / 1024).max(1);
        let chunk_size = n.div_ceil(num_chunks);

        // Phase 1: local suffix sums within each chunk; collect chunk totals.
        let chunk_sums: Vec<T> = v
            .par_chunks_mut(chunk_size)
            .map(chunk_suffix_sum_inplace)
            .collect();

        // Phase 2: exclusive suffix sums of the per-chunk totals.
        let corrections = exclusive_suffix_sums(&chunk_sums);

        // Phase 3: add each chunk's correction to every element of the chunk.
        v.par_chunks_mut(chunk_size)
            .enumerate()
            .for_each(|(idx, chunk)| {
                let c = corrections[idx];
                if !c.ais_zero() {
                    for elem in chunk.iter_mut() {
                        elem.aadd_assign(&c);
                    }
                }
            });
        return;
    }

    // Sequential suffix-sum is exactly the single-chunk case of phase 1.
    chunk_suffix_sum_inplace(v);
}

/// Apply permutation: out[i] = v[perm[i]]
fn permute_safe<F: Clone + Send + Sync>(v: &[F], perm: &[usize]) -> Vec<F> {
    assert_eq!(v.len(), perm.len());
    // Rayon branch gated out under Kani (see `accumulate_inplace`); both branches
    // apply the identical `v[perm[i]]` indexing, so the sequential proof covers
    // the panic-safety of both.
    #[cfg(not(kani))]
    if v.len() >= PARALLEL_THRESHOLD {
        return perm.par_iter().map(|&p| v[p].clone()).collect();
    }
    perm.iter().map(|&p| v[p].clone()).collect()
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
///
/// Both branches share the `fold_quad` kernel (proved in
/// `kani_proofs::fold_quad_correct`); the parallel branch only distributes the
/// independent per-group sums across threads.
fn apply_f_fold<T: Additive>(v: &[T]) -> Vec<T> {
    assert!(v.len().is_multiple_of(4));
    let n = v.len() / 4;
    // Rayon branch gated out under Kani (see `accumulate_inplace`); both branches
    // map the identical `fold_quad` kernel.
    #[cfg(not(kani))]
    if n >= PARALLEL_THRESHOLD / 4 {
        return (0..n).into_par_iter().map(|i| fold_quad(v, i)).collect();
    }
    (0..n).map(|i| fold_quad(v, i)).collect()
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

/// Bounded formal proofs (run with `cargo kani`). These verify the RAA scalar
/// kernels — the suffix-sum chunking and fold logic that mutation testing
/// flagged as subtle — over *all* inputs up to a small bound, complementing the
/// sampled-size `tests` below which only check specific large inputs.
///
/// The kernels are generic over [`Additive`]; here they are instantiated with a
/// tiny commutative monoid (`Toy` = wrapping `u64` = ℤ/2⁶⁴) that Kani can reason
/// about symbolically. Because the kernels rely only on the monoid laws
/// (associativity, commutativity, identity), every identity proved for `Toy`
/// holds for BN254's scalar field too — the proofs verify the *exact* production
/// kernels, just at a model-checkable element type. The parallel branches reduce
/// to these same kernels under rayon, whose only effect is execution order of
/// independent per-chunk work — irrelevant to the (order-independent) result.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Model element: the commutative monoid ℤ/2⁶⁴ (wrapping `u64`). Wrapping
    /// addition keeps the operation total (no overflow panic) and associative +
    /// commutative, exactly the structure the kernels assume of a field's `+`.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Toy(u64);

    impl Additive for Toy {
        fn azero() -> Self {
            Toy(0)
        }
        fn aadd_assign(&mut self, rhs: &Self) {
            self.0 = self.0.wrapping_add(rhs.0);
        }
        fn ais_zero(&self) -> bool {
            self.0 == 0
        }
    }

    impl kani::Arbitrary for Toy {
        fn any() -> Self {
            Toy(kani::any())
        }
    }

    /// Independent specification of a suffix sum: `out[i] = Σ v[i..]`. Written as
    /// plainly as possible so it is obviously correct by inspection — it is the
    /// oracle the chunked algorithm is checked against.
    fn naive_suffix(v: &[Toy]) -> Vec<Toy> {
        let n = v.len();
        let mut out = vec![Toy(0); n];
        let mut s = Toy(0);
        for i in (0..n).rev() {
            s.aadd_assign(&v[i]);
            out[i] = s;
        }
        out
    }

    /// Sequential mirror of `accumulate_inplace`'s *parallel* branch: identical
    /// code, with `chunks_mut`/`for` standing in for `par_chunks_mut`/`for_each`.
    /// Verifying this verifies the parallel branch's logic for any chunking.
    fn chunked_model(v: &mut [Toy], chunk_size: usize) {
        let chunk_sums: Vec<Toy> = v
            .chunks_mut(chunk_size)
            .map(chunk_suffix_sum_inplace)
            .collect();
        let corrections = exclusive_suffix_sums(&chunk_sums);
        for (idx, chunk) in v.chunks_mut(chunk_size).enumerate() {
            let c = corrections[idx];
            if !c.ais_zero() {
                for elem in chunk.iter_mut() {
                    elem.aadd_assign(&c);
                }
            }
        }
    }

    /// Phase 2 is the off-by-one-prone step that once hid dead code. Prove it
    /// meets its spec exactly: `corr[i] = Σ chunk_sums[i+1..]`, `corr[last] = 0`.
    #[kani::proof]
    #[kani::unwind(7)]
    fn exclusive_suffix_sums_matches_spec() {
        const M: usize = 5;
        let cs: [Toy; M] = kani::any();
        let corr = exclusive_suffix_sums(&cs[..]);
        assert_eq!(corr.len(), M);
        for i in 0..M {
            let mut expect = Toy(0);
            for j in (i + 1)..M {
                expect.aadd_assign(&cs[j]);
            }
            assert_eq!(corr[i], expect);
        }
    }

    /// The whole chunked suffix-sum (the parallel branch's logic) equals the
    /// naive suffix sum, for every input. This is the property the dead-code bug
    /// could have broken.
    ///
    /// `CS` is the chunk size. It is a const generic (not a symbolic value) on
    /// purpose: a symbolic stride makes `chunks_mut`'s pointer arithmetic
    /// pathological for CBMC, while enumerating every concrete `CS` in `1..=N`
    /// covers *all* possible chunkings of an `N`-element slice — exhaustively
    /// equivalent to a symbolic chunk size, but fast. `CS >= N` is the
    /// single-chunk (sequential) case.
    fn chunked_equals_naive<const N: usize, const CS: usize>() {
        let a: [Toy; N] = kani::any();
        let expected = naive_suffix(&a);
        let mut b = a;
        chunked_model(&mut b, CS);
        for i in 0..N {
            assert_eq!(b[i], expected[i]);
        }
    }

    // N = 4: CS in 1..=4 exhausts every chunking (4×1, 2×2, 3+1, 1×4).
    #[kani::proof]
    #[kani::unwind(7)]
    fn chunked_suffix_sum_equals_naive_cs1() {
        chunked_equals_naive::<4, 1>();
    }
    #[kani::proof]
    #[kani::unwind(7)]
    fn chunked_suffix_sum_equals_naive_cs2() {
        chunked_equals_naive::<4, 2>();
    }
    #[kani::proof]
    #[kani::unwind(7)]
    fn chunked_suffix_sum_equals_naive_cs3() {
        chunked_equals_naive::<4, 3>();
    }
    #[kani::proof]
    #[kani::unwind(7)]
    fn chunked_suffix_sum_equals_naive_cs4() {
        chunked_equals_naive::<4, 4>();
    }

    /// The production entry point on its sequential branch (n < threshold) also
    /// equals the naive reference.
    #[kani::proof]
    #[kani::unwind(6)]
    fn accumulate_inplace_sequential_equals_naive() {
        const N: usize = 4;
        let a: [Toy; N] = kani::any();
        let expected = naive_suffix(&a);
        let mut b = a;
        accumulate_inplace(&mut b);
        for i in 0..N {
            assert_eq!(b[i], expected[i]);
        }
    }

    /// Fold reduces 4n→n with `out[i] = Σ v[4i..4i+4]`, and the index arithmetic
    /// `4i+k` never goes out of bounds for multiple-of-4 input.
    #[kani::proof]
    #[kani::unwind(10)] // N=8 symbolic array => Arbitrary fills via an 8-iteration loop
    fn apply_f_fold_matches_spec() {
        const N: usize = 8; // n = 2 groups
        let a: [Toy; N] = kani::any();
        let out = apply_f_fold(&a[..]);
        assert_eq!(out.len(), N / 4);
        for i in 0..(N / 4) {
            let mut expect = a[4 * i];
            expect.aadd_assign(&a[4 * i + 1]);
            expect.aadd_assign(&a[4 * i + 2]);
            expect.aadd_assign(&a[4 * i + 3]);
            assert_eq!(out[i], expect);
        }
    }

    /// `permute_safe` with in-range indices never panics and yields
    /// `out[i] = v[perm[i]]`. (In production the indices come from a real
    /// permutation, so they are always in range — that is the precondition.)
    #[kani::proof]
    #[kani::unwind(6)]
    fn permute_safe_in_bounds_is_correct() {
        const N: usize = 4;
        let v: [Toy; N] = kani::any();
        let perm: [usize; N] = kani::any();
        for i in 0..N {
            kani::assume(perm[i] < N);
        }
        let out = permute_safe(&v[..], &perm[..]);
        assert_eq!(out.len(), N);
        for i in 0..N {
            assert_eq!(out[i], v[perm[i]]);
        }
    }

    /// For any valid permutation, `inverse_permutation` produces its true
    /// inverse (both `inv[perm[i]] = i` and `perm[inv[j]] = j`) and never panics.
    #[kani::proof]
    #[kani::unwind(6)]
    fn inverse_permutation_inverts_valid_permutation() {
        const N: usize = 4;
        let perm: [usize; N] = kani::any();
        // A valid permutation: in range and pairwise distinct (=> a bijection).
        for i in 0..N {
            kani::assume(perm[i] < N);
        }
        for i in 0..N {
            for j in (i + 1)..N {
                kani::assume(perm[i] != perm[j]);
            }
        }
        let inv = inverse_permutation(&perm[..]);
        assert_eq!(inv.len(), N);
        for i in 0..N {
            assert_eq!(inv[perm[i]], i);
        }
        for j in 0..N {
            assert_eq!(perm[inv[j]], j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::Zero;
    use ark_std::test_rng;

    #[test]
    fn test_suffix_sum() {
        let mut v = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        accumulate_inplace(&mut v);
        assert_eq!(v[0], Fr::from(10u64)); // 1+2+3+4
        assert_eq!(v[1], Fr::from(9u64)); // 2+3+4
        assert_eq!(v[2], Fr::from(7u64)); // 3+4
        assert_eq!(v[3], Fr::from(4u64)); // 4
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
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
            Fr::from(6u64),
            Fr::from(7u64),
            Fr::from(8u64),
        ];
        let folded = apply_f_fold(&v);
        assert_eq!(folded.len(), 2);
        assert_eq!(folded[0], Fr::from(10u64)); // 1+2+3+4
        assert_eq!(folded[1], Fr::from(26u64)); // 5+6+7+8
    }

    // The parallel branches of apply_f_fold / accumulate_inplace / permute_safe
    // are gated behind PARALLEL_THRESHOLD, so all the small tests above only hit
    // the sequential paths. These tests exercise the parallel paths at size
    // >= PARALLEL_THRESHOLD against independent sequential references. (Found via
    // cargo-mutants: 16 surviving mutants in apply_f_fold's parallel branch.)

    #[test]
    fn test_fold_parallel_path() {
        // big_n = PARALLEL_THRESHOLD => fold n = N/4 >= PARALLEL_THRESHOLD/4 => parallel branch.
        let len = PARALLEL_THRESHOLD;
        let v: Vec<Fr> = (0..len).map(|j| Fr::from(j as u64)).collect();
        let folded = apply_f_fold(&v);
        assert_eq!(folded.len(), len / 4);
        for (i, f) in folded.iter().enumerate() {
            // (4i) + (4i+1) + (4i+2) + (4i+3) = 16i + 6
            assert_eq!(*f, Fr::from(16u64 * i as u64 + 6), "fold mismatch at {i}");
        }
    }

    #[test]
    fn test_accumulate_parallel_matches_sequential_reference() {
        let len = PARALLEL_THRESHOLD; // hits the parallel suffix-sum path
        let vals: Vec<Fr> = (0..len).map(|j| Fr::from((j as u64 % 251) + 1)).collect();

        // Independent reference: expected[i] = sum(vals[i..]).
        let mut expected = vec![Fr::zero(); len];
        let mut s = Fr::zero();
        for i in (0..len).rev() {
            s += vals[i];
            expected[i] = s;
        }

        let mut v = vals.clone();
        accumulate_inplace(&mut v);
        assert_eq!(v, expected, "parallel suffix-sum disagrees with reference");
    }

    #[test]
    fn test_permute_parallel_matches_reference() {
        let len = PARALLEL_THRESHOLD; // hits the parallel permute path
        let perm: Vec<usize> = (0..len).rev().collect(); // reversal permutation
        let v: Vec<Fr> = (0..len).map(|j| Fr::from(j as u64)).collect();
        let out = permute_safe(&v, &perm);
        assert_eq!(out.len(), len);
        for i in 0..len {
            assert_eq!(out[i], v[perm[i]], "permute mismatch at {i}");
        }
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
        assert!(
            is_nonzero,
            "TOperator output should be nonzero for nonzero input"
        );
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
            assert_eq!(
                r1[i] + r2[i],
                r_combined[i],
                "linearity failed at index {i}"
            );
        }
    }
}
