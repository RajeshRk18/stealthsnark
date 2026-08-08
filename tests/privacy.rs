//! Privacy tests. The entire reason this system exists is that the server must
//! learn nothing about the witness from the masked vectors it receives. None of
//! that is exercised by the correctness tests, so this file targets it directly.
//!
//! Two families of test:
//!   1. Noise-freshness guards — the LPN noise `e` (and hence the mask `r = T·e`)
//!      must be independently re-sampled for every query and every MSM. Reusing
//!      noise across the main/check queries would let a cheating server pass the
//!      consistency check; reusing it across the five MSMs would correlate them.
//!      These are *structural regression guards*: if a future refactor shares one
//!      `DualLPNInstance`, the test fails loudly.
//!   2. Masking-quality smoke tests — the mask must actually cover the witness,
//!      and the masked output distribution must not depend on the witness. The
//!      statistical test is self-calibrated (cross-witness distance vs.
//!      same-witness baseline) so it is a robust gross-bug detector, not a
//!      flaky crypto-grade indistinguishability proof.

use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use stealthsnark::emsm::dual_lpn::DualLPNInstance;
use stealthsnark::emsm::emsm::{encrypt, EmsmPublicParams};
use stealthsnark::emsm::sparse_vec::SparseVector;
use stealthsnark::groth16::circuit::CubeCircuit;
use stealthsnark::groth16::server_aided::{
    client_encrypt, malicious_client_encrypt, ServerAidedProvingKey,
};

fn noise_eq(a: &SparseVector<Fr>, b: &SparseVector<Fr>) -> bool {
    a.entries == b.entries
}

// ─── 1. Noise-freshness guards ───────────────────────────────────────────────

#[test]
fn semi_honest_uses_distinct_noise_per_msm() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let circuit_for_setup = CubeCircuit::<Fr> { x: None };
    let (pk, _vk) =
        Groth16::<ark_bn254::Bn254>::circuit_specific_setup(circuit_for_setup, &mut rng).unwrap();
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

    let circuit = CubeCircuit {
        x: Some(Fr::from(3u64)),
    };
    let (_req, state) =
        client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng).unwrap();

    // All five MSMs must carry independently sampled noise.
    let noises: [&DualLPNInstance<Fr>; 5] = [
        &state.lpn_h,
        &state.lpn_l,
        &state.lpn_a,
        &state.lpn_b_g1,
        &state.lpn_b_g2,
    ];
    for i in 0..noises.len() {
        for j in (i + 1)..noises.len() {
            assert!(
                !noise_eq(&noises[i].noise, &noises[j].noise),
                "noise reused between MSM {i} and {j} — masks would be correlated"
            );
        }
    }
}

#[test]
fn malicious_main_and_check_noise_are_independent() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let circuit_for_setup = CubeCircuit::<Fr> { x: None };
    let (pk, _vk) =
        Groth16::<ark_bn254::Bn254>::circuit_specific_setup(circuit_for_setup, &mut rng).unwrap();
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

    let circuit = CubeCircuit {
        x: Some(Fr::from(3u64)),
    };
    let (_req, state) =
        malicious_client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng).unwrap();

    // Within each MSM, the main query and the consistency-check query MUST use
    // independent noise — otherwise the c·z relationship leaks and a cheating
    // server can forge a consistent-looking response.
    let states = [
        ("h", &state.ds_h),
        ("l", &state.ds_l),
        ("a", &state.ds_a),
        ("b_g1", &state.ds_b_g1),
        ("b_g2", &state.ds_b_g2),
    ];
    for (label, ds) in states {
        assert!(
            !noise_eq(&ds.lpn.noise, &ds.lpn_check.noise),
            "main/check noise reused for MSM {label} — breaks consistency-check soundness"
        );
    }
}

#[test]
fn repeated_encryption_resamples_noise() {
    // Encrypting the same witness twice must use fresh noise each time, otherwise
    // an observer that sees two transcripts could cancel the mask.
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let n = 64;
    let generators: Vec<_> = (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();
    let params = EmsmPublicParams::<G1>::new(generators, &mut rng);
    let witness: Vec<Fr> = (0..n).map(|i| Fr::from(i as u64)).collect();

    let (v1, lpn1) = encrypt(&params, &witness, &mut rng);
    let (v2, lpn2) = encrypt(&params, &witness, &mut rng);

    assert!(
        !noise_eq(&lpn1.noise, &lpn2.noise),
        "noise must be re-sampled on every encryption"
    );
    assert_ne!(v1, v2, "masked vectors for the same witness must differ");
}

// ─── 2. Masking-quality smoke tests ──────────────────────────────────────────

#[test]
fn mask_covers_every_coordinate() {
    // Every coordinate of the witness must be actually masked: masked[j] != z[j]
    // for all j (i.e. r[j] != 0). A structurally dead coordinate would leak that
    // witness entry in the clear.
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let n = 128;
    let generators: Vec<_> = (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();
    let params = EmsmPublicParams::<G1>::new(generators, &mut rng);

    // Run several samples so a coordinate that is only *sometimes* masked still
    // gets caught.
    let mut ever_unmasked = vec![false; n];
    for _ in 0..32 {
        let witness: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let (masked, _lpn) = encrypt(&params, &witness, &mut rng);
        for j in 0..n {
            if masked[j] == witness[j] {
                ever_unmasked[j] = true;
            }
        }
    }
    let leaked: Vec<usize> = (0..n).filter(|&j| ever_unmasked[j]).collect();
    assert!(
        leaked.is_empty(),
        "coordinates left unmasked (r[j]==0): {leaked:?}"
    );
}

#[test]
fn each_coordinate_of_mask_is_non_constant() {
    // Across samples, each coordinate of the mask r must take at least two
    // distinct values. A coordinate stuck at a constant is not hiding anything.
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let n = 96;
    let t_generators: Vec<_> = (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();
    let params = EmsmPublicParams::<G1>::new(t_generators, &mut rng);

    let witness = vec![Fr::from(0u64); n];
    let mut first: Vec<Option<Fr>> = vec![None; n];
    let mut varies = vec![false; n];
    for _ in 0..48 {
        // masked == r because witness is all-zero
        let (r, _lpn) = encrypt(&params, &witness, &mut rng);
        for j in 0..n {
            match first[j] {
                None => first[j] = Some(r[j]),
                Some(v0) if v0 != r[j] => varies[j] = true,
                _ => {}
            }
        }
    }
    let stuck: Vec<usize> = (0..n).filter(|&j| !varies[j]).collect();
    assert!(
        stuck.is_empty(),
        "mask coordinates stuck at a constant: {stuck:?}"
    );
}

/// Low-nibble (16-bin) histogram of the field elements' least-significant byte.
fn nibble_histogram(samples: &[Fr]) -> [f64; 16] {
    let mut counts = [0u64; 16];
    for v in samples {
        let bytes = v.into_bigint().to_bytes_le();
        let nibble = (bytes[0] & 0x0f) as usize;
        counts[nibble] += 1;
    }
    let total = samples.len() as f64;
    let mut h = [0.0; 16];
    for i in 0..16 {
        h[i] = counts[i] as f64 / total;
    }
    h
}

/// Total-variation distance between two distributions over the same bins.
fn tvd(a: &[f64; 16], b: &[f64; 16]) -> f64 {
    0.5 * (0..16).map(|i| (a[i] - b[i]).abs()).sum::<f64>()
}

#[test]
fn masked_output_distribution_is_witness_independent() {
    // Self-calibrated indistinguishability smoke test. We compare the masked
    // distribution under two *very different* witnesses against the baseline
    // variation between two independent batches of the *same* witness. If masking
    // works, cross-witness distance ≈ same-witness baseline. If masking leaks the
    // witness (e.g. r ≡ 0), cross-witness distance blows up to ~1.0.
    let mut rng = ChaCha20Rng::seed_from_u64(6);
    let n = 64;
    let generators: Vec<_> = (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();
    let params = EmsmPublicParams::<G1>::new(generators, &mut rng);

    let batch = 4000usize;
    let coord = 0usize; // inspect a single coordinate of the masked vector

    let z0 = vec![Fr::from(0u64); n];
    let big = Fr::from(0x0123_4567_89ab_cdefu64);
    let z1 = vec![big; n];

    let sample_coord = |z: &[Fr], count: usize, rng: &mut ChaCha20Rng| -> Vec<Fr> {
        (0..count)
            .map(|_| {
                let (masked, _) = encrypt(&params, z, rng);
                masked[coord]
            })
            .collect()
    };

    let a0 = nibble_histogram(&sample_coord(&z0, batch, &mut rng));
    let b0 = nibble_histogram(&sample_coord(&z0, batch, &mut rng)); // same witness, fresh batch
    let a1 = nibble_histogram(&sample_coord(&z1, batch, &mut rng)); // different witness

    let same_witness = tvd(&a0, &b0);
    let cross_witness = tvd(&a0, &a1);

    // Cross-witness variation must not exceed the same-witness baseline by more
    // than a small margin. With 4000 samples over 16 bins the sampling noise in
    // TVD is ~0.02–0.04, so a 0.06 margin is comfortable yet still catches gross
    // leakage (which would push cross_witness toward 1.0).
    assert!(
        cross_witness <= same_witness + 0.06,
        "masked distribution depends on the witness: \
         same-witness TVD={same_witness:.4}, cross-witness TVD={cross_witness:.4}"
    );
}

#[test]
fn proof_blinders_make_each_proof_unique() {
    // The r,s blinders must randomize the proof: proving the same statement twice
    // must yield distinct proof elements (Groth16 zero-knowledge requirement).
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let circuit_for_setup = CubeCircuit::<Fr> { x: None };
    let (pk, _vk) =
        Groth16::<ark_bn254::Bn254>::circuit_specific_setup(circuit_for_setup, &mut rng).unwrap();
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

    use stealthsnark::groth16::server_aided::{client_decrypt, server_evaluate};
    let prove = |rng: &mut ChaCha20Rng| {
        let circuit = CubeCircuit {
            x: Some(Fr::from(3u64)),
        };
        let (req, st) = client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, rng).unwrap();
        let resp = server_evaluate(&sapk, &req).unwrap();
        client_decrypt(&sapk, &resp, &st)
    };
    let p1 = prove(&mut rng);
    let p2 = prove(&mut rng);
    assert!(
        p1.a != p2.a || p1.b != p2.b || p1.c != p2.c,
        "two proofs of the same statement are identical — blinders not applied"
    );
}
