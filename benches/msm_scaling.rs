//! Performance regression benchmarks.
//!
//! Two things worth watching over time:
//!   * the EMSM primitive (encrypt / server MSM / decrypt) should scale ~linearly
//!     in the vector length — a superlinear regression would signal an accidental
//!     O(n^2) in the RAA-code path;
//!   * end-to-end server-aided proving should stay dominated by the server MSM,
//!     not by client-side masking.
//!
//! Run with `cargo bench`. These are not assertions; criterion tracks deltas
//! across runs in target/criterion and flags regressions.

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use stealthsnark::emsm::emsm::{decrypt, encrypt, EmsmPublicParams};
use stealthsnark::groth16::circuit::CubeCircuit;
use stealthsnark::groth16::server_aided::{
    client_decrypt, client_encrypt, server_evaluate, ServerAidedProvingKey,
};

fn bench_emsm(c: &mut Criterion) {
    let mut group = c.benchmark_group("emsm");
    for &n in &[256usize, 1024, 4096] {
        let mut rng = ChaCha20Rng::seed_from_u64(n as u64);
        let generators: Vec<_> = (0..n).map(|_| G1::rand(&mut rng).into_affine()).collect();
        let params = EmsmPublicParams::<G1>::new(generators, &mut rng);
        let preprocessed = params.preprocess();
        let witness: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        group.bench_with_input(BenchmarkId::new("encrypt", n), &n, |b, _| {
            b.iter(|| black_box(encrypt(&params, &witness, &mut rng)))
        });

        let (masked, lpn) = encrypt(&params, &witness, &mut rng);
        group.bench_with_input(BenchmarkId::new("server_msm", n), &n, |b, _| {
            b.iter(|| black_box(params.server_computation(&masked).unwrap()))
        });

        let server_result = params.server_computation(&masked).unwrap();
        group.bench_with_input(BenchmarkId::new("decrypt", n), &n, |b, _| {
            b.iter(|| black_box(decrypt(server_result, &lpn, &preprocessed)))
        });
    }
    group.finish();
}

fn bench_server_aided_proving(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
    let (pk, _vk) =
        Groth16::<Bn254>::circuit_specific_setup(CubeCircuit::<Fr> { x: None }, &mut rng).unwrap();
    let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

    c.bench_function("server_aided_prove_cube", |b| {
        b.iter(|| {
            let circuit = CubeCircuit { x: Some(Fr::from(3u64)) };
            let (req, st) =
                client_encrypt::<LibsnarkReduction, _, _>(&sapk, circuit, &mut rng).unwrap();
            let resp = server_evaluate(&sapk, &req).unwrap();
            black_box(client_decrypt(&sapk, &resp, &st))
        })
    });
}

criterion_group!(benches, bench_emsm, bench_server_aided_proving);
criterion_main!(benches);
