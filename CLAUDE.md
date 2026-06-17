# StealthSnark — Claude Instructions

## Project
Rust implementation of "Single-Server Private Outsourcing of zk-SNARKs" (Abbaszadeh, Hafezi, Katz, Meiklejohn). Paper PDF: `/Users/rajeshkanna/papers/Server-aided-Snarks.pdf`.

## Architecture
- **EMSM** (Encrypted Multi-Scalar Multiplication): core primitive in `src/emsm/`
- **Server-Aided Groth16**: outsources 5 MSMs via EMSM in `src/groth16/`
  - Semi-honest: `client_encrypt` / `server_evaluate` / `client_decrypt`
  - Malicious-secure: `malicious_client_encrypt` / `malicious_server_evaluate_groth16` / `malicious_client_decrypt` (double-query consistency check per MSM)
- **Circom Integration**: `src/groth16/circom.rs` loads Circom circuits via ark-circom 0.5
- **Protocol**: HTTP client-server (axum + reqwest) in `src/protocol/` and `src/bin/`
  - Session-bound: each client gets a session ID; /setup and /prove are scoped per session
  - All deserialization is fallible with MAX_VEC_LEN cap (no panics on untrusted input)
- **Circuits**: sample Circom circuits in `circuits/`, compiled artifacts in `circuits/build/` (gitignored)
- Reference implementation: https://github.com/h-hafezi/server-aided-snarks (arkworks 0.4, library-only, no networking)

## Key Dependencies
- arkworks 0.5.x ecosystem (ark-ff, ark-ec, ark-poly, ark-bn254, ark-groth16, etc.)
- ark-circom 0.5 (with default features — wasmer needs its default compiler backend)
- num-bigint 0.4 (for CircomBuilder::push_input)
- BN254 as primary curve
- tokio + axum for server, reqwest for client
- rayon for parallelism

## Conventions
- Edition 2021 (required by arkworks)
- Generic over CurveGroup where possible (EMSM works for G1 and G2)
- `client_encrypt` is generic over `QAP: R1CSToQAP` — use `LibsnarkReduction` for native circuits, `CircomReduction` for Circom circuits
- Parallel ops via rayon above threshold (2^16 elements)
- CanonicalSerialize/CanonicalDeserialize for arkworks types -> Vec<u8> -> serde wrappers for HTTP
- All deserialization is fallible (`Result` return types) — never panic on untrusted input
- `Pedersen::commit` returns `Result<G, PedersenError>` — propagate, don't unwrap
- ark-circom returns `eyre::Report` errors; map to anyhow via `.map_err(|e| anyhow::anyhow!("{e}"))`
- Circom tests need `#[tokio::test]` (wasmer's virtual-fs requires a tokio reactor)
- Binaries use `OsRng` for cryptographic randomness; `seed_from_u64` only in tests

## Tracking
- `PLAN.md` — implementation plan
- `TODO.md` — detailed task checklist
- `PROGRESS.md` — log of completed work chunks

## Testing
- `cargo test` — unit tests (EMSM, Groth16 native + Circom, protocol) + integration suites
- **See `VERIFICATION.md`** for the full strategy. Verification suites in `tests/`:
  - `differential.rs` — server-aided proof vs stock ark-groth16 (correctness oracle)
  - `privacy.rs` — witness-hiding: noise-freshness guards + statistical indistinguishability
  - `malicious_soundness.rs` — proptest tamper detection across all 10 MSM results
  - `session_stress.rs` — concurrent multi-key session isolation
- Fuzzing: `cargo +nightly fuzz run {vec_deser,message_parsing,malicious_response}`
- Mutation testing: `cargo mutants` (scoped via `.cargo/mutants.toml`)
- Formal verification: `cargo kani --no-default-features --lib` — bounded proofs
  of the RAA kernels (suffix-sum chunking, fold, permutation) in
  `src/emsm/raa_code.rs` (`#[cfg(kani)] mod kani_proofs`). Kernels are generic
  over the `Additive` trait so proofs run on a model monoid (wrapping `u64`)
  instead of BN254. Rayon branches are `#[cfg(not(kani))]`-gated (CBMC can't
  model rayon); their logic is verified rayon-free via `chunked_model`.
  `--no-default-features --lib` excludes the wasmer `circom` path / `client` bin.
- Benchmarks: `cargo bench` (criterion, `benches/msm_scaling.rs`)
- Critical correctness: EMSM roundtrip, Groth16 proof verification
- Circom tests skip gracefully if `circuits/build/` artifacts not found
- Run `./circuits/compile.sh` before testing Circom circuits

## Features
- `circom` (default ON) — gates the ark-circom/wasmer integration and the `client` binary.
  Build the lean core without wasmer via `--no-default-features` (required for cargo-fuzz,
  whose sanitizer toolchain cannot compile wasmer).

## Build & Run
```sh
./circuits/compile.sh   # compile Circom circuits (requires circom 2.x)
cargo build
cargo test              # 25 tests
# Terminal 1:
cargo run --bin server
# Terminal 2:
cargo run --bin client  # runs Circom multiplier2 circuit through server-aided Groth16
```
