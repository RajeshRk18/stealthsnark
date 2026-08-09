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
  - **Two listeners.** Data plane (`/v1/*`, authenticated, TLS when configured) and
    admin plane (`/livez`, `/readyz`, `/metrics`, loopback-only, no credential).
    A probe must work without a credential; `/metrics` must not leave the host
  - Versioned endpoints: `POST /v1/setup`, `POST /v1/prove`, `DELETE /v1/session`.
    Every `/v1` request must carry `x-stealthsnark-version: 2` (bincode is not
    self-describing, so a shape change would otherwise decode as garbage)
  - **Two credentials in two headers.** `Authorization: Bearer <api key>` (or a TLS
    client certificate) says *who you are*; `x-stealthsnark-session` says *which
    generators you mean*. Sessions record their owner, so a leaked session token is
    useless without the owner's credential — wrong owner is `403`, not `401`
  - **Sessions are server-issued**: `/v1/setup` returns a 256-bit token. Clients
    never choose a session id. Neither credential is ever logged — log the
    non-secret `session_label` instead
  - **The server always reclaims sessions itself**, by an idle TTL *and* an
    absolute max age (the idle clock resets on use, so it alone cannot bound a
    token's lifetime). The sweeper applies both with or without traffic. The two
    `DELETE` endpoints are client-side optimisations, never the only path:
    `/v1/session` returns quota at once, `/v1/sessions` reclaims all of a
    principal's sessions after a restart has lost the tokens
  - Sessions also have a per-process cap and a per-principal quota
  - Modules: `auth.rs` (principals, tiers, API keys, mTLS identity), `quota.rs`
    (token bucket, per-principal limits), `tls.rs` (rustls config, cert digests),
    `extract.rs` (auth middleware + extractors), `secret.rs` (random, hex, digest,
    constant-time compare), `config.rs`, `error.rs`, `metrics.rs`, `session.rs`
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
- All serialization *and* deserialization is fallible (`Result` return types) —
  never panic on a request path. `ark_to_bytes` / `ark_vec_to_bytes` return
  `Result`; prefer `SetupRequest::encode` / `ProveRequest::encode`, which handle
  the five-field repetition in one place
- `Pedersen::commit` returns `Result<G, PedersenError>` — propagate, don't unwrap
- **No CPU work on the async runtime.** Point deserialization (subgroup checks)
  and MSM evaluation both belong inside `tokio::task::spawn_blocking`. Never hold
  a lock across either — clone the `Arc<Session>` out and release
- Server config comes from the environment via `ServerConfig::from_env`; a
  malformed value fails startup rather than silently defaulting
- **`validate()` refuses unsafe combinations** rather than inferring intent from a
  missing variable — notably auth disabled on a non-loopback bind, mTLS without
  TLS, a non-loopback admin plane, and TLS configured without the `tls` feature
- **State requirements belong in the handler signature.** Use the `extract.rs`
  extractors (`ApiVersion`, `Caller`, `OwnedSession`), not manual header parsing.
  A handler that cannot be written without naming what it needs cannot forget it
- **Never log a credential.** API keys and session tokens are secrets; `Session`
  and `EmsmClient` have hand-written `Debug` impls that redact or summarise.
  Compare secrets with `secret::constant_time_eq`, store only `secret::sha256_hex`
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
  - `service_hardening.rs` — service-layer properties no crypto test can see:
    body limits, session-token auth, TTL eviction, session cap, version
    enforcement, distinguishable error codes, plane separation
  - `auth_quota.rs` — every route needs a credential, keys are verified, session
    ownership holds, and rate/session/body quota bind per principal
  - `tls_mtls.rs` — real handshakes: TLS trust, mTLS identity from a verified
    chain, unregistered certificates refused. Certificates are generated in memory
    by `rcgen`; none is committed. Gated on `#![cfg(feature = "tls")]`
  - `common/mod.rs` — shared harness for the HTTP suites (not a test target)
- **Use a realistic payload size somewhere.** Every crypto suite uses a toy
  circuit, which is exactly how axum's default 2 MiB body limit went unnoticed
  while silently rejecting every circuit worth outsourcing
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
- `tls` (default ON) — gates rustls, the TLS accept loop, and the `tls_mtls` suite.
  Separate from the core because the TLS listener needs its own accept loop
  (`rustls` + `hyper-util`) to read the client certificate, and because the lean
  core must stay buildable under the fuzz sanitizer. With it off, a configured TLS
  path is a startup error, never a silent downgrade.

## Build & Run
```sh
./circuits/compile.sh   # compile Circom circuits (requires circom 2.x)
cargo build
cargo test              # 166 tests; 151 with --no-default-features
# Terminal 1 — loopback, no auth, no TLS (development default):
cargo run --bin server
# Terminal 2:
cargo run --bin client  # runs Circom multiplier2 circuit through server-aided Groth16
```

Secured run (TLS + API key). See README for the mTLS variant:
```sh
cargo run --bin keygen -- --id alice --tier standard   # mint a key, print the record
STEALTHSNARK_AUTH=apikey STEALTHSNARK_AUTH_FILE=auth.json \
STEALTHSNARK_TLS_CERT=server.pem STEALTHSNARK_TLS_KEY=server.key \
cargo run --bin server
STEALTHSNARK_SERVER_URL=https://localhost:3000 STEALTHSNARK_CA_CERT=ca.pem \
STEALTHSNARK_API_KEY="ssk_..." cargo run --bin client
```
