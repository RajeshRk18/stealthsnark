# StealthSnark

Rust implementation of **"Single-Server Private Outsourcing of zk-SNARKs"** (Abbaszadeh, Hafezi, Katz, Meiklejohn).

A client outsources the heavy multi-scalar multiplication (MSM) work of Groth16 proving to an untrusted server, without revealing the witness. The witness is masked using LPN-based noise (the EMSM primitive), the server computes MSMs on masked data, and the client recovers a valid proof locally.

## How it works

```
CLIENT                                SERVER
 Groth16 trusted setup -> (pk, vk)
 EMSM preprocessing (5 MSMs)
 POST /setup {generators}  -------->  store generators
 Synthesize circuit, extract witness
 QAP reduction -> h polynomial
 Mask 5 scalar vectors with LPN noise
 POST /prove {masked vectors} ----->  MSM(masked, generators) x5
 <----- {5 MSM results}               return results
 Unmask results, assemble proof
 Groth16::verify(proof) -> OK
```

The server never sees the plaintext witness. Security relies on the Dual-LPN assumption.

## Quick start

### 1. Compile Circom circuits

```sh
./circuits/compile.sh
```

This compiles `multiplier2.circom` and `range_check.circom` into `circuits/build/` (R1CS + WASM artifacts).

### 2. Run tests

```sh
cargo test
```

Runs the full suite: EMSM primitives, Groth16 server-aided proving (native CubeCircuit + Circom circuits), protocol serialization, plus the verification suites described in [Security hardening & verification](#security-hardening--verification) below.

### 3. Run client/server demo

Terminal 1 -- start the server:

```sh
cargo run --bin server
```

Terminal 2 -- run the client (Circom multiplier2: `a=3, b=11 -> c=33`):

```sh
cargo run --bin client
```

The client performs Groth16 setup, sends generators to the server, masks the witness, delegates MSM computation, recovers the proof, verifies it locally, then releases the session.

## Running it as a service

### HTTP API

All request and response bodies are bincode over `application/octet-stream`.
Every `/v1` request must carry `x-stealthsnark-version: 1`; errors come back as
`{"code": "...", "message": "..."}` with a stable machine-readable `code`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/setup` | none | Upload generators, receive a session token |
| `POST` | `/v1/prove` | `Bearer <token>` | Evaluate the five MSMs |
| `DELETE` | `/v1/session` | `Bearer <token>` | Release generators early |
| `GET` | `/livez` | none | Process is up |
| `GET` | `/readyz` | none | Process can accept work (503 when saturated or draining) |
| `GET` | `/metrics` | none | Prometheus text format |

The session token is **issued by the server** and is a bearer credential — do not
log it. The server logs a separate short `session_label`, also returned to the
client, so the two sides can correlate a request without the token reaching a log
sink.

### Configuration

Everything is environment-driven; a malformed value fails startup rather than
silently taking a default.

| Variable | Default | Purpose |
|---|---|---|
| `STEALTHSNARK_BIND` | `127.0.0.1:3000` | Bind address. Loopback by default so an unauthenticated service is not exposed by accident. |
| `STEALTHSNARK_MAX_BODY_BYTES` | `268435456` (256 MiB) | Largest request body. **This is what decides the largest servable circuit** — see below. |
| `STEALTHSNARK_MAX_SESSIONS` | `64` | Cap on live sessions; each pins its generators in memory. |
| `STEALTHSNARK_SESSION_TTL_SECS` | `1800` | Idle timeout before a session is evicted. |
| `STEALTHSNARK_SWEEP_INTERVAL_SECS` | `60` | How often idle sessions are reclaimed. |
| `STEALTHSNARK_MAX_CONCURRENT_MSM` | `cores/2`, clamped to `[1,4]` | Concurrent MSM evaluations. Small on purpose: each MSM is already rayon-parallel internally. |
| `STEALTHSNARK_ADMISSION_WAIT_SECS` | `30` | How long a request waits for a slot before a 503. |
| `STEALTHSNARK_REQUEST_TIMEOUT_SECS` | `600` | Per-request ceiling. |
| `STEALTHSNARK_LOG` | `info` | `tracing` filter. |
| `STEALTHSNARK_LOG_FORMAT` | text | Set to `json` for structured logs. |
| `STEALTHSNARK_SERVER_URL` | `http://127.0.0.1:3000` | Client binary only. |

**Sizing the body limit.** `/v1/setup` uploads every generator for all five MSMs
in one body. A compressed G1 point is 32 bytes and a G2 point 64, so a circuit
needing 2^20 generators per MSM is roughly 192 MiB. The body is buffered before
decoding, so worst-case memory from in-flight bodies is about
`MAX_BODY_BYTES * MAX_CONCURRENT_MSM` — the server logs that product at startup.

Read `SECURITY.md` before exposing this to a network: it has no TLS and no client
authentication by design, and expects to sit behind a reverse proxy.

## Security hardening & verification

This is a cryptographic protocol where the dangerous failures are **silent**: a
proof can verify while the system is actually unsound (accepts forged proofs) or
leaking the witness. Ordinary happy-path tests don't catch those, so the project
is verified in depth, with each layer resting on an *oracle independent of the
code under test*. The full strategy lives in [`VERIFICATION.md`](VERIFICATION.md).

### Threat model

The **server is the adversary**. Two modes are implemented and tested:

- **Semi-honest** — follows the protocol but tries to learn the witness.
- **Malicious** — may also return wrong MSM results; defended by a double-query
  consistency check that detects tampering with overwhelming probability.

### Defense-in-depth layers

| Property protected | Silent failure it catches | How it's verified | Independent oracle |
|---|---|---|---|
| **Completeness / correctness** | recovered proof doesn't verify | `tests/differential.rs` | stock `ark-groth16` prover+verifier |
| **Witness privacy** | masked vectors leak the witness | `tests/privacy.rs` | self-calibrated statistical test |
| **Soundness vs malicious server** | tampered response yields a verifying proof | `tests/malicious_soundness.rs` + `fuzz/malicious_response` | Groth16 verifier + exhaustive tamper |
| **DoS / panic safety** | crash or OOM on malformed bytes | `fuzz/{vec_deser,message_parsing}` | libFuzzer |
| **Session isolation** | one client's generators leak into another's proof | `tests/session_stress.rs` | per-key verify under concurrency |
| **RAA kernel correctness** | a suffix-sum/fold/permute kernel is wrong on an untested input | `cargo kani` proofs in `src/emsm/raa_code.rs` | bounded model checking (CBMC) |
| **Test-suite adequacy** | tests pass even when the code is broken | `cargo mutants` | mutation testing |

Concretely, beyond the original unit suite this added:

- **Differential testing** — the server-aided proof (semi-honest *and*
  malicious) must verify *exactly like* a proof from the unmodified `ark-groth16`
  prover, across many witnesses, and must **fail** for a wrong public input.
- **Privacy testing** — the witness-hiding guarantee the whole system exists for:
  structural guards that the LPN noise is freshly re-sampled per MSM, per
  main/check query, and per call (no noise reuse); that every witness coordinate
  is actually masked; and a self-calibrated statistical test that the masked
  output distribution is independent of the witness.
- **Adversarial soundness testing** — every one of the ten MSM results is
  tampered individually and in random combinations (200-case property test);
  the consistency check must reject every one (random offsets bypass it only
  with probability ~2⁻²⁵⁴, so the hard assert cannot flake).
- **Fuzzing** (3 `cargo-fuzz` targets) — deserialization and the full
  request-parsing pipeline must never panic/OOM; plus a soundness fuzzer that
  hammers the malicious-response check.
- **Mutation testing** — `cargo mutants`, scoped to the 296 mutation points in
  the soundness-critical modules, proves the tests actually fail when the
  implementation is broken.
- **Formal verification** (`cargo kani`) — bounded model-checking proofs that the
  RAA scalar kernels (suffix-sum chunking, 4:1 fold, permutation/inverse) are
  correct for *all* inputs up to a small bound, not just the sampled sizes the
  tests hit. This is targeted precisely where mutation testing showed the logic
  was subtle. The kernels are proved over a tiny model monoid (wrapping `u64`)
  that the checker can reason about symbolically; because they rely only on the
  commutative-monoid laws, the results transfer to BN254's scalar field.
- **Benchmarks** — criterion tracks EMSM and proving cost to catch performance
  regressions.

### What this hardening caught

These layers paid for themselves immediately — two real gaps, both fixed:

1. **Memory-amplification DoS** (found by the `vec_deser` fuzzer on its first
   run). Deserialization read a length prefix up to 2²⁴ and pre-allocated
   `Vec::with_capacity(len)` before checking the body actually held that many
   elements — a tiny request could force a ~0.5–1.5 GB allocation. Fixed by
   capping the upfront allocation at a small constant (bounding by the remaining
   *byte* count is not enough — the allocation is `count × size_of::<T>()`,
   ~136× amplification for G2Affine), with a regression test, and confirmed by
   replaying the crash artifact plus a clean 200k-run campaign.

2. **Untested parallel code paths** (found by `cargo mutants`). 16 mutants
   survived in the parallel branch of the RAA-code fold, because every test ran
   below the 65536-element parallelism threshold — the rayon hot paths never
   executed. Closed with three large-size tests that check each parallel path
   (fold / suffix-sum / permute) against an independent sequential reference;
   re-running confirms it (81/98 mutants caught, the rest provably equivalent),
   and it surfaced a dead-code loop in the parallel suffix-sum that was removed.
   The accumulator's suffix-sum semantics were cross-checked against the paper.

See [`VERIFICATION.md`](VERIFICATION.md#findings) for details.

### Running each layer

```sh
cargo test                                   # unit + integration + verification suites
cargo +nightly fuzz run vec_deser            # also: message_parsing, malicious_response
cargo mutants                                # mutation testing (scoped via .cargo/mutants.toml)
cargo kani --no-default-features --lib       # formal proofs of the RAA kernels (CBMC)
cargo bench                                   # criterion performance benchmarks
```

`cargo kani` needs a one-time `cargo install --locked kani-verifier && cargo kani setup`.
The `--no-default-features --lib` flags exclude the wasmer-backed `circom` path,
which the model checker cannot compile.

Fuzzing requires the lean core without wasmer; the `fuzz/` crate already sets
`default-features = false`. The `circom` feature (on by default) gates the
`ark-circom`/wasmer integration and the `client` binary.

## Circuits

Two sample Circom circuits are included in `circuits/`:

| Circuit | Description | Constraints | Public output |
|---------|-------------|-------------|---------------|
| `multiplier2.circom` | `a * b = c` | 1 | `c` |
| `range_check.circom` | Prove value fits in 8 bits | 9 | `out = value` |

Source `.circom` files are committed. Build artifacts (`circuits/build/`) are gitignored -- run `./circuits/compile.sh` to generate them.

## Project structure

```
src/
  lib.rs
  emsm/                    # Encrypted Multi-Scalar Multiplication
    sparse_vec.rs           #   Sparse vector + error vector generation
    params.rs               #   LPN parameter table (100-bit security)
    raa_code.rs             #   TOperator: random-accumulate code (G = F*M*A*M*A)
    pedersen.rs             #   Pedersen commitments via MSM
    dual_lpn.rs             #   Dual-LPN masking: noise e + mask r = G*e
    emsm.rs                 #   Top-level encrypt / server_computation / decrypt
    malicious.rs            #   Malicious-secure variant (2x overhead, consistency check)
  groth16/
    circuit.rs              #   Demo CubeCircuit (x^3 + x + 5 = y)
    circom.rs               #   Circom circuit loading (ark-circom) + helpers
    server_aided.rs         #   ServerAidedProvingKey, client_encrypt/server_evaluate/client_decrypt
  protocol/
    messages.rs             #   Serde wrappers for arkworks serialization over HTTP
    config.rs               #   Env-driven ServerConfig (limits, timeouts, TTL)
    error.rs                #   ApiError -> status + stable machine-readable code
    metrics.rs              #   Prometheus counters (incl. cheating-server counter)
    session.rs              #   Token-keyed session store: TTL, cap, prebuilt keys
    server.rs               #   Axum handlers, admission control, health, shutdown
    client.rs               #   Reqwest client: setup / prove / release, timeouts
  bin/
    server.rs               #   Server binary (config + graceful shutdown)
    client.rs               #   Client binary (Circom multiplier2 end-to-end)
circuits/
  multiplier2.circom        #   a * b = c
  range_check.circom        #   8-bit range proof
  compile.sh                #   Compile all .circom files
tests/                     # Verification suites (see VERIFICATION.md)
  differential.rs           #   Server-aided proof vs stock ark-groth16
  privacy.rs                #   Witness-hiding: noise freshness + statistical
  malicious_soundness.rs    #   Adversarial tamper detection (proptest)
  session_stress.rs         #   Concurrent session isolation
  service_hardening.rs      #   Body limits, session auth, TTL, versioning, health
  integration.rs            #   End-to-end HTTP flow
  common/mod.rs             #   Shared harness for the HTTP suites
fuzz/                      # cargo-fuzz targets
  fuzz_targets/
    vec_deser.rs            #   Deserialization never panics/OOMs
    message_parsing.rs      #   Request-parse pipeline is panic-free
    malicious_response.rs   #   Soundness fuzzer for the consistency check
benches/
  msm_scaling.rs            #   Criterion EMSM + proving benchmarks
VERIFICATION.md            # Full verification strategy
SECURITY.md                # Disclosure policy + scope / non-goals
.cargo/mutants.toml        # cargo-mutants scope config
```

## Using your own Circom circuit

1. Write a `.circom` file and compile it (`circom circuit.circom --r1cs --wasm --sym -o build/`)
2. Use the helpers in `src/groth16/circom.rs`:

```rust
use stealthsnark::groth16::circom::{circom_setup, build_circuit, get_public_inputs};
use stealthsnark::groth16::server_aided::*;
use ark_circom::CircomReduction;

// Trusted setup
let (pk, vk) = circom_setup("path/to/circuit.wasm", "path/to/circuit.r1cs", &mut rng)?;
let sapk = ServerAidedProvingKey::setup(pk, &mut rng);

// Build circuit with witness
let circuit = build_circuit(
    "path/to/circuit.wasm",
    "path/to/circuit.r1cs",
    &[("input_name", 42.into())],
)?;
let public_inputs = get_public_inputs(&circuit).unwrap();

// Server-aided proving
let (request, state) = client_encrypt::<CircomReduction, _, _>(&sapk, circuit, &mut rng)?;
let response = server_evaluate(&sapk, &request);
let proof = client_decrypt(&sapk, &response, &state);
```

## References

- Abbaszadeh, Hafezi, Katz, Meiklejohn. *Single-Server Private Outsourcing of zk-SNARKs*. 2024.
- [Reference implementation](https://github.com/h-hafezi/server-aided-snarks) (arkworks 0.4, library-only)
- [arkworks](https://arkworks.rs/) ecosystem
- [ark-circom](https://github.com/gakonst/ark-circom)

## License

MIT
