# StealthSnark TODO

## Phase 1: Core EMSM Primitives

- [x] 1.0 Update Cargo.toml (edition 2021, all deps)
- [x] 1.1 `src/emsm/sparse_vec.rs` — SparseVector<F> type
- [x] 1.2 `src/emsm/params.rs` — LPN parameter table
- [x] 1.3 `src/emsm/raa_code.rs` — TOperator
- [x] 1.4 `src/emsm/pedersen.rs` — Pedersen commitment
- [x] 1.5 `src/emsm/dual_lpn.rs` — Dual LPN instance
- [x] 1.6 `src/emsm/emsm.rs` — EMSM protocol (encrypt/evaluate/decrypt + roundtrip test)
- [x] 1.7 `src/emsm/malicious.rs` — Malicious EMSM (challenge, dual queries, consistency check)
- [x] 1.8 Wire up `src/emsm/mod.rs`

## Phase 2: Server-Aided Groth16

- [x] 2.1 `src/groth16/circuit.rs` — Demo CubeCircuit (x^3 + x + 5 = y)
- [x] 2.2 `src/groth16/server_aided.rs` — ServerAidedProvingKey, client_encrypt/server_evaluate/client_decrypt
- [x] 2.3 Wire up `src/groth16/mod.rs`

## Phase 3: Networking

- [x] 3.1 `src/protocol/messages.rs` — Wire types (SetupRequest, ProveRequest, ProveResponse)
- [x] 3.2 `src/protocol/server.rs` — Axum server (POST /setup, POST /prove)
- [x] 3.3 `src/protocol/client.rs` — HTTP client (send_setup, send_prove)
- [x] 3.4 Wire up `src/protocol/mod.rs`

## Phase 4: Binaries + Integration

- [x] 4.1 `src/bin/server.rs` — Server binary (tokio::main, bind :3000)
- [x] 4.2 `src/bin/client.rs` — Client binary (full e2e flow)
- [x] 4.3 Finalize `src/lib.rs`
- [x] 4.4 Integration test: spawn server in-process, run client, verify proof + session isolation

## Phase 5: Circom Circuit Integration

- [x] 5.1 `circuits/multiplier2.circom` — a * b = c (1 constraint)
- [x] 5.2 `circuits/range_check.circom` — 8-bit range proof (9 constraints)
- [x] 5.3 `circuits/compile.sh` — compile script
- [x] 5.4 Add ark-circom 0.5 + num-bigint 0.4 to Cargo.toml
- [x] 5.5 Make `client_encrypt` generic over `QAP: R1CSToQAP`
- [x] 5.6 `src/groth16/circom.rs` — circom_setup, build_circuit, get_public_inputs + 2 e2e tests
- [x] 5.7 Update `src/bin/client.rs` to use Circom multiplier2 circuit
- [x] 5.8 All 25 tests passing, zero warnings

## Phase 6: Hardening & Polish

- [x] 6.1 Cargo clippy clean (zero warnings)
- [x] 6.2 Error handling cleanup (fallible deser, Result-based Pedersen::commit, no panics on untrusted input)
- [x] 6.3 README with usage instructions
- [x] 6.4 Wire malicious EMSM into server-aided Groth16 flow (malicious_client_encrypt/decrypt + 2 tests)
- [x] 6.5 Replace deterministic RNG seeds in binaries with OsRng
- [x] 6.6 Session-bound /setup and /prove (per-session generator storage, session ID in envelopes)
- [x] 6.7 Harden protocol: fallible deserialization, MAX_VEC_LEN cap, no panics on malformed input
- [x] 6.8 pad_or_trim warns on length mismatch
- [x] 6.9 Integration tests (e2e + session isolation)

All TODOs complete. 32 tests (30 unit + 2 integration), zero clippy warnings.
