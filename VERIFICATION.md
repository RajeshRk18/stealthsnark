# StealthSnark — Verification Strategy

This document describes how the implementation is verified, organised by the
**security property** each layer protects — not by the tool used. The guiding
principle is that every check should rest on an *oracle independent of the code
under test*, because the dangerous failures here are silent: a proof can verify
while the system is unsound or leaking the witness.

## Threat model & properties

The server is the adversary. Two modes are supported and tested:

- **Semi-honest** — the server follows the protocol but tries to learn the witness.
- **Malicious** — the server may also return wrong MSM results (double-query
  consistency check defends against this).

| Property | What a silent failure looks like | How it's verified | Independent oracle |
|----------|----------------------------------|-------------------|--------------------|
| **EMSM correctness** | unmask ≠ true MSM | `emsm.rs` roundtrip unit tests | the math (plaintext MSM) |
| **Completeness** | recovered proof doesn't verify | `differential.rs`, `integration.rs` | `ark-groth16` verifier |
| **Proof validity = reference** | server-aided proof isn't a real Groth16 proof | `differential.rs` | stock `ark-groth16` prover |
| **Witness privacy** | masked vectors leak the witness | `privacy.rs` (noise-freshness + statistical) | self-calibrated distribution test |
| **Soundness vs malicious server** | tampered response yields a verifying proof | `malicious_soundness.rs`, fuzz `malicious_response` | Groth16 verifier + exhaustive tamper |
| **DoS / panic safety** | crash or OOM on malformed bytes | fuzz `vec_deser`, `message_parsing` | libFuzzer |
| **Session isolation** | one session's generators leak into another | `session_stress.rs` | per-key verify under concurrency |
| **Session authenticity** | a client acts on a session it was not issued | `service_hardening.rs`, `session.rs` unit tests | server-issued 256-bit tokens |
| **Client authentication** | an unregistered caller reaches a `/v1` route | `auth_quota.rs`, `auth.rs` unit tests | every route probed with no credential |
| **Session ownership** | a leaked token works without its owner's credential | `auth_quota.rs` | a second principal replays the token |
| **Quota isolation** | one client consumes another's allowance | `auth_quota.rs`, `quota.rs` unit tests | two principals, one floods |
| **Transport security** | TLS does not verify, or mTLS identity is forgeable | `tls_mtls.rs` | real handshakes against a throwaway CA |
| **Credential secrecy** | a key or token reaches a log or the auth file | `auth.rs`, `secret.rs` unit tests | digest-only storage, redacting `Debug` |
| **Servable circuit size** | the transport silently rejects every useful circuit | `service_hardening.rs` | payload above the old 2 MiB ceiling |
| **Bounded memory** | abandoned sessions pin generators forever | `service_hardening.rs`, `session.rs` unit tests | TTL eviction + session cap |
| **Diagnosability** | distinct failures are indistinguishable to a client | `service_hardening.rs` | stable machine-readable error codes |
| **RAA kernel correctness (all inputs ≤ bound)** | a suffix-sum / fold / permute kernel is wrong on an untested input | `cargo kani` proofs in `raa_code.rs` | bounded model checking (CBMC) |
| **Test-suite adequacy** | tests pass even when code is broken | `cargo mutants` | mutation testing |

## Test layers & how to run them

### 1. Unit + integration tests (`cargo test`)

```sh
cargo test                 # all unit tests + every integration suite below
```

Integration suites (in `tests/`):

- **`differential.rs`** — the server-aided proof (semi-honest *and* malicious)
  must verify exactly like a stock `ark-groth16` proof for the same circuit and
  witness, across many witnesses; and must **fail** for a wrong public input.
  `ark-groth16` is the independent reference we are outsourcing, so this is the
  strongest cheap correctness oracle.
- **`privacy.rs`** — the witness-hiding property the whole system exists for:
  - noise/mask is freshly sampled per MSM, per main/check query, and per call
    (structural regression guards against noise reuse);
  - every witness coordinate is actually masked and the mask is non-constant;
  - the masked output distribution is independent of the witness
    (self-calibrated: cross-witness TVD vs same-witness baseline — robust, not
    a crypto-grade proof);
  - proof blinders randomise each proof.
- **`malicious_soundness.rs`** — tampering with *each* of the ten MSM results
  (individually, then random combinations via proptest) must be rejected
  outright. Random offsets pass the consistency check only with probability
  ~2^-254, so the hard assert cannot flake — and anything weaker would silently
  tolerate detection regressions (a `_ck`-only tamper never enters proof
  assembly, so a broken check would still hand back a verifying proof).
- **`session_stress.rs`** — many concurrent clients across two distinct keys;
  cross-session generator clobbering would surface as a verify failure. Also
  asserts that forged bearer tokens are refused with 401 under concurrency.
- **`service_hardening.rs`** — the service-layer properties that no
  cryptographic test can observe, because every crypto suite uses a toy circuit:

  | Test | Property |
  |---|---|
  | `setup_accepts_payload_above_the_old_2mib_ceiling` | a >2 MiB generator upload succeeds |
  | `setup_rejects_payload_above_configured_limit` | the cap is real and yields a clean 413 |
  | `forged_and_missing_tokens_are_refused` | no credential / a forged one ⇒ 401 |
  | `concurrent_setups_do_not_clobber_each_other` | independent tokens, no replacement |
  | `expired_sessions_are_refused_and_freed` | idle TTL stops resolving and frees memory |
  | `session_cap_is_enforced` | 429 + `Retry-After`, map does not grow |
  | `version_header_is_required_and_enforced` | absent/wrong version ⇒ 400 |
  | `failure_modes_are_distinguishable` | `malformed_body` ≠ `invalid_input` |
  | `length_mismatch_is_reported_as_invalid_input` | bad request does not kill the session |
  | `release_frees_the_session_and_invalidates_the_token` | explicit teardown works, double release ⇒ 401 |
  | `health_endpoints_are_unauthenticated_and_unversioned` | probes need no protocol knowledge |
  | `metrics_reflect_traffic` | counters move, incl. the cheating-server counter |

  The first of these is the one worth dwelling on. Five verification layers —
  differential, privacy, proptest soundness, fuzzing, Kani — all passed while
  axum's default 2 MiB body limit made the service unable to accept any circuit
  large enough to be worth outsourcing. Correctness oracles cannot see a
  capacity ceiling; only a realistically-sized payload can.

- **`auth_quota.rs`** — client authentication and per-principal quota over HTTP.
  The unit tests in `protocol::auth` and `protocol::quota` check the rules in
  isolation; these check the rules are *wired in*. A route mounted outside the
  authenticate layer, or a handler that forgot to charge quota, passes every unit
  test and fails here.

  | Test | Property |
  |---|---|
  | `every_data_plane_route_requires_a_credential` | no route serves an anonymous caller; 401 carries `WWW-Authenticate` |
  | `api_keys_are_verified` | a tampered secret and an unknown key id both fail, with the same message |
  | `a_session_token_is_useless_to_another_principal` | wrong owner ⇒ 403, and cannot release either |
  | `rate_limit_is_enforced_per_principal` | burst then 429 + `Retry-After`; a second principal is unaffected |
  | `session_quota_is_enforced_per_principal` | tier cap binds, and releasing restores the allowance |
  | `body_size_quota_is_enforced_per_tier` | 413 below the server-wide transport limit |
  | `unauthenticated_traffic_does_not_spend_a_principals_allowance` | check order: authenticate before charging quota |
  | `the_client_completes_a_session_with_an_api_key` | the real client flow verifies a proof end to end |

- **`tls_mtls.rs`** — real handshakes, because the mTLS identity path cannot be
  checked any other way: whether rustls verified the chain, and whether the
  resulting certificate digest reaches the middleware, only becomes true after a
  handshake completes. A throwaway CA, server certificate, and two client
  certificates are generated in memory by `rcgen`, so no private key is committed.
  Gated on `#![cfg(feature = "tls")]`.

  | Test | Property |
  |---|---|
  | `tls_serves_a_client_that_trusts_the_ca` | TLS works end to end |
  | `tls_rejects_a_client_that_does_not_trust_the_ca` | verification is real — if this passes, it is not happening |
  | `mtls_authenticates_a_registered_certificate` | identity from the handshake, no header |
  | `mtls_refuses_an_unregistered_certificate` | a valid chain is necessary but not sufficient |
  | `mtls_requires_a_certificate` | mTLS-only refuses at the handshake |
  | `any_mode_accepts_a_certificate_or_a_key` | optional client auth, so a key client still connects |
  | `mtls_identity_is_bound_to_its_sessions` | ownership holds regardless of how identity was proved |

  Worth recording: the first run of this suite failed with `KeyMismatch` and
  `BadSignature` because every test shared one PKI directory and parallel runs
  overwrote each other's keys. The symptom looked like a cryptographic fault and
  was a test-isolation bug.

### 2. Benchmarks (`cargo bench`)

```sh
cargo bench                # criterion; results + regression deltas in target/criterion
```

`benches/msm_scaling.rs` tracks EMSM encrypt/server/decrypt across sizes (watch
for superlinear regressions in the RAA path) and end-to-end proving cost.

### 3. Fuzzing (`cargo +nightly fuzz`)

Requires nightly + `cargo install cargo-fuzz` (already vendored under `fuzz/`).

```sh
cargo +nightly fuzz run vec_deser          # deserialization never panics/OOMs
cargo +nightly fuzz run message_parsing    # full request-parse pipeline is panic-free
cargo +nightly fuzz run malicious_response # soundness: tamper => caught, never forged
```

`malicious_response` is the soundness fuzzer: it builds the setup once, then on
each input copies the honest response, applies fuzz-driven tampering to the ten
components, and asserts every tamper is rejected (an untampered response must
still decrypt to a sound proof) — hunting directly for check-bypassing inputs.

### 4. Mutation testing (`cargo mutants`)

```sh
cargo install cargo-mutants
cargo mutants              # scoped to soundness/privacy-critical modules via .cargo/mutants.toml
```

Proves the tests above actually fail when the implementation is broken. A
**surviving** mutant in `malicious.rs`, `emsm.rs`, or `server_aided.rs` is a real
gap to close.

### 5. Formal verification (`cargo kani`)

```sh
cargo install --locked kani-verifier && cargo kani setup   # one-time
cargo kani --no-default-features --lib                      # run all proofs
```

Where do bounded proofs actually pay here? Not on the protocol math (proved on
paper by the authors), not on field/curve arithmetic (trusted to `arkworks`, and
intractable for a bit-blasting checker), and not on the witness-hiding property
(probabilistic, not an assertion). They pay on the **RAA scalar kernels** — the
suffix-sum chunking and 4:1 fold — which are pure, bounded, and exactly where
mutation testing already showed the logic is subtle enough to hide dead code.
Sampled-size tests check *specific* large inputs; these proofs check *all* inputs
up to a small bound.

The kernels are generic over a minimal `Additive` trait (identity, `+=`,
is-zero). Production runs them on BN254's scalar field via a blanket
`impl<F: Field> Additive for F`; the proofs run the **same** kernels on a tiny
model type `Toy` = wrapping `u64` (the monoid ℤ/2⁶⁴) that CBMC can reason about
symbolically. Because the kernels rely only on the commutative-monoid laws,
every identity proved for `Toy` transfers to any field. The parallel (rayon)
branches reduce to these same kernels; rayon only changes the execution order of
independent per-chunk work, which is irrelevant to the (order-independent)
result, so the sequential models faithfully cover them.

Harnesses (in `raa_code.rs`, `#[cfg(kani)] mod kani_proofs`):

| Harness | Proves |
|---------|--------|
| `exclusive_suffix_sums_matches_spec` | phase-2 corrections satisfy `corr[i] = Σ chunk_sums[i+1..]` (the step that hid dead code) |
| `chunked_suffix_sum_equals_naive_cs{1,2,3,4}` | the full chunked suffix sum equals the naive reference, for every input; the four chunk sizes exhaust **every** chunking of a 4-element slice |
| `accumulate_inplace_sequential_equals_naive` | the production entry point's sequential branch equals the naive reference |
| `apply_f_fold_matches_spec` | fold yields `out[i] = Σ v[4i..4i+4]`; the `4i+k` indexing never goes out of bounds |
| `permute_safe_in_bounds_is_correct` | with in-range indices, `permute_safe` never panics and yields `out[i] = v[perm[i]]` |
| `inverse_permutation_inverts_valid_permutation` | for any valid permutation, `inverse_permutation` returns its true inverse and never panics |

`--no-default-features --lib` is required so the wasmer-backed `circom` feature
(and the feature-gated `client` binary) are excluded — CBMC cannot codegen
wasmer, and the kernels don't need it.

**Why not Kani on `messages.rs`?** `ark_vec_from_bytes` has a data-dependent
loop bound (`0..len`, `len` up to 2²⁴), so the meaningful "no panic over all
inputs" property is out of reach for a bounded checker, and the real DoS property
is a *heap-allocation* bound CBMC doesn't model. That deserialization loop is
better served by the `vec_deser` fuzzer (its actual oracle), which is why no Kani
harness is added there.

## Findings

- **Memory-amplification DoS in `ark_vec_from_bytes`** (found by the `vec_deser`
  fuzzer on its first run). The function read a length prefix up to
  `MAX_VEC_LEN` (2²⁴) and called `Vec::with_capacity(len)` before checking the
  body actually contained that many elements — a tiny request with a maxed-out
  length prefix forced a ~0.5–1.5 GB allocation. Note that capping by the
  remaining *byte* count is not enough: the allocation is
  `count * size_of::<T>()` (~136 bytes per input byte for G2Affine), so a
  few-MB junk body would still buy hundreds of MB upfront. Fixed by capping the
  initial capacity at a small constant (`MAX_PREALLOC_ELEMS`) and letting the
  Vec grow amortized as elements actually decode. Regression:
  `messages::tests::test_huge_length_prefix_tiny_body_does_not_overallocate`.

- **Untested parallel paths in the RAA code** (found by `cargo mutants`). 16
  mutants survived in the parallel branch of `apply_f_fold`, and the parallel
  branches of `accumulate_inplace` and `permute_safe` were likewise uncovered —
  every existing test ran below `PARALLEL_THRESHOLD` (65536 elements), so the
  rayon paths in the hot loop never executed. A bug there would ship silently and
  only bite on large circuits. Closed with three large-size tests that check each
  parallel path against an independent sequential reference
  (`raa_code::tests::{test_fold_parallel_path,
  test_accumulate_parallel_matches_sequential_reference,
  test_permute_parallel_matches_reference}`). Re-running confirms it: of 98
  mutants on the RAA module, 81 are now caught and the 14 survivors are all
  *equivalent* mutants — they flip which already-verified branch runs (the
  `PARALLEL_THRESHOLD` comparisons) or change the parallel chunk count, neither
  of which alters the result. Investigating two survivors also surfaced **dead
  code** in `accumulate_inplace`'s parallel correction step (a first loop fully
  overwritten by the next), now removed. The accumulator's suffix-sum semantics
  were cross-checked against the paper (§2.3: A is the upper-triangular all-ones
  matrix, i.e. a suffix sum).

## Out of scope / future work

- **Field & curve arithmetic** is trusted to `arkworks` (not re-verified here),
  and is out of reach for a bit-blasting model checker anyway. The pure RAA
  kernels that *are* tractable are now covered by `cargo kani` (see §5). The
  protocol-level soundness/privacy theorems are proved on paper by the authors;
  re-proving them in a proof assistant (Lean/Coq) over abstract groups is a
  research effort, not a hardening step, and is deliberately not attempted.
- **Constant-timeness** of masking is not asserted (the server only sees masked
  data; timing channels are out of the current model).
- **Replay / freshness** protection at the protocol layer is intentionally left
  to the application embedding this library.
- **LPN parameter security** (`params.rs`, Table 3) is a trust assumption carried
  from the paper; the code enforces structural validity, not the security bound.
