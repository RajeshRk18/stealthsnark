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
  cross-session generator clobbering would surface as a verify failure.

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

- **Field & curve arithmetic** is trusted to `arkworks` (not re-verified here).
  A bit-precise model checker (e.g. `kani`) could formally verify small pure
  helpers (`pad_or_trim`, `MAX_VEC_LEN` bound, RAA fold) — a natural next step.
- **Constant-timeness** of masking is not asserted (the server only sees masked
  data; timing channels are out of the current model).
- **Replay / freshness** protection at the protocol layer is intentionally left
  to the application embedding this library.
- **LPN parameter security** (`params.rs`, Table 3) is a trust assumption carried
  from the paper; the code enforces structural validity, not the security bound.
