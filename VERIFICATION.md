# StealthSnark Testing, Benchmarks, and Verification

## Threat model and properties

The server is the adversary. Both modes are tested.

| Mode | Server behaviour |
|---|---|
| Semi-honest | Follows the protocol but tries to learn the witness |
| Malicious | Returns wrong MSM results |

| Property | What a silent failure looks like | How it's verified | Independent oracle |
|----------|----------------------------------|-------------------|--------------------|
| **EMSM correctness** | unmask ${\neq}$ true MSM | `emsm.rs` roundtrip unit tests | the math (plaintext MSM) |
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

### Benchmarks

```sh
cargo bench                
```

`benches/msm_scaling.rs` covers EMSM encrypt/server/decrypt across sizes and
end-to-end proving cost.

### Fuzzing

Requires nightly + `cargo install cargo-fuzz` (already vendored under `fuzz/`).
Fuzzing needs the lean core without wasmer; the `fuzz/` crate already sets
`default-features = false`.

```sh
cargo +nightly fuzz run vec_deser          

cargo +nightly fuzz run message_parsing   

cargo +nightly fuzz run malicious_response 
```

`malicious_response` is the soundness fuzzer. It builds the setup once, then on
each input copies the honest response, applies fuzz-driven tampering to the ten
components, and asserts every tamper is rejected

### Mutation testing

```sh
cargo install cargo-mutants
cargo mutants          
```

Checks that the tests actually fail when the implementation is broken. The
scope in `.cargo/mutants.toml` covers 296 mutation points across the
soundness-critical and privacy-critical modules.

### Formal verification

```sh
cargo install --locked kani-verifier && cargo kani setup   
cargo kani --no-default-features --lib                      
```

Read more about how proofs are implemented in code documentation.

## Findings

- `vec_deser` fuzzer found a memory amplification DoS in `ark_vec_from_bytes`. It has a hard cap at `MAX_VEC_LEN` = $2^{24}$. It calls `Vec::with_capacity(len)`. But the `len` comes from an untrusted input(read from raw bytes). So, it allocates before actually checking the body. `len` can be $2^{24}$ and body can still be empty. It is fixed by capping the initial capacity at much smaller constant.

- Mutation run exposed untested parallel paths in RAA algorithms. There may be bugs in the parallel paths that only hit on big circuits and wouldnt have been caught by the existing test suite. Large-size tests were added to use the parallel paths.
