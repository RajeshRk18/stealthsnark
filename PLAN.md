# StealthSnark: Server-Aided zk-SNARKs

Implement "Single-Server Private Outsourcing of zk-SNARKs" paper. Core: EMSM primitive + server-aided Groth16 over HTTP. Client masks witness with LPN noise, server computes MSMs on masked data, client recovers proof.

## Cargo.toml

Edition 2021 (arkworks compat). Dependencies:
- **arkworks 0.5**: ark-ff, ark-ec, ark-poly, ark-std, ark-serialize, ark-bn254, ark-groth16, ark-relations, ark-snark, ark-r1cs-std, ark-crypto-primitives
- **circom**: ark-circom 0.5 (default features), num-bigint 0.4
- **networking**: tokio (full), axum 0.8, reqwest 0.12
- **serialization**: serde, bincode 1.3
- **other**: rayon, rand, rand_chacha, thiserror, anyhow, tracing, tracing-subscriber

Two binaries: `src/bin/server.rs`, `src/bin/client.rs`.

## Module Layout

```
src/
  lib.rs
  emsm/
    mod.rs
    sparse_vec.rs    # SparseVector<F>: index-value pairs, error_vec generation
    params.rs        # LPN param table (Table 3): n -> (N=4n, t) for 100-bit security
    raa_code.rs      # TOperator<F>: G = F_r*M_p*A*M_q*A, multiply_sparse in O(N) additions
    pedersen.rs      # Pedersen<G>: MSM wrapper, commit/commit_sparse
    dual_lpn.rs      # DualLPNInstance<F>: noise e + mask r = G*e
    emsm.rs          # EmsmPublicParams, PreprocessedCommitments, encrypt/evaluate/decrypt
    malicious.rs     # 2x overhead variant: challenge c, dual queries, consistency check
  groth16/
    mod.rs
    circuit.rs       # Demo CubeCircuit (x^3+x+5=y) for e2e test
    circom.rs        # Circom circuit loading via ark-circom: setup, build, get_public_inputs
    server_aided.rs  # ServerAidedProvingKey, client_encrypt<QAP>/server_evaluate/client_decrypt
  protocol/
    mod.rs
    messages.rs      # Serde wrappers over CanonicalSerialize'd arkworks types
    server.rs        # Axum handlers: POST /setup, POST /prove
    client.rs        # Reqwest client: send_setup, send_prove
  bin/
    server.rs        # Listen on :3000, store generators, evaluate MSMs
    client.rs        # Circom multiplier2 e2e: setup -> EMSM preprocess -> encrypt -> delegate -> decrypt -> verify
circuits/
  multiplier2.circom # a * b = c (1 constraint)
  range_check.circom # 8-bit range proof (9 constraints)
  compile.sh         # Compile all .circom -> circuits/build/
```

## Implementation Phases

### Phase 1: Core EMSM Primitives
1. `sparse_vec.rs` — SparseVector with chunked error_vec generation (t entries across N/t chunks)
2. `params.rs` — hardcoded Table 3 lookup (n=2^10..2^24 -> t values, R=1/4, delta=0.05)
3. `raa_code.rs` — TOperator: random perms, accumulate_inplace (suffix-sum), permute_safe, apply_f_fold. Rayon parallel above 2^16
4. `pedersen.rs` — deterministic generators, MSM via `VariableBaseMSM::msm`, sparse MSM
5. `dual_lpn.rs` — sample sparse e, compute r = TOperator.multiply_sparse(e_dense)
6. `emsm.rs` — EmsmPublicParams::new(generators), preprocess() computes h=G^T*g (expand 4x, inverse perms, accumulate on group elements). server_computation(v) = MSM(v, generators). DualLPNInstance::mask_witness(z) = z+r, recompute_msm(em, preprocessed) = em - sparse_msm(e, h)
7. `malicious.rs` — encrypt sends (v=z+r, v_ck=c*z+r'), decrypt checks dm_ck == c*dm

### Phase 2: Server-Aided Groth16
8. `circuit.rs` — CubeCircuit implementing ConstraintSynthesizer
9. `server_aided.rs` — Main complexity:
   - ServerAidedProvingKey::setup(pk): create 5 EmsmPublicParams (h_query, l_query, a_query, b_g1_query, b_g2_query) + preprocess each
   - client_encrypt: synthesize circuit -> extract witness -> QAP witness_map -> get h,z vectors -> sample r,s -> mask 5 scalar vectors with independent DualLPN instances
   - server_evaluate: 5 standard MSMs on masked vectors
   - client_decrypt: unmask 5 results -> assemble pi_a, pi_b (G2), pi_c -> return Proof<E>

### Phase 3: Networking
10. `messages.rs` — SetupRequest (5 serialized generator vecs), ProveRequest (5 masked scalar vecs), ProveResponse (5 MSM results)
11. `server.rs` — Axum router, Arc<RwLock<ServerState>>, /setup stores generators, /prove evaluates MSMs
12. `client.rs` — reqwest POST calls with bincode body

### Phase 4: Binaries + Integration
13. `bin/server.rs` — tokio::main, bind :3000
14. `bin/client.rs` — Circom multiplier2 (a=3, b=11 -> c=33) through server-aided Groth16
15. Integration tests

### Phase 5: Circom Circuit Integration (COMPLETE)
16. `circuits/multiplier2.circom` + `circuits/range_check.circom` — sample Circom circuits
17. `circuits/compile.sh` — compile script
18. `src/groth16/circom.rs` — `circom_setup`, `build_circuit`, `get_public_inputs` helpers
19. `src/groth16/server_aided.rs` — `client_encrypt` generic over `QAP: R1CSToQAP`
20. `bin/client.rs` — updated to use Circom multiplier2 instead of CubeCircuit

## E2E Flow

```
CLIENT                              SERVER
 Groth16::setup() -> (pk, vk)
 ServerAidedProvingKey::setup(pk)
   (creates 5 TOperators + preprocess h=G^T*g)
 POST /setup {generators}  -------> store generators
 Synthesize circuit, get witness
 QAP witness_map -> h, z, rz, q
 Mask each with DualLPN noise
 POST /prove {v_h,v_l,v_a,v_b} --> MSM(v, generators) x5
 <--- {em_h, em_l, em_a,            return results
       em_b_g1, em_b_g2}
 Unmask: result = em - <e, h>
 Assemble proof (pi_a, pi_b, pi_c)
 Groth16::verify(proof) -> OK
```

## Key Technical Notes

- **EMSM is generic** over CurveGroup: works for both G1 and G2 (b_g2_query)
- **Each MSM gets independent LPN instance** (independent noise for security)
- **QAP witness map**: `client_encrypt<QAP: R1CSToQAP>` — use `LibsnarkReduction` for native R1CS, `CircomReduction` for Circom
- **Serialization bridge**: arkworks CanonicalSerialize -> Vec<u8> -> serde wrapper -> bincode over HTTP
- **Proof assembly**: must match ark_groth16::Proof<E> struct exactly for verify() to accept
- **BN254** as primary curve throughout
- **ark-circom 0.5**: needs default features (wasmer runtime); returns eyre errors (map to anyhow); needs tokio reactor for WASM witness calculator

## Testing

- Each module: unit tests for correctness
- **Critical test**: EMSM roundtrip — mask, server MSM, unmask, compare to plaintext MSM
- **Critical test**: server-aided Groth16 proof verifies via standard Groth16::verify()
- Integration: spawn axum server in-process, full client flow, verify proof
