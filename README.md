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

Runs 25 tests: EMSM primitives, Groth16 server-aided proving (native CubeCircuit + Circom circuits), protocol serialization.

### 3. Run client/server demo

Terminal 1 -- start the server:

```sh
cargo run --bin server
```

Terminal 2 -- run the client (Circom multiplier2: `a=3, b=11 -> c=33`):

```sh
cargo run --bin client
```

The client performs Groth16 setup, sends generators to the server, masks the witness, delegates MSM computation, recovers the proof, and verifies it locally.

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
    server.rs               #   Axum handlers: POST /setup, POST /prove
    client.rs               #   Reqwest client: send_setup, send_prove
  bin/
    server.rs               #   Server binary (listens on :3000)
    client.rs               #   Client binary (Circom multiplier2 end-to-end)
circuits/
  multiplier2.circom        #   a * b = c
  range_check.circom        #   8-bit range proof
  compile.sh                #   Compile all .circom files
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
