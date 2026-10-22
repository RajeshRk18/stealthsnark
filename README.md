# StealthSnark

Rust implementation of **"Single-Server Private Outsourcing of zk-SNARKs"**
(Abbaszadeh, Hafezi, Katz, Meiklejohn), and a server/client protocol built to run it.

A client outsources the heavy multi-scalar multiplication (MSM) work of Groth16
proving to an untrusted server without revealing the witness. The witness is
masked with LPN-based noise (the EMSM primitive), the server computes MSMs on
masked data, and the client demasks and recovers a valid proof locally.

- [ARCHITECTURE.md](ARCHITECTURE.md) covers how it is built and the invariants a change must not break. 
- [VERIFICATION.md](VERIFICATION.md) covers how each property is tested. The limitations are listed at the end of this file.
- [SERVER.md](SERVER.md) covers how to setup the server and get it running.

## Architecture

The client keeps the witness and the proof. The server only multiplies masked
scalars by generators it was given. Full detail, including the concurrency model
and the invariants a change must not break, in
[ARCHITECTURE.md](ARCHITECTURE.md).

### Protocol flow

```
CLIENT                                             SERVER
 Groth16 trusted setup -> (pk, vk)
 EMSM preprocessing (5 MSMs)
 POST /v1/setup {generators}      ------------->    store generators
                                  <-------------    {session token}
 Synthesize circuit, extract witness
 QAP reduction -> h polynomial
 Mask 5 scalar vectors with LPN noise
 POST /v1/prove {masked vectors}  ------------->    MSM(masked, generators) x5
                                  <-------------    {5 MSM results}
 Unmask results, assemble proof
 Groth16::verify(proof) -> OK
 DELETE /v1/session               ------------->    free generators
```

### Server

```
                        ┌───────────────────────── server process ─────────────────────────┐
                        │                                                                  │
                        │  DATA PLANE  STEALTHSNARK_BIND, TLS when configured              │
   ┌────────┐           │  ┌────────────────────────────────────────────────────────────┐  │
   │ client │──TLS─────►│  │ SetRequestId → Trace → Timeout → CatchPanic → BodyLimit     │  │
   │        │  api key  │  │                              │                              │  │
   │        │  or mTLS  │  │                    ┌─────────▼──────────┐                   │  │
   │        │  cert     │  │                    │   authenticate     │  version          │  │
   └────────┘           │  │                    │   (one layer, all  │  credential       │  │
                        │  │                    │    /v1 routes)     │  rate, body size  │  │
                        │  │                    └─────────┬──────────┘                   │  │
                        │  │                              │                              │  │
                        │  │   /v1/setup   /v1/prove   /v1/session   /v1/sessions         │  │
                        │  └──────┬────────────┬──────────────┬──────────────┬───────────┘  │
                        │         │            │              │              │              │
                        │         │  acquire MSM permit (semaphore, 4 by default)           │
                        │         ▼            ▼              │              │              │
                        │  ┌──────────────────────────┐       │              │              │
                        │  │  BLOCKING POOL           │       │              │              │
                        │  │  postcard decode         │       │              │              │
                        │  │  point decode (subgroup) │       │              │              │
                        │  │  Pedersen::commit x5     │       │              │              │
                        │  │  (rayon inside each)     │       │              │              │
                        │  └───────────┬──────────────┘       │              │              │
                        │              │                      │              │              │
                        │              ▼                      ▼              ▼              │
                        │  ┌──────────────────────────────────────────────────────────────┐  │
                        │  │ SessionStore   RwLock<HashMap<token, Arc<Session>>>          │  │
                        │  │   owner, five prebuilt Pedersen keys, created_ms, last_seen  │  │
                        │  │   idle TTL 30 min  +  max age 12 h  +  cap 64                │  │
                        │  └──────────────────────────────┬───────────────────────────────┘  │
                        │                                 │                                  │
                        │  ┌──────────────────────────────▼───────────────────────────────┐  │
                        │  │ sweeper, every 60 s, with or without traffic                 │  │
                        │  │   evict expired sessions, prune idle rate buckets            │  │
                        │  └──────────────────────────────────────────────────────────────┘  │
                        │                                                                    │
                        │  ADMIN PLANE  loopback only                         │
   ┌────────────┐       │  ┌──────────────────────────────────────────────────────────────┐  │
   │ prometheus │──HTTP►│  │ /livez    always 200 if the process is up                    │  │
   │ or probe   │       │  │ /readyz   503 when draining or when 0 MSM slots are free     │  │
   └────────────┘       │  │ /metrics  13 counters, 4 gauges, Prometheus text             │  │
                        │  └──────────────────────────────────────────────────────────────┘  │
                        └────────────────────────────────────────────────────────────────────┘
```

## Quick start

### 1. Compile Circom circuits

```sh
./circuits/compile.sh
```

Compiles the two sample circuits in `circuits/`.

### 2. Run tests

```sh
cargo test
```

Runs the full suite: EMSM primitives, Groth16 server-aided proving, protocol serialization.

### 3. Run client/server demo

Terminal 1, start the server:

```sh
cargo run --bin server
```

Terminal 2, run the client:

```sh
cargo run --bin client
```

## Checks

```sh
scripts/harness-check.sh quick      # library unit tests, seconds
scripts/harness-check.sh ci-linux   # what CI runs: build, all tests, fuzz crate, cargo deny
```

`ci-linux` needs `circom` 2.2.3 and `cargo-deny`. CI runs it on every push to `main`,
on pull requests, and weekly for new advisories.

## Using your own circuit

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
```

## Performance

My machine spec: Macbook M4 Air, 24GB RAM, 10 cores.

Benchmark setup: 8 concurrent clients. Clients and the server run in the same process (see benches/throughput.rs)

- server per request - server's time around one request's work excluding queue wait.
- req/s - number of requests processed across workers per second.

**1. Default admission bound (4):**

| generators | req/s | p50 | p95 | server per request |
|---|---|---|---|---|
| 4096 | 31.4 | 244 ms | 295 ms | 124 ms |
| 16384 | 9.3 | 838 ms | 984 ms | 417 ms |
| 65536 | 2.3 | 3221 ms | 4226 ms | 1664 ms |

---
---

**2. Various bounds at 16384 generators:**

| `STEALTHSNARK_MAX_CONCURRENT_MSM` | req/s | p95 | server per request |
|---|---|---|---|
| 1 | 8.2 | 1025 ms | 122 ms |
| 2 | 8.1 | 1061 ms | 244 ms |
| 4 | 7.8 | 1158 ms | 498 ms |
| 8 | 8.1 | 1743 ms | 814 ms |

Throughput is flat across the bounds while per request increases. This may be because each MSM already saturates the machine through rayon, so a larger bound does not add capacity. It just divides the same capacity among more requests and widens the tail(p95 grows by ~70%).

## Documentation

- Read [ARCHITECTURE.md](ARCHITECTURE.md) to understand the client and server protocol architecture.
- Read [SERVER.md](SERVER.md) to know how to set up the stealthsnark server.
- Read [VERIFICATION.md](VERIFICATION.md) to know how every property has been tested.

## Limitations and future TODOs

- Certificate identity is pinned by digest. mTLS identifies a client by the SHA-256 of its certificate, so a renewed certificate is a new identity and must be re-registered.
- API keys have no expiry. To revoke a key, remove its record from the auth file and send `SIGHUP`; the server reloads the file without a restart.
- Currently, user's quota is per process. Rate-limit and session counts live in memory, so it is fine for a single-server instance we have now. This can be a todo to demonstrate shared state in a distributed architecture if we implement multiple servers or clusters support.
- Session token lookup is not constant-time.
- Resource exhaustion is within the configured limits. Currently, server admits only `STEALTHSNARK_MAX_CONCURRENT_MSM` MSMs of up to `STEALTHSNARK_MAX_BODY_BYTES` each as we dont want the server to Dos attacked.

## References

- Abbaszadeh, Hafezi, Katz, Meiklejohn. *Single-Server Private Outsourcing of zk-SNARKs*. 2024.
- [Reference implementation](https://github.com/h-hafezi/server-aided-snarks)

## License

MIT
