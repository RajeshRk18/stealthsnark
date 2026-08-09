# StealthSnark

Rust implementation of **"Single-Server Private Outsourcing of zk-SNARKs"**
(Abbaszadeh, Hafezi, Katz, Meiklejohn), and a server built to run it.

A client outsources the heavy multi-scalar multiplication (MSM) work of Groth16
proving to an untrusted server without revealing the witness. The witness is
masked with LPN-based noise (the EMSM primitive), the server computes MSMs on
masked data, and the client recovers a valid proof locally. The server never sees
the plaintext witness; security rests on the Dual-LPN assumption.

The protocol is one layer. The other is an HTTP service meant to be operated, not
demonstrated: TLS and mutual TLS, API-key or client-certificate authentication,
sessions bound to their owner, per-client rate and session quota, bounded memory
under load, a loopback-only admin plane for health and metrics, graceful shutdown,
and a startup that refuses unsafe configurations instead of guessing at intent.
CPU-bound MSM work never runs on the async runtime, so a saturated server still
answers its own health checks.

[ARCHITECTURE.md](ARCHITECTURE.md) covers how it is built and the invariants a
change must not break. [VERIFICATION.md](VERIFICATION.md) covers how each property
is tested. [SECURITY.md](SECURITY.md) covers the scope and the non-goals.

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
                        │  │  bincode decode          │       │              │              │
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
                        │  ADMIN PLANE  loopback only, no credential                         │
   ┌────────────┐       │  ┌──────────────────────────────────────────────────────────────┐  │
   │ prometheus │──HTTP►│  │ /livez    always 200 if the process is up                    │  │
   │ or probe   │       │  │ /readyz   503 when draining or when 0 MSM slots are free     │  │
   └────────────┘       │  │ /metrics  14 counters, 4 gauges, Prometheus text             │  │
                        │  └──────────────────────────────────────────────────────────────┘  │
                        └────────────────────────────────────────────────────────────────────┘
```

Four decisions carry most of the design:

| Decision | Reason |
|---|---|
| Two listeners, admin on loopback | A probe must work without a credential; `/metrics` must not leave the host. One port would need a conditional rule that can be wrong unnoticed. |
| All decode and MSM work in `spawn_blocking` | Both are seconds to minutes of CPU. On the async runtime they starve tokio workers, including the health endpoints, so a wedged process looks healthy. |
| `std::sync::RwLock` plus `Arc<Session>` | A std guard is not `Send`, so the compiler prevents holding a lock across an `await`. `/v1/prove` clones a pointer and computes outside the lock. |
| Sessions bound to an owner | A leaked session token is inert without the owner's client credential. Wrong owner is `403`, not `401`. |

## Quick start

### 1. Compile Circom circuits

```sh
./circuits/compile.sh
```

Compiles the two sample circuits in `circuits/` (`multiplier2`, `a * b = c`, and
`range_check`, an 8-bit range proof) into `circuits/build/` as R1CS and WASM. The
demo and the Circom tests use them; build artifacts are gitignored.

### 2. Run tests

```sh
cargo test
```

Runs the full suite: EMSM primitives, Groth16 server-aided proving (native CubeCircuit + Circom circuits), protocol serialization, plus the verification suites described in [Security and verification](#security-and-verification) below.

### 3. Run client/server demo

Terminal 1, start the server:

```sh
cargo run --bin server
```

Terminal 2, run the client (Circom multiplier2: `a=3, b=11 -> c=33`):

```sh
cargo run --bin client
```

The client performs Groth16 setup, sends generators to the server, masks the witness, delegates MSM computation, recovers the proof, verifies it locally, then releases the session.

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

## Running it as a service

Reference. For why any of it is shaped this way, see
[ARCHITECTURE.md](ARCHITECTURE.md).

### API

Bodies are bincode over `application/octet-stream`. Errors are
`{"code": "...", "message": "..."}`, where `code` is stable and machine-readable.

| Method | Path | Headers | Purpose |
|---|---|---|---|
| `POST` | `/v1/setup` | version, credential | Upload generators, receive a session token |
| `POST` | `/v1/prove` | version, credential, session | Evaluate the five MSMs |
| `DELETE` | `/v1/session` | version, credential, session | Release one session early |
| `DELETE` | `/v1/sessions` | version, credential | Release every session this client owns |

| Header | Value |
|---|---|
| `x-stealthsnark-version` | `2`, required on every `/v1` request |
| `Authorization` | `Bearer <api key>`, omit under mTLS |
| `x-stealthsnark-session` | the token returned by `/v1/setup` |

Health and metrics are on the admin port, not here: `/livez`, `/readyz`, `/metrics`.

### Authentication

Set `STEALTHSNARK_AUTH` to `disabled`, `apikey`, `mtls`, or `any`. Anything but
`disabled` needs `STEALTHSNARK_AUTH_FILE`.

Mint a key. The secret is printed once and never stored; the file holds only its
SHA-256 digest.

```sh
cargo run --bin keygen -- --id alice --tier standard
```

It prints the record to add to the auth file:

```json
{
  "tiers": {
    "standard": {"max_sessions": 4, "max_body_bytes": 268435456,
                 "requests_per_sec": 2.0, "burst": 10}
  },
  "principals": [
    {"id": "alice", "tier": "standard",
     "api_key_id": "0123456789abcdef",
     "api_key_sha256": "<64 hex>",
     "tls_cert_sha256": "<64 hex, for mTLS>"}
  ]
}
```

### Limits

Server-wide limits come from the environment. Per-client limits come from the
caller's tier in the auth file.

| Limit | Stops |
|---|---|
| `requests_per_sec` + `burst` | One client flooding the service. Token bucket, so a legitimate burst is absorbed but the sustained rate binds. `429` + `Retry-After`. |
| `max_sessions` | One client pinning all the memory. `429`. |
| `max_body_bytes` | One client uploading more than its plan allows. Checked from `Content-Length` before the body is read, so an over-quota upload is refused rather than buffered then discarded. `413`. |

A session ends on whichever comes first, applied by a sweeper that runs with or
without traffic:

| Limit | Setting | Purpose |
|---|---|---|
| Idle timeout | `SESSION_TTL_SECS` | A cache policy. Reclaims memory a client stopped using. Each use resets it. |
| Maximum age | `SESSION_MAX_AGE_SECS` | A credential policy. Caps the total life of a token, which the idle timeout cannot: constant use would otherwise keep one token valid indefinitely. |

Both `DELETE` endpoints are optional, since the sweeper reclaims anyway.
`DELETE /v1/session` returns one session's quota immediately.
`DELETE /v1/sessions` takes no session token, only the client credential, and
releases every session the caller owns: use it after a restart has lost the
tokens.

### TLS and mutual TLS

```sh
STEALTHSNARK_TLS_CERT=server.pem \
STEALTHSNARK_TLS_KEY=server.key \
STEALTHSNARK_TLS_CLIENT_CA=ca.pem \
STEALTHSNARK_AUTH=mtls \
STEALTHSNARK_AUTH_FILE=auth.json \
cargo run --bin server
```

A client certificate must be **X.509 v3** because rustls rejects any version below v3 with `UnsupportedCertVersion`. `openssl x509 -req` emits v1 unless you
pass `-extfile` with at least one extension.

```sh
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -out client.pem -days 365 \
  -extfile <(printf "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth")
  ```

Failed handshakes are logged at `warn`, with the rustls error text.

The demo client reads its credentials from the environment:

```sh
STEALTHSNARK_SERVER_URL=https://localhost:3443 \
STEALTHSNARK_CA_CERT=ca.pem \
STEALTHSNARK_API_KEY="ssk_..." \
cargo run --bin client
# or, for mTLS, replace the key with a certificate and key in one PEM file:
STEALTHSNARK_CLIENT_IDENTITY=client-identity.pem
```

TLS is behind the `tls` feature, on by default. With the feature off, a configured
TLS path is a startup error, not a downgrade to plain HTTP.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `STEALTHSNARK_BIND` | `127.0.0.1:3000` | Data-plane bind address. Loopback by default so an unauthenticated service is not exposed by accident. |
| `STEALTHSNARK_ADMIN_BIND` | `127.0.0.1:3001` | Admin plane. Startup fails if this is not loopback. |
| `STEALTHSNARK_AUTH` | `disabled` | `disabled`, `apikey`, `mtls`, or `any`. |
| `STEALTHSNARK_AUTH_FILE` | none | JSON credential file. Required unless auth is disabled. |
| `STEALTHSNARK_TLS_CERT` / `_KEY` | none | Server certificate chain and private key. Must be set together. |
| `STEALTHSNARK_TLS_CLIENT_CA` | none | CA that signs client certificates. Required for mTLS. |
| `STEALTHSNARK_QUOTA_BUCKET_IDLE_SECS` | `600` | When an idle rate-limit bucket is forgotten. |
| `STEALTHSNARK_MAX_BODY_BYTES` | `268435456` (256 MiB) | Largest request body. **This is what decides the largest servable circuit**, see below. |
| `STEALTHSNARK_MAX_SESSIONS` | `64` | Cap on live sessions; each pins its generators in memory. |
| `STEALTHSNARK_SESSION_TTL_SECS` | `1800` | Idle timeout before a session is evicted. |
| `STEALTHSNARK_SESSION_MAX_AGE_SECS` | `43200` (12 h) | Absolute session lifetime, however often it is used. Must be >= the idle timeout. |
| `STEALTHSNARK_SWEEP_INTERVAL_SECS` | `60` | How often idle sessions are reclaimed. |
| `STEALTHSNARK_MAX_CONCURRENT_MSM` | `cores/2`, clamped to `[1,4]` | Concurrent MSM evaluations. Small on purpose: each MSM is already rayon-parallel internally. |
| `STEALTHSNARK_ADMISSION_WAIT_SECS` | `30` | How long a request waits for a slot before a 503. |
| `STEALTHSNARK_REQUEST_TIMEOUT_SECS` | `600` | Per-request ceiling. |
| `STEALTHSNARK_LOG` | `info` | `tracing` filter. |
| `STEALTHSNARK_LOG_FORMAT` | text | Set to `json` for structured logs. |
| `STEALTHSNARK_SERVER_URL` | `http://127.0.0.1:3000` | Client binary only. |
| `STEALTHSNARK_API_KEY` | none | Client binary only. |
| `STEALTHSNARK_CA_CERT` | none | Client binary only: trust a private CA. |
| `STEALTHSNARK_CLIENT_IDENTITY` | none | Client binary only: certificate and key in one PEM for mTLS. |

Startup refuses these combinations:

- authentication disabled on a non-loopback bind address.
- authentication enabled with no auth file.
- `mtls` without TLS
- an admin bind that is not loopback, or equal to the data bind.
- a TLS certificate without its key.
- TLS configured in a binary built without the `tls` feature.

**Sizing the body limit:** `/v1/setup` uploads every generator for all five MSMs
in one body. A compressed G1 point is 32 bytes and a G2 point 64, so 2^20
generators per MSM is about 192 MiB. Bodies are buffered before decoding, so
worst-case memory is `MAX_BODY_BYTES * MAX_CONCURRENT_MSM`, which the server logs
at startup.

## Security and verification

The server is the adversary in two modes. **Semi-honest** follows the protocol
but tries to learn the witness. **Malicious** may also return wrong MSM results,
which a double-query consistency check detects with probability about
`1 - 2^-254`.

The risk is silent failure: a proof can verify while the system is unsound or leaking the witness.  Every check therefore rests on an oracle independent of the code under test, across differential
testing, statistical privacy tests, proptest soundness, three fuzz targets, mutation testing, and bounded model checking with Kani. It has caught two real bugs so far.

[VERIFICATION.md](VERIFICATION.md) has details on the strategies, and the findings.

## References

- Abbaszadeh, Hafezi, Katz, Meiklejohn. *Single-Server Private Outsourcing of zk-SNARKs*. 2024.
- [Reference implementation](https://github.com/h-hafezi/server-aided-snarks) (arkworks 0.4, library-only)

## License

MIT
