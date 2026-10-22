# Running it as a service

Reference. For why any of it is shaped this way, see
[ARCHITECTURE.md](ARCHITECTURE.md).

## API

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

## Authentication

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

## Limits

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

## TLS and mutual TLS

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

## Configuration

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
| `STEALTHSNARK_MAX_RESIDENT_BYTES` | `8589934592` (8 GiB) | Cap on generator bytes pinned by all sessions together. A setup above it gets `session_limit`. Set it below the host's memory. |
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

Server startup refuses these mis-configs:

- authentication disabled on a non-loopback bind address.
- authentication enabled with no auth file.
- `mtls` without TLS
- an admin bind that is not loopback, or equal to the data bind.
- a TLS certificate without its key.
- TLS configured in a binary built without the `tls` feature.
