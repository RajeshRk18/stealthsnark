# StealthSnark Architecture

## 1. What shapes the design

The client offloads five multi-scalar multiplications (MSMs) per Groth16 proof.
Everything structural follows from one asymmetry in those five operations.

| Input | Depends on | Size | Sent |
|---|---|---|---|
| Bases (generators) | the circuit's proving key | 32 B per G1 point, 64 B per G2 point | once per session |
| Scalars | the witness | one field element per base | once per proof |

A circuit needing 2^20 generators per MSM uploads `4 * 2^20 * 32 + 2^20 * 64`,
about 192 MiB of bases, then a few MiB of scalars per proof. Re-uploading bases
per proof would dominate the cost the client is trying to avoid. That is the whole
reason a session exists: it is a server-side cache of large, reusable,
witness-independent data.

The second shaping fact is the trust model. The server is not a trusted component
that was locked down. It is an adversary the protocol tolerates:

- Scalars arrive masked with LPN-derived noise, so their values are statistically
  independent of the witness.
- In malicious mode the client sends two queries per MSM and cross-checks them, so
  a wrong result is caught with probability about `1 - 2^-254`. On the wire these
  are two `/v1/prove` calls on one session, in random order
  (`EmsmClient::send_prove_malicious`), so the server cannot tell which one is the
  check.

So confidentiality of the payload is not the backend's job. The cryptography
already has it. The backend's job is availability, isolation between clients, and
not becoming a liability itself. That explains choices that otherwise look
inconsistent: there is no encryption at rest for session data, because the data is
already masked, but startup refuses to bind a routable address without
authentication, because an open compute service is a real problem.

## 2. Module map

```
src/protocol/
  config.rs     ServerConfig, env parsing, refusal of unsafe combinations
  auth.rs       AuthMode, Principal, Tier, AuthStore, API keys, cert identity
  quota.rs      QuotaEnforcer: token bucket, body size, session allowance
  session.rs    Session, SessionStore, expiry, per-principal accounting
  extract.rs    authenticate middleware, ApiVersion / Caller / OwnedSession
  server.rs     AppState, both routers, TLS accept loop, handlers, shutdown
  error.rs      ApiError, status mapping, stable machine codes
  metrics.rs    atomic counters, Prometheus text rendering
  messages.rs   wire types, postcard helpers, protocol version and headers
  secret.rs     random_hex, hex, sha256_hex, constant_time_eq
  tls.rs        rustls config, client CA, certificate digests  (feature = "tls")
src/bin/
  server.rs     read config, load credentials, hand off to serve()
  client.rs     demo client, credentials from the environment
  keygen.rs     mint an API key, print the auth-file record
```

Dependency direction is one way. `secret.rs` and `messages.rs` depend on nothing
in the module. `auth.rs`, `quota.rs`, `session.rs` depend on `error.rs`.
`server.rs` and `extract.rs` sit on top of all of them. Nothing depends on
`server.rs`, which is what lets the integration tests build a router directly.

## 3. Process topology

One process, two listeners, one state object.

```
                     ┌──────────────────── one process ─────────────────────┐
                     │                                                      │
                     │  DATA PLANE            STEALTHSNARK_BIND             │
   client ──TLS────► │  /v1/setup  /v1/prove  /v1/session  /v1/sessions     │
                     │  credential required on every route                  │
                     │        │                                             │
                     │        ├──► AppState ◄──────────┐                    │
                     │        │      config            │                    │
                     │        │      auth              │                    │
                     │        │      quota             │                    │
                     │        │      sessions          │                    │
                     │        │      metrics           │                    │
                     │        │      msm_slots         │                    │
                     │        │      shutting_down     │                    │
                     │        │                        │                    │
                     │  ADMIN PLANE   loopback only    │                    │
   prometheus ─HTTP─►│  /livez  /readyz  /metrics ─────┘                    │
                     │  no credential                                       │
                     └──────────────────────────────────────────────────────┘
```

The two path sets have contradictory requirements. A health probe must answer
without a credential, because an orchestrator that has to authenticate to ask "are
you alive" is one more thing to misconfigure during an incident. `/metrics`
exposes session counts, resident bytes, and rejection reasons, which must not
leave the host.

On one port that needs a rule like "require a credential on every path except
these three". That is a conditional which can be wrong without anyone noticing.
Two ports encode the same policy structurally. `ServerConfig::validate` refuses
two addresses that are the same socket. The admin address is loopback by default.
An operator can set a non-loopback admin address, because a load balancer, a
Kubernetes `httpGet` probe, or a Prometheus server on another host cannot reach
loopback. Startup then logs a warning: the admin paths need no credential, so the
network must restrict that address.

`AppState` holds seven fields, each behind an `Arc`, so the `Clone` that axum
performs per request is seven pointer bumps. Both routers share one instance,
which is why the admin plane can report on data-plane state.

## 4. Startup

`src/bin/server.rs` is 53 lines. The order matters, because each step can fail and
failing earlier is cheaper.

1. Initialise tracing. `STEALTHSNARK_LOG` sets the filter,
   `STEALTHSNARK_LOG_FORMAT=json` switches format.
2. `ServerConfig::from_env()`. A malformed value is an error, never a silent
   default, so a typo cannot degrade the service quietly.
3. `config.validate()`. Stops here, before any port is bound.
4. `AuthStore::from_file()`. Stops here too, so no port is ever opened with
   nothing behind it.
5. `serve(AppState::with_auth(config, auth))`.

`validate()` refuses eight combinations. The first is the one that matters most,
because no missing environment variable may produce an open compute service.

| Refused | Reason |
|---|---|
| auth disabled and bind is not loopback | an open service |
| auth enabled and no auth file | nothing to authenticate against |
| `mtls` without TLS | mTLS identity comes from the handshake |
| `mtls` without a client CA | nothing to verify certificates against |
| TLS cert without key, or key without cert | half a configuration |
| TLS configured, binary built without the `tls` feature | would serve plain HTTP on a port believed encrypted |
| admin bind is the data bind socket (same port, same or wildcard address) | the open plane would share the closed port |
| `session_max_age < session_ttl` | the idle timeout would be unreachable |

Startup logs `peak_body_mib`, which is
`max_body_bytes * max_concurrent_uploads + 9/4 * max_body_bytes * max_concurrent_msm`:
every upload slot full, plus the decoded points of every setup in progress. That
product, not either factor alone, is the worst-case resident memory from in-flight
requests. An operator raising the body limit for a bigger circuit needs to see the
multiplication happen.

## 5. The request path

### 5.1 Middleware order

`Router::layer` wraps, so **the last call is the outermost** and a request meets
the layers bottom-up. This is the opposite of `ServiceBuilder` reading order.

```
request
  │
  ├─ strip x-request-id    drop an id the client sent
  ├─ SetRequestId          assign x-request-id (uuid)
  ├─ Trace                 open a span; later log lines carry the id
  ├─ PropagateRequestId    on the way out, copy the id onto the response
  ├─ request_timeout       504 `timeout` on expiry
  ├─ CatchPanic            innermost shared layer
  │
  ├─ DefaultBodyLimit      max_body_bytes            ┐ data plane only
  ├─ authenticate          version, credential, quota ┘
  │
  ├─ routing
  └─ handler
```

Two placements are deliberate.

`SetRequestId` is outermost so `Trace` below it can attach the id to every log
line for the request, and so `PropagateRequestId` finds an id to copy onto the
response. Every response carries `x-request-id`, which is the observable proof
that the order is this way round.

`CatchPanic` is innermost, directly around the handler, where a panic can
realistically originate. One bad request becomes one 500 instead of a dead
process. A panic in `Trace` would not be caught, which is acceptable: those layers
do not touch untrusted data.

The timeout returns 504 with code `timeout`, not retryable. It is a server
condition, so not 408, which would blame the client. It is not 503 either: the
response is gone, but the MSM in `spawn_blocking` keeps running and keeps its
slot, so a client that retries at once only queues the same work a second time.
Set `STEALTHSNARK_REQUEST_TIMEOUT_SECS` above the slowest MSM you serve.

### 5.2 Authentication runs before routing

`Router::layer` wraps unmatched requests too, so a request to a path that does not
exist is rejected by the middleware before the router can produce a 404. An
unauthenticated caller therefore cannot enumerate which paths exist. A 404 is only
observable with a valid version header.

### 5.3 Why the check is a layer and not a call in each handler?

The first version called `require_version(&headers)?` and `bearer_token(&headers)?`
by hand at the top of every handler. That works exactly as long as every handler
remembers, and a handler that forgets has no authentication with nothing in the
diff to notice, because the missing code is not there to read.

Now the check runs once as a layer, and a handler states its requirements in its
own signature:

```rust
async fn handle_prove(
    State(app): State<AppState>,
    _version: ApiVersion,      // version negotiated
    Caller(principal): Caller, // authenticated
    owned: OwnedSession,       // authorised for this specific session
    body: Bytes,
) -> Result<Bytes, ApiError>
```

The extractors read what the layer placed in the request extensions. `Caller`
returns `ApiError::Internal` if that extension is missing, which can only happen
if a route were mounted outside the layer. Failing closed matters: the alternative
is an open door.

### 5.4 Check order inside `authenticate`

```
version  ->  credential  ->  rate  ->  body size
```

Rising order of cost, and one security property falls out of it. Rate limiting
happens only after the caller is known, so an unauthenticated flood is rejected at
step 2 and never touches any principal's bucket.

## 6. Concurrency model


### 6.1 The async and blocking boundary

```
 tokio worker threads                    blocking pool
 ────────────────────                    ─────────────
 accept, parse headers
 auth, quota, session lookup
 acquire MSM permit  ──────spawn_blocking──► postcard decode
                                            point decode (subgroup checks)
                                            Pedersen::commit x5  (rayon inside)
                                            serialise results
 write response      ◄──────────────────────┘
```

An MSM takes seconds to minutes. In an `async fn` with noawait point, that occupies a tokio worker for the whole duration. With `worker_threads` equal to core count, a few concurrent requests starve the
runtime, including the health endpoints, so an orchestrator cannot discover the process is wedged and a load balancer keeps sending traffic.

The non-obvious half is that deserialization had to move as well, not only the
MSM. `deserialize_compressed` performs an on-curve check and a subgroup check per
point. It is not parsing; it is quite heavy cryptographic work.

### 6.2 Admission control

`msm_slots` is a `Semaphore` with `max_concurrent_msm` permits. The default is
`cores/2` clamped to `[1, 4]`, not one per core, because an arkworks MSM is
already rayon-parallel internally and saturates the machine on its own. Admitting
eight concurrently does not raise throughput; it multiplies peak memory by eight
and makes every request slower.

A request waits up to `admission_wait` for a permit, then gets 503 with
`Retry-After`. Shedding beats queueing without limit: a client learns at once that
it should back off, rather than after a timeout it cannot tell apart from a crash.

The permit is moved into the blocking closure, so it is released exactly when the
MSMs finish rather than when the async wrapper returns:

```rust
tokio::task::spawn_blocking(move || {
    let _permit = permit;
    evaluate_msms(&session, &body)
})
```

`/v1/setup` also takes a permit although it computes no MSM, because decoding
192 MiB of generators is minutes of the same CPU work.

Bodies have their own semaphore, `upload_slots`, with `max_concurrent_uploads`
permits (default `2 * max_concurrent_msm`). `TieredBody` takes a permit before it
reads the first byte, and the handler moves it into the blocking closure with the
MSM permit. Without it, axum reads the body in the extractor, before the handler
can wait for an MSM slot, so every connection could hold a full body in memory
while it waits. A separate semaphore, not the MSM one, because a slow upload would
otherwise hold a compute slot while it sends.

### 6.3 Lock discipline

`SessionStore` uses `std::sync::RwLock`, not `tokio::sync::RwLock`. A std guard is
not `Send`, so it cannot be held across an `await`. The type system therefore
prevents the exact bug the first version had: a read guard held across all five
MSM evaluations, which blocked every `/v1/setup` for the duration of any proof.

`Arc<Session>` is the other half. `/v1/prove` holds the lock only long enough to
clone a pointer:

```rust
let session = app.sessions.get_owned(&token, &principal.id)?;  // lock held ~ns
// lock released here
tokio::task::spawn_blocking(move || evaluate_msms(&session, &body))
```

Lock poisoning is recovered rather than propagated:

```rust
fn read(&self) -> RwLockReadGuard<'_, HashMap<String, Arc<Session>>> {
    self.inner.read().unwrap_or_else(|e| e.into_inner())
}
```

A panic while the lock is held cannot leave the map structurally invalid, because
the only operations are insert, remove, and retain on owned values. Recovering the
guard beats failing every later request for ever on one poisoned lock.

Timekeeping uses one `Instant` epoch plus `u64` millisecond offsets, so a timestamp
fits in an `AtomicU64` and `last_seen` can be updated under a read lock.

## 7. Session model

```rust
pub struct Session {
    pub label: String,          // short, non-secret, appears in logs
    pub owner: String,          // principal id
    pub generators: Generators, // five prebuilt Pedersen instances
    pub resident_bytes: usize,
    created_ms: u64,            // fixed: bounds total lifetime
    last_seen_ms: AtomicU64,    // moves: bounds idle time
}
```

Four properties of this struct are load-bearing.

**The token is not in it.** The token is the map key. `label` is a separate 12 hex
character non-secret id, minted independently, and it is what appears in logs.

**`Generators` holds five `Pedersen` instances built once at setup**, not raw
point vectors rebuilt per request. The first version stored `Vec<G1Affine>` and
the prove handler cloned all five sets and rebuilt all five `Pedersen` structs on
every request, tens of MiB of memcpy per proof for nothing.

**`Debug` is hand-written** and prints generator counts, not points. A derived
implementation would dump millions of curve points, turning one stray `{:?}` into
an unusable log and a memory spike.

**`created_ms` is fixed and `last_seen_ms` moves.** That is what makes two
independent limits possible.

### 7.1 Four ways a session ends

| Ending | Driven by | Purpose |
|---|---|---|
| idle timeout | server sweeper | reclaim memory a client stopped using |
| maximum age | server sweeper | bound the lifetime of a bearer token |
| `DELETE /v1/session` | client | return the client's own quota at once |
| `DELETE /v1/sessions` | client | reclaim quota after losing the tokens |

The server always reclaims on its own. The two client endpoints are
optimisations, never the only path.

The idle timeout resets on every use, so alone it cannot bound a credential: a
client proving once every 25 minutes would keep one token valid for months.
`created_ms` closes that. `expiry_reason` checks idle first, so an idle session is
reported as idle rather than old, and the two reasons are counted separately
because an operator debugging a vanished session needs to know which limit ended
it.

The server cannot do better than a timeout, because it has no way to know which
`/v1/prove` is the last one. The generators come from the proving key, not the
witness, so one client may legitimately prove many statements against them.

### 7.2 One ordering subtlety

`insert` sweeps before testing capacity:

```rust
self.sweep();                                   // before the capacity test
let mut map = self.write();
if map.len() >= self.max_sessions { return Err(ApiError::SessionLimit); }
```

Without that, a map full of abandoned sessions would reject a legitimate new one
even though every entry in it was already dead.

The per-principal allowance is checked under the same write lock. `/v1/setup`
also checks it before the decode, as a fast refusal, but that check alone lets
concurrent setups from one principal all pass.

`SessionLimit` (process-wide) and `SessionQuotaExceeded` (per-principal) are
distinct errors sharing status 429. The first says the host is full, the second
says one client is.

### 7.3 The sweeper

```rust
let mut ticker = tokio::time::interval(state.config.sweep_interval);
ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
```

`Delay` rather than the default `Burst`, because if the process was starved and
missed ticks, running several sweeps back to back achieves nothing.

Each tick sweeps sessions, then prunes idle quota buckets. Without the second, the
bucket map grows once per distinct principal and never shrinks. The sweeper runs
with or without traffic, which is the point: an idle server must still release
memory.

## 8. Identity

Two credentials, in two headers, and the separation is what buys the properties.

| Header | Answers | Required on |
|---|---|---|
| `Authorization: Bearer <api key>` | who are you | every `/v1` route, unless mTLS supplies it |
| `x-stealthsnark-session` | which stored generators | `/v1/prove`, `/v1/session` |

A session records its owner, so `get_owned` refuses a token presented by anyone
else. A leaked session token is inert without the owner's client credential, and
wrong owner is 403 while unknown token is 401. Those are different claims: 401
says the credential may be stale, 403 says no retry with this identity can work.

This forced the protocol version to 2. Version 1 put the session token in
`Authorization`, so a v1 client against a v2 server would present a session token
where an API key is expected. The version header turns that into a clear
rejection. Version 3 changed the body encoding from bincode to postcard.

### 8.1 API keys

Format `ssk_<key id>_<secret>`: 16 hex characters of key id, 64 of secret, which
is 256 bits. The `ssk_` prefix makes a leaked key greppable by secret scanners.

The key id exists so lookup is one map probe. Without it, verification would scan
every record and compare the presented secret against each stored digest in turn,
which is more work and a timing surface that grows with the number of principals.

Only `SHA-256(secret)` is stored. One unsalted round is correct here, not a
weakness: the secret is 256 bits of CSPRNG output, so there is no dictionary to
attack, and a slow KDF would only add latency to every request. A user-chosen
password would need Argon2.

`constant_time_eq` compares contents in constant time but compares lengths
normally. That is deliberate. A digest length is public; where two digests first
differ must not leak, because that turns recovery into a byte-at-a-time search.

A wrong secret and an unknown key id return the identical message, so key ids
cannot be enumerated. A test asserts the two strings are equal, which means a
future more helpful error message breaks the build.

### 8.2 Certificate identity

A client is identified by `SHA-256(certificate DER)`. The order of operations is
what makes it sound:

1. rustls verifies the chain against the configured client CA. A certificate that
   fails here never reaches application code; the handshake fails.
2. The TLS listener computes the leaf digest and inserts `PeerCertDigest` into the
   request extensions.
3. `AuthStore` maps an already-verified digest to a principal.

A valid chain is necessary but not sufficient. The CA decides who may connect,
this service decides who is a known principal.

Digest identity also avoids parsing X.509 subject names, which would be attack
surface for no benefit. The cost is that a renewed certificate is a new identity
and must be re-registered.

### 8.3 The anonymous principal

With `STEALTHSNARK_AUTH=disabled` every caller is `anonymous` on
`Tier::unlimited()`. The reasoning is worth recording because the first version
got it wrong. A per-principal quota exists to stop one client starving others.
With one shared identity it cannot do that; it becomes a second, surprising
server-wide limit. Concretely, the default tier's `max_sessions: 4` silently
overrode `STEALTHSNARK_MAX_SESSIONS=64`, and an operator setting 64 got 4 with
nothing in the logs explaining why.

`unlimited()` uses `f64::from(u32::MAX)` as the rate rather than `f64::INFINITY`,
because the token bucket computes `tokens + elapsed * rate`, and
`INFINITY * 0.0` is `NaN`, and `NaN >= 1.0` is false, so every request would be
refused for ever.

## 9. Quota

### 9.1 The token bucket

```rust
fn try_spend(&mut self, now: Instant, rate_per_sec: f64, burst: u32) -> bool {
    let elapsed = now.saturating_duration_since(self.last_seen).as_secs_f64();
    self.last_seen = now;
    self.tokens = (self.tokens + elapsed * rate_per_sec).min(f64::from(burst));
    if self.tokens >= 1.0 { self.tokens -= 1.0; true } else { false }
}
```

A bucket rather than a fixed window, because a fixed window lets a caller send two
full windows of traffic across the boundary. A bucket has no boundary. It starts
full, so a first request never waits, and refill is capped at `burst`, so a long
idle period cannot accumulate unbounded credit.

The refusal computes a real `Retry-After` from the deficit rather than a constant:

```rust
let deficit = 1.0 - bucket.tokens;
let wait = (deficit / tier.requests_per_sec).clamp(1.0, 3600.0);
```

Buckets are swept on the same tick as sessions, and the sweep rule has a
subtlety: a bucket is dropped only if it is both idle and refilled to full.
Discarding a bucket that still owes tokens would hand the principal a free burst.

### 9.2 Body size

Checked from `Content-Length` in the middleware, before the body is read, so an
over-quota upload is refused rather than buffered and then discarded. For a
192 MiB payload that distinction is the point. A missing or unparseable
`Content-Length` is treated as unknown and allowed through, with the transport
`DefaultBodyLimit` as the backstop for a chunked or dishonest sender.

### 9.3 Session allowance

Counted live by walking the map, excluding entries that are expired but not yet
swept, so a principal is not charged for allowance it no longer holds.

### 9.4 Requests in progress

The MSM and upload slots are shared by all principals, and the rate limit counts
requests, not the time they take. A prove takes seconds, so one principal at 2
requests per second could keep every slot full. `TieredBody` therefore calls
`QuotaEnforcer::enter` before it takes an upload slot. The tier's `max_inflight`
(default 2) caps the setup and prove requests one principal has in progress. The
guard lives with the body and decrements on drop, so the slot is free when the
MSMs finish. A refusal is `inflight_limit`, 429, `Retry-After: 1`.

## 10. Error model

`ApiError` has 16 variants, each with a stable machine code. Wire shape is
`{"code": "...", "message": "..."}`.

| Code | Status | Retryable |
|---|---|---|
| `unsupported_version` | 400 | no |
| `malformed_body` | 400 | no |
| `invalid_input` | 400 | no |
| `unauthenticated` | 401 | no |
| `missing_token` | 401 | no |
| `unknown_session` | 401 | no |
| `forbidden` | 403 | no |
| `body_too_large` | 413 | no |
| `rate_limited` | 429 | yes |
| `session_quota_exceeded` | 429 | yes |
| `inflight_limit` | 429 | yes |
| `session_limit` | 429 | yes |
| `overloaded` | 503 | yes |
| `shutting_down` | 503 | yes |
| `timeout` | 504 | no |
| `internal` | 500 | no |

Four rules behind the table:

- `internal` never leaks its detail. The detail is logged at `error` level and the
  client gets a generic message. A test asserts the detail does not appear in
  `to_string()`.
- Only `unauthenticated` carries `WWW-Authenticate`. RFC 9110 requires a challenge
  on a 401, and it tells a client which credential to present. A test iterates
  every variant and asserts exactly one sets it.
- `Retry-After` comes from the error. `rate_limited` carries its own computed
  delay; the others use 5 seconds.
- Distinguishability is the goal. The first version returned a bare 400 with no
  body for every failure, so a client could not tell a length mismatch from a bad
  point encoding from corrupt framing: three problems, three different fixes, one
  indistinguishable response.

The client mirrors this. `classify(code)` maps every code to `client_error`,
`auth_error`, `permission_error`, `transient`, or `server_error`, and a test walks
every `ApiError` variant to assert none is unclassified. A new variant fails the
build until the client handles it.

## 11. Wire format

postcard, `application/octet-stream`, protocol version 3. Version 2 used bincode,
which is unmaintained (RUSTSEC-2025-0141).

| Level | Layout |
|---|---|
| A byte field | varint (LEB128) length, then the bytes |
| Inside a field | arkworks `u64` element count little-endian, then each element compressed |

A minimal valid `SetupRequest` with five empty generator sets is 45 bytes: five
fields, each a 1 byte varint length of 8 followed by an 8 byte arkworks count of
zero.

```python
field = struct.pack('<Q', 0)                                          # 0 elements
body  = b''.join(bytes([len(field)]) + field for _ in range(5))       # varint 8 is one byte
```

`wire_decode` refuses bytes after the message, so a body cannot carry a hidden
suffix. Request fields are `Cow<[u8]>` and borrow from the body when decoded, so
the server does not copy the generators before it parses them.

**postcard is not self-describing.** A struct that gains a field decodes as
something rather than failing, which is silent corruption. That is the entire
reason the version header is mandatory.

Deserialization is bounded twice:

```rust
if len > MAX_VEC_LEN { anyhow::bail!("vec length {len} exceeds maximum {MAX_VEC_LEN}"); }
let cap = (len as usize).min(cursor.len()).min(MAX_PREALLOC_ELEMS);
```

`MAX_VEC_LEN` is 2^24. The capacity is capped at `MAX_PREALLOC_ELEMS` (1024)
regardless, because bounding by the remaining byte count still amplifies:
allocation is `count * size_of::<T>()`, about 136 bytes per input byte for
`G2Affine`, so a few MB body could force hundreds of MB before the first decode
fails.

`MAX_VEC_LEN` is a structural bound, not the effective one. The effective limit is
`max_body_bytes`, which is what decides the largest servable circuit.

## 12. Observability

Handlers emit tracing fields, not interpolated strings, so a sink can query them:

```
INFO session established principal=alice tier=standard auth="mutual_tls"
     session=4b5c37d6dd86 h=4 l=2 a=2 b_g1=2 b_g2=2 resident_mib=0
     elapsed_ms=3 active_sessions=1
```

No credential ever appears. The `session` field is the non-secret label.

TLS handshake failures log at `warn`, not `debug`. Under mTLS a rejected handshake
means a client cannot connect at all, and the rustls error text is the only thing
that says why. At `debug` the operator sees an unreachable service and a silent
server.

`/metrics` renders 13 counters and 4 gauges from atomics, hand-rolled rather than
via a metrics framework, because the render is a `writeln!` loop.

`rejected_unauthenticated_total` deserves an alert: a sustained rise is credential
guessing.

A failed malicious-mode consistency check is the most important signal the system
can emit, but only the client can see it: the check runs on the client, after both
responses arrive. A server metric for it would always be zero. The client reports
it as `MaliciousError::ConsistencyCheckFailed`, and the demo client logs it at
`error`.

## 13. Health, readiness, shutdown

| Endpoint | Returns |
|---|---|
| `/livez` | 200 whenever the process is up |
| `/readyz` | 503 if draining, 503 if `msm_slots_free == 0`, else 200 |

Liveness answers "should you restart me". Readiness answers "should you send me
work". Saturated is not a reason to restart, so `/livez` stays 200 while `/readyz`
fails and a load balancer routes away.

```
SIGINT or SIGTERM
  -> shutting_down = true
  -> /readyz returns 503            load balancer drains
  -> accept loop stops accepting    live connections continue
  -> sweeper exits
  -> in-flight requests finish
  -> "server stopped cleanly"
```

The two planes are joined with `tokio::join!` so the admin plane stays up while
the data plane drains. A probe keeps answering throughout shutdown, which is
exactly when an orchestrator is watching.

Killing a proof mid-flight discards the most expensive thing in the system: the
client has already paid for a trusted setup and a multi-hundred-MiB upload.

## 14. TLS listener

`axum::serve` cannot expose the peer certificate to a handler, and mTLS identity
is useless if the handler cannot see who connected. So the TLS path drives its own
accept loop: accept TCP, handshake with a 15 second timeout, read the leaf digest,
insert it into the request extensions, then serve the connection with
`hyper_util`'s auto builder, which negotiates HTTP/2 or HTTP/1.1 from the ALPN
list the config advertises.

Owning the loop means owning what `axum::serve` did for free:

| Responsibility | Implementation |
|---|---|
| graceful shutdown | `AtomicBool` polled in a `select!` against `accept()`; then `GracefulShutdown` tells each connection to finish its requests and close, and `serve_tls` waits up to `request_timeout` for them |
| connection cap | 1024-permit semaphore; unbounded half-open handshakes are a memory exhaustion path |
| handshake timeout | 15 s; without it a client that opens a socket and sends nothing holds a slot for ever |
| header read timeout | `header_read_timeout`, 10 s; hyper applies it only when a timer is set, so the builder sets `TokioTimer`. Without it a client that sends header bytes slowly holds a slot for ever, before authentication runs |
| HTTP/2 streams | 8 concurrent streams per connection (hyper default 200), keep-alive ping every 30 s |
| ALPN | `alpn_protocols = ["h2", "http/1.1"]`, or you get HTTP/1.1 only |
| protocol version | TLS 1.3 only; every client is under the operator's control |

TLS sits behind a default-on `tls` feature so the lean core stays buildable under
the cargo-fuzz sanitizer. With the feature off, configured TLS is a startup error,
never a downgrade.

## 15. Resource budget

| Source | Worst case |
|---|---|
| in-flight request bodies | `max_body_bytes * max_concurrent_uploads`, 256 MiB * 8 = 2 GiB |
| resident session generators | `min(max_sessions * per-session size, max_resident_bytes)` |
| decoded points during a setup | about `9/4 * max_body_bytes` per concurrent MSM |
| rate buckets | about 50 bytes per distinct principal, swept |

The session count cap is the loose one: 64 sessions of a 2^20 circuit is about
12 GiB. `STEALTHSNARK_MAX_RESIDENT_BYTES` (default 8 GiB) bounds the bytes instead.
`insert` sums the resident bytes under the write lock and refuses a setup that
would go above the budget with `session_limit`. The startup log prints both
`max_resident_mib` and `peak_body_mib`.

## 16. Invariants a change must not break

1. No CPU-bound work on the async runtime. Point decoding and MSM evaluation both
   belong inside `spawn_blocking`.
2. No lock held across an `await` or across expensive work. Clone the
   `Arc<Session>` out and release.
3. Every `/v1` route sits under the `authenticate` layer. A route added outside it
   has no authentication.
4. A handler declares its requirements as extractors. Do not parse headers by hand.
5. No credential in a log, a `Debug` impl, or an error message. Compare secrets
   with `secret::constant_time_eq`; store only `secret::sha256_hex`.
6. Serialization and deserialization are both fallible. Never panic on a request
   path.
7. Bump `PROTOCOL_VERSION` when any type in `messages.rs` changes shape or any
   header changes meaning. Adding an endpoint does not require it.
8. `validate()` refuses unsafe configurations rather than inferring intent from a
   missing variable.

## 17. Where to add things

| Change | Touch |
|---|---|
| a new endpoint | `server.rs` route table plus a handler; it inherits auth and quota from the layer |
| a new limit | `config.rs` field plus `validate()`, then enforce in `quota.rs` or the handler |
| a new credential kind | `auth.rs` `AuthMode` and `AuthStore::authenticate`; identity plumbing is already in the extensions |
| a new error case | `error.rs` variant plus `code()`, `status()`, and `client.rs` `classify()`; the exhaustiveness test will tell you |
| a new metric | `metrics.rs` field plus a row in `render()` |
