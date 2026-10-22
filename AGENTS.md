# AGENTS.md

## Objective

Rust implementation of server-aided Groth16 proving ("Single-Server Private Outsourcing of zk-SNARKs"): the EMSM masking primitive (`src/emsm`), the server-aided prover (`src/groth16`), and an HTTP server and client (`src/protocol`, `src/bin`). `ARCHITECTURE.md` §16 lists the invariants a change must not break.

## Commands

| Task | Command |
|---|---|
| Quick check | `scripts/harness-check.sh quick` |
| CI parity | `scripts/harness-check.sh ci-linux` (or `ci-macos`) |
| Build | `cargo build --all-targets --all-features` |
| Test | `cargo test --all-features` |
| Supply chain | `cargo deny check` |
| Circuits | `./circuits/compile.sh` (circom 2.2.3) |
| Throughput benchmark | `cargo bench --bench throughput` |

## Prerequisites and known failures

- The circom tests skip themselves when `circuits/build/` is missing. The harness compiles the circuits first, so CI runs them.
- On x86_64 Linux, Rust 1.89 and later cannot link the `circom` feature: `ark-circom` 0.5 -> `wasmer-vm` 4.4 needs `__rust_probestack`, which Rust removed. CI pins Rust 1.88. Use `cargo +1.88` on Linux. arm64 macOS is not affected.
- The crate is not rustfmt-clean. `cargo fmt` rewrites many files; do not run it on the whole crate in a feature change.
- The server speaks TLS 1.3 only. macOS `/usr/bin/curl` (SecureTransport) cannot connect to it.
- Bodies are postcard. Bump `PROTOCOL_VERSION` in `src/protocol/messages.rs` when a message changes shape.

## Guardrails

- Change check commands only in `scripts/harness-check.sh`. CI calls that script.
- An ignore in `deny.toml` must be transitive and carry a reason.
