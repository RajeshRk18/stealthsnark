#!/usr/bin/env bash
# One command path for local checks and CI.
#   scripts/harness-check.sh quick      library unit tests, seconds
#   scripts/harness-check.sh ci-linux   what CI runs on Linux
#   scripts/harness-check.sh ci-macos   the same checks on macOS
set -euo pipefail
cd "$(dirname "$0")/.."

# The circom tests skip themselves when the circuits are missing, so CI must
# build them or those tests pass without running.
need_circuits() {
  if [ -f circuits/build/multiplier2.r1cs ] && [ -f circuits/build/range_check.r1cs ]; then
    return
  fi
  command -v circom >/dev/null || { echo "harness: install circom 2.2.3 to compile circuits/" >&2; exit 1; }
  ./circuits/compile.sh
}

need_tool() {
  command -v "$1" >/dev/null || { echo "harness: $1 is missing; run: cargo install --locked $1" >&2; exit 1; }
}

full() {
  need_circuits
  need_tool cargo-deny
  cargo build --all-targets --all-features --locked
  cargo test --all-features --locked
  # The lean core that the fuzz crate builds (no circom, no tls).
  cargo check --lib --no-default-features --locked
  cargo check --manifest-path fuzz/Cargo.toml
  cargo deny check
}

case "${1:-quick}" in
  quick) cargo test --all-features --lib ;;
  ci-linux | ci-macos) full ;;
  *) echo "usage: $0 quick|ci-linux|ci-macos" >&2; exit 2 ;;
esac
