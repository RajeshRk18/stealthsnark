#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
mkdir -p "$BUILD_DIR"

for circuit in "$SCRIPT_DIR"/*.circom; do
    name="$(basename "$circuit" .circom)"
    echo "Compiling $name..."
    circom "$circuit" --r1cs --wasm --sym -o "$BUILD_DIR"
    echo "  -> $BUILD_DIR/${name}.r1cs"
    echo "  -> $BUILD_DIR/${name}_js/${name}.wasm"
done

echo "Done. All circuits compiled to $BUILD_DIR/"
