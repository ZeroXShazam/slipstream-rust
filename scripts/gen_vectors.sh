#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VECTOR_DIR="${ROOT_DIR}/tools/vector_gen"
OUTPUT_DIR="${ROOT_DIR}/fixtures/vectors"

mkdir -p "${OUTPUT_DIR}"

cargo run -p slipstream-dns --bin gen_vectors -- "${VECTOR_DIR}/vectors.txt" > "${OUTPUT_DIR}/dns-vectors.json"

printf "Wrote %s\n" "${OUTPUT_DIR}/dns-vectors.json"
