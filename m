#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_dir"

# The defaults live in `m.env`, beside this script. What is typed goes last,
# so a flag beats the file and a typed `--config` replaces it.
exec cargo run --release -- --config m.env "$@"
