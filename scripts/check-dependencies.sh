#!/usr/bin/env bash
set -euo pipefail

cargo deny --all-features --locked check
# Same client-only RSA reachability exception as deny.toml; private key loading
# is rejected by the TLS provider and client authentication is disabled.
cargo audit --ignore RUSTSEC-2023-0071
