#! /bin/bash
set -e

export TERM=xterm-256color

# Statements waiting to be executed
statements=(
    "cargo fetch --locked"
    "cargo clippy --all-features --all-targets -- -D warnings"
    "cargo test"
    "cargo doc --no-deps -p ratchetx2 -p primitives -p x3dh -p xeddsa"
    # The pure-Rust crates must keep building for the browser. This only checks (no linking),
    # so getrandom's "custom" backend stands in for the wasm_js backend an app would enable.
    "RUSTFLAGS='--cfg getrandom_backend=\"custom\"' cargo check --target wasm32-unknown-unknown --no-default-features -p ratchetx2 -p xeddsa -p primitives"
)

# loop echo and executing statements
for statement in "${statements[@]}"; do
    echo "$(tput setaf 3)$statement$(tput sgr0)"
    eval $statement
    echo
done
