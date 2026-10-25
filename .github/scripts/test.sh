#! /bin/bash
set -e

export TERM=xterm-256color

LIBS="-p ratchetx2 -p xeddsa -p x3dh -p party -p storage -p protocol -p session"

# Statements waiting to be executed
statements=(
    "cargo fetch --locked"
    "cargo clippy --all-features --all-targets -- -D warnings"
    # Each optional feature must build on its own too. Without protox, protoc compiles the protos.
    "cargo clippy --all-targets --no-default-features $LIBS -- -D warnings"
    "cargo clippy --all-targets --features serde -p ratchetx2 -p xeddsa -p x3dh -p party -p protocol -p session -- -D warnings"
    "cargo clippy --all-targets --features rkyv -p ratchetx2 -p xeddsa -p x3dh -p party -p protocol -p session -- -D warnings"
    "cargo clippy --all-targets --features prost -p ratchetx2 -p x3dh -p party -p session -- -D warnings"
    "cargo clippy --all-targets --features server -p protocol -- -D warnings"
    "cargo clippy --all-targets --features grpc -p protocol -p session -- -D warnings"
    "cargo test --all-features"
    "RUSTDOCFLAGS='-D warnings' cargo doc --no-deps $LIBS"
    # The libraries must keep building for the browser. This only checks (no linking), so
    # getrandom's "custom" backend stands in for the wasm_js backend an app would enable.
    "RUSTFLAGS='--cfg getrandom_backend=\"custom\"' cargo check --target wasm32-unknown-unknown $LIBS"
    "RUSTFLAGS='--cfg getrandom_backend=\"custom\"' cargo check --target wasm32-unknown-unknown --features server,serde,rkyv -p protocol"
    "RUSTFLAGS='--cfg getrandom_backend=\"custom\"' cargo check --target wasm32-unknown-unknown --features serde,rkyv,prost -p session"
)

# loop echo and executing statements
for statement in "${statements[@]}"; do
    echo "$(tput setaf 3)$statement$(tput sgr0)"
    eval $statement
    echo
done
