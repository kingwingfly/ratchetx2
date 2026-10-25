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
    "cargo clippy --all-targets --features connect -p protocol -p session -- -D warnings"
    "cargo test --all-features"
    "RUSTDOCFLAGS='-D warnings' cargo doc --no-deps $LIBS"
    # The libraries must keep building for the browser. This only checks (no linking), so
    # getrandom's "custom" backend stands in for the wasm_js backend an app would enable.
    "RUSTFLAGS='--cfg getrandom_backend=\"custom\"' cargo check --target wasm32-unknown-unknown $LIBS"
    "RUSTFLAGS='--cfg getrandom_backend=\"custom\"' cargo check --target wasm32-unknown-unknown --features server,serde,rkyv,connect -p protocol"
    "RUSTFLAGS='--cfg getrandom_backend=\"custom\"' cargo check --target wasm32-unknown-unknown --features serde,rkyv,prost -p session"
    # The web client and the Worker, which enable the wasm_js backend themselves.
    "cargo clippy --target wasm32-unknown-unknown -p e2ee_chat_web -p e2ee_chat_worker -- -D warnings"
    "cargo clippy --target wasm32-unknown-unknown --features conformance -p e2ee_chat_worker -- -D warnings"
    # The previews' workers, each with its features only, as the web client's trunk build compiles them.
    "cargo clippy --target wasm32-unknown-unknown --features pdf,worker --bins -p e2ee_chat_preview -- -D warnings"
    "cargo clippy --target wasm32-unknown-unknown --features audio,worker --bins -p e2ee_chat_preview -- -D warnings"
    "cargo clippy --target wasm32-unknown-unknown --features search,worker --bins -p e2ee_chat_preview -- -D warnings"
    "cargo clippy --target wasm32-unknown-unknown --features diagram,worker --bins -p e2ee_chat_preview -- -D warnings"
    "cargo clippy --target wasm32-unknown-unknown --features code,worker --bins -p e2ee_chat_preview -- -D warnings"
)

# loop echo and executing statements
for statement in "${statements[@]}"; do
    echo "$(tput setaf 3)$statement$(tput sgr0)"
    eval $statement
    echo
done
