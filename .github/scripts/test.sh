#!/usr/bin/env bash
set -euo pipefail

export TERM="${TERM:-xterm-256color}"

LIBS=(-p ratchetx2 -p xeddsa -p x3dh -p party -p storage -p protocol -p session)

YELLOW=""
RESET=""
if command -v tput >/dev/null 2>&1; then
    YELLOW="$(tput setaf 3 || true)"
    RESET="$(tput sgr0 || true)"
fi

run() {
    printf '%s%s%s\n' "$YELLOW" "$*" "$RESET"
    "$@"
    echo
}

run cargo fetch --locked
run cargo fmt --all -- --check
run cargo clippy --locked --all-features --all-targets -- -D warnings

# Each optional feature must build on its own too. Without protox, protoc compiles the protos.
run cargo clippy --locked --all-targets --no-default-features "${LIBS[@]}" -- -D warnings
run cargo clippy --locked --all-targets --features serde -p ratchetx2 -p xeddsa -p x3dh -p party -p protocol -p session -- -D warnings
run cargo clippy --locked --all-targets --features prost -p ratchetx2 -p x3dh -p party -p session -- -D warnings
run cargo clippy --locked --all-targets --features server -p protocol -- -D warnings
run cargo clippy --locked --all-targets --features connect -p protocol -p session -- -D warnings

# Isolated post-quantum suite checks. `session` integration tests also reference `session::proto`,
# so check `session --lib` without `prost` and `--all-targets` with `,prost`.
run cargo clippy --locked --all-targets --features ml-kem-768 -p ratchetx2 -p x3dh -p party -- -D warnings
run cargo clippy --locked --lib --features ml-kem-768 -p session -- -D warnings
run cargo clippy --locked --all-targets --features ml-kem-768,prost -p session -- -D warnings
run cargo clippy --locked --all-targets --features ml-kem-1024 -p ratchetx2 -p x3dh -p party -- -D warnings
run cargo clippy --locked --lib --features ml-kem-1024 -p session -- -D warnings
run cargo clippy --locked --all-targets --features ml-kem-1024,prost -p session -- -D warnings
run cargo clippy --locked --all-targets --features pq -p ratchetx2 -p x3dh -p party -p storage -p protocol -- -D warnings
run cargo clippy --locked --lib --features pq -p session -- -D warnings

# Preview library feature isolation on host.
run cargo clippy --locked --all-targets --no-default-features -p e2ee_chat_preview -- -D warnings
run cargo clippy --locked --all-targets --features rpc -p e2ee_chat_preview -- -D warnings

run cargo test --locked --all-features

# Post-quantum + prost persistence feature matrix (including non-PQ fail-closed checks).
run cargo test --locked --features prost -p ratchetx2 -p x3dh -p party -p session
run cargo test --locked --features ml-kem-768,prost -p ratchetx2 -p x3dh -p party -p session
run cargo test --locked --features ml-kem-1024,prost -p ratchetx2 -p x3dh -p party -p session
run cargo test --locked --features pq,prost -p ratchetx2 -p x3dh -p party -p session

run env RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps "${LIBS[@]}"
run env RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps --all-features "${LIBS[@]}"

# The libraries must keep building for the browser. This only checks (no linking), so
# getrandom's "custom" backend stands in for the wasm_js backend an app would enable.
run env RUSTFLAGS='--cfg getrandom_backend="custom"' cargo check --locked --target wasm32-unknown-unknown "${LIBS[@]}"
run env RUSTFLAGS='--cfg getrandom_backend="custom"' cargo check --locked --target wasm32-unknown-unknown --features server,serde,connect -p protocol
run env RUSTFLAGS='--cfg getrandom_backend="custom"' cargo check --locked --target wasm32-unknown-unknown --features serde,prost -p session

# The web client and the Worker, which enable the wasm_js backend themselves.
run cargo clippy --locked --target wasm32-unknown-unknown -p e2ee_chat_web -p e2ee_chat_worker -- -D warnings
run cargo clippy --locked --target wasm32-unknown-unknown --no-default-features -p e2ee_chat_web -- -D warnings
run cargo clippy --locked --target wasm32-unknown-unknown --no-default-features --features ml-kem-768 -p e2ee_chat_web -- -D warnings
run cargo clippy --locked --target wasm32-unknown-unknown --no-default-features --features ml-kem-1024 -p e2ee_chat_web -- -D warnings
run cargo clippy --locked --target wasm32-unknown-unknown --features conformance -p e2ee_chat_worker -- -D warnings

# Preview library feature isolation and workers for WebAssembly.
run cargo clippy --locked --target wasm32-unknown-unknown --no-default-features -p e2ee_chat_preview -- -D warnings
run cargo clippy --locked --target wasm32-unknown-unknown --features rpc -p e2ee_chat_preview -- -D warnings
# The previews' workers, each with its features only, as the web client's trunk build compiles them.
run cargo clippy --locked --target wasm32-unknown-unknown --features pdf,worker --bins -p e2ee_chat_preview -- -D warnings
run cargo clippy --locked --target wasm32-unknown-unknown --features audio,worker --bins -p e2ee_chat_preview -- -D warnings
run cargo clippy --locked --target wasm32-unknown-unknown --features search,worker --bins -p e2ee_chat_preview -- -D warnings
run cargo clippy --locked --target wasm32-unknown-unknown --features diagram,worker --bins -p e2ee_chat_preview -- -D warnings
run cargo clippy --locked --target wasm32-unknown-unknown --no-default-features --features markdown,worker -p e2ee_chat_preview -- -D warnings
run cargo clippy --locked --target wasm32-unknown-unknown --features code,worker --bins -p e2ee_chat_preview -- -D warnings
