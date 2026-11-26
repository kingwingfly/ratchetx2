#!/usr/bin/env bash
set -euo pipefail

export TERM="${TERM:-xterm-256color}"

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

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# Assert wasm-bindgen-test-runner matches Cargo.lock's wasm-bindgen version before running wasm tests.
LOCK_WBG_VERSION="$(awk '/^name = "wasm-bindgen"$/{f=1; next} f && /^version = /{gsub(/"/, "", $3); print $3; exit}' Cargo.lock)"
RUNNER_WBG_VERSION="$(wasm-bindgen-test-runner --version | awk '{print $2}')"
if [ -n "$LOCK_WBG_VERSION" ] && [ "$LOCK_WBG_VERSION" != "$RUNNER_WBG_VERSION" ]; then
    printf 'wasm-bindgen-test-runner (%s) does not match Cargo.lock wasm-bindgen (%s)\n' \
        "$RUNNER_WBG_VERSION" "$LOCK_WBG_VERSION" >&2
    exit 1
fi

# 1. `e2ee_chat_preview` wasm32 RPC wire & worker dispatch tests.
run env CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
    cargo test --locked --target wasm32-unknown-unknown -p e2ee_chat_preview --features worker --test rpc_wire

# 2. `e2ee_chat_web` in-module browser wasm32 tests (`vault.rs` & `workers.rs`).
run env CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
    cargo test --locked --target wasm32-unknown-unknown -p e2ee_chat_web --bin e2ee_chat_web

# 3. Build local Worker (`worker-build --dev`) and web client (`trunk build`).
cd "$REPO_ROOT/e2ee_chat_worker"
run worker-build --dev
if [ ! -x node_modules/.bin/wrangler ]; then
    run npm ci
fi

cd "$REPO_ROOT/e2ee_chat_web"
if [ "${E2E_RELEASE_BUILD:-0}" = "1" ]; then
    run trunk build --release
else
    # Size-optimized, symbol-stripped dev build keeps all WASM workers (including
    # `preview_diagram_bg.wasm`, which is 29 MiB with `debuginfo` vs 17 MiB with `symbols`)
    # comfortably under Cloudflare Workers' 25 MiB static-asset cap for `wrangler dev --assets`
    # without paying full `lto = "fat"` release link times.
    run env \
        CARGO_PROFILE_DEV_OPT_LEVEL="${CARGO_PROFILE_DEV_OPT_LEVEL:-z}" \
        CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}" \
        CARGO_PROFILE_DEV_STRIP="${CARGO_PROFILE_DEV_STRIP:-symbols}" \
        trunk build
fi

# 4. Run Playwright Chromium + chromium-bfcache smoke suite against local `wrangler dev`.
cd "$REPO_ROOT/e2ee_chat_web/e2e"
if [ ! -x node_modules/.bin/playwright ]; then
    run npm ci
fi
run npx playwright test "$@"
