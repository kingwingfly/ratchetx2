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
cd "$REPO_ROOT/e2ee_chat_worker"

# 1. Production build check (never includes `--features conformance`).
run worker-build --release

# 2. Tier 2 real `workerd` integration & storage conformance suite.
run worker-build --dev --features conformance
if [ ! -x node_modules/.bin/vitest ]; then
    run npm ci
fi
run npm run test:workerd
