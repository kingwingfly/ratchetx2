#!/usr/bin/env bash
set -euo pipefail

export TERM="${TERM:-xterm-256color}"

if [ "$#" -lt 1 ] || [ -z "$1" ]; then
    echo "Usage: $0 <crate-name> [cargo-publish-args...]" >&2
    exit 2
fi

crate="$1"
shift

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

run cargo publish --locked -p "$crate" "$@"
