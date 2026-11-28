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

if [ "${E2E_SKIP_WASM_TESTS:-0}" != "1" ]; then
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

    # 2. `e2ee_chat_web` in-module browser wasm32 tests (`vault.rs`, `workers.rs`, `kdf_worker.rs`).
    run env CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
        cargo test --locked --target wasm32-unknown-unknown -p e2ee_chat_web --bin e2ee_chat_web
fi

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

# 3b. Verify 11-WASM & 10-worker-manifest bundle integrity on `e2ee_chat_web/dist`.
verify_web_bundle() {
    dist_dir="$1"
    assets_dir="$dist_dir/assets"
    index_html="$dist_dir/index.html"

    [ -f "$index_html" ] || { printf 'e2e.sh: missing %s\n' "$index_html" >&2; exit 1; }
    [ -f "$dist_dir/media-worker.js" ] || { printf 'e2e.sh: missing root %s/media-worker.js\n' "$dist_dir" >&2; exit 1; }
    [ -f "$dist_dir/_headers" ] || { printf 'e2e.sh: missing root %s/_headers\n' "$dist_dir" >&2; exit 1; }
    [ -d "$assets_dir" ] || { printf 'e2e.sh: missing %s\n' "$assets_dir" >&2; exit 1; }

    # Assert exactly 11 hashed `*_bg.wasm` binaries exist in `dist/assets/`.
    wasm_total=0
    for wasm_file in "$assets_dir"/*_bg.wasm; do
        [ -f "$wasm_file" ] || continue
        wasm_total=$((wasm_total + 1))
    done
    if [ "$wasm_total" -ne 11 ]; then
        printf 'e2e.sh: expected exactly 11 *_bg.wasm files in %s, found %d\n' "$assets_dir" "$wasm_total" >&2
        ls -la "$assets_dir"/*_bg.wasm >&2 || true
        exit 1
    fi

    for expected_bin in \
        e2ee_chat_web \
        vault_kdf \
        preview_pdf \
        preview_audio \
        preview_search \
        preview_diagram \
        preview_markdown \
        preview_code_web \
        preview_code_systems \
        preview_code_apps \
        preview_code_scripts
    do
        match_count=0
        for candidate in "$assets_dir/${expected_bin}-"*_bg.wasm; do
            [ -f "$candidate" ] || continue
            base="$(basename "$candidate")"
            hash_part="${base#"${expected_bin}-"}"
            hash_part="${hash_part%_bg.wasm}"
            case "$hash_part" in
                [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*)
                    case "$hash_part" in
                        *[!0-9a-f]*)
                            printf 'e2e.sh: non-hex hash in WASM filename: %s\n' "$base" >&2
                            exit 1
                            ;;
                    esac
                    match_count=$((match_count + 1))
                    ;;
                *)
                    printf 'e2e.sh: unhashed or short-hash WASM filename: %s\n' "$base" >&2
                    exit 1
                    ;;
            esac
        done
        if [ "$match_count" -ne 1 ]; then
            printf 'e2e.sh: expected 1 hashed %s-*_bg.wasm in %s, found %d\n' \
                "$expected_bin" "$assets_dir" "$match_count" >&2
            exit 1
        fi
    done

    # Assert zero inline `<script>` tags exist in `dist/index.html`.
    awk '
    { html = (NR == 1 ? $0 : html "\n" $0) }
    END {
        lower = tolower(html)
        pos = 1
        script_count = 0
        while (match(substr(lower, pos), /<script([ \t\r\n>\/]|$)/)) {
            start = pos + RSTART - 1
            rest_lower = substr(lower, start)
            rest_orig = substr(html, start)
            gt = index(rest_orig, ">")
            if (gt == 0) {
                print "e2e.sh: unclosed <script> tag in index.html" > "/dev/stderr"
                exit 1
            }
            open_tag = substr(rest_orig, 1, gt)
            if (tolower(open_tag) !~ /[ \t\r\n]src[ \t\r\n]*=[ \t\r\n]*"[^"]+"/) {
                print "e2e.sh: inline <script> tag without src found in index.html" > "/dev/stderr"
                exit 1
            }
            after_gt = substr(rest_lower, gt + 1)
            close_pos = index(after_gt, "</script>")
            if (close_pos == 0) {
                print "e2e.sh: missing </script> closing tag in index.html" > "/dev/stderr"
                exit 1
            }
            body = substr(rest_orig, gt + 1, close_pos - 1)
            gsub(/[ \t\r\n]/, "", body)
            if (length(body) != 0) {
                print "e2e.sh: non-empty inline <script> body found in index.html" > "/dev/stderr"
                exit 1
            }
            script_count++
            pos = start + gt + close_pos + 8
        }
        if (script_count != 1) {
            printf("e2e.sh: expected 1 external <script> tag in index.html, found %d\n", script_count) > "/dev/stderr"
            exit 1
        }
    }
    ' "$index_html"

    # Assert `<meta name="e2ee-worker-manifest">` contains all 10 expected worker keys
    # pointing to existing hashed `/assets/*_loader.js` files on disk.
    node - "$dist_dir" <<'EOF'
const fs = require('node:fs');
const path = require('node:path');

const distDir = process.argv[2];
const html = fs.readFileSync(path.join(distDir, 'index.html'), 'utf8');
const match = html.match(/<meta\s+name="e2ee-worker-manifest"\s+content='([^']+)'\s*\/?>/);
if (!match) {
  console.error('e2e.sh: missing <meta name="e2ee-worker-manifest"> in dist/index.html');
  process.exit(1);
}
const manifest = JSON.parse(match[1]);
const expectedKeys = [
  'vault_kdf',
  'pdf',
  'audio',
  'search',
  'diagram',
  'markdown',
  'code_web',
  'code_systems',
  'code_apps',
  'code_scripts',
].sort();
const actualKeys = Object.keys(manifest).sort();
if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
  console.error(
    `e2e.sh: worker manifest keys mismatch.\n  expected: ${expectedKeys.join(', ')}\n  actual:   ${actualKeys.join(', ')}`,
  );
  process.exit(1);
}
for (const key of expectedKeys) {
  const url = manifest[key];
  const expectedPrefix = key === 'vault_kdf' ? 'vault_kdf' : `preview_${key}`;
  const pattern = new RegExp(`^/assets/${expectedPrefix}-[0-9a-f]{8,}_loader\\.js$`);
  if (typeof url !== 'string' || !pattern.test(url)) {
    console.error(`e2e.sh: invalid worker manifest URL for "${key}": ${String(url)}`);
    process.exit(1);
  }
  const diskPath = path.join(distDir, url.slice(1));
  if (!fs.existsSync(diskPath)) {
    console.error(`e2e.sh: worker loader missing on disk for "${key}": ${diskPath}`);
    process.exit(1);
  }
}
EOF

    printf 'Verified web bundle integrity: 11 hashed *_bg.wasm files, 10 worker manifest entries, 0 inline <script> tags, root media-worker.js & _headers present.\n'
}

run verify_web_bundle "$REPO_ROOT/e2ee_chat_web/dist"

# 4. Run Playwright suite against local `wrangler dev`.
cd "$REPO_ROOT/e2ee_chat_web/e2e"
if [ ! -x node_modules/.bin/playwright ]; then
    run npm ci
fi
run npx playwright test "$@"
