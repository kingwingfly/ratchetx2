#!/bin/sh
# Trunk post_build hook for content-hashed assets under strict CSP (zero inline scripts):
# 1. Locates the hashed main JS/WASM bundle under `$TRUNK_STAGING_DIR/assets/`.
# 2. Rewrites `init.js` with the hashed main JS/WASM URLs BEFORE hashing `init.js` ->
#    `assets/init-<sha256>.js` and removes unhashed `init.js`.
# 3. Auto-discovers every `*_loader.js` worker (preview workers, future `vault_kdf`,
#    `preview_markdown`, etc.), content-hashes its JS/WASM/loader triplet into `assets/`
#    with rooted URLs, and injects `<meta name="e2ee-worker-manifest" content='...'>`.
# 4. Rewrites `index.html`'s `modulepreload` and external `init-<hash>.js` `<script>` tag.
# 5. Asserts zero inline `<script>` tags, every referenced asset exists on disk under
#    `$TRUNK_STAGING_DIR`, zero unhashed files remain in `assets/`, and `media-worker.js`
#    stays unhashed at root.
set -eu

LC_ALL=C
export LC_ALL

fail() {
    printf 'post_build.sh: %s\n' "$1" >&2
    exit 1
}

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print substr($1, 1, 16)}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print substr($1, 1, 16)}'
    else
        fail "neither sha256sum nor shasum is available"
    fi
}

is_hex_hash() {
    case "$1" in
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*)
            case "$1" in
                *[!0-9a-f]*) return 1 ;;
                *) return 0 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

STAGE="${TRUNK_STAGING_DIR:-}"
[ -n "$STAGE" ] || fail "TRUNK_STAGING_DIR is not set"
[ -d "$STAGE" ] || fail "TRUNK_STAGING_DIR does not exist: $STAGE"

ASSETS="$STAGE/assets"
INDEX="$STAGE/index.html"
RAW_INIT="$STAGE/init.js"

[ -f "$INDEX" ] || fail "missing $INDEX"
[ -f "$RAW_INIT" ] || fail "missing $RAW_INIT"
[ -f "$STAGE/media-worker.js" ] || fail "missing unhashed root media-worker.js"
[ -f "$STAGE/_headers" ] || fail "missing root _headers"
[ -d "$ASSETS" ] || fail "missing $ASSETS directory (expected data-target-path=\"assets\")"

PUBLIC_URL="${TRUNK_PUBLIC_URL:-/}"
case "$PUBLIC_URL" in
    */) ;;
    *) PUBLIC_URL="${PUBLIC_URL}/" ;;
esac

# Relocate any worker bundles that Trunk may have emitted at staging root (defensive across
# Trunk versions if `data-target-path` is ignored on worker links).
for root_loader in "$STAGE"/*_loader.js; do
    [ -e "$root_loader" ] || continue
    loader_name="$(basename "$root_loader")"
    stem="${loader_name%_loader.js}"
    mv "$root_loader" "$ASSETS/$loader_name"
    [ -f "$STAGE/${stem}.js" ] && mv "$STAGE/${stem}.js" "$ASSETS/${stem}.js"
    [ -f "$STAGE/${stem}_bg.wasm" ] && mv "$STAGE/${stem}_bg.wasm" "$ASSETS/${stem}_bg.wasm"
done

# 1. Discover the single hashed main JS & WASM pair in `$ASSETS`.
MAIN_JS=""
MAIN_JS_COUNT=0
for f in "$ASSETS"/e2ee_chat_web-*.js; do
    [ -e "$f" ] || continue
    base="$(basename "$f")"
    case "$base" in
        *_loader.js) continue ;;
    esac
    MAIN_JS="$base"
    MAIN_JS_COUNT=$((MAIN_JS_COUNT + 1))
done
[ "$MAIN_JS_COUNT" -eq 1 ] || fail "expected 1 hashed e2ee_chat_web-*.js in $ASSETS, found $MAIN_JS_COUNT"

MAIN_WASM=""
MAIN_WASM_COUNT=0
for f in "$ASSETS"/e2ee_chat_web-*_bg.wasm; do
    [ -e "$f" ] || continue
    MAIN_WASM="$(basename "$f")"
    MAIN_WASM_COUNT=$((MAIN_WASM_COUNT + 1))
done
[ "$MAIN_WASM_COUNT" -eq 1 ] || fail "expected 1 hashed e2ee_chat_web-*_bg.wasm in $ASSETS, found $MAIN_WASM_COUNT"

[ ! -e "$STAGE/e2ee_chat_web.js" ] || fail "unexpected unhashed root e2ee_chat_web.js"
[ ! -e "$STAGE/e2ee_chat_web_bg.wasm" ] || fail "unexpected unhashed root e2ee_chat_web_bg.wasm"
[ ! -e "$ASSETS/e2ee_chat_web.js" ] || fail "unexpected unhashed assets/e2ee_chat_web.js"
[ ! -e "$ASSETS/e2ee_chat_web_bg.wasm" ] || fail "unexpected unhashed assets/e2ee_chat_web_bg.wasm"

MAIN_JS_URL="${PUBLIC_URL}assets/${MAIN_JS}"
MAIN_WASM_URL="${PUBLIC_URL}assets/${MAIN_WASM}"

# 2. Rewrite `init.js` with hashed main JS & WASM URLs BEFORE hashing `init.js`.
TMP_INIT="$STAGE/.init.rewritten.tmp"
TMP_INDEX="$STAGE/.index.rewritten.tmp"
TMP_LOADER="$STAGE/.loader.rewritten.tmp"
trap 'rm -f "$TMP_INIT" "$TMP_INDEX" "$TMP_LOADER"' EXIT

awk -v js_url="$MAIN_JS_URL" -v wasm_url="$MAIN_WASM_URL" '
BEGIN { js_hits = 0; wasm_hits = 0 }
{
    if (index($0, "./e2ee_chat_web.js") > 0) {
        gsub(/\.\/e2ee_chat_web\.js/, js_url)
        js_hits++
    }
    if (index($0, "./e2ee_chat_web_bg.wasm") > 0) {
        gsub(/\.\/e2ee_chat_web_bg\.wasm/, wasm_url)
        wasm_hits++
    }
    print
}
END {
    if (js_hits != 1 || wasm_hits != 1) {
        printf("post_build.sh: expected 1 JS and 1 WASM substitution in init.js (got %d, %d)\n", js_hits, wasm_hits) > "/dev/stderr"
        exit 1
    }
}
' "$RAW_INIT" > "$TMP_INIT"

INIT_HASH="$(hash_file "$TMP_INIT")"
[ -n "$INIT_HASH" ] || fail "failed to compute SHA-256 hash of rewritten init.js"

INIT_FILE="init-${INIT_HASH}.js"
INIT_URL="${PUBLIC_URL}assets/${INIT_FILE}"
mv "$TMP_INIT" "$ASSETS/$INIT_FILE"
rm -f "$RAW_INIT"

# 3. Auto-discover every `*_loader.js` worker in `$ASSETS`, content-hash its JS, WASM, and
# rewritten loader shim (Trunk's `data-type="worker"` omits filehash and emits `./assets/...`
# relative imports when `data-target-path="assets"` is set), and build the manifest JSON.
# With `LC_ALL=C`, POSIX glob expansion is deterministically ASCII-sorted and space-safe.
MANIFEST_JSON="{"
MANIFEST_FIRST=1
MANIFEST_KEYS=""
LOADER_COUNT=0

for loader_path in "$ASSETS"/*_loader.js; do
    [ -f "$loader_path" ] || continue
    loader_file="$(basename "$loader_path")"
    loader_stem="${loader_file%_loader.js}"

    # Derive logical binary name whether or not Trunk already appended `-<hexhash>`.
    bin_name="$loader_stem"
    case "$loader_stem" in
        *-*)
            maybe_hash="${loader_stem##*-}"
            if is_hex_hash "$maybe_hash"; then
                bin_name="${loader_stem%-*}"
            fi
            ;;
    esac
    [ -n "$bin_name" ] || fail "missing binary prefix in worker loader filename: $loader_file"

    # Extract referenced `.js` and `_bg.wasm` basenames from Trunk's loader shim.
    raw_js_ref="$(awk -F'"' '{ for (i = 2; i <= NF; i += 2) if ($i ~ /\.js$/) { print $i; exit } }' "$loader_path")"
    raw_wasm_ref="$(awk -F'"' '{ for (i = 2; i <= NF; i += 2) if ($i ~ /_bg\.wasm$/) { print $i; exit } }' "$loader_path")"
    [ -n "$raw_js_ref" ] || fail "could not find worker JS import inside $loader_file"
    [ -n "$raw_wasm_ref" ] || fail "could not find worker WASM path inside $loader_file"

    js_base="$(basename "$raw_js_ref")"
    wasm_base="$(basename "$raw_wasm_ref")"
    [ -f "$ASSETS/$js_base" ] || fail "missing worker JS for $loader_file: $ASSETS/$js_base"
    [ -f "$ASSETS/$wasm_base" ] || fail "missing worker WASM for $loader_file: $ASSETS/$wasm_base"

    # Content-hash worker JS if not already hashed.
    js_stem="${js_base%.js}"
    js_final="$js_base"
    case "$js_stem" in
        "${bin_name}-"*)
            if ! is_hex_hash "${js_stem#"${bin_name}-"}"; then
                js_hash="$(hash_file "$ASSETS/$js_base")"
                js_final="${bin_name}-${js_hash}.js"
                mv "$ASSETS/$js_base" "$ASSETS/$js_final"
            fi
            ;;
        *)
            js_hash="$(hash_file "$ASSETS/$js_base")"
            js_final="${bin_name}-${js_hash}.js"
            mv "$ASSETS/$js_base" "$ASSETS/$js_final"
            ;;
    esac

    # Content-hash worker WASM if not already hashed.
    wasm_stem="${wasm_base%_bg.wasm}"
    wasm_final="$wasm_base"
    case "$wasm_stem" in
        "${bin_name}-"*)
            if ! is_hex_hash "${wasm_stem#"${bin_name}-"}"; then
                wasm_hash="$(hash_file "$ASSETS/$wasm_base")"
                wasm_final="${bin_name}-${wasm_hash}_bg.wasm"
                mv "$ASSETS/$wasm_base" "$ASSETS/$wasm_final"
            fi
            ;;
        *)
            wasm_hash="$(hash_file "$ASSETS/$wasm_base")"
            wasm_final="${bin_name}-${wasm_hash}_bg.wasm"
            mv "$ASSETS/$wasm_base" "$ASSETS/$wasm_final"
            ;;
    esac

    # Rewrite loader with rooted `/assets/` URLs BEFORE hashing the loader itself, and convert
    # async wasm_bindgen init rejection (e.g. 404 WASM on deploy skew) into a worker error event.
    worker_js_url="${PUBLIC_URL}assets/${js_final}"
    worker_wasm_url="${PUBLIC_URL}assets/${wasm_final}"
    printf 'importScripts("%s");wasm_bindgen({module_or_path:"%s"}).catch(function(e){setTimeout(function(){throw e;},0);});\n' \
        "$worker_js_url" "$worker_wasm_url" > "$TMP_LOADER"

    loader_hash="$(hash_file "$TMP_LOADER")"
    loader_final="${bin_name}-${loader_hash}_loader.js"
    mv "$TMP_LOADER" "$ASSETS/$loader_final"
    if [ "$loader_file" != "$loader_final" ]; then
        rm -f "$loader_path"
    fi

    case "$bin_name" in
        preview_*) key="${bin_name#preview_}" ;;
        *) key="$bin_name" ;;
    esac
    case "$key" in
        ""|*[!a-zA-Z0-9_-]*) fail "unsafe worker manifest key '$key' from $loader_file" ;;
    esac
    case " $MANIFEST_KEYS " in
        *" $key "*) fail "duplicate worker manifest key '$key'" ;;
    esac
    MANIFEST_KEYS="$MANIFEST_KEYS $key"

    loader_url="${PUBLIC_URL}assets/${loader_final}"
    if [ "$MANIFEST_FIRST" -eq 1 ]; then
        MANIFEST_FIRST=0
    else
        MANIFEST_JSON="${MANIFEST_JSON},"
    fi
    MANIFEST_JSON="${MANIFEST_JSON}\"${key}\":\"${loader_url}\""
    LOADER_COUNT=$((LOADER_COUNT + 1))
done
MANIFEST_JSON="${MANIFEST_JSON}}"

[ "$LOADER_COUNT" -ge 1 ] || fail "no *_loader.js workers found in $ASSETS"

# 4. Rewrite `index.html`: update `modulepreload` & `init-<hash>.js`, and inject `<meta>`.
META_TAG="    <meta name=\"e2ee-worker-manifest\" content='${MANIFEST_JSON}' />"
awk -v preload_url="$MAIN_JS_URL" -v init_url="$INIT_URL" -v meta_tag="$META_TAG" '
BEGIN { preload_hits = 0; init_hits = 0; meta_inserted = 0 }
{
    if (index($0, "href=\"/e2ee_chat_web.js\"") > 0) {
        print meta_tag
        meta_inserted++
        sub(/href="\/e2ee_chat_web\.js"/, "href=\"" preload_url "\"")
        preload_hits++
    }
    if (index($0, "src=\"/init.js\"") > 0) {
        sub(/src="\/init\.js"/, "src=\"" init_url "\"")
        init_hits++
    }
    print
}
END {
    if (preload_hits != 1 || init_hits != 1 || meta_inserted != 1) {
        printf("post_build.sh: index.html rewrite mismatch (preload=%d, init=%d, meta=%d)\n", preload_hits, init_hits, meta_inserted) > "/dev/stderr"
        exit 1
    }
}
' "$INDEX" > "$TMP_INDEX"
mv "$TMP_INDEX" "$INDEX"

# 5. Loud post-build verification assertions against the written staging output.

# (a) Zero inline `<script>` tags in `index.html`: every `<script>` must carry `src="..."` and
# have an empty body between `>` and `</script>` (portable across gawk, mawk, and BSD awk).
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
            print "post_build.sh: unclosed <script> tag in index.html" > "/dev/stderr"
            exit 1
        }
        open_tag = substr(rest_orig, 1, gt)
        if (tolower(open_tag) !~ /[ \t\r\n]src[ \t\r\n]*=[ \t\r\n]*"[^"]+"/) {
            print "post_build.sh: inline <script> tag without src found in index.html: " open_tag > "/dev/stderr"
            exit 1
        }
        after_gt = substr(rest_lower, gt + 1)
        close_pos = index(after_gt, "</script>")
        if (close_pos == 0) {
            print "post_build.sh: missing </script> closing tag in index.html" > "/dev/stderr"
            exit 1
        }
        body = substr(rest_orig, gt + 1, close_pos - 1)
        gsub(/[ \t\r\n]/, "", body)
        if (length(body) != 0) {
            print "post_build.sh: non-empty inline <script> body found in index.html" > "/dev/stderr"
            exit 1
        }
        script_count++
        pos = start + gt + close_pos + 8
    }
    if (script_count != 1) {
        printf("post_build.sh: expected 1 external <script> tag in index.html, found %d\n", script_count) > "/dev/stderr"
        exit 1
    }
}
' "$INDEX"

# Helper to assert a rooted `${PUBLIC_URL}...` URL maps to an existing file inside `$STAGE`.
assert_stage_url() {
    url="$1"
    label="$2"
    case "$url" in
        "${PUBLIC_URL}"*)
            rel="${url#"$PUBLIC_URL"}"
            ;;
        *)
            fail "$label URL '$url' does not start with '$PUBLIC_URL'"
            ;;
    esac
    [ -n "$rel" ] || fail "$label URL '$url' resolves to empty path"
    [ -f "$STAGE/$rel" ] || fail "$label target does not exist on disk: $STAGE/$rel (from $url)"
}

# (b) Verify every URL in `<meta name="e2ee-worker-manifest">`, every worker loader, `index.html`,
# and `init-*.js` exists on disk under `$TRUNK_STAGING_DIR`, and every file in `assets/` is hashed.
MANIFEST_FROM_HTML="$(awk '
/name="e2ee-worker-manifest"/ {
    if (match($0, /content='\''[^'\'']+'\''/)) {
        s = substr($0, RSTART + 9, RLENGTH - 10)
        print s
    }
}
' "$INDEX")"
[ -n "$MANIFEST_FROM_HTML" ] || fail "failed to extract <meta name=\"e2ee-worker-manifest\"> from index.html"

VERIFIED_MANIFEST_ENTRIES=0
for entry_url in $(printf '%s\n' "$MANIFEST_FROM_HTML" | awk -F'"' '{ for (i = 4; i <= NF; i += 4) print $i }'); do
    assert_stage_url "$entry_url" "manifest worker"
    case "$entry_url" in
        "${PUBLIC_URL}assets/"*-[0-9a-f]*_loader.js) ;;
        *) fail "manifest worker URL is not a hashed /assets/*_loader.js path: $entry_url" ;;
    esac
    loader_rel="${entry_url#"$PUBLIC_URL"}"
    loader_refs="$(awk -F'"' '{ for (i = 2; i <= NF; i += 2) if ($i ~ /\.(js|wasm)$/) print $i }' "$STAGE/$loader_rel")"
    loader_ref_count=0
    for ref in $loader_refs; do
        assert_stage_url "$ref" "worker loader ($loader_rel)"
        loader_ref_count=$((loader_ref_count + 1))
    done
    [ "$loader_ref_count" -eq 2 ] || fail "expected 2 asset URLs (JS + WASM) in $loader_rel, found $loader_ref_count"
    VERIFIED_MANIFEST_ENTRIES=$((VERIFIED_MANIFEST_ENTRIES + 1))
done
[ "$VERIFIED_MANIFEST_ENTRIES" -eq "$LOADER_COUNT" ] || fail "manifest entry count mismatch: expected $LOADER_COUNT, verified $VERIFIED_MANIFEST_ENTRIES"

assert_stage_url "$MAIN_JS_URL" "main JS"
assert_stage_url "$MAIN_WASM_URL" "main WASM"
assert_stage_url "$INIT_URL" "hashed init.js"

# Re-extract URLs directly from the written `init-<hash>.js` and verify them on disk.
INIT_REFS="$(awk -F'"' '{ for (i = 2; i <= NF; i += 2) if ($i ~ /\.(js|wasm)$/) print $i }' "$ASSETS/$INIT_FILE")"
INIT_REF_COUNT=0
for ref in $INIT_REFS; do
    assert_stage_url "$ref" "init.js import/module"
    INIT_REF_COUNT=$((INIT_REF_COUNT + 1))
done
[ "$INIT_REF_COUNT" -eq 2 ] || fail "expected 2 asset URLs (JS + WASM) in $INIT_FILE, found $INIT_REF_COUNT"
[ ! -e "$STAGE/init.js" ] || fail "unhashed root init.js was not removed"

# Verify every JS/WASM/CSS file inside `$ASSETS` is content-hashed (immutable cache safe).
for asset_path in "$ASSETS"/*; do
    [ -f "$asset_path" ] || continue
    asset_name="$(basename "$asset_path")"
    case "$asset_name" in
        *-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
        *) fail "unhashed asset found under immutable /assets/: $asset_name" ;;
    esac
done

# (c) Verify `media-worker.js` remains unhashed at root and no hashed copy exists.
[ -f "$STAGE/media-worker.js" ] || fail "media-worker.js missing at staging root"
for bad_sw in "$STAGE"/media-worker-*.js "$ASSETS"/media-worker*.js; do
    [ ! -e "$bad_sw" ] || fail "media-worker.js must remain unhashed at root; found $bad_sw"
done
