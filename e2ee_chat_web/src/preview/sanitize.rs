use data_url::DataUrl;

use super::PreviewBudget;

/// Maximum encoded and decoded byte size allowed for inline Markdown `data:image/...;base64,` URLs.
pub(super) const IMAGE_DATA_URL_MAX: usize = 2 * 1024 * 1024;
/// Maximum attributes retained per HTML/MathML start tag.
const MAX_TAG_ATTRS: usize = 64;
/// Maximum nesting depth for open/dropped tag stacks.
const MAX_STACK_DEPTH: usize = 256;

/// Strictly validate highlighted HTML returned by the syntax-highlighting worker: only balanced
/// `<span class="hl-[a-z0-9_-]+">` / `</span>` tags and entity-escaped text (no raw `<`, `>`, or
/// malformed `&` entities).
pub fn validate_highlight_html(html: &str) -> Result<(), String> {
    const OPEN_PREFIX: &[u8] = b"<span class=\"hl-";
    const CLOSE_TAG: &[u8] = b"</span>";

    let bytes = html.as_bytes();
    let mut i = 0usize;
    let mut depth = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'<' => {
                if bytes[i..].starts_with(CLOSE_TAG) {
                    depth = depth
                        .checked_sub(1)
                        .ok_or_else(|| "unbalanced </span> in highlighted output".to_string())?;
                    i += CLOSE_TAG.len();
                } else if bytes[i..].starts_with(OPEN_PREFIX) {
                    i += OPEN_PREFIX.len();
                    let name_start = i;
                    while i < bytes.len()
                        && (bytes[i].is_ascii_lowercase()
                            || bytes[i].is_ascii_digit()
                            || bytes[i] == b'-'
                            || bytes[i] == b'_')
                    {
                        i += 1;
                    }
                    if i == name_start || !bytes[i..].starts_with(b"\">") {
                        return Err("unexpected span class in highlighted output".to_string());
                    }
                    i += 2;
                    depth = depth.checked_add(1).ok_or_else(|| {
                        "excessive span nesting in highlighted output".to_string()
                    })?;
                } else {
                    return Err("unexpected HTML tag in highlighted output".to_string());
                }
            }
            b'>' => return Err("unescaped '>' in highlighted output".to_string()),
            b'&' => {
                i += 1;
                let semi = bytes[i..]
                    .iter()
                    .take(12)
                    .position(|&b| b == b';')
                    .ok_or_else(|| "unterminated HTML entity in highlighted output".to_string())?;
                let entity = &bytes[i..i + semi];
                let valid = matches!(entity, b"amp" | b"lt" | b"gt" | b"quot" | b"apos")
                    || entity
                        .strip_prefix(b"#x")
                        .or_else(|| entity.strip_prefix(b"#X"))
                        .is_some_and(|rest| {
                            !rest.is_empty() && rest.iter().all(u8::is_ascii_hexdigit)
                        })
                    || entity.strip_prefix(b"#").is_some_and(|rest| {
                        !rest.is_empty() && rest.iter().all(u8::is_ascii_digit)
                    });
                if !valid {
                    return Err("invalid HTML entity in highlighted output".to_string());
                }
                i += semi + 1;
            }
            _ => i += 1,
        }
    }
    if depth != 0 {
        return Err("unclosed <span> in highlighted output".to_string());
    }
    Ok(())
}

/// Validate an allowed link destination (`http://`, `https://`, `mailto:`, or `#` fragment) with
/// no ASCII control characters, returning the trimmed URL with any scheme prefix normalized to
/// lowercase (preserving case-sensitive path/query/fragment components).
pub(super) fn normalize_safe_href(url: &str) -> Option<String> {
    let trimmed = url.trim_matches(|c: char| c.is_ascii_whitespace());
    if trimmed.is_empty() || trimmed.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    if trimmed.starts_with('#') {
        return Some(trimmed.to_string());
    }
    for scheme in ["http://", "https://", "mailto:"] {
        if let Some(prefix) = trimmed.get(..scheme.len())
            && prefix.eq_ignore_ascii_case(scheme)
        {
            return Some(format!("{scheme}{}", &trimmed[scheme.len()..]));
        }
    }
    None
}

/// Whether `url` is a bounded, base64-encoded raster `data:image/{png,jpeg,gif,webp,avif};base64,`
/// URL parsed via `data-url` (explicitly rejecting `data:image/svg+xml`, non-base64 payloads,
/// invalid base64, and control characters).
pub(super) fn is_safe_image_src(url: &str) -> bool {
    let trimmed = url.trim_matches(|c: char| c.is_ascii_whitespace());
    if trimmed.is_empty()
        || trimmed.len() > IMAGE_DATA_URL_MAX
        || trimmed.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return false;
    }
    let Some((header, body)) = trimmed.split_once(',') else {
        return false;
    };
    if header.contains('#') || body.is_empty() {
        return false;
    }
    let has_base64 = header.rsplit_once(';').is_some_and(|(_, last)| {
        last.trim_matches(|c: char| c.is_ascii_whitespace())
            .eq_ignore_ascii_case("base64")
    });
    if !has_base64 {
        return false;
    }
    let Ok(parsed) = DataUrl::process(trimmed) else {
        return false;
    };
    let mime = parsed.mime_type();
    if mime.type_ != "image"
        || !matches!(
            mime.subtype.as_str(),
            "png" | "jpeg" | "gif" | "webp" | "avif"
        )
    {
        return false;
    }
    let mut decoded_bytes = 0usize;
    let Ok(fragment) = parsed.decode(|chunk| {
        decoded_bytes = decoded_bytes.saturating_add(chunk.len());
        if decoded_bytes > IMAGE_DATA_URL_MAX {
            Err(())
        } else {
            Ok(())
        }
    }) else {
        return false;
    };
    fragment.is_none() && decoded_bytes > 0
}

/// Maximum allowed absolute magnitude for a CSS/MathML dimension unit, normalized to `<= 20em`
/// equivalent (assuming 1em = 16px = 12pt = 1pc = 1/6in = 2ex = 100%).
pub(super) fn math_dimension_unit_max(unit: &str) -> Option<f64> {
    Some(match unit {
        "em" => 20.0,
        "ex" => 40.0,
        "px" => 320.0,
        "pt" => 240.0,
        "pc" => 20.0,
        "in" => 3.3333,
        "cm" => 8.4666,
        "mm" => 84.666,
        "%" => 2000.0,
        _ => return None,
    })
}

pub(super) fn push_escaped_char(out: &mut String, c: char) {
    match c {
        '&' => out.push_str("&amp;"),
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        _ => out.push(c),
    }
}

pub(super) fn push_escaped_text(out: &mut String, text: &str) {
    let mut last = 0;
    for (i, b) in text.bytes().enumerate() {
        let repl = match b {
            b'&' => "&amp;",
            b'<' => "&lt;",
            b'>' => "&gt;",
            _ => continue,
        };
        out.push_str(&text[last..i]);
        out.push_str(repl);
        last = i + 1;
    }
    out.push_str(&text[last..]);
}

/// Escape `text` for HTML elements and attribute values in a single pass.
pub(super) fn push_escaped_attr(out: &mut String, text: &str) {
    let mut last = 0;
    for (i, b) in text.bytes().enumerate() {
        let repl = match b {
            b'&' => "&amp;",
            b'<' => "&lt;",
            b'>' => "&gt;",
            b'"' => "&quot;",
            b'\'' => "&#39;",
            _ => continue,
        };
        out.push_str(&text[last..i]);
        out.push_str(repl);
        last = i + 1;
    }
    out.push_str(&text[last..]);
}

/// `text` escaped for HTML, in elements and attributes.
pub(super) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    push_escaped_attr(&mut out, text);
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TagNamespace {
    Html,
    MathMl,
}

macro_rules! sorted_tag_table {
    ($name:ident, [$($tag:literal),+ $(,)?]) => {
        const $name: &[&str] = &[$($tag),+];
    };
}

sorted_tag_table!(
    RAW_TEXT_DROP_TAGS,
    [
        "iframe", "noembed", "noframes", "noscript", "script", "style", "textarea", "title", "xmp",
    ]
);

sorted_tag_table!(
    VOID_DROP_TAGS,
    [
        "area", "base", "col", "embed", "frame", "keygen", "link", "menuitem", "meta", "param",
        "source", "track", "wbr",
    ]
);

sorted_tag_table!(
    CONTAINER_DROP_TAGS,
    [
        "applet", "audio", "button", "canvas", "form", "frameset", "object", "portal", "select",
        "svg", "template", "video",
    ]
);

sorted_tag_table!(
    HTML_TAGS,
    [
        "a",
        "blockquote",
        "br",
        "code",
        "dd",
        "del",
        "div",
        "dl",
        "dt",
        "em",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "img",
        "input",
        "li",
        "math",
        "ol",
        "p",
        "pre",
        "span",
        "strong",
        "sub",
        "sup",
        "table",
        "tbody",
        "td",
        "th",
        "thead",
        "tr",
        "ul",
    ]
);

sorted_tag_table!(
    MATHML_TAGS,
    [
        "mfrac",
        "mi",
        "mn",
        "mo",
        "mover",
        "mroot",
        "mrow",
        "mspace",
        "msqrt",
        "msub",
        "msubsup",
        "msup",
        "mtable",
        "mtd",
        "mtext",
        "mtr",
        "munder",
        "munderover",
    ]
);

fn lookup_sorted_tag(table: &'static [&'static str], tag: &str) -> Option<&'static str> {
    table.binary_search(&tag).ok().map(|idx| table[idx])
}

#[cfg(test)]
pub(super) fn tag_tables_are_sorted() -> bool {
    [
        RAW_TEXT_DROP_TAGS,
        VOID_DROP_TAGS,
        CONTAINER_DROP_TAGS,
        HTML_TAGS,
        MATHML_TAGS,
    ]
    .into_iter()
    .all(|table| table.windows(2).all(|w| w[0] < w[1]))
}

struct DropFrame {
    tag: String,
    depth: usize,
}

/// Memoization state that guarantees `parse_start_tag` never rescans failed EOF states in O(n^2)
/// on malformed unclosed tags or quotes. Allocates zero memory on well-formed HTML.
struct ParseFailCache {
    no_gt_from: usize,
    no_dquote_from: usize,
    no_squote_from: usize,
    /// Per-byte bitset allocated lazily on the first unclosed start tag:
    /// bit 0 = attr-loop boundary fails at EOF,
    /// bit 1 = attr-name byte fails at EOF,
    /// bit 2 = unquoted-value byte fails at EOF.
    failed_bytes: Vec<u8>,
}

impl ParseFailCache {
    const fn new() -> Self {
        Self {
            no_gt_from: usize::MAX,
            no_dquote_from: usize::MAX,
            no_squote_from: usize::MAX,
            failed_bytes: Vec::new(),
        }
    }

    fn is_failed(&self, pos: usize, bit: u8) -> bool {
        self.failed_bytes
            .get(pos)
            .is_some_and(|&flags| flags & bit != 0)
    }

    fn mark_failed(&mut self, len: usize, positions: &[(usize, u8)]) {
        if self.failed_bytes.is_empty() {
            self.failed_bytes.resize(len, 0);
        }
        for &(pos, bit) in positions {
            if let Some(slot) = self.failed_bytes.get_mut(pos) {
                *slot |= bit;
            }
        }
    }

    fn mark_failed_range(&mut self, len: usize, start: usize, end: usize, bit: u8) {
        if self.failed_bytes.is_empty() {
            self.failed_bytes.resize(len, 0);
        }
        for slot in &mut self.failed_bytes[start..end.min(len)] {
            *slot |= bit;
        }
    }
}

/// Strict allowlist HTML/MathML sanitizer over rendered Markdown HTML (defense-in-depth).
///
/// Only permits safe Markdown HTML tags, safe MathML Core tags (exclusively inside `<math>` and
/// outside MathML text integration points), and explicitly validated attributes. Drops comments,
/// declarations, processing instructions, dangerous subtrees (`<script>`, `<style>`, `<iframe>`,
/// `<svg>`, `<object>`, `<form>`, etc.), `style`, `ping`, `on*` handlers, unsafe URL schemes,
/// and non-allowlisted CSS classes.
pub(super) fn sanitize_html(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut out = String::with_capacity(input.len());
    let mut open_stack: Vec<&'static str> = Vec::new();
    let mut drop_stack: Vec<DropFrame> = Vec::new();
    let mut math_depth: usize = 0;
    let mut fail_cache = ParseFailCache::new();

    while i < bytes.len() {
        let Some(rel_lt) = bytes[i..].iter().position(|&b| b == b'<') else {
            if drop_stack.is_empty() {
                emit_sanitized_text(&mut out, &input[i..]);
            }
            break;
        };
        if rel_lt > 0 && drop_stack.is_empty() {
            emit_sanitized_text(&mut out, &input[i..i + rel_lt]);
        }
        i += rel_lt;

        // Comment: <!-- ... -->, <!-->, <!--->, <!-- ... --!>
        if bytes[i..].starts_with(b"<!--") {
            if let Some(end) = find_comment_end(&bytes[i + 4..]) {
                i += 4 + end;
            } else {
                break;
            }
            continue;
        }
        // CDATA: <![CDATA[ ... ]]>
        if bytes.len() >= i + 9 && bytes[i..i + 9].eq_ignore_ascii_case(b"<![cdata[") {
            if let Some(end) = find_subslice(&bytes[i + 9..], b"]]>") {
                i += 9 + end + 3;
            } else {
                break;
            }
            continue;
        }
        // Declaration <!...> or Processing Instruction <?...>
        if bytes.get(i + 1).is_some_and(|&b| b == b'!' || b == b'?') {
            if i + 2 >= fail_cache.no_gt_from {
                break;
            }
            if let Some(end) = bytes[i + 2..].iter().position(|&b| b == b'>') {
                i += 2 + end + 1;
            } else {
                fail_cache.no_gt_from = fail_cache.no_gt_from.min(i + 2);
                break;
            }
            continue;
        }

        // Closing tag: </name ...>
        if bytes.get(i + 1) == Some(&b'/') {
            let name_start = i + 2;
            let mut name_end = name_start;
            while name_end < bytes.len() && is_tag_name_byte(bytes[name_end]) {
                name_end += 1;
            }
            if name_end >= fail_cache.no_gt_from {
                break;
            }
            let Some(gt_rel) = bytes[name_end..].iter().position(|&b| b == b'>') else {
                fail_cache.no_gt_from = fail_cache.no_gt_from.min(name_end);
                break;
            };
            let next_i = name_end + gt_rel + 1;
            let name = input[name_start..name_end].to_ascii_lowercase();
            i = next_i;

            if !drop_stack.is_empty() {
                if let Some(pos) = drop_stack.iter().rposition(|frame| frame.tag == name) {
                    if drop_stack[pos].depth > 1 {
                        drop_stack.truncate(pos + 1);
                        drop_stack[pos].depth -= 1;
                    } else {
                        drop_stack.truncate(pos);
                    }
                }
                continue;
            }
            if let Some(pos) = open_stack.iter().rposition(|&open| open == name) {
                while open_stack.len() > pos {
                    let popped = open_stack.pop().expect("non-empty");
                    if popped == "math" {
                        math_depth = math_depth.saturating_sub(1);
                    }
                    out.push_str("</");
                    out.push_str(popped);
                    out.push('>');
                }
            }
            continue;
        }

        // Opening tag: <name ...>
        if !bytes.get(i + 1).is_some_and(u8::is_ascii_alphabetic) {
            if drop_stack.is_empty() {
                out.push_str("&lt;");
            }
            i += 1;
            continue;
        }

        let Some((tag_name, attrs, self_closing, next_i)) =
            parse_start_tag(input, i, &mut fail_cache)
        else {
            // Unclosed tag: drop remaining bytes if dropping subtree, otherwise escape `<`.
            if drop_stack.is_empty() {
                out.push_str("&lt;");
            }
            i += 1;
            continue;
        };
        i = next_i;

        if !drop_stack.is_empty() {
            // Skip rawtext elements verbatim even inside dropped containers (e.g. `<svg><script>`)
            // so `</svg>` or `<svg>` inside script/style content cannot desync `drop_stack`.
            if is_raw_text_drop_tag(&tag_name) {
                let foreign_self_closing =
                    self_closing && drop_stack.iter().any(|frame| frame.tag == "svg");
                if !foreign_self_closing {
                    i = skip_raw_text_element(input, i, &tag_name);
                }
                continue;
            }
            if !self_closing {
                if let Some(top) = drop_stack.last_mut()
                    && top.tag == tag_name
                {
                    top.depth = top.depth.saturating_add(1);
                } else if is_container_drop_tag(&tag_name) && drop_stack.len() < MAX_STACK_DEPTH {
                    drop_stack.push(DropFrame {
                        tag: tag_name,
                        depth: 1,
                    });
                }
            }
            continue;
        }

        // Raw-text dangerous elements: skip verbatim to matching </tag>.
        if is_raw_text_drop_tag(&tag_name) {
            i = skip_raw_text_element(input, i, &tag_name);
            continue;
        }
        // Void dangerous elements: drop tag only.
        if is_void_drop_tag(&tag_name) {
            continue;
        }
        // Container dangerous elements: drop entire subtree.
        if is_container_drop_tag(&tag_name) {
            if !(self_closing && tag_name == "svg") {
                drop_stack.push(DropFrame {
                    tag: tag_name,
                    depth: 1,
                });
            }
            continue;
        }

        // Inside MathML token elements (`mi`, `mn`, `mo`, `mtext`), HTML5 switches to HTML
        // parsing at MathML text integration points; disallow all child tags to prevent
        // `<mspace />` and HTML-in-MathML parser differentials.
        if math_depth > 0
            && open_stack
                .last()
                .is_some_and(|&top| is_mathml_text_integration_point(top))
        {
            continue;
        }

        // Namespace-separated tag allowlist.
        let (namespace, canon_tag) = if math_depth > 0 {
            let Some(tag) = lookup_sorted_tag(MATHML_TAGS, &tag_name) else {
                continue;
            };
            (TagNamespace::MathMl, tag)
        } else {
            let Some(tag) = lookup_sorted_tag(HTML_TAGS, &tag_name) else {
                continue;
            };
            (TagNamespace::Html, tag)
        };

        // Special handling for tasklist checkboxes: only allow `<input type="checkbox">`.
        if canon_tag == "input" {
            let is_checkbox = attrs
                .iter()
                .find(|(k, _)| k == "type")
                .is_some_and(|(_, v)| {
                    decode_entities(v, true)
                        .trim_matches(|c: char| c.is_ascii_whitespace())
                        .eq_ignore_ascii_case("checkbox")
                });
            if is_checkbox {
                let checked = attrs.iter().any(|(k, _)| k == "checked");
                out.push_str("<input disabled=\"\" type=\"checkbox\"");
                if checked {
                    out.push_str(" checked=\"\"");
                }
                out.push_str(" />");
            }
            continue;
        }

        let void_tag = matches!(canon_tag, "br" | "hr" | "img" | "mspace");
        if !void_tag && open_stack.len() >= MAX_STACK_DEPTH {
            continue;
        }

        out.push('<');
        out.push_str(canon_tag);
        emit_sanitized_attrs(&mut out, namespace, canon_tag, &attrs);
        if void_tag {
            out.push_str(" />");
        } else if (math_depth > 0 || canon_tag == "math") && self_closing {
            // HTML5 immediately closes self-closing `<math/>` and foreign MathML elements without
            // keeping them on the stack of open elements.
            out.push_str("></");
            out.push_str(canon_tag);
            out.push('>');
        } else {
            out.push('>');
            if canon_tag == "math" {
                math_depth += 1;
            }
            open_stack.push(canon_tag);
        }
    }

    while let Some(popped) = open_stack.pop() {
        out.push_str("</");
        out.push_str(popped);
        out.push('>');
    }
    out
}

/// Find the end of an HTML5 comment (`<!-->`, `<!--->`, `-->`, or `--!>`) in `after_open` (which
/// begins right after `<!--`), returning the byte offset immediately after the closing `>`.
fn find_comment_end(after_open: &[u8]) -> Option<usize> {
    if after_open.starts_with(b">") {
        return Some(1);
    }
    if after_open.starts_with(b"->") {
        return Some(2);
    }
    let mut i = 0;
    while i + 2 < after_open.len() {
        if after_open[i] == b'-' && after_open[i + 1] == b'-' {
            if after_open[i + 2] == b'>' {
                return Some(i + 3);
            }
            if after_open[i + 2] == b'!' && after_open.get(i + 3) == Some(&b'>') {
                return Some(i + 4);
            }
        }
        i += 1;
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn is_tag_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b':' | b'_')
}

fn is_mathml_text_integration_point(tag: &str) -> bool {
    matches!(tag, "mi" | "mn" | "mo" | "mtext")
}

type ParsedStartTag = (String, Vec<(String, String)>, bool, usize);

fn parse_start_tag(
    input: &str,
    start: usize,
    fail_cache: &mut ParseFailCache,
) -> Option<ParsedStartTag> {
    let bytes = input.as_bytes();
    let mut i = start + 1;
    let name_start = i;
    while i < bytes.len() && is_tag_name_byte(bytes[i]) {
        i += 1;
    }
    if i == name_start || i >= fail_cache.no_gt_from {
        return None;
    }
    let tag_name = input[name_start..i].to_ascii_lowercase();
    let mut attrs: Vec<(String, String)> = Vec::new();
    let mut attr_budget = PreviewBudget::new(MAX_TAG_ATTRS);
    let mut self_closing = false;
    let mut last_quote_end = i;
    let mut visited_loop: Vec<(usize, u8)> = Vec::new();
    let mut visited_ranges: Vec<(usize, usize, u8)> = Vec::new();

    let commit_fail = |cache: &mut ParseFailCache,
                       visited_loop: &[(usize, u8)],
                       visited_ranges: &[(usize, usize, u8)]| {
        cache.mark_failed(bytes.len(), visited_loop);
        for &(s, e, bit) in visited_ranges {
            cache.mark_failed_range(bytes.len(), s, e, bit);
        }
    };

    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || i >= fail_cache.no_gt_from || fail_cache.is_failed(i, 1) {
            if i >= bytes.len() {
                fail_cache.no_gt_from = fail_cache.no_gt_from.min(last_quote_end);
            }
            commit_fail(fail_cache, &visited_loop, &visited_ranges);
            return None;
        }
        visited_loop.push((i, 1));

        if bytes[i] == b'>' {
            return Some((tag_name, attrs, self_closing, i + 1));
        }
        if bytes[i] == b'/' {
            if bytes.get(i + 1) == Some(&b'>') {
                self_closing = true;
                return Some((tag_name, attrs, self_closing, i + 2));
            }
            // HTML5 treats stray `/` inside a tag as an attribute separator (e.g. `<img/onerror=...>`).
            i += 1;
            continue;
        }

        let attr_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && !matches!(bytes[i], b'=' | b'>' | b'/')
        {
            if fail_cache.is_failed(i, 2) {
                visited_ranges.push((attr_start, i, 2));
                commit_fail(fail_cache, &visited_loop, &visited_ranges);
                return None;
            }
            i += 1;
        }
        if i == attr_start {
            i += 1;
            continue;
        }
        visited_ranges.push((attr_start, i, 2));
        let attr_end = i;

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let val_slice = if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= bytes.len() {
                fail_cache.no_gt_from = fail_cache.no_gt_from.min(last_quote_end);
                commit_fail(fail_cache, &visited_loop, &visited_ranges);
                return None;
            }
            match bytes[i] {
                b'"' | b'\'' => {
                    let quote = bytes[i];
                    i += 1;
                    let val_start = i;
                    let no_quote_from = if quote == b'"' {
                        fail_cache.no_dquote_from
                    } else {
                        fail_cache.no_squote_from
                    };
                    if i >= no_quote_from {
                        commit_fail(fail_cache, &visited_loop, &visited_ranges);
                        return None;
                    }
                    let Some(rel_end) = bytes[i..].iter().position(|&b| b == quote) else {
                        if quote == b'"' {
                            fail_cache.no_dquote_from = fail_cache.no_dquote_from.min(i);
                        } else {
                            fail_cache.no_squote_from = fail_cache.no_squote_from.min(i);
                        }
                        commit_fail(fail_cache, &visited_loop, &visited_ranges);
                        return None;
                    };
                    let val = &input[val_start..val_start + rel_end];
                    i = val_start + rel_end + 1;
                    last_quote_end = i;
                    val
                }
                _ => {
                    let val_start = i;
                    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                        if fail_cache.is_failed(i, 4) {
                            visited_ranges.push((val_start, i, 4));
                            commit_fail(fail_cache, &visited_loop, &visited_ranges);
                            return None;
                        }
                        i += 1;
                    }
                    visited_ranges.push((val_start, i, 4));
                    // Per HTML5 §13.2.5.38, `/` inside an unquoted attribute value is part of the
                    // value (e.g. `<a href=https://example.com/>`), never a self-closing flag.
                    &input[val_start..i]
                }
            }
        } else {
            ""
        };

        if !attr_budget.is_truncated() {
            let attr_name = input[attr_start..attr_end].to_ascii_lowercase();
            // Keep only the first occurrence of each attribute name (matching HTML5 parsing rules),
            // bounded to at most `MAX_TAG_ATTRS` unique attributes.
            if !attrs.iter().any(|(existing, _)| existing == &attr_name) && attr_budget.try_push() {
                attrs.push((attr_name, val_slice.to_string()));
            }
        }
    }
}

fn skip_raw_text_element(input: &str, start: usize, tag: &str) -> usize {
    let bytes = input.as_bytes();
    let tag_bytes = tag.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        let Some(rel) = bytes[i..].iter().position(|&b| b == b'<') else {
            return bytes.len();
        };
        i += rel;
        let close_start = i + 2;
        if bytes.get(i + 1) == Some(&b'/')
            && bytes.len() >= close_start + tag_bytes.len()
            && bytes[close_start..close_start + tag_bytes.len()].eq_ignore_ascii_case(tag_bytes)
        {
            let after = close_start + tag_bytes.len();
            if bytes
                .get(after)
                .is_some_and(|&b| b == b'>' || b == b'/' || b.is_ascii_whitespace())
            {
                if let Some(gt) = bytes[after..].iter().position(|&b| b == b'>') {
                    return after + gt + 1;
                }
                return bytes.len();
            }
        }
        i += 1;
    }
    bytes.len()
}

fn is_raw_text_drop_tag(tag: &str) -> bool {
    lookup_sorted_tag(RAW_TEXT_DROP_TAGS, tag).is_some()
}

fn is_void_drop_tag(tag: &str) -> bool {
    lookup_sorted_tag(VOID_DROP_TAGS, tag).is_some()
}

fn is_container_drop_tag(tag: &str) -> bool {
    lookup_sorted_tag(CONTAINER_DROP_TAGS, tag).is_some()
}

fn is_safe_footnote_id(id: &str) -> bool {
    let max_chars = if id.starts_with("fn-") { 67 } else { 64 };
    !id.is_empty()
        && id.len() <= 256
        && id.chars().count() <= max_chars
        && id
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn emit_sanitized_attrs(
    out: &mut String,
    namespace: TagNamespace,
    tag: &'static str,
    attrs: &[(String, String)],
) {
    let mut external_http_link = false;
    for (name, raw_value) in attrs {
        let decoded = decode_entities(raw_value, true);
        let validated: Option<String> = match (namespace, tag, name.as_str()) {
            (TagNamespace::Html, "a", "href") => {
                if let Some(normalized) = normalize_safe_href(&decoded) {
                    if let Some(fragment) = normalized.strip_prefix('#') {
                        if fragment.is_empty() {
                            Some("#".to_string())
                        } else if fragment.starts_with("fn-") {
                            Some(normalized)
                        } else {
                            Some(format!("#fn-{fragment}"))
                        }
                    } else {
                        if normalized.starts_with("http://") || normalized.starts_with("https://") {
                            external_http_link = true;
                        }
                        Some(normalized)
                    }
                } else {
                    Some("#".to_string())
                }
            }
            (TagNamespace::Html, "a" | "img", "title") | (TagNamespace::Html, "img", "alt") => {
                Some(decoded)
            }
            (TagNamespace::Html, "img", "src") => is_safe_image_src(&decoded).then(|| {
                decoded
                    .trim_matches(|c: char| c.is_ascii_whitespace())
                    .to_string()
            }),
            (TagNamespace::Html, "code", "data-lang") => {
                let valid = decoded.len() <= 64
                    && decoded.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'+' | b'#' | b'.')
                    });
                valid.then_some(decoded)
            }
            (TagNamespace::Html, "ol", "start") => {
                let valid = !decoded.is_empty()
                    && decoded.len() <= 10
                    && decoded.bytes().all(|b| b.is_ascii_digit());
                valid.then_some(decoded)
            }
            (TagNamespace::Html, "p", "class") => {
                filter_allowed_classes(&decoded, &["preview-note"])
            }
            (TagNamespace::Html, "blockquote", "class") => filter_allowed_classes(
                &decoded,
                &[
                    "markdown-alert",
                    "markdown-alert-note",
                    "markdown-alert-tip",
                    "markdown-alert-important",
                    "markdown-alert-warning",
                    "markdown-alert-caution",
                ],
            ),
            (TagNamespace::Html, "sup", "class") => filter_allowed_classes(
                &decoded,
                &["footnote-reference", "footnote-definition-label"],
            ),
            (TagNamespace::Html, "div", "class") => {
                filter_allowed_classes(&decoded, &["footnote-definition"])
            }
            (TagNamespace::Html, "div", "id") => is_safe_footnote_id(&decoded).then(|| {
                if decoded.starts_with("fn-") {
                    decoded
                } else {
                    format!("fn-{decoded}")
                }
            }),
            (TagNamespace::Html, "math", "display") => match decoded.as_str() {
                "inline" | "block" => Some(decoded),
                _ => None,
            },
            (TagNamespace::MathMl, _, "displaystyle") => match decoded.as_str() {
                "true" | "false" => Some(decoded),
                _ => None,
            },
            (TagNamespace::MathMl, _, "scriptlevel") => match decoded.as_str() {
                "0" | "1" | "2" => Some(decoded),
                _ => None,
            },
            (TagNamespace::MathMl, _, "class") => filter_allowed_classes(&decoded, MATHML_CLASSES),
            (TagNamespace::MathMl, "mi", "mathvariant") => (decoded == "normal").then_some(decoded),
            (
                TagNamespace::MathMl,
                "mo",
                "stretchy" | "symmetric" | "largeop" | "movablelimits",
            ) => match decoded.as_str() {
                "true" | "false" => Some(decoded),
                _ => None,
            },
            (TagNamespace::MathMl, "mspace", "width") => {
                is_safe_math_dimension(&decoded, true).then_some(decoded)
            }
            (TagNamespace::MathMl, "mo", "minsize" | "maxsize")
            | (TagNamespace::MathMl, "mspace", "height" | "depth")
            | (TagNamespace::MathMl, "mfrac", "linethickness") => {
                is_safe_math_dimension(&decoded, false).then_some(decoded)
            }
            _ => None,
        };

        if let Some(value) = validated {
            out.push(' ');
            out.push_str(name);
            out.push_str("=\"");
            push_escaped_attr(out, &value);
            out.push('"');
        }
    }
    if external_http_link {
        out.push_str(" target=\"_blank\" rel=\"noopener noreferrer\"");
    }
}

const MATHML_CLASSES: &[&str] = &[
    "ml-alignlike",
    "ml-align",
    "ml-with-eqn",
    "ml-arraylike",
    "ml-cells-left",
    "ml-cells-right",
    "ml-cases",
    "ml-multline",
    "ml-left-solid",
    "ml-right-solid",
    "ml-left-dashed",
    "ml-right-dashed",
    "ml-border-only",
    "ml-hline",
    "ml-hdashline",
    "ml-nonumber",
    "ml-cell-left",
    "ml-cell-right",
    "ml-negated",
    "ml-small",
    "ml-box",
];

fn filter_allowed_classes(raw: &str, allowed: &[&str]) -> Option<String> {
    let kept: Vec<&str> = raw
        .split_ascii_whitespace()
        .filter(|token| allowed.contains(token))
        .collect();
    (!kept.is_empty()).then(|| kept.join(" "))
}

fn is_safe_math_dimension(value: &str, allow_negative: bool) -> bool {
    if value.is_empty() || value.len() > 20 {
        return false;
    }
    let rest = if let Some(stripped) = value.strip_prefix('-') {
        if !allow_negative {
            return false;
        }
        stripped
    } else {
        value
    };
    let unit = ["em", "ex", "mm", "cm", "in", "pt", "pc", "px", "%"]
        .into_iter()
        .find(|u| rest.ends_with(u));
    let Some(unit) = unit else {
        return false;
    };
    let Some(max) = math_dimension_unit_max(unit) else {
        return false;
    };
    let num = &rest[..rest.len() - unit.len()];
    if num.is_empty() {
        return false;
    }
    let digits_valid = match num.split_once('.') {
        Some((int, frac)) => {
            !int.is_empty()
                && !frac.is_empty()
                && int.bytes().all(|b| b.is_ascii_digit())
                && frac.bytes().all(|b| b.is_ascii_digit())
        }
        None => num.bytes().all(|b| b.is_ascii_digit()),
    };
    if !digits_valid {
        return false;
    }
    num.parse::<f64>()
        .is_ok_and(|parsed| parsed.is_finite() && parsed >= 0.0 && parsed <= max)
}

fn emit_sanitized_text(out: &mut String, text: &str) {
    let decoded = decode_entities(text, false);
    push_escaped_text(out, &decoded);
}

/// Decode common HTML character references so attribute validators cannot be bypassed by entity
/// encoding (e.g. `&#x6a;avascript:` or `javascript&colon;`).
fn decode_entities(input: &str, aggressive_attr: bool) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            let start = i;
            i += 1;
            while i < bytes.len() && bytes[i] != b'&' {
                i += 1;
            }
            out.push_str(&input[start..i]);
            continue;
        }
        if let Some((decoded, consumed)) = parse_entity(&input[i..], aggressive_attr) {
            out.push(decoded);
            i += consumed;
        } else {
            out.push('&');
            i += 1;
        }
    }
    out
}

fn parse_entity(s: &str, aggressive_attr: bool) -> Option<(char, usize)> {
    let rest = s.strip_prefix('&')?;
    if let Some(num) = rest.strip_prefix('#') {
        let (radix, digits_str, prefix_len) =
            if let Some(hex) = num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
                (16, hex, 3)
            } else {
                (10, num, 2)
            };
        let digit_len = digits_str
            .bytes()
            .take_while(|b| {
                if radix == 16 {
                    b.is_ascii_hexdigit()
                } else {
                    b.is_ascii_digit()
                }
            })
            .count();
        if digit_len == 0 {
            return None;
        }
        let has_semi = digits_str.as_bytes().get(digit_len) == Some(&b';');
        if !has_semi && !aggressive_attr {
            return None;
        }
        let code = u32::from_str_radix(&digits_str[..digit_len], radix).ok()?;
        let ch = match code {
            0 => '\u{FFFD}',
            c => char::from_u32(c).unwrap_or('\u{FFFD}'),
        };
        let consumed = prefix_len + digit_len + usize::from(has_semi);
        return Some((ch, consumed));
    }

    let name_len = rest
        .bytes()
        .take_while(u8::is_ascii_alphabetic)
        .count()
        .min(16);
    if name_len == 0 {
        return None;
    }
    let has_semi = rest.as_bytes().get(name_len) == Some(&b';');
    if !has_semi {
        return None;
    }
    let name = &rest[..name_len];
    let ch = match name {
        "amp" | "AMP" => '&',
        "lt" | "LT" => '<',
        "gt" | "GT" => '>',
        "quot" | "QUOT" => '"',
        "apos" => '\'',
        "nbsp" => '\u{00A0}',
        _ if aggressive_attr && name.eq_ignore_ascii_case("colon") => ':',
        _ if aggressive_attr && name.eq_ignore_ascii_case("tab") => '\t',
        _ if aggressive_attr && name.eq_ignore_ascii_case("newline") => '\n',
        _ => return None,
    };
    Some((ch, 1 + name_len + 1))
}
