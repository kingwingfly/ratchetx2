use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use ammonia::{Builder, UrlRelative};
use data_url::DataUrl;

/// Maximum encoded and decoded byte size allowed for inline Markdown `data:image/...;base64,` URLs.
const IMAGE_DATA_URL_MAX: usize = 2 * 1024 * 1024;
/// Maximum byte length allowed for `a[href]` values in the defense-in-depth sanitizer.
const HREF_MAX: usize = 4 * 1024;
/// Maximum byte length allowed for free-text attributes (`a[title]`, `img[title]`, `img[alt]`).
const ATTR_TEXT_MAX: usize = 1024;
/// Maximum text-node bytes between breaks when text contains `&` or `0xC2` (UTF-8 NBSP/Latin-1
/// prefix), preventing quadratic `memchr3` rescans in `html5ever 0.40`'s `HtmlSerializer`.
const ENTITY_RUN_SPLIT_BYTES: usize = 512;

const CLEAN_CONTENT_TAGS: &[&str] = &[
    // Raw-text / script-capable / styling / form-input elements whose entire subtree is dropped.
    "applet", "audio", "button", "canvas", "form", "frameset", "iframe", "noembed", "noframes",
    "noscript", "object", "portal", "script", "select", "style", "svg", "template", "textarea",
    "title", "video", "xmp",
];

const HTML_TAGS: &[&str] = &[
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
];

const MATHML_TAGS: &[&str] = &[
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
];

const BLOCKQUOTE_ALERT_CLASSES: &[&str] = &[
    "markdown-alert",
    "markdown-alert-note",
    "markdown-alert-tip",
    "markdown-alert-important",
    "markdown-alert-warning",
    "markdown-alert-caution",
];

const SUP_FOOTNOTE_CLASSES: &[&str] = &["footnote-reference", "footnote-definition-label"];

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

static SANITIZER: LazyLock<Builder<'static>> = LazyLock::new(build_sanitizer);

#[cfg(test)]
pub(super) fn tag_tables_are_sorted() -> bool {
    [CLEAN_CONTENT_TAGS, HTML_TAGS, MATHML_TAGS]
        .into_iter()
        .all(|table| table.windows(2).all(|w| w[0] < w[1]))
}

fn is_html_tag(tag: &str) -> bool {
    HTML_TAGS.binary_search(&tag).is_ok()
}

fn is_mathml_tag(tag: &str) -> bool {
    MATHML_TAGS.binary_search(&tag).is_ok()
}

fn is_mathml_text_integration_point(tag: &str) -> bool {
    matches!(tag, "mi" | "mn" | "mo" | "mtext")
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
fn push_escaped_attr(out: &mut String, text: &str) {
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

fn is_safe_footnote_id(id: &str) -> bool {
    let max_chars = if id.starts_with("fn-") { 67 } else { 64 };
    !id.is_empty()
        && id.len() <= 256
        && id.chars().count() <= max_chars
        && id
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

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

fn clamp_utf8_prefix(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn filter_attribute<'a>(element: &str, attribute: &str, value: &'a str) -> Option<Cow<'a, str>> {
    match (element, attribute) {
        ("a", "href") => {
            if let Some(normalized) =
                normalize_safe_href(value).filter(|normalized| normalized.len() <= HREF_MAX)
            {
                if let Some(fragment) = normalized.strip_prefix('#') {
                    if fragment.is_empty() {
                        Some(Cow::Borrowed("#"))
                    } else if fragment.starts_with("fn-") {
                        Some(Cow::Owned(normalized))
                    } else {
                        Some(Cow::Owned(format!("#fn-{fragment}")))
                    }
                } else {
                    Some(Cow::Owned(normalized))
                }
            } else {
                Some(Cow::Borrowed("#"))
            }
        }
        ("a" | "img", "title") | ("img", "alt") => {
            Some(Cow::Borrowed(clamp_utf8_prefix(value, ATTR_TEXT_MAX)))
        }
        ("img", "src") => is_safe_image_src(value)
            .then(|| Cow::Borrowed(value.trim_matches(|c: char| c.is_ascii_whitespace()))),
        ("input", "type") => value
            .trim_matches(|c: char| c.is_ascii_whitespace())
            .eq_ignore_ascii_case("checkbox")
            .then_some(Cow::Borrowed("checkbox")),
        ("input", "checked" | "disabled") => Some(Cow::Borrowed("")),
        ("code", "data-lang") => {
            let valid = value.len() <= 64
                && value.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'+' | b'#' | b'.')
                });
            valid.then_some(Cow::Borrowed(value))
        }
        ("ol", "start") => {
            let valid =
                !value.is_empty() && value.len() <= 10 && value.bytes().all(|b| b.is_ascii_digit());
            valid.then_some(Cow::Borrowed(value))
        }
        ("p", "class") => filter_allowed_classes(value, &["preview-note"]).map(Cow::Owned),
        ("blockquote", "class") => {
            filter_allowed_classes(value, BLOCKQUOTE_ALERT_CLASSES).map(Cow::Owned)
        }
        ("sup", "class") => filter_allowed_classes(value, SUP_FOOTNOTE_CLASSES).map(Cow::Owned),
        ("div", "class") => filter_allowed_classes(value, &["footnote-definition"]).map(Cow::Owned),
        ("div", "id") => is_safe_footnote_id(value).then(|| {
            if value.starts_with("fn-") {
                Cow::Borrowed(value)
            } else {
                Cow::Owned(format!("fn-{value}"))
            }
        }),
        ("math", "display") => matches!(value, "inline" | "block").then_some(Cow::Borrowed(value)),
        (tag, "class") if is_mathml_tag(tag) => {
            filter_allowed_classes(value, MATHML_CLASSES).map(Cow::Owned)
        }
        (tag, "displaystyle") if is_mathml_tag(tag) => {
            matches!(value, "true" | "false").then_some(Cow::Borrowed(value))
        }
        (tag, "scriptlevel") if is_mathml_tag(tag) => {
            matches!(value, "0" | "1" | "2").then_some(Cow::Borrowed(value))
        }
        ("mi", "mathvariant") => (value == "normal").then_some(Cow::Borrowed(value)),
        ("mo", "stretchy" | "symmetric" | "largeop" | "movablelimits") => {
            matches!(value, "true" | "false").then_some(Cow::Borrowed(value))
        }
        ("mspace", "width") => is_safe_math_dimension(value, true).then_some(Cow::Borrowed(value)),
        ("mo", "minsize" | "maxsize")
        | ("mspace", "height" | "depth")
        | ("mfrac", "linethickness") => {
            is_safe_math_dimension(value, false).then_some(Cow::Borrowed(value))
        }
        _ => None,
    }
}

fn build_sanitizer() -> Builder<'static> {
    let mut tags: HashSet<&'static str> =
        HashSet::with_capacity(HTML_TAGS.len() + MATHML_TAGS.len());
    tags.extend(HTML_TAGS.iter().copied());
    tags.extend(MATHML_TAGS.iter().copied());

    let clean_content_tags: HashSet<&'static str> = CLEAN_CONTENT_TAGS.iter().copied().collect();

    let mut tag_attributes: HashMap<&'static str, HashSet<&'static str>> = HashMap::new();
    tag_attributes.insert("a", HashSet::from(["href", "title"]));
    tag_attributes.insert("img", HashSet::from(["src", "alt", "title"]));
    tag_attributes.insert("input", HashSet::from(["type", "checked", "disabled"]));
    tag_attributes.insert("code", HashSet::from(["data-lang"]));
    tag_attributes.insert("ol", HashSet::from(["start"]));
    tag_attributes.insert("div", HashSet::from(["id"]));
    tag_attributes.insert("math", HashSet::from(["display"]));
    for &tag in MATHML_TAGS {
        let mut attrs = HashSet::from(["displaystyle", "scriptlevel"]);
        match tag {
            "mi" => {
                attrs.insert("mathvariant");
            }
            "mo" => {
                attrs.extend([
                    "stretchy",
                    "symmetric",
                    "largeop",
                    "movablelimits",
                    "minsize",
                    "maxsize",
                ]);
            }
            "mspace" => {
                attrs.extend(["width", "height", "depth"]);
            }
            "mfrac" => {
                attrs.insert("linethickness");
            }
            _ => {}
        }
        tag_attributes.insert(tag, attrs);
    }

    let mut allowed_classes: HashMap<&'static str, HashSet<&'static str>> = HashMap::new();
    allowed_classes.insert("p", HashSet::from(["preview-note"]));
    allowed_classes.insert(
        "blockquote",
        BLOCKQUOTE_ALERT_CLASSES.iter().copied().collect(),
    );
    allowed_classes.insert("sup", SUP_FOOTNOTE_CLASSES.iter().copied().collect());
    allowed_classes.insert("div", HashSet::from(["footnote-definition"]));
    let mathml_class_set: HashSet<&'static str> = MATHML_CLASSES.iter().copied().collect();
    for &tag in MATHML_TAGS {
        allowed_classes.insert(tag, mathml_class_set.clone());
    }

    let mut builder = Builder::empty();
    builder
        .tags(tags)
        .clean_content_tags(clean_content_tags)
        .generic_attributes(HashSet::new())
        .tag_attributes(tag_attributes)
        .allowed_classes(allowed_classes)
        .url_schemes(HashSet::from(["http", "https", "mailto", "data"]))
        .url_relative(UrlRelative::PassThrough)
        .link_rel(None)
        .strip_comments(true)
        .attribute_filter(filter_attribute);
    builder
}

/// Strict allowlist HTML/MathML sanitizer over rendered Markdown HTML (defense-in-depth).
///
/// Uses `ammonia` (`html5ever` HTML5 parser/serializer) for tag/attribute allowlisting,
/// comment/declaration/subtree removal, and entity normalization, followed by a narrow pass over
/// ammonia's canonical output enforcing:
/// 1. Conditional `target="_blank" rel="noopener noreferrer"` on `http(s)` links only (never on
///    `mailto:` or `#fn-` fragments), plus `href="#"` fallback if ammonia stripped an unsafe link.
/// 2. Task-list `<input type="checkbox" disabled>` only (dropping arbitrary `<input>` elements).
/// 3. Strict MathML namespace and text-integration isolation (no MathML tags outside `<math>`,
///    and no HTML/foreign child tags inside `<mi>`, `<mn>`, `<mo>`, or `<mtext>`).
pub(super) fn sanitize_html(input: &str) -> String {
    let prepared = break_long_entity_text_runs(input);
    let cleaned = SANITIZER.clean(&prepared).to_string();
    postprocess_ammonia_html(&cleaned)
}

fn find_html5_comment_close(after_open: &str) -> Option<usize> {
    if after_open.starts_with('>') {
        return Some(1);
    }
    if after_open.starts_with("->") {
        return Some(2);
    }
    let bytes = after_open.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'-' && bytes[i + 1] == b'-' {
            if bytes[i + 2] == b'>' {
                return Some(i + 3);
            }
            if bytes[i + 2] == b'!' && bytes.get(i + 3) == Some(&b'>') {
                return Some(i + 4);
            }
        }
        i += 1;
    }
    None
}

fn is_opaque_container_tag(tag_lower: &str) -> bool {
    matches!(
        tag_lower,
        "script"
            | "style"
            | "textarea"
            | "title"
            | "xmp"
            | "iframe"
            | "noembed"
            | "noframes"
            | "noscript"
            | "svg"
    )
}

/// Find the byte offset immediately after a case-insensitive closing tag `</{tag_lower}...>`
/// inside `rest`.
fn find_closing_tag_end(rest: &str, tag_lower: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    let tlen = tag_lower.len();
    let mut pos = 0;
    while let Some(rel) = rest[pos..].find("</") {
        let start = pos + rel;
        let name_start = start + 2;
        let name_end = name_start + tlen;
        if name_end <= bytes.len()
            && rest[name_start..name_end].eq_ignore_ascii_case(tag_lower)
            && matches!(
                bytes.get(name_end),
                Some(b'>' | b'/' | b' ' | b'\t' | b'\n' | b'\r' | b'\x0C')
            )
        {
            return rest[name_end..].find('>').map(|gt| name_end + gt + 1);
        }
        pos = name_start;
    }
    None
}

/// Scan from `<` (`tag_start`) to the byte immediately after the matching `>`, ignoring `>`
/// inside single- or double-quoted attribute values. Returns `None` if unclosed before EOF.
fn find_start_tag_end(input: &str, tag_start: usize) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut i = tag_start + 1;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(i + 1),
            None => {}
        }
        i += 1;
    }
    None
}

/// Split long HTML Data-state text runs containing `&` or `0xC2` into `<= ENTITY_RUN_SPLIT_BYTES`
/// chunks separated by empty HTML comments (`<!---->`).
///
/// `html5ever 0.40`'s `HtmlSerializer::write_escaped` runs `memchr3(quote, '<', '>', slice)` over
/// the entire remaining text node before checking for `&` / `0xC2`, which degrades to `O(n^2)` on
/// large text nodes full of `&` or NBSP (`\u{00A0}`). Because `ammonia` strips comments while
/// leaving the adjacent `NodeData::Text` siblings unmerged, splitting at `&` / `0xC2` boundaries
/// keeps serialization strictly `O(n)` with byte-for-byte identical output.
///
/// Comments, declarations, tags, `<plaintext>`, and rawtext/RCDATA/SVG containers are copied
/// verbatim so HTML5 tokenization and tree construction are never perturbed.
fn break_long_entity_text_runs(input: &str) -> Cow<'_, str> {
    if input.len() <= ENTITY_RUN_SPLIT_BYTES
        || !input.as_bytes().iter().any(|&b| b == b'&' || b == 0xC2)
    {
        return Cow::Borrowed(input);
    }

    let mut out: Option<String> = None;
    let mut i = 0usize;

    while i < input.len() {
        let text_end = input[i..].find('<').map_or(input.len(), |off| i + off);
        let text = &input[i..text_end];
        if text.len() > ENTITY_RUN_SPLIT_BYTES {
            let bytes = text.as_bytes();
            let mut last_break = 0usize;
            for (j, &b) in bytes.iter().enumerate() {
                if (b == b'&' || b == 0xC2) && j - last_break >= ENTITY_RUN_SPLIT_BYTES {
                    let buf = out.get_or_insert_with(|| {
                        let mut s = String::with_capacity(input.len() + input.len() / 64);
                        s.push_str(&input[..i]);
                        s
                    });
                    buf.push_str(&text[last_break..j]);
                    buf.push_str("<!---->");
                    last_break = j;
                }
            }
            if let Some(buf) = out.as_mut() {
                buf.push_str(&text[last_break..]);
            }
        } else if let Some(buf) = out.as_mut() {
            buf.push_str(text);
        }

        i = text_end;
        if i >= input.len() {
            break;
        }

        // Handle markup starting at `<`.
        let rest = &input[i..];
        if let Some(after_comment) = rest.strip_prefix("<!--") {
            let next = match find_html5_comment_close(after_comment) {
                Some(end) => i + 4 + end,
                None => input.len(),
            };
            if let Some(buf) = out.as_mut() {
                buf.push_str(&input[i..next]);
            }
            i = next;
            continue;
        }

        let second = rest.as_bytes().get(1).copied();
        if matches!(second, Some(b'!' | b'?')) {
            let next = rest.find('>').map_or(input.len(), |gt| i + gt + 1);
            if let Some(buf) = out.as_mut() {
                buf.push_str(&input[i..next]);
            }
            i = next;
            continue;
        }

        if second == Some(b'/') {
            let next = rest.find('>').map_or(input.len(), |gt| i + gt + 1);
            if let Some(buf) = out.as_mut() {
                buf.push_str(&input[i..next]);
            }
            i = next;
            continue;
        }

        if second.is_some_and(|b| b.is_ascii_alphabetic()) {
            let name_end = rest[1..]
                .bytes()
                .position(|b| !b.is_ascii_alphanumeric() && b != b'-')
                .map_or(rest.len(), |off| 1 + off);
            let tag_name = &rest[1..name_end];
            let Some(tag_end) = find_start_tag_end(input, i) else {
                if let Some(buf) = out.as_mut() {
                    buf.push_str(rest);
                }
                break;
            };
            let tag_lower = tag_name.to_ascii_lowercase();
            if tag_lower == "plaintext" {
                if let Some(buf) = out.as_mut() {
                    buf.push_str(rest);
                }
                break;
            }
            if is_opaque_container_tag(&tag_lower) {
                let after_open = &input[tag_end..];
                let close_end = find_closing_tag_end(after_open, &tag_lower);
                // Inside `<script>`, `<!--` can enter Script Data Escaped state where `</script>`
                // might not close the element; bail out verbatim to preserve exact HTML5 semantics.
                let script_has_comment = tag_lower == "script"
                    && close_end
                        .map_or(after_open, |end| &after_open[..end])
                        .contains("<!--");
                let next = match (close_end, script_has_comment) {
                    (Some(end), false) => tag_end + end,
                    _ => input.len(),
                };
                if let Some(buf) = out.as_mut() {
                    buf.push_str(&input[i..next]);
                }
                i = next;
                continue;
            }
            if let Some(buf) = out.as_mut() {
                buf.push_str(&input[i..tag_end]);
            }
            i = tag_end;
            continue;
        }

        // Stray `<` not opening a tag (e.g. `a < b`).
        if let Some(buf) = out.as_mut() {
            buf.push('<');
        }
        i += 1;
    }

    match out {
        Some(s) => Cow::Owned(s),
        None => Cow::Borrowed(input),
    }
}

/// Iterate `name="value"` attributes inside an ammonia-serialized start tag slice.
fn parse_canonical_attrs(mut attrs_slice: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    while !attrs_slice.is_empty() {
        attrs_slice = attrs_slice.trim_start_matches(' ');
        if attrs_slice.is_empty() {
            break;
        }
        let Some(eq) = attrs_slice.find("=\"") else {
            break;
        };
        let name = &attrs_slice[..eq];
        let rest = &attrs_slice[eq + 2..];
        let Some(end_quote) = rest.find('"') else {
            break;
        };
        let value = &rest[..end_quote];
        out.push((name, value));
        attrs_slice = &rest[end_quote + 1..];
    }
    out
}

/// Emit a text segment from ammonia's `HtmlSerializer`, restoring `HtmlSerializer`'s `&nbsp;`
/// back to U+00A0 without touching `&amp;nbsp;`.
fn push_canonical_text(out: &mut String, text: &str) {
    if !text.contains("&nbsp;") {
        out.push_str(text);
        return;
    }
    let mut rest = text;
    while let Some(pos) = rest.find("&nbsp;") {
        out.push_str(&rest[..pos]);
        out.push('\u{00A0}');
        rest = &rest[pos + 6..];
    }
    out.push_str(rest);
}

/// Scan from `<` (`tag_start`) in `html5ever`-serialized canonical HTML to the index of the
/// closing `>`, ignoring any `>` inside double-quoted attribute values (`"..."`).
fn find_canonical_tag_end(cleaned: &str, tag_start: usize) -> Option<usize> {
    let bytes = cleaned.as_bytes();
    let mut in_quote = false;
    let mut i = tag_start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_quote = !in_quote,
            b'>' if !in_quote => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Narrow post-pass over `ammonia`'s canonical `html5ever`-serialized output.
pub(super) fn postprocess_ammonia_html(cleaned: &str) -> String {
    let mut out = String::with_capacity(cleaned.len() + 64);
    let mut i = 0;
    let mut in_math = false;
    let mut suppressed_math_depth: usize = 0;
    let mut open_math: Vec<&str> = Vec::new();
    let mut suppressed_tip_depth: usize = 0;

    while i < cleaned.len() {
        let Some(rel_lt) = cleaned[i..].find('<') else {
            push_canonical_text(&mut out, &cleaned[i..]);
            break;
        };
        if rel_lt > 0 {
            push_canonical_text(&mut out, &cleaned[i..i + rel_lt]);
        }
        let tag_start = i + rel_lt;
        let Some(tag_end) = find_canonical_tag_end(cleaned, tag_start) else {
            push_canonical_text(&mut out, &cleaned[tag_start..]);
            break;
        };
        let inside = &cleaned[tag_start + 1..tag_end];
        i = tag_end + 1;

        if let Some(close_name) = inside.strip_prefix('/') {
            let tag = close_name.trim();
            if in_math {
                if tag == "math" {
                    if suppressed_math_depth > 0 {
                        suppressed_math_depth -= 1;
                    } else {
                        while let Some(popped) = open_math.pop() {
                            out.push_str("</");
                            out.push_str(popped);
                            out.push('>');
                        }
                        suppressed_tip_depth = 0;
                        in_math = false;
                        out.push_str("</math>");
                    }
                } else if open_math
                    .last()
                    .is_some_and(|&top| is_mathml_text_integration_point(top))
                {
                    // Inside a MathML text integration point, only its own outer closing tag is
                    // emitted; nested same-tag closers decrement `suppressed_tip_depth`, and any
                    // stripped HTML/MathML child closing tags are dropped.
                    if open_math.last() == Some(&tag) {
                        if suppressed_tip_depth > 0 {
                            suppressed_tip_depth -= 1;
                        } else {
                            open_math.pop();
                            out.push_str("</");
                            out.push_str(tag);
                            out.push('>');
                        }
                    }
                } else if is_mathml_tag(tag)
                    && let Some(pos) = open_math.iter().rposition(|&open| open == tag)
                {
                    while open_math.len() > pos {
                        let popped = open_math.pop().expect("non-empty");
                        out.push_str("</");
                        out.push_str(popped);
                        out.push('>');
                    }
                }
            } else if is_html_tag(tag) && tag != "math" {
                out.push_str("</");
                out.push_str(tag);
                out.push('>');
            }
            continue;
        }

        let (tag, attrs_str) = match inside.find(' ') {
            Some(sp) => (&inside[..sp], &inside[sp..]),
            None => (inside, ""),
        };

        if in_math {
            // Suppress any nested `<math>` inside an active `<math>` (including inside text
            // integration points) so its closing `</math>` can never close the outer `<math>`.
            if tag == "math" {
                suppressed_math_depth += 1;
                continue;
            }
            // Inside MathML text integration points (`mi`, `mn`, `mo`, `mtext`), drop all child
            // tags while preserving their text content to prevent HTML-in-MathML differentials.
            if let Some(&top) = open_math.last()
                && is_mathml_text_integration_point(top)
            {
                if tag == top {
                    suppressed_tip_depth += 1;
                }
                continue;
            }
            if is_mathml_tag(tag) {
                if tag == "mspace" && cleaned[i..].starts_with("</mspace>") {
                    i += "</mspace>".len();
                    out.push_str("<mspace");
                    out.push_str(attrs_str);
                    out.push_str(" />");
                } else {
                    open_math.push(tag);
                    out.push('<');
                    out.push_str(tag);
                    out.push_str(attrs_str);
                    out.push('>');
                }
            }
            continue;
        }

        match tag {
            "math" => {
                in_math = true;
                out.push_str("<math");
                out.push_str(attrs_str);
                out.push('>');
            }
            "input" => {
                let attrs = parse_canonical_attrs(attrs_str);
                let is_checkbox = attrs.iter().any(|&(k, v)| k == "type" && v == "checkbox");
                if is_checkbox {
                    let checked = attrs.iter().any(|&(k, _)| k == "checked");
                    out.push_str("<input disabled=\"\" type=\"checkbox\"");
                    if checked {
                        out.push_str(" checked=\"\"");
                    }
                    out.push_str(" />");
                }
            }
            "a" => {
                let attrs = parse_canonical_attrs(attrs_str);
                let href = attrs.iter().find(|&&(k, _)| k == "href").map(|&(_, v)| v);
                out.push_str("<a");
                match href {
                    None => {
                        // Ammonia stripped a disallowed scheme (e.g. `javascript:`) before
                        // `attribute_filter`; neutralize to `#`.
                        out.push_str(" href=\"#\"");
                        out.push_str(attrs_str);
                    }
                    Some(url) if url.starts_with("http://") || url.starts_with("https://") => {
                        out.push_str(attrs_str);
                        out.push_str(" target=\"_blank\" rel=\"noopener noreferrer\"");
                    }
                    Some(_) => {
                        out.push_str(attrs_str);
                    }
                }
                out.push('>');
            }
            "br" | "hr" | "img" => {
                out.push('<');
                out.push_str(tag);
                out.push_str(attrs_str);
                out.push_str(" />");
            }
            _ if is_html_tag(tag) => {
                out.push('<');
                out.push_str(tag);
                out.push_str(attrs_str);
                out.push('>');
            }
            _ => {}
        }
    }

    if in_math {
        while let Some(popped) = open_math.pop() {
            out.push_str("</");
            out.push_str(popped);
            out.push('>');
        }
        out.push_str("</math>");
    }

    out
}
