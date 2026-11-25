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
                    depth = depth
                        .checked_add(1)
                        .ok_or_else(|| "excessive span nesting in highlighted output".to_string())?;
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
                let valid = if let Some(rest) = entity.strip_prefix(b"#x").or_else(|| entity.strip_prefix(b"#X")) {
                    !rest.is_empty() && rest.iter().all(u8::is_ascii_hexdigit)
                } else if let Some(rest) = entity.strip_prefix(b"#") {
                    !rest.is_empty() && rest.iter().all(u8::is_ascii_digit)
                } else {
                    !entity.is_empty() && entity.iter().all(u8::is_ascii_alphanumeric)
                };
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

/// Whether `url` is an allowed inline image `data:image/` URL with no ASCII control characters.
pub(super) fn is_safe_image_src(url: &str) -> bool {
    let trimmed = url.trim_matches(|c: char| c.is_ascii_whitespace());
    if trimmed.is_empty() || trimmed.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    trimmed.to_ascii_lowercase().starts_with("data:image/")
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
    for c in text.chars() {
        push_escaped_char(out, c);
    }
}

/// `text` escaped for HTML, in elements and attributes.
pub(super) fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Strict allowlist HTML/MathML sanitizer over rendered Markdown HTML (defense-in-depth).
///
/// Only permits safe Markdown HTML tags, safe MathML Core tags (exclusively inside `<math>`),
/// and explicitly validated attributes. Drops comments, declarations, processing instructions,
/// dangerous subtrees (`<script>`, `<style>`, `<iframe>`, `<svg>`, `<object>`, `<form>`, etc.),
/// `style`, `ping`, `on*` handlers, unsafe URL schemes, and non-allowlisted CSS classes.
pub(super) fn sanitize_html(input: &str) -> String {
    const MAX_STACK_DEPTH: usize = 256;

    let bytes = input.as_bytes();
    let mut i = 0;
    let mut out = String::with_capacity(input.len());
    let mut open_stack: Vec<&'static str> = Vec::new();
    let mut drop_stack: Vec<String> = Vec::new();
    let mut math_depth: usize = 0;

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

        // Comment: <!-- ... -->
        if bytes[i..].starts_with(b"<!--") {
            if let Some(end) = find_subslice(&bytes[i + 4..], b"-->") {
                i += 4 + end + 3;
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
            if let Some(end) = bytes[i + 2..].iter().position(|&b| b == b'>') {
                i += 2 + end + 1;
            } else {
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
            let Some(gt_rel) = bytes[name_end..].iter().position(|&b| b == b'>') else {
                break;
            };
            let next_i = name_end + gt_rel + 1;
            let name = input[name_start..name_end].to_ascii_lowercase();
            i = next_i;

            if !drop_stack.is_empty() {
                if let Some(pos) = drop_stack.iter().rposition(|open| open == &name) {
                    drop_stack.truncate(pos);
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

        let Some((tag_name, attrs, self_closing, next_i)) = parse_start_tag(input, i) else {
            // Unclosed tag: drop remaining bytes if dropping subtree, otherwise escape `<`.
            if drop_stack.is_empty() {
                out.push_str("&lt;");
            }
            i += 1;
            continue;
        };
        i = next_i;

        if !drop_stack.is_empty() {
            if !self_closing && drop_stack.last().is_some_and(|top| top == &tag_name) {
                drop_stack.push(tag_name);
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
                drop_stack.push(tag_name);
            }
            continue;
        }

        // Namespace-separated tag allowlist.
        let allowed = if math_depth > 0 {
            canonical_mathml_tag(&tag_name)
        } else {
            canonical_html_tag(&tag_name)
        };
        let Some(canon_tag) = allowed else {
            continue;
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
        emit_sanitized_attrs(&mut out, canon_tag, &attrs);
        if void_tag {
            out.push_str(" />");
        } else if math_depth > 0 && self_closing {
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

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn is_tag_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b':' | b'_')
}

type ParsedStartTag = (String, Vec<(String, String)>, bool, usize);

fn parse_start_tag(input: &str, start: usize) -> Option<ParsedStartTag> {
    let bytes = input.as_bytes();
    let mut i = start + 1;
    let name_start = i;
    while i < bytes.len() && is_tag_name_byte(bytes[i]) {
        i += 1;
    }
    if i == name_start {
        return None;
    }
    let tag_name = input[name_start..i].to_ascii_lowercase();
    let mut attrs: Vec<(String, String)> = Vec::new();
    let mut self_closing = false;

    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
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
            i += 1;
        }
        if i == attr_start {
            i += 1;
            continue;
        }
        let attr_name = input[attr_start..i].to_ascii_lowercase();

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let value = if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= bytes.len() {
                return None;
            }
            match bytes[i] {
                b'"' | b'\'' => {
                    let quote = bytes[i];
                    i += 1;
                    let val_start = i;
                    let rel_end = bytes[i..].iter().position(|&b| b == quote)?;
                    let val = input[val_start..val_start + rel_end].to_string();
                    i = val_start + rel_end + 1;
                    val
                }
                _ => {
                    let val_start = i;
                    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                        i += 1;
                    }
                    let mut val_end = i;
                    if val_end > val_start
                        && bytes.get(val_end) == Some(&b'>')
                        && bytes[val_end - 1] == b'/'
                    {
                        val_end -= 1;
                        self_closing = true;
                    }
                    input[val_start..val_end].to_string()
                }
            }
        } else {
            String::new()
        };

        // Keep only the first occurrence of each attribute name (matching HTML5 parsing rules).
        if !attrs.iter().any(|(existing, _)| existing == &attr_name) {
            attrs.push((attr_name, value));
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
    matches!(
        tag,
        "script"
            | "style"
            | "title"
            | "textarea"
            | "xmp"
            | "iframe"
            | "noembed"
            | "noframes"
            | "noscript"
    )
}

fn is_void_drop_tag(tag: &str) -> bool {
    matches!(
        tag,
        "embed"
            | "base"
            | "meta"
            | "link"
            | "frame"
            | "param"
            | "source"
            | "track"
            | "area"
            | "col"
            | "wbr"
            | "keygen"
            | "menuitem"
    )
}

fn is_container_drop_tag(tag: &str) -> bool {
    matches!(
        tag,
        "svg"
            | "object"
            | "form"
            | "template"
            | "applet"
            | "frameset"
            | "audio"
            | "video"
            | "select"
            | "button"
            | "canvas"
            | "portal"
    )
}

fn canonical_html_tag(tag: &str) -> Option<&'static str> {
    Some(match tag {
        "h1" => "h1",
        "h2" => "h2",
        "h3" => "h3",
        "h4" => "h4",
        "h5" => "h5",
        "h6" => "h6",
        "p" => "p",
        "blockquote" => "blockquote",
        "pre" => "pre",
        "code" => "code",
        "ul" => "ul",
        "ol" => "ol",
        "li" => "li",
        "dl" => "dl",
        "dt" => "dt",
        "dd" => "dd",
        "hr" => "hr",
        "br" => "br",
        "em" => "em",
        "strong" => "strong",
        "del" => "del",
        "sub" => "sub",
        "sup" => "sup",
        "span" => "span",
        "div" => "div",
        "a" => "a",
        "img" => "img",
        "table" => "table",
        "thead" => "thead",
        "tbody" => "tbody",
        "tr" => "tr",
        "th" => "th",
        "td" => "td",
        "input" => "input",
        "math" => "math",
        _ => return None,
    })
}

fn canonical_mathml_tag(tag: &str) -> Option<&'static str> {
    Some(match tag {
        "mrow" => "mrow",
        "mi" => "mi",
        "mn" => "mn",
        "mo" => "mo",
        "mtext" => "mtext",
        "mspace" => "mspace",
        "mfrac" => "mfrac",
        "msqrt" => "msqrt",
        "mroot" => "mroot",
        "msub" => "msub",
        "msup" => "msup",
        "msubsup" => "msubsup",
        "munder" => "munder",
        "mover" => "mover",
        "munderover" => "munderover",
        "mtable" => "mtable",
        "mtr" => "mtr",
        "mtd" => "mtd",
        _ => return None,
    })
}

fn emit_sanitized_attrs(out: &mut String, tag: &'static str, attrs: &[(String, String)]) {
    let mut external_http_link = false;
    for (name, raw_value) in attrs {
        let decoded = decode_entities(raw_value, true);
        let validated: Option<String> = match (tag, name.as_str()) {
            ("a", "href") => {
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
            ("a" | "img", "title") | ("img", "alt") => Some(decoded),
            ("img", "src") => {
                if is_safe_image_src(&decoded) {
                    Some(
                        decoded
                            .trim_matches(|c: char| c.is_ascii_whitespace())
                            .to_string(),
                    )
                } else {
                    Some(String::new())
                }
            }
            ("code", "data-lang") => {
                let valid = decoded.len() <= 64
                    && decoded.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'+' | b'#' | b'.')
                    });
                valid.then_some(decoded)
            }
            ("ol", "start") => {
                let valid = !decoded.is_empty()
                    && decoded.len() <= 10
                    && decoded.bytes().all(|b| b.is_ascii_digit());
                valid.then_some(decoded)
            }
            ("blockquote", "class") => filter_allowed_classes(
                &decoded,
                &[
                    "markdown-alert-note",
                    "markdown-alert-tip",
                    "markdown-alert-important",
                    "markdown-alert-warning",
                    "markdown-alert-caution",
                ],
            ),
            ("sup", "class") => filter_allowed_classes(
                &decoded,
                &["footnote-reference", "footnote-definition-label"],
            ),
            ("div", "class") => filter_allowed_classes(&decoded, &["footnote-definition"]),
            ("div", "id") => {
                let max_len = if decoded.starts_with("fn-") { 67 } else { 64 };
                let valid = !decoded.is_empty()
                    && decoded.len() <= max_len
                    && decoded
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
                valid.then(|| {
                    if decoded.starts_with("fn-") {
                        decoded
                    } else {
                        format!("fn-{decoded}")
                    }
                })
            }
            ("math", "display") => match decoded.as_str() {
                "inline" | "block" => Some(decoded),
                _ => None,
            },
            (
                "mrow" | "mi" | "mn" | "mo" | "mtext" | "mspace" | "mfrac" | "msqrt" | "mroot"
                | "msub" | "msup" | "msubsup" | "munder" | "mover" | "munderover" | "mtable"
                | "mtr" | "mtd",
                "displaystyle",
            ) => match decoded.as_str() {
                "true" | "false" => Some(decoded),
                _ => None,
            },
            (
                "mrow" | "mi" | "mn" | "mo" | "mtext" | "mspace" | "mfrac" | "msqrt" | "mroot"
                | "msub" | "msup" | "msubsup" | "munder" | "mover" | "munderover" | "mtable"
                | "mtr" | "mtd",
                "scriptlevel",
            ) => match decoded.as_str() {
                "0" | "1" | "2" => Some(decoded),
                _ => None,
            },
            (
                "mrow" | "mi" | "mn" | "mo" | "mtext" | "mspace" | "mfrac" | "msqrt" | "mroot"
                | "msub" | "msup" | "msubsup" | "munder" | "mover" | "munderover" | "mtable"
                | "mtr" | "mtd",
                "class",
            ) => filter_allowed_classes(&decoded, MATHML_CLASSES),
            ("mi", "mathvariant") => (decoded == "normal").then_some(decoded),
            ("mo", "stretchy" | "symmetric" | "largeop" | "movablelimits") => {
                match decoded.as_str() {
                    "true" | "false" => Some(decoded),
                    _ => None,
                }
            }
            ("mo", "minsize" | "maxsize")
            | ("mspace", "width" | "height" | "depth")
            | ("mfrac", "linethickness") => is_safe_math_dimension(&decoded).then_some(decoded),
            _ => None,
        };

        if let Some(value) = validated {
            out.push(' ');
            out.push_str(name);
            out.push_str("=\"");
            out.push_str(&escape(&value));
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

fn is_safe_math_dimension(value: &str) -> bool {
    if value.is_empty() || value.len() > 20 {
        return false;
    }
    let rest = value.strip_prefix('-').unwrap_or(value);
    let unit = ["em", "ex", "mm", "cm", "in", "pt", "pc", "px", "%"]
        .into_iter()
        .find(|u| rest.ends_with(u));
    let Some(unit) = unit else {
        return false;
    };
    let num = &rest[..rest.len() - unit.len()];
    if num.is_empty() {
        return false;
    }
    match num.split_once('.') {
        Some((int, frac)) => {
            !int.is_empty()
                && !frac.is_empty()
                && int.bytes().all(|b| b.is_ascii_digit())
                && frac.bytes().all(|b| b.is_ascii_digit())
        }
        None => num.bytes().all(|b| b.is_ascii_digit()),
    }
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
