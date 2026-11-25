//! Mermaid diagrams as SVG, laid out and drawn by merman, in Mermaid's dark theme. Rendered SVGs
//! are bounded in source/output size, dimension-clamped, and verified free of active content or
//! remote resource references.

use merman::model::resources::InputResourceLimitId;
use merman::svg::{RenderResourcePolicy, ResourceLimitId, SvgPipeline, SvgPipelinePreset};
use merman::{
    MermaidEngine, OperationControl, RenderOutput, RenderRequest, Renderer,
    SourcePresentationConfig, SvgEnvironment, SvgRequest,
};

use crate::Worker;
use crate::rpc::{Method, Request, Response, WorkerService};

/// Maximum Mermaid source length accepted (64 KiB).
pub use crate::rpc::DIAGRAM_SOURCE_MAX as MAX_SOURCE_BYTES;
/// Maximum rendered SVG byte length returned (2 MiB).
pub use crate::rpc::DIAGRAM_SVG_MAX as MAX_SVG_BYTES;
/// Maximum finite width or height applied to an SVG from its `viewBox`.
pub const MAX_VIEWBOX_DIMENSION: f64 = 8192.0;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
const OPERATION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

fn operation_control() -> OperationControl {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        OperationControl::new().with_deadline(OPERATION_DEADLINE)
    }
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        OperationControl::new()
    }
}

/// Reusable Mermaid SVG renderer implementing [`WorkerService`].
pub struct DiagramService {
    renderer: Renderer,
    request_template: SvgRequest,
}

impl Default for DiagramService {
    fn default() -> Self {
        Self::new()
    }
}

impl DiagramService {
    pub fn new() -> Self {
        let policy = RenderResourcePolicy::constrained()
            .with_limit(
                ResourceLimitId::Input(InputResourceLimitId::MaxSourceBytes),
                MAX_SOURCE_BYTES,
            )
            .expect("MAX_SOURCE_BYTES is a valid resource limit")
            .with_limit(ResourceLimitId::MaxSvgBytes, MAX_SVG_BYTES)
            .expect("MAX_SVG_BYTES is a valid resource limit");
        let theme = SourcePresentationConfig::from_value(serde_json::json!({
            "theme": "dark",
            "htmlLabels": false,
            "flowchart": { "htmlLabels": false },
            "securityLevel": "strict"
        }));
        let renderer = Renderer::new()
            .with_presentation_engine(MermaidEngine::new().with_site_config(theme))
            .with_resource_policy(*policy.input_policy());
        let request_template = SvgRequest {
            environment: SvgEnvironment::deterministic().with_resource_policy(policy),
            pipeline: Some(SvgPipeline::from_preset(SvgPipelinePreset::ResvgSafe)),
            ..SvgRequest::default()
        };
        Self {
            renderer,
            request_template,
        }
    }

    /// Render the Mermaid diagram `source` as a validated, sized SVG.
    pub fn svg(&self, source: &str) -> Result<String, String> {
        if source.len() > MAX_SOURCE_BYTES {
            return Err("the diagram is too large".to_string());
        }
        let request =
            RenderRequest::svg(source, operation_control(), self.request_template.clone());
        let raw = match self.renderer.render(request) {
            Ok(RenderOutput::Svg(Some(svg))) => svg,
            Ok(_) => return Err("not a Mermaid diagram".to_string()),
            Err(e) => return Err(e.to_string()),
        };
        if raw.svg().len() > MAX_SVG_BYTES {
            return Err("the rendered diagram is too large".to_string());
        }
        let output = sized(raw.svg())?;
        if output.len() > MAX_SVG_BYTES {
            return Err("the rendered diagram is too large".to_string());
        }
        validate_safe_svg(&output)?;
        Ok(output)
    }
}

impl WorkerService for DiagramService {
    fn accepts(&self, method: Method) -> bool {
        method.is_served_by(Worker::Diagram)
    }

    fn handle(&mut self, req: Request) -> Result<Response, String> {
        match req {
            Request::Svg(source) => self.svg(&source).map(Response::Svg),
            other => Err(format!("no method {}", other.method().as_str())),
        }
    }
}

/// The Mermaid diagram `source`, as SVG, sized as it is drawn.
pub fn svg(source: &str) -> Result<String, String> {
    DiagramService::new().svg(source)
}

#[derive(Debug, Clone, Copy)]
struct ParsedAttr<'a> {
    /// Span covering leading whitespace + `name="value"` inside the start tag body.
    full_start: usize,
    full_end: usize,
    name: &'a str,
    value: &'a str,
}

/// Locate the `<svg ...>` start tag (skipping XML prologs, comments, and DOCTYPE declarations),
/// returning `(tag_open_index, attrs_start, attrs_end, tag_close_end, self_closing)`.
fn find_svg_start_tag(svg: &str) -> Option<(usize, usize, usize, usize, bool)> {
    let bytes = svg.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'<' {
            return None;
        }
        if bytes[i..].starts_with(b"<!--") {
            let close = svg[i + 4..].find("-->")?;
            i = i + 4 + close + 3;
            continue;
        }
        if bytes[i..].starts_with(b"<?") {
            let close = svg[i + 2..].find("?>")?;
            i = i + 2 + close + 2;
            continue;
        }
        if bytes[i..].starts_with(b"<!") {
            // Skip <!DOCTYPE ...> respecting quotes and optional `[...]` internal subset.
            i += 2;
            let mut quote: Option<u8> = None;
            let mut bracket_depth = 0usize;
            while i < bytes.len() {
                let b = bytes[i];
                if let Some(q) = quote {
                    if b == q {
                        quote = None;
                    }
                } else {
                    match b {
                        b'"' | b'\'' => quote = Some(b),
                        b'[' => bracket_depth += 1,
                        b']' => bracket_depth = bracket_depth.saturating_sub(1),
                        b'>' if bracket_depth == 0 => {
                            i += 1;
                            break;
                        }
                        _ => {}
                    }
                }
                i += 1;
            }
            continue;
        }
        // Opening element tag: check if it is `<svg` (or `<svg:...`? Root must be `svg`).
        let name_start = i + 1;
        let mut name_end = name_start;
        while name_end < bytes.len()
            && !bytes[name_end].is_ascii_whitespace()
            && bytes[name_end] != b'>'
            && bytes[name_end] != b'/'
        {
            name_end += 1;
        }
        let name = &svg[name_start..name_end];
        if !name.eq_ignore_ascii_case("svg") {
            return None;
        }
        // Scan until unquoted `>`.
        let mut j = name_end;
        let mut quote: Option<u8> = None;
        while j < bytes.len() {
            let b = bytes[j];
            if let Some(q) = quote {
                if b == q {
                    quote = None;
                }
            } else if b == b'"' || b == b'\'' {
                quote = Some(b);
            } else if b == b'>' {
                break;
            }
            j += 1;
        }
        if j >= bytes.len() || quote.is_some() {
            return None;
        }
        // Detect trailing `/` before `>` (ignoring whitespace before `/`).
        let mut content_end = j;
        while content_end > name_end && bytes[content_end - 1].is_ascii_whitespace() {
            content_end -= 1;
        }
        let self_closing = content_end > name_end && bytes[content_end - 1] == b'/';
        let attrs_end = if self_closing { content_end - 1 } else { j };
        return Some((i, name_end, attrs_end, j + 1, self_closing));
    }
    None
}

/// Parse attributes within a tag's attribute slice `attrs`, returning their exact spans.
fn parse_attributes(attrs: &str) -> Result<Vec<ParsedAttr<'_>>, String> {
    let bytes = attrs.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let full_start = i;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'/'
            && bytes[i] != b'>'
        {
            i += 1;
        }
        let name = &attrs[name_start..i];
        if name.is_empty() {
            return Err("malformed SVG attribute".to_string());
        }
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let value = if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= bytes.len() {
                return Err("unterminated SVG attribute".to_string());
            }
            let quote = bytes[i];
            if quote == b'"' || quote == b'\'' {
                i += 1;
                let val_start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                if i >= bytes.len() {
                    return Err("unterminated quoted SVG attribute".to_string());
                }
                let val = &attrs[val_start..i];
                i += 1;
                val
            } else {
                let val_start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                &attrs[val_start..i]
            }
        } else {
            ""
        };
        out.push(ParsedAttr {
            full_start,
            full_end: i,
            name,
            value,
        });
    }
    Ok(out)
}

/// Parse and clamp a `viewBox` attribute's width and height, requiring finite positive numbers
/// bounded by [`MAX_VIEWBOX_DIMENSION`].
fn parse_viewbox_dimensions(view: &str) -> Result<(f64, f64), String> {
    let numbers: Vec<f64> = view
        .split(|c: char| c.is_ascii_whitespace() || c == ',')
        .filter(|n| !n.is_empty())
        .map(|n| n.parse::<f64>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid diagram viewBox".to_string())?;
    let [min_x, min_y, width, height]: [f64; 4] = numbers
        .try_into()
        .map_err(|_| "invalid diagram viewBox".to_string())?;
    if !min_x.is_finite()
        || !min_y.is_finite()
        || !width.is_finite()
        || !height.is_finite()
        || width <= 0.0
        || height <= 0.0
    {
        return Err("invalid diagram viewBox dimensions".to_string());
    }
    if width <= MAX_VIEWBOX_DIMENSION && height <= MAX_VIEWBOX_DIMENSION {
        return Ok((width, height));
    }
    let scale = MAX_VIEWBOX_DIMENSION / width.max(height);
    let sw = width * scale;
    let sh = height * scale;
    if sw.is_finite() && sh.is_finite() && sw > 0.0 && sh > 0.0 {
        Ok((sw.min(MAX_VIEWBOX_DIMENSION), sh.min(MAX_VIEWBOX_DIMENSION)))
    } else {
        Ok((
            width.min(MAX_VIEWBOX_DIMENSION),
            height.min(MAX_VIEWBOX_DIMENSION),
        ))
    }
}

/// `svg` with the width and height of its view box, in place of a width of 100% that fills what
/// it is in: as an image, that leaves it no size of its own.
fn sized(svg: &str) -> Result<String, String> {
    let Some((_, attrs_start, attrs_end, tag_close_end, self_closing)) = find_svg_start_tag(svg)
    else {
        return Ok(svg.to_string());
    };
    let attrs_slice = &svg[attrs_start..attrs_end];
    let attrs = parse_attributes(attrs_slice)?;
    let Some(view_attr) = attrs.iter().find(|a| a.name == "viewBox") else {
        return Ok(svg.to_string());
    };
    let (width, height) = parse_viewbox_dimensions(view_attr.value)?;

    let mut rebuilt = String::with_capacity(svg.len() + 32);
    rebuilt.push_str(&svg[..attrs_start]);
    let mut cursor = 0usize;
    for attr in &attrs {
        if matches!(attr.name, "width" | "height" | "style") {
            rebuilt.push_str(&attrs_slice[cursor..attr.full_start]);
            cursor = attr.full_end;
        }
    }
    rebuilt.push_str(&attrs_slice[cursor..]);
    while rebuilt.ends_with(|c: char| c.is_ascii_whitespace()) {
        rebuilt.pop();
    }
    rebuilt.push_str(&format!(r#" width="{width}" height="{height}""#));
    if self_closing {
        rebuilt.push_str("/>");
    } else {
        rebuilt.push('>');
    }
    rebuilt.push_str(&svg[tag_close_end..]);
    Ok(rebuilt)
}

/// Decode basic XML character references (`&#...;`, `&#x...;`, and common named entities) so
/// obfuscated schemes like `&#106;avascript:` cannot evade safety checks.
fn decode_xml_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        if let Some(semi) = after.find(';') {
            let entity = &after[..semi];
            let decoded = if let Some(hex) = entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
            {
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
            } else if let Some(dec) = entity.strip_prefix('#') {
                dec.parse::<u32>().ok().and_then(char::from_u32)
            } else {
                match entity {
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    "colon" => Some(':'),
                    "tab" => Some('\t'),
                    "newline" => Some('\n'),
                    _ => None,
                }
            };
            if let Some(ch) = decoded {
                out.push(ch);
                rest = &after[semi + 1..];
                continue;
            }
        }
        out.push('&');
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Strip CSS comments (`/* ... */`) and lowercase for directive/URL inspection.
fn strip_css_comments_lower(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find("*/") {
            rest = &after[end + 2..];
        } else {
            rest = "";
            break;
        }
    }
    out.push_str(rest);
    out.to_ascii_lowercase()
}

/// Returns `true` if CSS/attribute text contains an `@import`, `javascript:`, `vbscript:`, or
/// remote `url(http...)` / `url(//...)` reference.
fn contains_unsafe_css_or_url(raw: &str) -> bool {
    let decoded = decode_xml_entities(raw);
    let stripped = strip_css_comments_lower(&decoded);
    let compact: String = stripped
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && !c.is_control())
        .collect();
    if compact.contains("javascript:")
        || compact.contains("vbscript:")
        || compact.contains("data:text/html")
        || compact.contains("@import")
        || compact.contains("expression(")
    {
        return true;
    }
    let mut search = compact.as_str();
    while let Some(pos) = search.find("url(") {
        let after = &search[pos + 4..];
        let trimmed = after.trim_start_matches(['"', '\'']);
        if trimmed.starts_with("http:")
            || trimmed.starts_with("https:")
            || trimmed.starts_with("//")
            || trimmed.starts_with("javascript:")
            || trimmed.starts_with("vbscript:")
            || trimmed.starts_with("data:text/html")
        {
            return true;
        }
        search = after;
    }
    false
}

/// Verify rendered SVG contains no `<script>`, `<foreignObject>`, `on*` event attributes,
/// `javascript:`/`vbscript:`/`data:text/html` URLs, remote `url(http...)`, or `@import` rules.
fn validate_safe_svg(svg: &str) -> Result<(), String> {
    if svg.len() > MAX_SVG_BYTES {
        return Err("the rendered diagram is too large".to_string());
    }
    let bytes = svg.as_bytes();
    let mut i = 0;
    let mut in_style = false;
    let mut style_start = 0usize;

    while i < bytes.len() {
        let Some(rel) = svg[i..].find('<') else {
            break;
        };
        let lt = i + rel;
        if bytes[lt..].starts_with(b"<!--") {
            let Some(close) = svg[lt + 4..].find("-->") else {
                return Err("unclosed XML comment in SVG".to_string());
            };
            i = lt + 4 + close + 3;
            continue;
        }
        if bytes[lt..].starts_with(b"<![CDATA[") {
            let Some(close) = svg[lt + 9..].find("]]>") else {
                return Err("unclosed CDATA section in SVG".to_string());
            };
            let cdata = &svg[lt + 9..lt + 9 + close];
            if in_style && contains_unsafe_css_or_url(cdata) {
                return Err("unsafe CSS directive or remote URL in SVG".to_string());
            }
            i = lt + 9 + close + 3;
            continue;
        }
        if bytes[lt..].starts_with(b"<?") {
            let Some(close) = svg[lt + 2..].find("?>") else {
                return Err("unclosed processing instruction in SVG".to_string());
            };
            i = lt + 2 + close + 2;
            continue;
        }
        if bytes[lt..].starts_with(b"<!") {
            let Some(close) = svg[lt + 2..].find('>') else {
                return Err("unclosed XML declaration in SVG".to_string());
            };
            i = lt + 2 + close + 1;
            continue;
        }

        // Find end of tag respecting single/double quotes.
        let mut j = lt + 1;
        let mut quote: Option<u8> = None;
        while j < bytes.len() {
            let b = bytes[j];
            if let Some(q) = quote {
                if b == q {
                    quote = None;
                }
            } else if b == b'"' || b == b'\'' {
                quote = Some(b);
            } else if b == b'>' {
                break;
            }
            j += 1;
        }
        if j >= bytes.len() || quote.is_some() {
            return Err("unclosed tag in SVG".to_string());
        }

        let is_closing = bytes.get(lt + 1) == Some(&b'/');
        let name_start = if is_closing { lt + 2 } else { lt + 1 };
        let mut name_end = name_start;
        while name_end < j && !bytes[name_end].is_ascii_whitespace() && bytes[name_end] != b'/' {
            name_end += 1;
        }
        let raw_tag = &svg[name_start..name_end];
        let local_tag = raw_tag.rsplit_once(':').map_or(raw_tag, |(_, local)| local);

        if is_closing {
            if in_style && local_tag.eq_ignore_ascii_case("style") {
                if contains_unsafe_css_or_url(&svg[style_start..lt]) {
                    return Err("unsafe CSS directive or remote URL in SVG".to_string());
                }
                in_style = false;
            }
            i = j + 1;
            continue;
        }

        if local_tag.eq_ignore_ascii_case("script")
            || local_tag.eq_ignore_ascii_case("foreignobject")
            || local_tag.eq_ignore_ascii_case("iframe")
            || local_tag.eq_ignore_ascii_case("object")
            || local_tag.eq_ignore_ascii_case("embed")
            || local_tag.eq_ignore_ascii_case("applet")
            || local_tag.eq_ignore_ascii_case("handler")
            || local_tag.eq_ignore_ascii_case("listener")
        {
            return Err(format!("disallowed <{local_tag}> element in SVG"));
        }

        let mut attrs_end = j;
        while attrs_end > name_end && bytes[attrs_end - 1].is_ascii_whitespace() {
            attrs_end -= 1;
        }
        let self_closing = attrs_end > name_end && bytes[attrs_end - 1] == b'/';
        if self_closing {
            attrs_end -= 1;
        }

        let attrs = parse_attributes(&svg[name_end..attrs_end])?;
        for attr in attrs {
            let local_attr = attr
                .name
                .rsplit_once(':')
                .map_or(attr.name, |(_, local)| local);
            if local_attr.len() > 2
                && local_attr[..2].eq_ignore_ascii_case("on")
                && local_attr[2..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(format!("disallowed event attribute `{}` in SVG", attr.name));
            }
            if contains_unsafe_css_or_url(attr.value) {
                return Err(format!("unsafe value in SVG attribute `{}`", attr.name));
            }
            if local_attr.eq_ignore_ascii_case("href") || local_attr.eq_ignore_ascii_case("src") {
                let decoded = decode_xml_entities(attr.value);
                let compact: String = decoded
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace() && !c.is_control())
                    .map(|c| c.to_ascii_lowercase())
                    .collect();
                if compact.starts_with("http:")
                    || compact.starts_with("https:")
                    || compact.starts_with("//")
                    || compact.starts_with("javascript:")
                    || compact.starts_with("vbscript:")
                    || compact.starts_with("data:text/html")
                {
                    return Err(format!(
                        "disallowed remote or active `{}` in SVG",
                        attr.name
                    ));
                }
            }
        }

        if local_tag.eq_ignore_ascii_case("style") && !self_closing {
            in_style = true;
            style_start = j + 1;
        }

        i = j + 1;
    }

    if in_style {
        return Err("unclosed <style> element in SVG".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_attr<'a>(svg: &'a str, name: &str) -> Option<&'a str> {
        let (_, attrs_start, attrs_end, _, _) = find_svg_start_tag(svg)?;
        parse_attributes(&svg[attrs_start..attrs_end])
            .ok()?
            .into_iter()
            .find(|a| a.name == name)
            .map(|a| a.value)
    }

    #[test]
    fn flowchart() {
        let svg = svg("flowchart LR\n  A[Alice] --> W[Worker] --> B[Bob]").unwrap();
        assert!(!svg[..svg.find('>').unwrap()].contains("100%"), "{svg}");
        assert!(root_attr(&svg, "width").is_some_and(|w| w.parse::<f64>().unwrap() > 100.0));
        assert!(root_attr(&svg, "height").is_some_and(|h| h.parse::<f64>().unwrap() > 10.0));
        assert!(svg.contains("Alice") && svg.contains("Bob"));
        assert!(!svg.to_ascii_lowercase().contains("<script"));
        assert!(!svg.to_ascii_lowercase().contains("<foreignobject"));
    }

    #[test]
    fn sequence_diagram() {
        assert!(svg("sequenceDiagram\n  Alice->>Bob: hi\n  Bob-->>Alice: hello").is_ok());
    }

    #[test]
    fn not_a_diagram() {
        assert!(svg("this is not mermaid").is_err());
    }

    #[test]
    fn rejects_oversized_source() {
        let huge = format!("flowchart LR\n{}", "A-->B\n".repeat(MAX_SOURCE_BYTES / 5));
        assert!(huge.len() > MAX_SOURCE_BYTES);
        assert!(svg(&huge).is_err());
    }

    #[test]
    fn sizes_from_the_view_box() {
        assert_eq!(
            sized(
                r#"<svg id="m" width="100%" style="max-width: 572px;" viewBox="0 0 572 61"><g/></svg>"#
            )
            .unwrap(),
            r#"<svg id="m" viewBox="0 0 572 61" width="572" height="61"><g/></svg>"#
        );
    }

    #[test]
    fn sized_handles_prolog_comments_quoted_gt_and_self_closing() {
        let with_prolog = concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            "\n<!-- leading comment -->\n",
            r#"<svg data-expr="a > b" width="100%" viewBox="0 0 320 180" />"#,
        );
        let out = sized(with_prolog).unwrap();
        assert_eq!(
            out,
            concat!(
                r#"<?xml version="1.0" encoding="UTF-8"?>"#,
                "\n<!-- leading comment -->\n",
                r#"<svg data-expr="a > b" viewBox="0 0 320 180" width="320" height="180"/>"#,
            )
        );
    }

    #[test]
    fn sized_validates_and_clamps_viewbox_dimensions() {
        for bad in [
            r#"<svg viewBox="0 0 NaN 100"/>"#,
            r#"<svg viewBox="0 0 inf 100"/>"#,
            r#"<svg viewBox="0 0 -10 100"/>"#,
            r#"<svg viewBox="0 0 0 100"/>"#,
            r#"<svg viewBox="0 0 100"/>"#,
        ] {
            assert!(sized(bad).is_err(), "expected error for {bad}");
        }

        let huge = sized(r#"<svg viewBox="0 0 16384 8192"><g/></svg>"#).unwrap();
        assert_eq!(root_attr(&huge, "width"), Some("8192"));
        assert_eq!(root_attr(&huge, "height"), Some("4096"));

        let extreme = sized(r#"<svg viewBox="0 0 1e300 1"><g/></svg>"#).unwrap();
        let w: f64 = root_attr(&extreme, "width").unwrap().parse().unwrap();
        let h: f64 = root_attr(&extreme, "height").unwrap().parse().unwrap();
        assert!(w.is_finite() && w > 0.0 && w <= MAX_VIEWBOX_DIMENSION);
        assert!(h.is_finite() && h > 0.0 && h <= MAX_VIEWBOX_DIMENSION);
    }

    #[test]
    fn validate_safe_svg_rejects_active_content_and_remote_urls() {
        assert!(
            validate_safe_svg(r##"<svg viewBox="0 0 10 10"><style>.a{fill:url(#g)}</style><use href="#g"/></svg>"##)
                .is_ok()
        );
        for unsafe_svg in [
            r#"<svg><script>alert(1)</script></svg>"#,
            r#"<svg><SCRIPT>alert(1)</SCRIPT></svg>"#,
            r#"<svg><foreignObject><div>hi</div></foreignObject></svg>"#,
            r#"<svg onload="alert(1)"></svg>"#,
            r#"<svg><rect onclick='alert(1)'/></svg>"#,
            r#"<svg><a href="javascript:alert(1)">x</a></svg>"#,
            r#"<svg><a xlink:href="&#106;avascript:alert(1)">x</a></svg>"#,
            r#"<svg><image href="https://evil.example/track.png"/></svg>"#,
            r#"<svg><style>@import url("https://evil.example/a.css");</style></svg>"#,
            r#"<svg><style>.a{background:url(http://evil.example/x.png)}</style></svg>"#,
            r#"<svg><rect style="fill: url(https://evil.example/x)"/></svg>"#,
        ] {
            assert!(
                validate_safe_svg(unsafe_svg).is_err(),
                "expected rejection for {unsafe_svg}"
            );
        }
    }

    #[test]
    fn diagram_service_reuses_renderer_and_dispatches() {
        let mut service = DiagramService::new();
        assert!(service.accepts(Method::Svg));
        assert!(!service.accepts(Method::Find));

        let Response::Svg(first) = service
            .handle(Request::Svg("flowchart LR\nA-->B".into()))
            .unwrap()
        else {
            panic!("expected Svg");
        };
        let Response::Svg(second) = service
            .handle(Request::Svg("sequenceDiagram\nA->>B: hi".into()))
            .unwrap()
        else {
            panic!("expected Svg");
        };
        assert!(first.contains("<svg"));
        assert!(second.contains("<svg"));
        assert!(service.handle(Request::Close { doc_id: 1 }).is_err());
    }
}
