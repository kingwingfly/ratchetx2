//! File previews for the E2EE chat web client. The page starts a dedicated worker when it first
//! needs a preview engine, keeping the engine and its work off the page's thread.
//!
//! [`Worker`], [`language`], [`audio::Tags`] and the Rust request and response types in [`rpc`]
//! are available with default features. The `rpc` feature adds the JavaScript codec for both
//! sides of the worker protocol. Each engine and the worker runtime have their own feature.
//!
//! - `pdf` draws PDF pages with hayro.
//! - `audio` reads audio tags and covers with lofty.
//! - `search` searches text with regular expressions in linear time.
//! - `diagram` draws Mermaid diagrams as SVG with merman.
//! - `markdown` renders Markdown, MathML, and reveal.js slides with pulldown-cmark, pulldown-latex, and ammonia.
//! - `code` highlights source with tree-sitter and arborium's grammars.
//! - `worker` serves the page's requests and includes the `rpc` codec.
//!
//! A worker posts [`READY`] once it listens. The page sends `[id, method, ...arguments]`.
//! The worker replies with `[id, true, value]` or `[id, false, error_string]`.

pub mod audio;
#[cfg(any(
    feature = "code-web",
    feature = "code-systems",
    feature = "code-apps",
    feature = "code-scripts",
))]
pub mod code;
#[cfg(feature = "diagram")]
pub mod diagram;
pub mod language;
#[cfg(feature = "markdown")]
pub mod markdown;
#[cfg(feature = "pdf")]
pub mod pdf;
pub mod rpc;
#[cfg(feature = "search")]
pub mod search;
pub mod sniff;
#[cfg(feature = "worker")]
pub mod worker;

pub use rpc::WorkerService;

use language::Group;

/// What a worker says once it listens.
pub const READY: &str = "ready";

/// Strictly validate highlighted HTML output in O(N): only balanced `<span class="hl-[a-z0-9_-]+">`
/// and `</span>` tags plus bounded entity-escaped text (no raw `<`, `>`, or malformed/overlong `&`
/// entities).
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

/// The workers, by what they do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Worker {
    /// `open(bytes)` returns a document ID and its page sizes in points. `render(document,
    /// page, width)` returns `[width, height, RGBA pixels]` at the requested width subject to
    /// the side and area limits. `close(document)` releases the document.
    Pdf,
    /// `svg(source)`: the Mermaid diagram `source`, as SVG.
    Diagram,
    /// `markdown(source)` returns sanitized HTML; `slides(source)` returns columns of slide HTML.
    Markdown,
    /// `find(text, pattern, case, regex)`: the matches of `pattern` in `text`, `[[start, end,
    /// ...], more]`, in UTF-16 code units, or else why the pattern is invalid.
    Search,
    /// `tags(bytes)`: what the audio file's tags say of it, `[title, artist, album, year, cover's
    /// MIME type, cover]`, each null if they do not say, or null if it has none.
    Audio,
    /// `highlight(language, text)`: `text`, highlighted as `language`, by its name in
    /// [`language::LANGUAGES`], as HTML.
    Code(Group),
}

impl Worker {
    /// The logical key for this worker in the page's `<meta name="e2ee-worker-manifest">`.
    pub fn key(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Diagram => "diagram",
            Self::Markdown => "markdown",
            Self::Audio => "audio",
            Self::Search => "search",
            Self::Code(Group::Web) => "code_web",
            Self::Code(Group::Systems) => "code_systems",
            Self::Code(Group::Apps) => "code_apps",
            Self::Code(Group::Scripts) => "code_scripts",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn worker_keys_are_unique_and_canonical() {
        let all = [
            (Worker::Pdf, "pdf"),
            (Worker::Diagram, "diagram"),
            (Worker::Markdown, "markdown"),
            (Worker::Audio, "audio"),
            (Worker::Search, "search"),
            (Worker::Code(Group::Web), "code_web"),
            (Worker::Code(Group::Systems), "code_systems"),
            (Worker::Code(Group::Apps), "code_apps"),
            (Worker::Code(Group::Scripts), "code_scripts"),
        ];
        let mut seen = HashSet::new();
        for (worker, expected) in all {
            assert_eq!(worker.key(), expected);
            assert!(seen.insert(expected));
        }
    }

    #[test]
    fn validate_highlight_html_accepts_valid_and_rejects_malicious() {
        assert!(validate_highlight_html("").is_ok());
        assert!(
            validate_highlight_html(
                r#"<span class="hl-keyword">fn</span> <span class="hl-function_name">f</span>(&amp;&lt;&gt;&quot;&apos;&#39;&#x27;)"#
            )
            .is_ok()
        );
        for bad in [
            "<script>alert(1)</script>",
            r#"<span class="hl-keyword" onclick="alert(1)">fn</span>"#,
            r#"<span class="other">fn</span>"#,
            r#"<span class="hl-">fn</span>"#,
            r#"<span class="hl-Bad">fn</span>"#,
            r#"<span class="hl-keyword">unclosed"#,
            "</span>",
            "a < b",
            "a > b",
            "a & b",
            "a &unknown; b",
            "a &#1234567890123; b",
        ] {
            assert!(
                validate_highlight_html(bad).is_err(),
                "expected rejection for {bad}"
            );
        }
    }
}
