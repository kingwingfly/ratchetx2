//! Code highlighted by tree-sitter, with arborium's grammars and highlight queries, as HTML:
//! escaped text in spans whose classes name what it is, e.g. `hl-keyword` or `hl-string`.
//!
//! [`web`], [`systems`], [`apps`] and [`scripts`] each highlight a [`Group`] of languages, and
//! link only their grammars, so that each worker takes only its own.

use std::sync::Arc;

use arborium::advanced::{CompiledGrammar, GrammarConfig};
use arborium::{Config, GrammarStore, Highlighter, HtmlFormat};

use crate::Worker;
use crate::rpc::{Method, Request, Response, WorkerService};

#[cfg(doc)]
use crate::language::Group;

/// Maximum input byte length highlighted by [`Code::highlight`] (1,000,000 bytes).
pub use crate::rpc::HIGHLIGHT_MAX;

/// The grammar of a language, by its name, if one of a group's.
type Grammars = fn(&str) -> Option<GrammarConfig<'static>>;
/// Embedded languages within the same group that `name` may inject during highlighting.
type Embeds = fn(&str) -> &'static [&'static str];

/// A highlighter of a group of languages whose grammars are compiled lazily on demand.
pub struct Code {
    names: &'static [&'static str],
    grammars: Grammars,
    embeds: Embeds,
    store: Arc<GrammarStore>,
    highlighter: Highlighter,
}

impl Code {
    fn new(names: &'static [&'static str], grammars: Grammars, embeds: Embeds) -> Self {
        let store = Arc::new(GrammarStore::new());
        let config = Config {
            html_format: HtmlFormat::ClassNamesWithPrefix("hl".to_string()),
            ..Config::default()
        };
        Self {
            names,
            grammars,
            embeds,
            highlighter: Highlighter::with_store_and_config(store.clone(), config),
            store,
        }
    }

    /// Lazily compile `name` and any embedded target grammars belonging to this group,
    /// propagating query compilation errors rather than silently ignoring them.
    fn ensure_compiled(&self, name: &str, visiting: &mut Vec<&'static str>) -> Result<(), String> {
        let Some(&canonical) = self.names.iter().find(|&&n| n == name) else {
            return Err(format!("unsupported language: {name}"));
        };
        if visiting.contains(&canonical) {
            return Ok(());
        }
        visiting.push(canonical);
        if self.store.get(canonical).is_none() {
            let config = (self.grammars)(canonical)
                .ok_or_else(|| format!("unsupported language: {canonical}"))?;
            let grammar = CompiledGrammar::new(config)
                .map_err(|e| format!("failed to compile {canonical} grammar: {e}"))?;
            self.store.insert(canonical, Arc::new(grammar));
        }
        for &dep in (self.embeds)(canonical) {
            if self.names.contains(&dep) {
                self.ensure_compiled(dep, visiting)?;
            }
        }
        Ok(())
    }

    /// `text`, highlighted as the language `name`, bounded by [`HIGHLIGHT_MAX`] and strictly
    /// validated to contain only `<span class="hl-[a-z0-9_-]+">`, `</span>`, and escaped text.
    pub fn highlight(&mut self, name: &str, text: &str) -> Result<String, String> {
        if text.len() > HIGHLIGHT_MAX {
            return Err("the file is too large to highlight".to_string());
        }
        self.ensure_compiled(name, &mut Vec::new())?;
        let html = self
            .highlighter
            .highlight(name, text)
            .map_err(|e| e.to_string())?;
        validate_highlight_html(&html)?;
        Ok(html)
    }
}

impl WorkerService for Code {
    fn accepts(&self, method: Method) -> bool {
        method.is_served_by(Worker::Code(crate::language::Group::Web))
    }

    fn handle(&mut self, req: Request) -> Result<Response, String> {
        match req {
            Request::Highlight { language, text } => {
                self.highlight(&language, &text).map(Response::Highlighted)
            }
            other => Err(format!("no method {}", other.method().as_str())),
        }
    }
}

/// Strictly validate highlighted HTML output in O(N): only balanced `<span class="hl-[a-z0-9_-]+">`
/// and `</span>` tags plus entity-escaped text (no raw `<`, `>`, or malformed `&` entities).
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
                    if depth == 0 {
                        return Err("unexpected closing span in highlighted HTML".to_string());
                    }
                    depth -= 1;
                    i += CLOSE_TAG.len();
                } else if bytes[i..].starts_with(OPEN_PREFIX) {
                    i += OPEN_PREFIX.len();
                    let name_start = i;
                    while i < bytes.len()
                        && (bytes[i].is_ascii_lowercase()
                            || bytes[i].is_ascii_digit()
                            || bytes[i] == b'_'
                            || bytes[i] == b'-')
                    {
                        i += 1;
                    }
                    if i == name_start || !bytes[i..].starts_with(b"\">") {
                        return Err("invalid highlight span tag in HTML".to_string());
                    }
                    depth += 1;
                    i += 2;
                } else {
                    return Err("disallowed tag in highlighted HTML".to_string());
                }
            }
            b'>' => {
                return Err("unescaped '>' in highlighted HTML".to_string());
            }
            b'&' => {
                let rest = &bytes[i + 1..];
                let Some(semi) = rest.iter().position(|&b| b == b';') else {
                    return Err("unescaped '&' in highlighted HTML".to_string());
                };
                let entity = &rest[..semi];
                let valid = matches!(entity, b"amp" | b"lt" | b"gt" | b"quot" | b"apos")
                    || (entity.len() >= 2
                        && entity[0] == b'#'
                        && entity[1..].iter().all(u8::is_ascii_digit))
                    || (entity.len() >= 3
                        && entity[0] == b'#'
                        && matches!(entity[1], b'x' | b'X')
                        && entity[2..].iter().all(u8::is_ascii_hexdigit));
                if !valid {
                    return Err("invalid HTML entity in highlighted HTML".to_string());
                }
                i += semi + 2;
            }
            _ => i += 1,
        }
    }

    if depth != 0 {
        return Err("unclosed span in highlighted HTML".to_string());
    }
    Ok(())
}

/// A function returning the [`Code`] of the languages it lists, by name and arborium's crate,
/// which links only their grammars.
macro_rules! group {
    (
        $(#[$meta:meta])*
        $group:ident:
        grammars { $($name:literal => $krate:ident),+ $(,)? }
        embeds { $($emb_from:literal => [$($emb_to:literal),* $(,)?]),* $(,)? }
    ) => {
        $(#[$meta])*
        pub fn $group() -> Code {
            Code::new(
                &[$($name),+],
                |name| match name {
                    $($name => Some(GrammarConfig {
                        language: $krate::language().into(),
                        highlights_query: &$krate::HIGHLIGHTS_QUERY,
                        injections_query: $krate::INJECTIONS_QUERY,
                        locals_query: $krate::LOCALS_QUERY,
                    }),)+
                    _ => None,
                },
                |name| match name {
                    $($emb_from => &[$($emb_to),*],)*
                    _ => &[],
                },
            )
        }
    };
}

group!(
    #[cfg(feature = "code-web")]
    /// [`Group::Web`]'s languages, with JSDoc, which JavaScript's comments embed.
    web:
    grammars {
        "javascript" => arborium_javascript,
        "jsdoc" => arborium_jsdoc,
        "typescript" => arborium_typescript,
        "tsx" => arborium_tsx,
        "json" => arborium_json,
        "html" => arborium_html,
        "css" => arborium_css,
        "scss" => arborium_scss,
        "vue" => arborium_vue,
        "xml" => arborium_xml,
        "markdown" => arborium_markdown,
        "yaml" => arborium_yaml,
        "toml" => arborium_toml,
        "php" => arborium_php,
        "sql" => arborium_sql,
    }
    embeds {
        "html" => ["css", "javascript"],
        "javascript" => ["jsdoc"],
        "typescript" => ["jsdoc"],
        "tsx" => ["jsdoc"],
        "vue" => ["css", "scss", "javascript", "typescript", "tsx"],
        "markdown" => ["yaml", "toml", "html"],
        "php" => ["html"],
    }
);

group!(
    #[cfg(feature = "code-systems")]
    /// [`Group::Systems`]' languages.
    systems:
    grammars {
        "rust" => arborium_rust,
        "c" => arborium_c,
        "cpp" => arborium_cpp,
        "go" => arborium_go,
        "zig" => arborium_zig,
        "bash" => arborium_bash,
        "make" => arborium_make,
        "dockerfile" => arborium_dockerfile,
        "nix" => arborium_nix,
        "diff" => arborium_diff,
        "proto" => arborium_proto,
        "lua" => arborium_lua,
        "ini" => arborium_ini,
    }
    embeds {
        "make" => ["bash"],
        "nix" => ["bash"],
        "lua" => ["c"],
    }
);

group!(
    #[cfg(feature = "code-apps")]
    /// [`Group::Apps`]' languages.
    apps:
    grammars {
        "java" => arborium_java,
        "kotlin" => arborium_kotlin,
        "scala" => arborium_scala,
        "c-sharp" => arborium_c_sharp,
        "swift" => arborium_swift,
        "dart" => arborium_dart,
    }
    embeds {}
);

group!(
    #[cfg(feature = "code-scripts")]
    /// [`Group::Scripts`]' languages.
    scripts:
    grammars {
        "python" => arborium_python,
        "ruby" => arborium_ruby,
        "elixir" => arborium_elixir,
        "haskell" => arborium_haskell,
        "ocaml" => arborium_ocaml,
        "julia" => arborium_julia,
    }
    embeds {
        "elixir" => ["python"],
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(
        feature = "code-web",
        feature = "code-systems",
        feature = "code-apps",
        feature = "code-scripts"
    ))]
    #[test]
    fn every_language_highlights_in_its_group() {
        use crate::language::{Group, LANGUAGES};

        fn code(group: Group) -> Code {
            match group {
                Group::Web => web(),
                Group::Systems => systems(),
                Group::Apps => apps(),
                Group::Scripts => scripts(),
            }
        }

        for group in Group::ALL {
            let mut code = code(group);
            for language in LANGUAGES.iter().filter(|l| l.group == group) {
                assert!(
                    code.highlight(language.name, "x").is_ok(),
                    "{} in {group:?}",
                    language.name
                );
            }
            // Every grammar's queries compile when its group's languages are highlighted.
            for name in code.names {
                assert!(code.store.get(name).is_some(), "{name}'s queries");
            }
        }
    }

    #[cfg(feature = "code-systems")]
    #[test]
    fn spans_line_up_after_wide_characters() {
        let html = systems()
            .highlight("rust", "// héllo 世界 😀\nfn main() { let s = \"wörld\"; }")
            .unwrap();
        assert!(
            html.contains(r#"<span class="hl-keyword">fn</span>"#),
            "{html}"
        );
        assert!(
            html.contains(r#"<span class="hl-string">&quot;wörld&quot;</span>"#),
            "{html}"
        );
    }

    #[cfg(feature = "code-web")]
    #[test]
    fn text_is_escaped() {
        let html = web()
            .highlight("html", "<script>alert(1)</script> &amp;")
            .unwrap();
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;"), "{html}");
    }

    #[cfg(feature = "code-web")]
    #[test]
    fn embedded_languages_highlight() {
        let html = web()
            .highlight("html", "<script>const x = 1;</script>")
            .unwrap();
        assert!(
            html.contains(r#"<span class="hl-keyword">const</span>"#),
            "{html}"
        );
    }

    #[cfg(feature = "code-web")]
    #[test]
    fn lazy_compilation_loads_only_requested_grammar_and_its_embeds() {
        let mut code = web();
        assert!(code.highlight("json", r#"{"a": 1}"#).is_ok());
        assert!(code.store.get("json").is_some());
        assert!(code.store.get("typescript").is_none());
        assert!(code.store.get("html").is_none());
        assert!(code.store.get("vue").is_none());

        assert!(
            code.highlight("html", "<script>const x = 1;</script>")
                .is_ok()
        );
        assert!(code.store.get("html").is_some());
        assert!(code.store.get("css").is_some());
        assert!(code.store.get("javascript").is_some());
        assert!(code.store.get("jsdoc").is_some());
        assert!(code.store.get("vue").is_none());
        assert!(code.store.get("php").is_none());
    }

    #[cfg(feature = "code-apps")]
    #[test]
    fn other_groups_languages_do_not() {
        assert!(apps().highlight("rust", "fn main() {}").is_err());
    }

    #[cfg(feature = "code-systems")]
    #[test]
    fn highlight_enforces_input_size_cap() {
        let huge = "x".repeat(HIGHLIGHT_MAX + 1);
        assert!(systems().highlight("rust", &huge).is_err());
    }

    #[cfg(feature = "code-systems")]
    #[test]
    fn query_compile_errors_are_surfaced() {
        let mut broken = Code::new(
            &["broken"],
            |name| {
                (name == "broken").then(|| GrammarConfig {
                    language: arborium_rust::language().into(),
                    highlights_query: "(not_a_real_node_type_xyz) @keyword",
                    injections_query: "",
                    locals_query: "",
                })
            },
            |_| &[],
        );
        assert!(broken.highlight("broken", "fn main() {}").is_err());
        assert!(broken.store.get("broken").is_none());
    }

    #[test]
    fn validate_highlight_html_accepts_valid_and_rejects_malicious() {
        assert!(validate_highlight_html("").is_ok());
        assert!(
            validate_highlight_html(
                r#"<span class="hl-keyword">fn</span> <span class="hl-function_name">f</span>(&amp;&lt;&gt;&quot;&#39;&#x27;)"#
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
        ] {
            assert!(
                validate_highlight_html(bad).is_err(),
                "expected rejection for {bad}"
            );
        }
    }

    #[cfg(feature = "code-systems")]
    #[test]
    fn code_worker_service_dispatches_and_rejects_other_methods() {
        let mut code = systems();
        assert!(code.accepts(Method::Highlight));
        assert!(!code.accepts(Method::Svg));
        let Response::Highlighted(html) = code
            .handle(Request::Highlight {
                language: "rust".into(),
                text: "let x = 1;".into(),
            })
            .unwrap()
        else {
            panic!("expected Highlighted");
        };
        assert!(html.contains(r#"<span class="hl-keyword">let</span>"#));
        assert!(code.handle(Request::Close { doc_id: 1 }).is_err());
    }
}
