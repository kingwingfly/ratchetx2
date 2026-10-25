//! Code highlighted by tree-sitter, with arborium's grammars and highlight queries, as HTML:
//! escaped text in spans whose classes name what it is, e.g. `hl-keyword` or `hl-string`.
//!
//! [`web`], [`systems`], [`apps`] and [`scripts`] each highlight a [`Group`] of languages, and
//! link only their grammars, so that each worker takes only its own.

use std::sync::Arc;

use arborium::advanced::{CompiledGrammar, GrammarConfig};
use arborium::{Config, GrammarStore, Highlighter, HtmlFormat};

#[cfg(doc)]
use crate::language::Group;

/// The grammar of a language, by its name, if one of a group's.
type Grammars = fn(&str) -> Option<GrammarConfig<'static>>;

/// A highlighter of a group of languages.
pub struct Code {
    names: &'static [&'static str],
    grammars: Grammars,
    store: Arc<GrammarStore>,
    highlighter: Highlighter,
    compiled: bool,
}

impl Code {
    fn new(names: &'static [&'static str], grammars: Grammars) -> Self {
        let store = Arc::new(GrammarStore::new());
        let config = Config {
            html_format: HtmlFormat::ClassNamesWithPrefix("hl".to_string()),
            ..Config::default()
        };
        Self {
            names,
            grammars,
            highlighter: Highlighter::with_store_and_config(store.clone(), config),
            store,
            compiled: false,
        }
    }

    /// `text`, highlighted as the language `name`.
    pub fn highlight(&mut self, name: &str, text: &str) -> Result<String, String> {
        // All of them at once, the first time: a language embeds others, as HTML does
        // JavaScript, and those are highlighted only if their grammars are in the store.
        if !self.compiled {
            self.compiled = true;
            for name in self.names {
                let Some(config) = (self.grammars)(name) else {
                    continue;
                };
                if let Ok(grammar) = CompiledGrammar::new(config) {
                    self.store.insert(*name, Arc::new(grammar));
                }
            }
        }
        self.highlighter
            .highlight(name, text)
            .map_err(|e| e.to_string())
    }
}

/// A function returning the [`Code`] of the languages it lists, by name and arborium's crate,
/// which links only their grammars.
macro_rules! group {
    ($(#[$doc:meta])* $group:ident: $($name:literal => $krate:ident),+ $(,)?) => {
        $(#[$doc])*
        pub fn $group() -> Code {
            Code::new(&[$($name),+], |name| match name {
                $($name => Some(GrammarConfig {
                    language: $krate::language().into(),
                    highlights_query: &$krate::HIGHLIGHTS_QUERY,
                    injections_query: $krate::INJECTIONS_QUERY,
                    locals_query: $krate::LOCALS_QUERY,
                }),)+
                _ => None,
            })
        }
    };
}

group!(
    /// [`Group::Web`]'s languages, with JSDoc, which JavaScript's comments embed.
    web:
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
);

group!(
    /// [`Group::Systems`]' languages.
    systems:
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
);

group!(
    /// [`Group::Apps`]' languages.
    apps:
    "java" => arborium_java,
    "kotlin" => arborium_kotlin,
    "scala" => arborium_scala,
    "c-sharp" => arborium_c_sharp,
    "swift" => arborium_swift,
    "dart" => arborium_dart,
);

group!(
    /// [`Group::Scripts`]' languages.
    scripts:
    "python" => arborium_python,
    "ruby" => arborium_ruby,
    "elixir" => arborium_elixir,
    "haskell" => arborium_haskell,
    "ocaml" => arborium_ocaml,
    "julia" => arborium_julia,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::{Group, LANGUAGES};

    fn code(group: Group) -> Code {
        match group {
            Group::Web => web(),
            Group::Systems => systems(),
            Group::Apps => apps(),
            Group::Scripts => scripts(),
        }
    }

    #[test]
    fn every_language_highlights_in_its_group() {
        for group in Group::ALL {
            let mut code = code(group);
            for language in LANGUAGES.iter().filter(|l| l.group == group) {
                assert!(
                    code.highlight(language.name, "x").is_ok(),
                    "{} in {group:?}",
                    language.name
                );
            }
            // And every grammar's queries compile.
            for name in code.names {
                assert!(code.store.get(name).is_some(), "{name}'s queries");
            }
        }
    }

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

    #[test]
    fn text_is_escaped() {
        let html = web()
            .highlight("html", "<script>alert(1)</script> &amp;")
            .unwrap();
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;"), "{html}");
    }

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

    #[test]
    fn other_groups_languages_do_not() {
        assert!(apps().highlight("rust", "fn main() {}").is_err());
    }
}
