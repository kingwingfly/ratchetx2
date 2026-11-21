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
//! - `code` highlights source with tree-sitter and arborium's grammars.
//! - `worker` serves the page's requests and includes the `rpc` codec.
//!
//! A worker posts [`READY`] once it listens. The page sends `[id, method, ...arguments]`.
//! The worker replies with `[id, true, value]` or `[id, false, error_string]`.

pub mod audio;
#[cfg(feature = "code")]
pub mod code;
#[cfg(feature = "diagram")]
pub mod diagram;
pub mod language;
#[cfg(feature = "pdf")]
pub mod pdf;
pub mod rpc;
#[cfg(feature = "search")]
pub mod search;
#[cfg(feature = "worker")]
pub mod worker;

use language::Group;

/// What a worker says once it listens.
pub const READY: &str = "ready";

/// The workers, by what they do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Worker {
    /// `open(bytes)` returns a document ID and its page sizes in points. `render(document,
    /// page, width)` returns `[width, height, RGBA pixels]` at the requested width subject to
    /// the side and area limits. `close(document)` releases the document.
    Pdf,
    /// `svg(source)`: the Mermaid diagram `source`, as SVG.
    Diagram,
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
    /// The script that starts the worker, which the trunk build makes.
    pub fn script(self) -> &'static str {
        match self {
            Self::Pdf => "/preview_pdf_loader.js",
            Self::Diagram => "/preview_diagram_loader.js",
            Self::Audio => "/preview_audio_loader.js",
            Self::Search => "/preview_search_loader.js",
            Self::Code(Group::Web) => "/preview_code_web_loader.js",
            Self::Code(Group::Systems) => "/preview_code_systems_loader.js",
            Self::Code(Group::Apps) => "/preview_code_apps_loader.js",
            Self::Code(Group::Scripts) => "/preview_code_scripts_loader.js",
        }
    }
}
