//! The E2EE chat web client's file previews that are too large to load with the page: PDF pages,
//! Mermaid diagrams, highlighted code, what audio files' tags say, and searches. Each runs in a
//! web worker
//! of its own, which the page starts when a preview first needs it, and which keeps the work off
//! the page's thread.
//!
//! The web client takes only [`language`], to know which worker highlights what, [`Worker`], to
//! start them, and [`audio::Tags`]. The engines are features, each a worker's:
//!
//! - `pdf`: [`pdf`], PDF pages as pixels, drawn by hayro.
//! - `audio`: [`audio::tags`], what audio files' tags say of them, read by lofty.
//! - `search`: [`search`], text searched with regular expressions, in linear time.
//! - `diagram`: [`diagram`], Mermaid diagrams as SVG, laid out and drawn by merman.
//! - `code`: [`code`], code highlighted by tree-sitter, with arborium's grammars.
//! - `worker`: [`worker`], serving a page's requests in a web worker.
//!
//! A page asks a worker `[id, method, ...arguments]`, and it answers `[id, true, value]`, or
//! `[id, false, error]`; it says [`READY`] once it listens, as what comes before goes unheard.

pub mod audio;
#[cfg(feature = "code")]
pub mod code;
#[cfg(feature = "diagram")]
pub mod diagram;
pub mod language;
#[cfg(feature = "pdf")]
pub mod pdf;
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
    /// `open(bytes)`: a document's ID and its pages' sizes, in points, `[width, height, ...]`;
    /// `render(document, page, width)`: the page drawn `width` pixels wide, `[width, height,
    /// RGBA pixels]`; `close(document)`.
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
