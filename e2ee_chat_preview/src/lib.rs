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
#[cfg(feature = "pdf")]
pub mod pdf;
pub mod rpc;
#[cfg(feature = "search")]
pub mod search;
#[cfg(feature = "worker")]
pub mod worker;

pub use rpc::WorkerService;

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
    /// The logical key for this worker in the page's `<meta name="e2ee-worker-manifest">`.
    pub fn key(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Diagram => "diagram",
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
}
