//! What the viewer shows of a file. Its kind comes from its content first, as the sender's name
//! and type are only hints, then from its name; for some kinds, Rust prepares what shows:
//! Markdown as HTML, slides, tables, listings of archives, and cards of contacts and events.
//!
//! Every file comes from a peer: Markdown's raw HTML shows as written text, its links go only to
//! the web or mail, and its images only come from `data:` URLs; the page's Content-Security-Policy
//! stops the rest.

use std::{
    fmt::Write as _,
    io::{Cursor, Read},
};

pub use e2ee_chat_preview::audio::Tags;
use e2ee_chat_preview::language::{self, Language};
use flate2::read::GzDecoder;
use pulldown_cmark::{CodeBlockKind, CowStr, Event, Options, Parser, Tag, TagEnd};
use pulldown_latex::{
    Storage,
    config::DisplayMode,
    event::{
        ArrayColumn, ColorChange, ColorTarget, ColumnAlignment, Content, DelimiterSize,
        DelimiterType, Dimension, DimensionUnit, EnvironmentFlow, Event as LatexEvent, Font,
        Grouping, Line, ScriptPosition, ScriptType, StateChange, Style, Visual,
    },
};

/// The most bytes of text shown, ...
pub const TEXT_MAX: usize = 5_000_000;
/// ... and highlighted, which takes a while.
pub const HIGHLIGHT_MAX: usize = 1_000_000;
/// The most rows of a table shown, ...
pub const ROWS_MAX: usize = 1_000;
/// ... the most columns per row of a table shown, ...
pub const COLS_MAX: usize = 100;
/// ... the most cells of a table shown in total, ...
pub const CELLS_MAX: usize = 20_000;
/// ... and entries of an archive.
pub const ENTRIES_MAX: usize = 10_000;
/// The most bytes a gzipped tar archive is unpacked to, to list it: listing reads through every
/// file in it, on the page's thread, and a small file can unpack to gigabytes.
pub const UNPACKED_MAX: u64 = 64 << 20;

/// Office documents, which show no preview, not even as the archives some of them are.
const OFFICE: [&str; 13] = [
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "odg", "pages", "numbers",
    "key",
];

/// Documents by their extension, which may be archives by content, as office documents are.
const DOCUMENTS: [&str; 17] = [
    "pdf", "txt", "text", "md", "markdown", "rtf", "epub", "csv", "tsv", "vcf", "vcard", "ics",
    "ical", "log", "tex", "djvu", "xps",
];

/// Archives by their extension, for an attachment, whose content is not here.
const ARCHIVES: [&str; 12] = [
    "zip", "tar", "gz", "tgz", "bz2", "xz", "zst", "7z", "rar", "jar", "apk", "dmg",
];

/// Media by their extension, for an attachment, whose content is not here.
const IMAGES: [&str; 13] = [
    "png", "jpg", "jpeg", "gif", "webp", "avif", "bmp", "ico", "svg", "heic", "heif", "tif", "tiff",
];
const VIDEOS: [&str; 8] = ["mp4", "m4v", "mov", "webm", "mkv", "avi", "ogv", "3gp"];
const AUDIO: [&str; 9] = [
    "mp3", "m4a", "aac", "ogg", "oga", "opus", "flac", "wav", "weba",
];

/// What sort of file it is, which a chat's file browser groups it by. Kept in the history as a
/// number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum Sort {
    /// Not known yet, as it was not sorted when it came.
    Unknown = 0,
    Image = 1,
    Video = 2,
    Audio = 3,
    /// PDF, office documents, text, and other documents to read.
    Document = 4,
    /// Source code and data in a language, e.g. Rust or JSON.
    Code = 5,
    Archive = 6,
    Other = 7,
}

/// The sort of `data`, the file `name` of the MIME type `mime` by its sender: by its content
/// first, for the formats with a signature known here, as the sender's name and type are only
/// hints; then by its name, then by its type. `data` is empty if its bytes are not here, as for
/// an attachment.
pub fn sort(name: &str, mime: &str, data: &[u8]) -> Sort {
    let lower = name.to_lowercase();
    let extension = lower
        .rsplit_once('.')
        .map_or("", |(_, extension)| extension);
    let mime = mime.to_lowercase();
    if let Some(media) = media_mime(&lower, &mime, data) {
        return media_sort(media);
    }
    if data.starts_with(b"%PDF-") {
        return Sort::Document;
    }
    // Before archives by content, as office documents are ZIP archives.
    if OFFICE.contains(&extension) || DOCUMENTS.contains(&extension) {
        return Sort::Document;
    }
    let archive = matches!(
        data,
        [b'P', b'K', 3, 4, ..]
            | [b'P', b'K', 5, 6, ..]
            | [0x1F, 0x8B, ..]
            | [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, ..]
            | [b'R', b'a', b'r', b'!', 0x1A, 0x07, ..]
            | [0xFD, b'7', b'z', b'X', b'Z', 0, ..]
            | [b'B', b'Z', b'h', ..]
            | [0x28, 0xB5, 0x2F, 0xFD, ..]
    ) || data.get(257..262) == Some(b"ustar");
    if archive || ARCHIVES.contains(&extension) {
        return Sort::Archive;
    }
    if IMAGES.contains(&extension) {
        return Sort::Image;
    }
    if VIDEOS.contains(&extension) {
        return Sort::Video;
    }
    if AUDIO.contains(&extension) {
        return Sort::Audio;
    }
    if language::of_file(&lower).is_some() {
        return Sort::Code;
    }
    match mime.split_once('/') {
        Some(("image", _)) => return Sort::Image,
        Some(("video", _)) => return Sort::Video,
        Some(("audio", _)) => return Sort::Audio,
        Some(("text", _)) => return Sort::Document,
        _ if mime == "application/pdf" => return Sort::Document,
        _ if mime.contains("zip") || mime.contains("compressed") || mime.ends_with("x-tar") => {
            return Sort::Archive;
        }
        _ => {}
    }
    // Any other text is a document, as its sender wrote it.
    let text = !data.is_empty() && std::str::from_utf8(data).is_ok_and(|text| !text.contains('\0'));
    if text { Sort::Document } else { Sort::Other }
}

/// The sort of media of the MIME type `mime`.
fn media_sort(mime: &str) -> Sort {
    match mime.split_once('/') {
        Some(("image", _)) => Sort::Image,
        Some(("video", _)) => Sort::Video,
        _ => Sort::Audio,
    }
}

/// The MIME type of `data`, the file `name` of the MIME type `mime` by its sender, if it is an
/// image, a video or audio the browser shows: by its first bytes, or, for media without a
/// signature known here, by the type its sender gave, as [`kind`] has it.
pub fn media_mime(name: &str, mime: &str, data: &[u8]) -> Option<&'static str> {
    match sniff_media(&name.to_lowercase(), data) {
        Some(Kind::Image(mime) | Kind::Video(mime) | Kind::Audio(mime)) => Some(mime),
        // Media no browser here shows, as HEIF images.
        Some(_) => None,
        None => match hinted_media(mime) {
            Some(Kind::Video(mime) | Kind::Audio(mime)) => Some(mime),
            _ => None,
        },
    }
}

/// Media without a signature known here, as the sender's browser named them.
fn hinted_media(mime: &str) -> Option<Kind> {
    Some(match mime.to_lowercase().as_str() {
        "video/mp4" => Kind::Video("video/mp4"),
        "video/webm" => Kind::Video("video/webm"),
        "audio/mpeg" => Kind::Audio("audio/mpeg"),
        "audio/aac" => Kind::Audio("audio/aac"),
        _ => return None,
    })
}

/// What a file shows as.
#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// An image, a video or audio, shown by the browser from a blob of this MIME type.
    Image(&'static str),
    Video(&'static str),
    Audio(&'static str),
    Pdf,
    /// Markdown, as HTML, with its source, which can also show as slides.
    Markdown {
        html: String,
        source: String,
    },
    /// Text, highlighted as the language of this name in
    /// [`LANGUAGES`](e2ee_chat_preview::language::LANGUAGES), if any, unless too long.
    Code {
        text: String,
        language: Option<&'static str>,
    },
    Table(Table),
    Archive(Listing),
    /// Contacts or events.
    Cards(Vec<Card>),
    Diff(Vec<(DiffLine, String)>),
    None,
}

/// The rows of a table, the first one as its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub rows: Vec<Vec<String>>,
    /// Whether the table was truncated by [`ROWS_MAX`], [`COLS_MAX`], or [`CELLS_MAX`].
    pub more: bool,
    /// Whether one or more rows had more than [`COLS_MAX`] columns.
    pub truncated_columns: bool,
    /// Whether rendering stopped early due to [`CELLS_MAX`].
    pub truncated_cells: bool,
}

impl Table {
    /// Human-readable truncation notice, if any limit was reached.
    #[allow(dead_code)] // Exposed for table preview UI wiring.
    pub fn notice(&self) -> Option<String> {
        if !self.more {
            return None;
        }
        let mut parts = Vec::new();
        if self.truncated_cells {
            parts.push(format!("at most {CELLS_MAX} cells"));
        } else if self.rows.len() >= ROWS_MAX {
            parts.push(format!("the first {ROWS_MAX} rows"));
        }
        if self.truncated_columns {
            parts.push(format!("the first {COLS_MAX} columns per row"));
        }
        if parts.is_empty() {
            parts.push(format!("the first {ROWS_MAX} rows"));
        }
        Some(format!("Only {} show.", parts.join(" and ")))
    }
}

/// The entries of an archive, all of them, or the first, if listing more would take too long.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub entries: Vec<Entry>,
    pub complete: bool,
}

/// A file or directory in an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub size: u64,
    pub directory: bool,
}

/// A contact or an event: its name, then its fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    pub title: String,
    pub fields: Vec<(&'static str, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffLine {
    /// `--- a/file` or `+++ b/file`, or what comes before the hunks.
    File,
    /// `@@ -1,2 +1,3 @@`.
    Hunk,
    Added,
    Removed,
    Context,
}

/// What `data`, the file `name` of the MIME type `mime` by its sender, shows as.
pub fn kind(name: &str, mime: &str, data: &[u8]) -> Kind {
    let lower = name.to_lowercase();
    let extension = lower
        .rsplit_once('.')
        .map_or("", |(_, extension)| extension);
    if OFFICE.contains(&extension) {
        return Kind::None;
    }
    if let Some(kind) = sniff(&lower, data).or_else(|| hinted_media(mime)) {
        return kind;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return Kind::None;
    };
    if text.len() > TEXT_MAX || text.contains('\0') {
        return Kind::None;
    }
    match extension {
        "md" | "markdown" | "mdown" | "mkd" => Kind::Markdown {
            html: markdown(text),
            source: text.to_string(),
        },
        "csv" => table(text, b','),
        "tsv" => table(text, b'\t'),
        "json" => {
            let pretty = serde_json::from_str::<serde_json::Value>(text)
                .and_then(|value| serde_json::to_string_pretty(&value));
            code(
                pretty.unwrap_or_else(|_| text.to_string()),
                language::named("json"),
            )
        }
        "diff" | "patch" => Kind::Diff(diff(text)),
        "vcf" | "vcard" => Kind::Cards(contacts(text)),
        "ics" | "ical" => Kind::Cards(events(text)),
        // An SVG image showed already, as `sniff` found it; any other `.svg` shows as XML.
        _ => code(text.to_string(), language::of_file(name)),
    }
}

/// `text`, highlighted as `language`, unless it is too long for that.
fn code(text: String, language: Option<&'static Language>) -> Kind {
    let language = language
        .filter(|_| text.len() <= HIGHLIGHT_MAX)
        .map(|language| language.name);
    Kind::Code { text, language }
}

/// The MIME type of the image `data`, the file `name`, if the browser shows it: PNG, JPEG, GIF,
/// WebP, AVIF, BMP and ICO by their first bytes, and SVG by its name and tag. An SVG shows as an
/// image only, where its scripts do not run.
pub fn image_mime(name: &str, data: &[u8]) -> Option<&'static str> {
    if let Some(mime) = crate::content::image_type(data) {
        return Some(mime);
    }
    match data {
        [
            _,
            _,
            _,
            _,
            b'f',
            b't',
            b'y',
            b'p',
            b'a',
            b'v',
            b'i',
            b'f' | b's',
            ..,
        ] => Some("image/avif"),
        [b'B', b'M', ..] if data.len() > 26 => Some("image/bmp"),
        [0, 0, 1, 0, count, ..] if *count > 0 => Some("image/x-icon"),
        _ if name.to_lowercase().ends_with(".svg")
            && std::str::from_utf8(data).is_ok_and(|text| text.contains("<svg")) =>
        {
            Some("image/svg+xml")
        }
        _ => None,
    }
}

/// The kind of the file `name`, lowercase, by its first bytes, for the formats that have them.
fn sniff(name: &str, data: &[u8]) -> Option<Kind> {
    if data.starts_with(b"%PDF-") {
        return Some(Kind::Pdf);
    }
    if let Some(media) = sniff_media(name, data) {
        return Some(media);
    }
    Some(match data {
        [b'P', b'K', 3, 4, ..] | [b'P', b'K', 5, 6, ..] => Kind::Archive(zip(data)?),
        [0x1F, 0x8B, ..] => Kind::Archive(tar(GzDecoder::new(data), UNPACKED_MAX)?),
        // Already as large as it gets, and listed as fast as it is read.
        _ if data.get(257..262) == Some(b"ustar") => Kind::Archive(tar(data, u64::MAX)?),
        _ => return None,
    })
}

/// The kind of the media file `name`, lowercase, by its first bytes, if it is media: an image,
/// a video or audio, or [`Kind::None`] for media no browser here shows.
fn sniff_media(name: &str, data: &[u8]) -> Option<Kind> {
    if let Some(mime) = image_mime(name, data) {
        return Some(Kind::Image(mime));
    }
    let window = &data[..data.len().min(64)];
    let has = |needle: &[u8]| window.windows(needle.len()).any(|bytes| bytes == needle);
    Some(match data {
        // ISO base media: MP4, QuickTime, M4A; HEIF images no browser here shows.
        [_, _, _, _, b'f', b't', b'y', b'p', brand @ ..] => match brand.get(..4)? {
            b"qt  " => Kind::Video("video/quicktime"),
            b"M4A " | b"M4B " | b"M4P " => Kind::Audio("audio/mp4"),
            b"heic" | b"heix" | b"hevc" | b"mif1" | b"msf1" => Kind::None,
            _ => Kind::Video("video/mp4"),
        },
        [0x1A, 0x45, 0xDF, 0xA3, ..] if has(b"webm") => Kind::Video("video/webm"),
        [0x1A, 0x45, 0xDF, 0xA3, ..] => Kind::Video("video/x-matroska"),
        [b'O', b'g', b'g', b'S', ..] if has(b"theora") => Kind::Video("video/ogg"),
        [b'O', b'g', b'g', b'S', ..] => Kind::Audio("audio/ogg"),
        [b'f', b'L', b'a', b'C', ..] => Kind::Audio("audio/flac"),
        [
            b'R',
            b'I',
            b'F',
            b'F',
            _,
            _,
            _,
            _,
            b'W',
            b'A',
            b'V',
            b'E',
            ..,
        ] => Kind::Audio("audio/wav"),
        [b'I', b'D', b'3', ..] => Kind::Audio("audio/mpeg"),
        // ADTS AAC, then MPEG audio frames.
        [0xFF, second, ..] if second & 0xF6 == 0xF0 => Kind::Audio("audio/aac"),
        [0xFF, second, ..] if second & 0xE0 == 0xE0 && second & 0x06 != 0 => {
            Kind::Audio("audio/mpeg")
        }
        _ => return None,
    })
}

/// The entries of the ZIP archive `data`, at most [`ENTRIES_MAX`]. They come from its central
/// directory, unpacking nothing.
fn zip(data: &[u8]) -> Option<Listing> {
    let mut archive = ::zip::ZipArchive::new(Cursor::new(data)).ok()?;
    let entries = (0..archive.len().min(ENTRIES_MAX))
        .map(|index| {
            let file = archive.by_index_raw(index).ok()?;
            Some(Entry {
                path: file.name().ok()?.into_owned(),
                size: file.size(),
                directory: file.is_dir(),
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(Listing {
        complete: entries.len() == archive.len(),
        entries,
    })
}

/// The entries of the tar archive `reader` reads, at most [`ENTRIES_MAX`], from no more than
/// its first `limit` bytes. Listing an entry reads through the one before it, so the listing
/// stops at the entry that crosses the limit, or that is damaged. Not an archive, if not even
/// its first entry reads.
fn tar(reader: impl Read, limit: u64) -> Option<Listing> {
    let mut archive = ::tar::Archive::new(reader.take(limit));
    let mut entries = Vec::new();
    let mut complete = true;
    for entry in archive.entries().ok()? {
        let entry = entry.ok().and_then(|entry| {
            Some(Entry {
                path: entry.path().ok()?.to_string_lossy().into_owned(),
                size: entry.header().size().ok()?,
                directory: entry.header().entry_type().is_dir(),
            })
        });
        match entry {
            Some(entry) if entries.len() < ENTRIES_MAX => entries.push(entry),
            _ => {
                complete = false;
                break;
            }
        }
    }
    // Read up to the limit: what came after it went unread.
    complete &= archive.into_inner().limit() > 0;
    (complete || !entries.is_empty()).then_some(Listing { entries, complete })
}

/// Markdown `source` as HTML: GitHub's flavour, with maths, as MathML. Raw HTML shows as
/// written, and HTML comments not at all, such as reveal.js's slide attributes. Code blocks are
/// `<pre><code data-lang="…">`, for the page to highlight, or to draw if Mermaid.
pub fn markdown(source: &str) -> String {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_MATH
        | Options::ENABLE_GFM;
    let mut in_comment = false;
    let events = Parser::new_ext(source, options).filter_map(|event| {
        Some(match event {
            Event::Html(html) | Event::InlineHtml(html) => {
                let comment = in_comment || html.trim_start().starts_with("<!--");
                in_comment = comment && !html.contains("-->");
                if comment {
                    return None;
                }
                Event::Text(html)
            }
            Event::Start(Tag::Link {
                link_type,
                dest_url,
                title,
                id,
            }) => Event::Start(Tag::Link {
                link_type,
                dest_url: safe_link(dest_url),
                title,
                id,
            }),
            Event::Start(Tag::Image {
                link_type,
                dest_url,
                title,
                id,
            }) => Event::Start(Tag::Image {
                link_type,
                dest_url: safe_image(dest_url),
                title,
                id,
            }),
            Event::Start(Tag::CodeBlock(kind)) => {
                let lang = match &kind {
                    CodeBlockKind::Fenced(info) => info.split_whitespace().next().unwrap_or(""),
                    CodeBlockKind::Indented => "",
                };
                Event::Html(format!("<pre><code data-lang=\"{}\">", escape(lang)).into())
            }
            Event::End(TagEnd::CodeBlock) => Event::Html("</code></pre>\n".into()),
            Event::InlineMath(tex) => Event::InlineHtml(mathml(&tex, DisplayMode::Inline).into()),
            Event::DisplayMath(tex) => Event::Html(mathml(&tex, DisplayMode::Block).into()),
            event => event,
        })
    });
    let mut html = String::new();
    pulldown_cmark::html::push_html(&mut html, events);
    sanitize_html(&html)
}

/// A link to the web, to mail, or within the document; any other goes nowhere.
fn safe_link(url: CowStr<'_>) -> CowStr<'_> {
    if is_safe_href(&url) {
        url.trim().to_string().into()
    } else {
        "#".into()
    }
}

/// An image from a `data:image/` URL; any other shows none, rather than reach out.
fn safe_image(url: CowStr<'_>) -> CowStr<'_> {
    if is_safe_image_src(&url) {
        url.trim().to_string().into()
    } else {
        "".into()
    }
}

/// Whether `url` is an allowed link destination (`http:`, `https:`, `mailto:`, or `#` fragment)
/// with no ASCII control characters.
fn is_safe_href(url: &str) -> bool {
    let trimmed = url.trim_matches(|c: char| c.is_ascii_whitespace());
    if trimmed.is_empty() || trimmed.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    ["http://", "https://", "mailto:", "#"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Whether `url` is an allowed inline image `data:image/` URL with no ASCII control characters.
fn is_safe_image_src(url: &str) -> bool {
    let trimmed = url.trim_matches(|c: char| c.is_ascii_whitespace());
    if trimmed.is_empty() || trimmed.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    trimmed.to_ascii_lowercase().starts_with("data:image/")
}

/// Maximum `pulldown-latex` events rendered in a single expression before falling back to raw TeX.
const MATH_EVENTS_MAX: usize = 20_000;
/// Maximum MathML group/script/visual nesting depth before falling back to raw TeX.
const MATH_DEPTH_MAX: usize = 128;
/// Maximum output bytes for a single MathML expression before falling back to raw TeX.
const MATH_HTML_MAX: usize = 256 * 1024;

/// The TeX `tex` as CSP-safe, HTML-escaped MathML, or HTML-escaped raw TeX on any parser or
/// rendering error.
fn mathml(tex: &str, display_mode: DisplayMode) -> String {
    let storage = Storage::new();
    let parser = pulldown_latex::Parser::new(tex, &storage);
    let mut events = Vec::new();
    for event in parser {
        let Ok(event) = event else {
            return escape(tex);
        };
        if events.len() >= MATH_EVENTS_MAX {
            return escape(tex);
        }
        events.push(event);
    }
    match MathmlRenderer::new(&events, display_mode).render() {
        Ok(rendered) => rendered,
        Err(()) => escape(tex),
    }
}

/// Strict HTML-escaping, zero-inline-style MathML renderer walking `pulldown-latex` events
/// directly.
struct MathmlRenderer<'a> {
    events: &'a [LatexEvent<'a>],
    cursor: usize,
    display_mode: DisplayMode,
    out: String,
    env_stack: Vec<MathEnv>,
    state_stack: Vec<MathState>,
    previous_atom: Option<MathAtom>,
}

#[derive(Clone, Copy)]
enum MathAtom {
    Bin,
    Op,
    Rel,
    Open,
    Close,
    Punct,
    Ord,
    Inner,
}

#[derive(Debug, Clone, PartialEq)]
enum MathEnvGrouping {
    Normal,
    LeftRight {
        closing: Option<char>,
    },
    Array {
        cols: Box<[ArrayColumn]>,
        cols_index: usize,
    },
    Matrix,
    Cases {
        used_align: bool,
        left: bool,
    },
    Align,
    Alignat {
        pairs: u16,
        columns_used: u16,
    },
    SubArray,
    Gather,
    Multline,
    Split {
        used_align: bool,
    },
    Equation,
}

#[derive(Debug, Clone, PartialEq)]
enum MathEnv {
    Group(MathEnvGrouping),
    Visual {
        ty: Visual,
        count: u8,
    },
    Script {
        ty: ScriptType,
        above_below: bool,
        count: u8,
        fn_application: bool,
    },
}

#[derive(Debug, Clone, Copy, Default)]
struct MathState {
    font: Option<Font>,
    border: bool,
    style: Option<Style>,
}

impl<'a> MathmlRenderer<'a> {
    fn new(events: &'a [LatexEvent<'a>], display_mode: DisplayMode) -> Self {
        Self {
            events,
            cursor: 0,
            display_mode,
            out: String::new(),
            env_stack: Vec::with_capacity(16),
            state_stack: vec![MathState::default()],
            previous_atom: None,
        }
    }

    fn state(&self) -> MathState {
        self.state_stack.last().copied().unwrap_or_default()
    }

    fn check_bounds(&self) -> Result<(), ()> {
        if self.out.len() > MATH_HTML_MAX || self.env_stack.len() > MATH_DEPTH_MAX {
            Err(())
        } else {
            Ok(())
        }
    }

    fn peek(&self) -> Option<&'a LatexEvent<'a>> {
        self.events.get(self.cursor)
    }

    fn next_event(&mut self) -> Option<&'a LatexEvent<'a>> {
        let event = self.events.get(self.cursor)?;
        self.cursor += 1;
        Some(event)
    }

    fn open_tag(&mut self, tag: &'static str, classes: Option<&'static str>) {
        let state = self.state();
        self.out.push('<');
        self.out.push_str(tag);
        if let Some(style) = state.style
            && !matches!(
                self.env_stack.last(),
                Some(
                    MathEnv::Script {
                        ty: ScriptType::Subscript | ScriptType::Superscript,
                        count: 0,
                        ..
                    } | MathEnv::Script {
                        ty: ScriptType::SubSuperscript,
                        count: 0 | 1,
                        ..
                    }
                )
            )
        {
            let (displaystyle, scriptlevel) = match style {
                Style::Display => ("true", "0"),
                Style::Text => ("false", "0"),
                Style::Script => ("false", "1"),
                Style::ScriptScript => ("false", "2"),
            };
            let _ = write!(
                self.out,
                " displaystyle=\"{displaystyle}\" scriptlevel=\"{scriptlevel}\""
            );
        }
        match (classes, state.border) {
            (Some(cls), true) => {
                let _ = write!(self.out, " class=\"{cls} ml-box\"");
            }
            (Some(cls), false) => {
                let _ = write!(self.out, " class=\"{cls}\"");
            }
            (None, true) => self.out.push_str(" class=\"ml-box\""),
            (None, false) => {}
        }
    }

    fn render(mut self) -> Result<String, ()> {
        let mode = match self.display_mode {
            DisplayMode::Inline => "inline",
            DisplayMode::Block => "block",
        };
        let _ = write!(self.out, "<math display=\"{mode}\">");

        while let Some(event) = self.next_event() {
            self.write_event(event)?;
            self.check_bounds()?;

            while let Some((tag, count, fn_application)) =
                self.env_stack.last_mut().and_then(|env| match env {
                    MathEnv::Group(_) => None,
                    MathEnv::Visual { ty, count } => Some((visual_tag(*ty), count, None)),
                    MathEnv::Script {
                        ty,
                        above_below,
                        count,
                        fn_application,
                    } => Some((script_tag(*ty, *above_below), count, Some(*fn_application))),
                })
            {
                if *count != 0 {
                    *count -= 1;
                    break;
                }
                self.out.push_str("</");
                self.out.push_str(tag);
                self.out.push('>');
                self.set_previous_atom(MathAtom::Inner);
                self.env_stack.pop();

                if fn_application.unwrap_or(false)
                    && let Some(atom) = self.next_atom()
                {
                    self.out.push_str("<mo>\u{2061}</mo>");
                    if !matches!(atom, MathAtom::Open | MathAtom::Punct | MathAtom::Close) {
                        self.out.push_str("<mspace width=\"0.1667em\" />");
                    }
                }
            }
            self.check_bounds()?;
        }

        if !self.env_stack.is_empty() || self.state_stack.len() != 1 {
            return Err(());
        }
        self.out.push_str("</math>");
        Ok(self.out)
    }

    fn write_event(&mut self, event: &'a LatexEvent<'a>) -> Result<(), ()> {
        match event {
            LatexEvent::Content(content) => self.write_content(*content, false),
            LatexEvent::Begin(grouping) => {
                self.previous_atom = None;
                let math_env = !matches!(grouping, Grouping::Normal | Grouping::LeftRight(_, _));
                if math_env {
                    self.state_stack.push(MathState::default());
                } else {
                    let last_state = self.state();
                    self.state_stack.push(last_state);
                    while let Some(LatexEvent::StateChange(state_change)) = self.peek() {
                        let state_change = *state_change;
                        self.handle_state_change(state_change);
                        self.next_event();
                    }
                    self.open_tag("mrow", None);
                    self.out.push('>');
                    if let Some(top) = self.state_stack.last_mut() {
                        *top = MathState {
                            font: top.font,
                            ..MathState::default()
                        };
                    }
                }

                let emit_start_lines = |out: &mut String, cursor: &mut usize| {
                    if let Some(LatexEvent::EnvironmentFlow(EnvironmentFlow::StartLines {
                        lines,
                    })) = self.events.get(*cursor)
                    {
                        write_env_horizontal_lines(out, lines);
                        *cursor += 1;
                    }
                };

                let env_group = match grouping {
                    Grouping::Normal => MathEnvGrouping::Normal,
                    Grouping::LeftRight(opening, closing) => {
                        if let Some(delim) = *opening {
                            self.open_tag("mo", None);
                            self.out.push_str(" stretchy=\"true\">");
                            push_escaped_char(&mut self.out, delim);
                            self.out.push_str("</mo>");
                        }
                        self.previous_atom = Some(MathAtom::Open);
                        MathEnvGrouping::LeftRight { closing: *closing }
                    }
                    Grouping::Align { eq_numbers } => {
                        self.out
                            .push_str("<mtable class=\"ml-alignlike ml-align");
                        if *eq_numbers {
                            self.out.push_str(" ml-with-eqn");
                        }
                        self.out.push_str("\"><mtr");
                        emit_start_lines(&mut self.out, &mut self.cursor);
                        self.out.push_str("><mtd>");
                        MathEnvGrouping::Align
                    }
                    Grouping::Matrix { alignment } => {
                        self.out.push_str("<mtable class=\"ml-arraylike");
                        self.out.push_str(match alignment {
                            ColumnAlignment::Left => " ml-cells-left\"",
                            ColumnAlignment::Center => "\"",
                            ColumnAlignment::Right => " ml-cells-right\"",
                        });
                        self.out.push_str("><mtr");
                        emit_start_lines(&mut self.out, &mut self.cursor);
                        self.out.push_str("><mtd>");
                        MathEnvGrouping::Matrix
                    }
                    Grouping::Cases { left } => {
                        self.out.push_str("<mrow>");
                        if *left {
                            self.out.push_str("<mo stretchy=\"true\">{</mo>");
                        }
                        self.out
                            .push_str("<mtable class=\"ml-cells-left ml-cases\"><mtr");
                        emit_start_lines(&mut self.out, &mut self.cursor);
                        self.out.push_str("><mtd>");
                        MathEnvGrouping::Cases {
                            left: *left,
                            used_align: false,
                        }
                    }
                    Grouping::Array(cols) => {
                        self.out.push_str("<mtable class=\"ml-arraylike\"><mtr");
                        emit_start_lines(&mut self.out, &mut self.cursor);
                        self.out.push('>');
                        let index = array_newline(&mut self.out, cols)?;
                        MathEnvGrouping::Array {
                            cols: cols.clone(),
                            cols_index: index,
                        }
                    }
                    Grouping::Aligned => {
                        self.out
                            .push_str("<mtable class=\"ml-alignlike ml-align\"><mtr");
                        emit_start_lines(&mut self.out, &mut self.cursor);
                        self.out.push_str("><mtd>");
                        MathEnvGrouping::Align
                    }
                    Grouping::SubArray { alignment } => {
                        self.out.push_str("<mtable");
                        match alignment {
                            ColumnAlignment::Left => {
                                self.out.push_str(" class=\"ml-cells-left\"");
                            }
                            ColumnAlignment::Center => {}
                            ColumnAlignment::Right => {
                                self.out.push_str(" class=\"ml-cells-right\"");
                            }
                        }
                        self.out.push_str("><mtr");
                        emit_start_lines(&mut self.out, &mut self.cursor);
                        self.out.push_str("><mtd>");
                        MathEnvGrouping::SubArray
                    }
                    Grouping::Alignat { pairs, eq_numbers } => {
                        self.out.push_str("<mtable class=\"ml-alignlike");
                        if *eq_numbers {
                            self.out.push_str(" ml-with-eqn");
                        }
                        self.out.push_str("\"><mtr");
                        emit_start_lines(&mut self.out, &mut self.cursor);
                        self.out.push_str("><mtd>");
                        MathEnvGrouping::Alignat {
                            pairs: *pairs,
                            columns_used: 0,
                        }
                    }
                    Grouping::Alignedat { pairs } => {
                        self.out.push_str("<mtable class=\"ml-alignlike\"><mtr");
                        emit_start_lines(&mut self.out, &mut self.cursor);
                        self.out.push_str("><mtd>");
                        MathEnvGrouping::Alignat {
                            pairs: *pairs,
                            columns_used: 0,
                        }
                    }
                    Grouping::Gather { eq_numbers } => {
                        self.out.push_str("<mtable");
                        if *eq_numbers {
                            self.out.push_str(" class=\"ml-with-eqn\"");
                        }
                        self.out.push_str("><mtr");
                        emit_start_lines(&mut self.out, &mut self.cursor);
                        self.out.push_str("><mtd>");
                        MathEnvGrouping::Gather
                    }
                    Grouping::Gathered => {
                        self.out.push_str("<mtable><mtr");
                        emit_start_lines(&mut self.out, &mut self.cursor);
                        self.out.push_str("><mtd>");
                        MathEnvGrouping::Gather
                    }
                    Grouping::Multline => {
                        self.out.push_str("<mtable class=\"ml-multline\"><mtr");
                        emit_start_lines(&mut self.out, &mut self.cursor);
                        self.out.push_str("><mtd>");
                        MathEnvGrouping::Multline
                    }
                    Grouping::Split => {
                        self.out.push_str("<mtable class=\"ml-alignlike\"><mtr");
                        emit_start_lines(&mut self.out, &mut self.cursor);
                        self.out.push_str("><mtd>");
                        MathEnvGrouping::Split { used_align: false }
                    }
                    Grouping::Equation { eq_numbers } => {
                        self.out.push_str("<mtable");
                        if *eq_numbers {
                            self.out.push_str(" class=\"ml-with-eqn\"");
                        }
                        self.out.push_str("><mtr><mtd>");
                        MathEnvGrouping::Equation
                    }
                };
                self.env_stack.push(MathEnv::Group(env_group));
                Ok(())
            }
            LatexEvent::End => {
                let Some(MathEnv::Group(grouping)) = self.env_stack.pop() else {
                    return Err(());
                };
                if self.state_stack.len() <= 1 {
                    return Err(());
                }
                self.state_stack.pop();
                self.previous_atom = Some(MathAtom::Inner);
                match grouping {
                    MathEnvGrouping::Normal => self.out.push_str("</mrow>"),
                    MathEnvGrouping::LeftRight { closing } => {
                        if let Some(delim) = closing {
                            self.open_tag("mo", None);
                            self.out.push_str(" stretchy=\"true\">");
                            push_escaped_char(&mut self.out, delim);
                            self.out.push_str("</mo>");
                        }
                        self.previous_atom = Some(MathAtom::Close);
                        self.out.push_str("</mrow>");
                    }
                    MathEnvGrouping::Matrix
                    | MathEnvGrouping::Align
                    | MathEnvGrouping::SubArray
                    | MathEnvGrouping::Gather
                    | MathEnvGrouping::Multline
                    | MathEnvGrouping::Equation
                    | MathEnvGrouping::Split { .. }
                    | MathEnvGrouping::Alignat { .. } => {
                        self.out.push_str("</mtd></mtr></mtable>");
                    }
                    MathEnvGrouping::Array { cols, cols_index } => {
                        self.out.push_str("</mtd>");
                        if let Some(rest) = cols.get(cols_index..) {
                            for col in rest {
                                match col {
                                    ArrayColumn::Separator(Line::Solid) => {
                                        self.out.push_str(
                                            "<mtd class=\"ml-right-solid ml-border-only\"></mtd>",
                                        );
                                    }
                                    ArrayColumn::Separator(Line::Dashed) => {
                                        self.out.push_str(
                                            "<mtd class=\"ml-right-dashed ml-border-only\"></mtd>",
                                        );
                                    }
                                    ArrayColumn::Column(_) => break,
                                }
                            }
                        }
                        self.out.push_str("</mtr></mtable>");
                    }
                    MathEnvGrouping::Cases { left, .. } => {
                        self.out.push_str("</mtd></mtr></mtable>");
                        if !left {
                            self.out.push_str("<mo stretchy=\"true\">}</mo>");
                        }
                        self.out.push_str("</mrow>");
                    }
                }
                Ok(())
            }
            LatexEvent::Visual(visual) => {
                let visual = *visual;
                if visual == Visual::Negation {
                    if let Some(LatexEvent::Content(
                        content @ (Content::Ordinary { .. }
                        | Content::Relation { .. }
                        | Content::BinaryOp { .. }
                        | Content::LargeOp { .. }
                        | Content::Delimiter { .. }
                        | Content::Punctuation(_)),
                    )) = self.peek()
                    {
                        let content = *content;
                        self.next_event();
                        return self.write_content(content, true);
                    }
                    self.open_tag("mrow", Some("ml-negated"));
                    self.out.push('>');
                    self.env_stack.push(MathEnv::Visual {
                        ty: visual,
                        count: 1,
                    });
                    return Ok(());
                }
                let count = match visual {
                    Visual::SquareRoot | Visual::Negation => 1,
                    Visual::Root | Visual::Fraction(_) => 2,
                };
                self.env_stack.push(MathEnv::Visual { ty: visual, count });
                self.open_tag(visual_tag(visual), None);
                if let Visual::Fraction(Some(dim)) = visual
                    && let Some(thickness) = format_dimension(dim)
                {
                    let _ = write!(self.out, " linethickness=\"{thickness}\"");
                }
                self.out.push('>');
                Ok(())
            }
            LatexEvent::Script { ty, position } => {
                let state = self.state();
                let above_below = match position {
                    ScriptPosition::Right => false,
                    ScriptPosition::AboveBelow => true,
                    ScriptPosition::Movable => {
                        state.style == Some(Style::Display)
                            || (state.style.is_none() && self.display_mode == DisplayMode::Block)
                    }
                };
                let count = match ty {
                    ScriptType::Subscript | ScriptType::Superscript => 2,
                    ScriptType::SubSuperscript => 3,
                };
                self.env_stack.push(MathEnv::Script {
                    ty: *ty,
                    above_below,
                    count,
                    fn_application: false,
                });
                self.open_tag(script_tag(*ty, above_below), None);
                self.out.push('>');
                Ok(())
            }
            LatexEvent::Space {
                width,
                height,
                depth,
            } => {
                self.out.push_str("<mspace");
                if let Some(width) = width.and_then(format_dimension) {
                    let _ = write!(self.out, " width=\"{width}\"");
                }
                if let Some(height) = height.and_then(format_dimension) {
                    let _ = write!(self.out, " height=\"{height}\"");
                }
                if let Some(depth) = depth.and_then(format_dimension) {
                    let _ = write!(self.out, " depth=\"{depth}\"");
                }
                self.out.push_str(" />");
                Ok(())
            }
            LatexEvent::StateChange(state_change) => {
                self.handle_state_change(*state_change);
                Ok(())
            }
            LatexEvent::EnvironmentFlow(EnvironmentFlow::NewLine {
                spacing,
                horizontal_lines,
            }) => {
                if let Some(top) = self.state_stack.last_mut() {
                    *top = MathState::default();
                }
                self.previous_atom = None;

                if let Some(MathEnv::Group(MathEnvGrouping::Array { cols, cols_index })) =
                    self.env_stack.last()
                {
                    let rest = cols.get(*cols_index..).unwrap_or(&[]);
                    array_close_line(&mut self.out, rest);
                } else if let Some(MathEnv::Group(MathEnvGrouping::Equation)) =
                    self.env_stack.last()
                {
                    return Ok(());
                } else if matches!(self.env_stack.last(), Some(MathEnv::Group(_))) {
                    self.out.push_str("</mtd></mtr><mtr");
                } else {
                    return Err(());
                }

                if let Some(spacing) = *spacing {
                    self.out.push('>');
                    if let Some(MathEnv::Group(MathEnvGrouping::Array { cols, cols_index })) =
                        self.env_stack.last_mut()
                    {
                        let mut index = array_newline(&mut self.out, cols)?;
                        if let Some(height) = format_dimension(spacing)
                            && spacing.value > 0.0
                        {
                            let _ = write!(self.out, "<mspace height=\"{height}\" />");
                        }
                        while index < *cols_index {
                            array_align(&mut self.out, cols, &mut index)?;
                        }
                        let rest = cols.get(index..).unwrap_or(&[]);
                        array_close_line(&mut self.out, rest);
                    } else {
                        self.out.push_str("<mtd class=\"ml-nonumber\">");
                        if let Some(height) = format_dimension(spacing)
                            && spacing.value > 0.0
                        {
                            let _ = write!(self.out, "<mspace height=\"{height}\" />");
                        }
                        self.out.push_str("</mtd></mtr><mtr");
                    }
                }
                write_env_horizontal_lines(&mut self.out, horizontal_lines);

                match self.env_stack.last_mut() {
                    Some(MathEnv::Group(
                        MathEnvGrouping::Cases { used_align, .. }
                        | MathEnvGrouping::Split { used_align },
                    )) => {
                        *used_align = false;
                        self.out.push_str("><mtd>");
                        Ok(())
                    }
                    Some(MathEnv::Group(
                        MathEnvGrouping::Matrix
                        | MathEnvGrouping::Align
                        | MathEnvGrouping::Gather
                        | MathEnvGrouping::SubArray
                        | MathEnvGrouping::Multline,
                    )) => {
                        self.out.push_str("><mtd>");
                        Ok(())
                    }
                    Some(MathEnv::Group(MathEnvGrouping::Array { cols, cols_index })) => {
                        self.out.push('>');
                        let new_index = array_newline(&mut self.out, cols)?;
                        *cols_index = new_index;
                        Ok(())
                    }
                    Some(MathEnv::Group(MathEnvGrouping::Alignat { columns_used, .. })) => {
                        *columns_used = 0;
                        self.out.push_str("><mtd>");
                        Ok(())
                    }
                    _ => Err(()),
                }
            }
            LatexEvent::EnvironmentFlow(EnvironmentFlow::Alignment) => {
                if let Some(top) = self.state_stack.last_mut() {
                    *top = MathState::default();
                }
                self.previous_atom = None;
                match self.env_stack.last_mut() {
                    Some(MathEnv::Group(
                        MathEnvGrouping::Cases {
                            used_align: false, ..
                        }
                        | MathEnvGrouping::Split { used_align: false },
                    )) => {
                        self.out.push_str("</mtd><mtd>");
                        Ok(())
                    }
                    Some(MathEnv::Group(MathEnvGrouping::Align | MathEnvGrouping::Matrix)) => {
                        self.out.push_str("</mtd><mtd>");
                        Ok(())
                    }
                    Some(MathEnv::Group(MathEnvGrouping::Alignat {
                        pairs,
                        columns_used,
                    })) if *columns_used / 2 <= *pairs => {
                        *columns_used += 1;
                        self.out.push_str("</mtd><mtd>");
                        Ok(())
                    }
                    Some(MathEnv::Group(MathEnvGrouping::Array { cols, cols_index })) => {
                        array_align(&mut self.out, cols, cols_index)
                    }
                    _ => Err(()),
                }
            }
            LatexEvent::EnvironmentFlow(EnvironmentFlow::StartLines { .. }) => Err(()),
        }
    }

    fn write_content(&mut self, content: Content<'a>, negate: bool) -> Result<(), ()> {
        match content {
            Content::Text(text) => {
                self.open_tag("mtext", None);
                self.out.push('>');
                let trimmed = text.trim();
                if text.starts_with(char::is_whitespace) {
                    self.out.push('\u{00A0}');
                }
                match self.state().font {
                    None => push_escaped_text(&mut self.out, trimmed),
                    Some(font) => {
                        for c in trimmed.chars() {
                            push_escaped_char(&mut self.out, map_font_char(font, c));
                        }
                    }
                }
                if !trimmed.is_empty() && text.ends_with(char::is_whitespace) {
                    self.out.push('\u{00A0}');
                }
                self.set_previous_atom(MathAtom::Ord);
                self.out.push_str("</mtext>");
            }
            Content::Number(number) => {
                self.open_tag("mn", None);
                self.out.push('>');
                let font = match self.state().font {
                    Some(Font::BoldSymbol) => Some(Font::Bold),
                    other => other,
                };
                for c in number.chars() {
                    let mapped = font.map_or(c, |f| map_font_char(f, c));
                    push_escaped_char(&mut self.out, mapped);
                }
                self.set_previous_atom(MathAtom::Ord);
                self.out.push_str("</mn>");
            }
            Content::Function(name) => {
                if matches!(
                    self.previous_atom,
                    Some(MathAtom::Inner | MathAtom::Close | MathAtom::Ord)
                ) {
                    self.out.push_str("<mspace width=\"0.1667em\" />");
                }
                self.open_tag("mi", None);
                if name.chars().count() == 1 {
                    self.out.push_str(" mathvariant=\"normal\">");
                } else {
                    self.out.push('>');
                }
                // Always HTML-escape operator/function names (e.g. \operatorname{...}, \mathop{...}).
                push_escaped_text(&mut self.out, name);
                self.set_previous_atom(MathAtom::Op);
                self.out.push_str("</mi>");

                if let Some(MathEnv::Script { fn_application, .. }) = self.env_stack.last_mut() {
                    *fn_application = true;
                } else if let Some(atom) = self.next_atom() {
                    self.out.push_str("<mo>\u{2061}</mo>");
                    if !matches!(atom, MathAtom::Open | MathAtom::Punct | MathAtom::Close) {
                        self.out.push_str("<mspace width=\"0.1667em\" />");
                    }
                }
            }
            Content::Ordinary { content, stretchy } => {
                if stretchy {
                    self.out.push_str("<mo stretchy=\"true\">");
                    push_escaped_char(&mut self.out, content);
                    if negate {
                        self.out.push('\u{0338}');
                    }
                    self.out.push_str("</mo>");
                } else {
                    self.open_tag("mi", None);
                    // TeX math style: uppercase Greek letters are upright by default.
                    let should_be_upright = content.is_uppercase() && !content.is_ascii_uppercase();
                    let mapped = match (self.state().font, should_be_upright) {
                        (Some(Font::UpRight), _) | (None, true) => {
                            self.out.push_str(" mathvariant=\"normal\">");
                            content
                        }
                        (Some(font), upright) => {
                            self.out.push('>');
                            let font = if font == Font::BoldSymbol {
                                if upright {
                                    Font::Bold
                                } else {
                                    Font::BoldItalic
                                }
                            } else {
                                font
                            };
                            map_font_char(font, content)
                        }
                        _ => {
                            self.out.push('>');
                            content
                        }
                    };
                    push_escaped_char(&mut self.out, mapped);
                    if negate {
                        self.out.push('\u{0338}');
                    }
                    self.set_previous_atom(MathAtom::Ord);
                    self.out.push_str("</mi>");
                }
            }
            Content::BinaryOp { content, small } => {
                let tag = if matches!(
                    self.previous_atom,
                    Some(MathAtom::Inner | MathAtom::Close | MathAtom::Ord)
                ) && !matches!(
                    self.env_stack.last(),
                    Some(
                        MathEnv::Script { .. }
                            | MathEnv::Visual {
                                ty: Visual::Root | Visual::Fraction(_) | Visual::SquareRoot,
                                ..
                            }
                    )
                ) && matches!(
                    self.next_atom(),
                    Some(
                        MathAtom::Inner
                            | MathAtom::Bin
                            | MathAtom::Op
                            | MathAtom::Ord
                            | MathAtom::Open
                    )
                ) {
                    self.set_previous_atom(MathAtom::Bin);
                    "mo"
                } else {
                    self.set_previous_atom(MathAtom::Ord);
                    "mi"
                };

                self.open_tag(tag, small.then_some("ml-small"));
                self.out.push('>');
                push_escaped_char(&mut self.out, content);
                if negate {
                    self.out.push('\u{0338}');
                }
                self.out.push_str("</");
                self.out.push_str(tag);
                self.out.push('>');
            }
            Content::Relation { content, small } => {
                let mut buf = [0u8; 8];
                let slice = content.encode_utf8_to_buf(&mut buf);
                let text = std::str::from_utf8(slice).map_err(|_| ())?;
                self.open_tag("mo", small.then_some("ml-small"));
                self.out.push('>');
                push_escaped_text(&mut self.out, text);
                if negate {
                    self.out.push('\u{0338}');
                }
                self.set_previous_atom(MathAtom::Rel);
                self.out.push_str("</mo>");
            }
            Content::LargeOp { content, small } => {
                self.open_tag("mo", None);
                if small {
                    self.out.push_str(" largeop=\"false\"");
                }
                self.out.push_str(" movablelimits=\"false\">");
                push_escaped_char(&mut self.out, content);
                if negate {
                    self.out.push('\u{0338}');
                }
                self.set_previous_atom(MathAtom::Op);
                self.out.push_str("</mo>");
            }
            Content::Delimiter { content, size, ty } => {
                self.open_tag("mo", None);
                let stretch = ty == DelimiterType::Fence || size.is_some();
                let _ = write!(self.out, " symmetric=\"{stretch}\" stretchy=\"{stretch}\"");
                if let Some(size) = size {
                    let em = match size {
                        DelimiterSize::Big => "1.2",
                        DelimiterSize::BIG => "1.8",
                        DelimiterSize::Bigg => "2.4",
                        DelimiterSize::BIGG => "3",
                    };
                    let _ = write!(self.out, " minsize=\"{em}em\" maxsize=\"{em}em\"");
                }
                self.out.push('>');
                push_escaped_char(&mut self.out, content);
                if negate {
                    self.out.push('\u{0338}');
                }
                self.set_previous_atom(match ty {
                    DelimiterType::Open => MathAtom::Open,
                    DelimiterType::Fence => MathAtom::Punct,
                    DelimiterType::Close => MathAtom::Close,
                });
                self.out.push_str("</mo>");
            }
            Content::Punctuation(content) => {
                self.open_tag("mo", None);
                self.out.push('>');
                push_escaped_char(&mut self.out, content);
                if negate {
                    self.out.push('\u{0338}');
                }
                self.set_previous_atom(MathAtom::Punct);
                self.out.push_str("</mo>");
            }
        }
        Ok(())
    }

    fn handle_state_change(&mut self, state_change: StateChange) {
        let Some(state) = self.state_stack.last_mut() else {
            return;
        };
        match state_change {
            StateChange::Font(font) => state.font = font,
            StateChange::Color(ColorChange { target, .. }) => {
                // Never emit inline `style="..."` (violates `style-src 'self'`); map boxed borders
                // to a static CSS utility class instead.
                if target == ColorTarget::Border {
                    state.border = true;
                }
            }
            StateChange::Style(style) => state.style = Some(style),
        }
    }

    fn set_previous_atom(&mut self, atom: MathAtom) {
        if !matches!(
            self.env_stack.last(),
            Some(
                MathEnv::Visual {
                    ty: Visual::Root | Visual::Fraction(_),
                    count: 0,
                } | MathEnv::Script {
                    ty: ScriptType::Subscript | ScriptType::Superscript,
                    count: 0,
                    ..
                } | MathEnv::Script {
                    ty: ScriptType::SubSuperscript,
                    count: 0 | 1,
                    ..
                }
            )
        ) {
            self.previous_atom = Some(atom);
        }
    }

    fn next_atom(&self) -> Option<MathAtom> {
        let mut idx = self.cursor;
        while let Some(next) = self.events.get(idx) {
            idx += 1;
            return match next {
                LatexEvent::StateChange(_)
                | LatexEvent::Space { .. }
                | LatexEvent::Visual(Visual::Negation)
                | LatexEvent::Script { .. } => continue,
                LatexEvent::End | LatexEvent::EnvironmentFlow(_) => None,
                LatexEvent::Visual(_) | LatexEvent::Begin(_) => Some(MathAtom::Inner),
                LatexEvent::Content(content) => match content {
                    Content::BinaryOp { .. } => Some(MathAtom::Bin),
                    Content::LargeOp { .. } => Some(MathAtom::Op),
                    Content::Relation { .. } => Some(MathAtom::Rel),
                    Content::Delimiter {
                        ty: DelimiterType::Open,
                        ..
                    } => Some(MathAtom::Open),
                    Content::Delimiter {
                        ty: DelimiterType::Close,
                        ..
                    } => Some(MathAtom::Close),
                    Content::Punctuation(_) => Some(MathAtom::Punct),
                    _ => Some(MathAtom::Ord),
                },
            };
        }
        None
    }
}

fn script_tag(ty: ScriptType, above_below: bool) -> &'static str {
    match (ty, above_below) {
        (ScriptType::Subscript, false) => "msub",
        (ScriptType::Superscript, false) => "msup",
        (ScriptType::SubSuperscript, false) => "msubsup",
        (ScriptType::Subscript, true) => "munder",
        (ScriptType::Superscript, true) => "mover",
        (ScriptType::SubSuperscript, true) => "munderover",
    }
}

fn visual_tag(visual: Visual) -> &'static str {
    match visual {
        Visual::Root => "mroot",
        Visual::Fraction(_) => "mfrac",
        Visual::SquareRoot => "msqrt",
        Visual::Negation => "mrow",
    }
}

fn format_dimension(dim: Dimension) -> Option<String> {
    const BP_PER_PT: f32 = 72.0 / 72.27;
    const BP_PER_SP: f32 = (1.0 / 65536.0) * BP_PER_PT;
    const BP_PER_DD: f32 = (1238.0 / 1157.0) * BP_PER_PT;
    const BP_PER_CC: f32 = 12.0 * BP_PER_DD;
    const EM_PER_MU: f32 = 1.0 / 18.0;
    if !dim.value.is_finite() {
        return None;
    }
    let (value, unit) = match dim.unit {
        DimensionUnit::Em => (dim.value, "em"),
        DimensionUnit::Mu => (dim.value * EM_PER_MU, "em"),
        DimensionUnit::Ex => (dim.value, "ex"),
        DimensionUnit::Mm => (dim.value, "mm"),
        DimensionUnit::Cm => (dim.value, "cm"),
        DimensionUnit::In => (dim.value, "in"),
        DimensionUnit::Bp => (dim.value, "pt"),
        DimensionUnit::Pt => (dim.value * BP_PER_PT, "pt"),
        DimensionUnit::Pc => (dim.value * BP_PER_PT, "pc"),
        DimensionUnit::Sp => (dim.value * BP_PER_SP, "pt"),
        DimensionUnit::Dd => (dim.value * BP_PER_DD, "pt"),
        DimensionUnit::Cc => (dim.value * BP_PER_CC, "pt"),
    };
    if !value.is_finite() {
        return None;
    }
    let clamped = value.clamp(-50.0, 50.0);
    let formatted = format!("{clamped:.4}");
    let trimmed = formatted.trim_end_matches('0').trim_end_matches('.');
    let trimmed = if trimmed == "-0" || trimmed.is_empty() {
        "0"
    } else {
        trimmed
    };
    Some(format!("{trimmed}{unit}"))
}

fn array_newline(out: &mut String, cols: &[ArrayColumn]) -> Result<usize, ()> {
    let mut index = 0;
    out.push_str("<mtd");
    for window in cols.windows(2) {
        match window {
            [ArrayColumn::Separator(line), ArrayColumn::Separator(_)] => {
                index += 1;
                out.push_str(match line {
                    Line::Solid => " class=\"ml-left-solid ml-border-only\"></mtd><mtd",
                    Line::Dashed => " class=\"ml-left-dashed ml-border-only\"></mtd><mtd",
                });
            }
            _ => break,
        }
    }

    let suffix = match (cols.get(index), cols.get(index + 1)) {
        (Some(ArrayColumn::Separator(line)), Some(ArrayColumn::Column(col))) => {
            out.push_str(match (line, col) {
                (Line::Solid, ColumnAlignment::Left) => " class=\"ml-left-solid ml-cell-left",
                (Line::Solid, ColumnAlignment::Center) => " class=\"ml-left-solid",
                (Line::Solid, ColumnAlignment::Right) => " class=\"ml-left-solid ml-cell-right",
                (Line::Dashed, ColumnAlignment::Left) => " class=\"ml-left-dashed ml-cell-left",
                (Line::Dashed, ColumnAlignment::Center) => " class=\"ml-left-dashed",
                (Line::Dashed, ColumnAlignment::Right) => " class=\"ml-left-dashed ml-cell-right",
            });
            index += 2;
            if let Some(ArrayColumn::Separator(line)) = cols.get(index) {
                index += 1;
                match line {
                    Line::Solid => " ml-right-solid\">",
                    Line::Dashed => " ml-right-dashed\">",
                }
            } else {
                "\">"
            }
        }
        (Some(ArrayColumn::Column(col)), Some(ArrayColumn::Separator(line))) => {
            index += 2;
            match (col, line) {
                (ColumnAlignment::Left, Line::Solid) => " class=\"ml-cell-left ml-right-solid\">",
                (ColumnAlignment::Left, Line::Dashed) => " class=\"ml-cell-left ml-right-dashed\">",
                (ColumnAlignment::Center, Line::Solid) => " class=\"ml-right-solid\">",
                (ColumnAlignment::Center, Line::Dashed) => " class=\"ml-right-dashed\">",
                (ColumnAlignment::Right, Line::Solid) => " class=\"ml-cell-right ml-right-solid\">",
                (ColumnAlignment::Right, Line::Dashed) => {
                    " class=\"ml-cell-right ml-right-dashed\">"
                }
            }
        }
        (Some(ArrayColumn::Column(col)), _) => {
            index += 1;
            match col {
                ColumnAlignment::Left => " class=\"ml-cell-left\">",
                ColumnAlignment::Center => ">",
                ColumnAlignment::Right => " class=\"ml-cell-right\">",
            }
        }
        (None, None) => ">",
        _ => return Err(()),
    };
    out.push_str(suffix);
    Ok(index)
}

fn array_align(
    out: &mut String,
    cols: &[ArrayColumn],
    cols_index: &mut usize,
) -> Result<(), ()> {
    out.push_str("</mtd><mtd");
    let rest = cols.get(*cols_index..).ok_or(())?;
    for col in rest {
        match col {
            ArrayColumn::Separator(line) => {
                *cols_index += 1;
                out.push_str(match line {
                    Line::Solid => " class=\"ml-right-solid ml-border-only\"></mtd><mtd",
                    Line::Dashed => " class=\"ml-right-dashed ml-border-only\"></mtd><mtd",
                });
            }
            ArrayColumn::Column(_) => break,
        }
    }

    let suffix = match (cols.get(*cols_index), cols.get(*cols_index + 1)) {
        (Some(ArrayColumn::Column(col)), Some(ArrayColumn::Separator(line))) => {
            *cols_index += 2;
            match (col, line) {
                (ColumnAlignment::Left, Line::Solid) => " class=\"ml-cell-left ml-right-solid\">",
                (ColumnAlignment::Left, Line::Dashed) => " class=\"ml-cell-left ml-right-dashed\">",
                (ColumnAlignment::Center, Line::Solid) => " class=\"ml-right-solid\">",
                (ColumnAlignment::Center, Line::Dashed) => " class=\"ml-right-dashed\">",
                (ColumnAlignment::Right, Line::Solid) => " class=\"ml-cell-right ml-right-solid\">",
                (ColumnAlignment::Right, Line::Dashed) => {
                    " class=\"ml-cell-right ml-right-dashed\">"
                }
            }
        }
        (Some(ArrayColumn::Column(col)), _) => {
            *cols_index += 1;
            match col {
                ColumnAlignment::Left => " class=\"ml-cell-left\">",
                ColumnAlignment::Center => ">",
                ColumnAlignment::Right => " class=\"ml-cell-right\">",
            }
        }
        _ => return Err(()),
    };
    out.push_str(suffix);
    Ok(())
}

fn array_close_line(out: &mut String, rest_cols: &[ArrayColumn]) {
    out.push_str("</mtd>");
    for col in rest_cols {
        match col {
            ArrayColumn::Separator(Line::Solid) => {
                out.push_str("<mtd class=\"ml-right-solid ml-border-only\"></mtd>");
            }
            ArrayColumn::Separator(Line::Dashed) => {
                out.push_str("<mtd class=\"ml-right-dashed ml-border-only\"></mtd>");
            }
            ArrayColumn::Column(_) => break,
        }
    }
    out.push_str("</mtr><mtr");
}

fn write_env_horizontal_lines(out: &mut String, lines: &[Line]) {
    let mut iter = lines.iter();
    if let Some(last_line) = iter.next_back() {
        for line in iter {
            out.push_str(match line {
                Line::Solid => " class=\"ml-hline\"><mtd class=\"ml-nonumber\"></mtd></mtr><mtr",
                Line::Dashed => {
                    " class=\"ml-hdashline\"><mtd class=\"ml-nonumber\"></mtd></mtr><mtr"
                }
            });
        }
        out.push_str(match last_line {
            Line::Solid => " class=\"ml-hline\"",
            Line::Dashed => " class=\"ml-hdashline\"",
        });
    }
}

/// Map a character to its Unicode Mathematical Alphanumeric Symbols variant for `font`.
fn map_font_char(font: Font, c: char) -> char {
    let code = match (font, c) {
        (Font::BoldScript, 'A'..='Z') => c as u32 + 0x1D48F,
        (Font::BoldScript, 'a'..='z') => c as u32 + 0x1D489,

        (Font::BoldItalic, 'A'..='Z') => c as u32 + 0x1D427,
        (Font::BoldItalic, 'a'..='z') => c as u32 + 0x1D421,
        (Font::BoldItalic, '\u{0391}'..='\u{03A1}' | '\u{03A3}'..='\u{03A9}') => c as u32 + 0x1D38B,
        (Font::BoldItalic, '\u{03F4}') => c as u32 + 0x1D339,
        (Font::BoldItalic, '\u{2207}') => c as u32 + 0x1B52E,
        (Font::BoldItalic, '\u{03B1}'..='\u{03C9}') => c as u32 + 0x1D385,
        (Font::BoldItalic, '\u{2202}') => c as u32 + 0x1B54D,
        (Font::BoldItalic, '\u{03F5}') => c as u32 + 0x1D35B,
        (Font::BoldItalic, '\u{03D1}') => c as u32 + 0x1D380,
        (Font::BoldItalic, '\u{03F0}') => c as u32 + 0x1D362,
        (Font::BoldItalic, '\u{03D5}') => c as u32 + 0x1D37E,
        (Font::BoldItalic, '\u{03F1}') => c as u32 + 0x1D363,
        (Font::BoldItalic, '\u{03D6}') => c as u32 + 0x1D37F,

        (Font::Bold, 'A'..='Z') => c as u32 + 0x1D3BF,
        (Font::Bold, 'a'..='z') => c as u32 + 0x1D3B9,
        (Font::Bold, '\u{0391}'..='\u{03A1}' | '\u{03A3}'..='\u{03A9}') => c as u32 + 0x1D317,
        (Font::Bold, '\u{03F4}') => c as u32 + 0x1D2C5,
        (Font::Bold, '\u{2207}') => c as u32 + 0x1B4BA,
        (Font::Bold, '\u{03B1}'..='\u{03C9}') => c as u32 + 0x1D311,
        (Font::Bold, '\u{2202}') => c as u32 + 0x1B4D9,
        (Font::Bold, '\u{03F5}') => c as u32 + 0x1D2E7,
        (Font::Bold, '\u{03D1}') => c as u32 + 0x1D30C,
        (Font::Bold, '\u{03F0}') => c as u32 + 0x1D2EE,
        (Font::Bold, '\u{03D5}') => c as u32 + 0x1D30A,
        (Font::Bold, '\u{03F1}') => c as u32 + 0x1D2EF,
        (Font::Bold, '\u{03D6}') => c as u32 + 0x1D30B,
        (Font::Bold, '\u{03DC}' | '\u{03DD}') => c as u32 + 0x1D7CA,
        (Font::Bold, '0'..='9') => c as u32 + 0x1D79E,

        (Font::Fraktur, 'A' | 'B' | 'D'..='G' | 'J'..='Q' | 'S'..='Y') => c as u32 + 0x1D4C3,
        (Font::Fraktur, 'C') => c as u32 + 0x20EA,
        (Font::Fraktur, 'H' | 'I') => c as u32 + 0x20C4,
        (Font::Fraktur, 'R') => c as u32 + 0x20CA,
        (Font::Fraktur, 'Z') => c as u32 + 0x20CE,
        (Font::Fraktur, 'a'..='z') => c as u32 + 0x1D4BD,

        (Font::Script, 'A' | 'C' | 'D' | 'G' | 'J' | 'K' | 'N'..='Q' | 'S'..='Z') => {
            c as u32 + 0x1D45B
        }
        (Font::Script, 'B') => c as u32 + 0x20EA,
        (Font::Script, 'E' | 'F') => c as u32 + 0x20EB,
        (Font::Script, 'H') => c as u32 + 0x20C3,
        (Font::Script, 'I') => c as u32 + 0x20C7,
        (Font::Script, 'L') => c as u32 + 0x20C6,
        (Font::Script, 'M') => c as u32 + 0x20E6,
        (Font::Script, 'R') => c as u32 + 0x20C9,
        (Font::Script, 'a'..='d' | 'f' | 'h'..='n' | 'p'..='z') => c as u32 + 0x1D455,
        (Font::Script, 'e') => c as u32 + 0x20CA,
        (Font::Script, 'g') => c as u32 + 0x20A3,
        (Font::Script, 'o') => c as u32 + 0x20C5,

        (Font::Monospace, 'A'..='Z') => c as u32 + 0x1D62F,
        (Font::Monospace, 'a'..='z') => c as u32 + 0x1D629,
        (Font::Monospace, '0'..='9') => c as u32 + 0x1D7C6,

        (Font::SansSerif, 'A'..='Z') => c as u32 + 0x1D55F,
        (Font::SansSerif, 'a'..='z') => c as u32 + 0x1D559,
        (Font::SansSerif, '0'..='9') => c as u32 + 0x1D7B2,

        (Font::DoubleStruck, 'A' | 'B' | 'D'..='G' | 'I'..='M' | 'O' | 'S'..='Y') => {
            c as u32 + 0x1D4F7
        }
        (Font::DoubleStruck, 'C') => c as u32 + 0x20BF,
        (Font::DoubleStruck, 'H') => c as u32 + 0x20C5,
        (Font::DoubleStruck, 'N') => c as u32 + 0x20C7,
        (Font::DoubleStruck, 'P' | 'Q') => c as u32 + 0x20C9,
        (Font::DoubleStruck, 'R') => c as u32 + 0x20CB,
        (Font::DoubleStruck, 'Z') => c as u32 + 0x20CA,
        (Font::DoubleStruck, 'a'..='z') => c as u32 + 0x1D4F1,
        (Font::DoubleStruck, '0'..='9') => c as u32 + 0x1D7A8,

        (Font::DoubleStruckItalic, 'D') => c as u32 + 0x2101,
        (Font::DoubleStruckItalic, 'd' | 'e') => c as u32 + 0x20E2,
        (Font::DoubleStruckItalic, 'i' | 'j') => c as u32 + 0x20DF,

        (Font::Italic, 'A'..='Z') => c as u32 + 0x1D3F3,
        (Font::Italic, 'a'..='g' | 'i'..='z') => c as u32 + 0x1D3ED,
        (Font::Italic, 'h') => c as u32 + 0x20A6,
        (Font::Italic, '\u{0391}'..='\u{03A1}' | '\u{03A3}'..='\u{03A9}') => c as u32 + 0x1D351,
        (Font::Italic, '\u{03F4}') => c as u32 + 0x1D2FF,
        (Font::Italic, '\u{2207}') => c as u32 + 0x1B4F4,
        (Font::Italic, '\u{03B1}'..='\u{03C9}') => c as u32 + 0x1D34B,
        (Font::Italic, '\u{2202}') => c as u32 + 0x1B513,
        (Font::Italic, '\u{03F5}') => c as u32 + 0x1D321,
        (Font::Italic, '\u{03D1}') => c as u32 + 0x1D346,
        (Font::Italic, '\u{03F0}') => c as u32 + 0x1D328,
        (Font::Italic, '\u{03D5}') => c as u32 + 0x1D344,
        (Font::Italic, '\u{03F1}') => c as u32 + 0x1D329,
        (Font::Italic, '\u{03D6}') => c as u32 + 0x1D345,

        (Font::BoldFraktur, 'A'..='Z') => c as u32 + 0x1D52B,
        (Font::BoldFraktur, 'a'..='z') => c as u32 + 0x1D525,

        (Font::SansSerifBoldItalic, 'A'..='Z') => c as u32 + 0x1D5FB,
        (Font::SansSerifBoldItalic, 'a'..='z') => c as u32 + 0x1D5F5,
        (Font::SansSerifBoldItalic, '\u{0391}'..='\u{03A1}' | '\u{03A3}'..='\u{03A9}') => {
            c as u32 + 0x1D3FF
        }
        (Font::SansSerifBoldItalic, '\u{03F4}') => c as u32 + 0x1D3AD,
        (Font::SansSerifBoldItalic, '\u{2207}') => c as u32 + 0x1B5A2,
        (Font::SansSerifBoldItalic, '\u{03B1}'..='\u{03C9}') => c as u32 + 0x1D3F9,
        (Font::SansSerifBoldItalic, '\u{2202}') => c as u32 + 0x1B5C1,
        (Font::SansSerifBoldItalic, '\u{03F5}') => c as u32 + 0x1D3CF,
        (Font::SansSerifBoldItalic, '\u{03D1}') => c as u32 + 0x1D3F4,
        (Font::SansSerifBoldItalic, '\u{03F0}') => c as u32 + 0x1D3D6,
        (Font::SansSerifBoldItalic, '\u{03D5}') => c as u32 + 0x1D3F2,
        (Font::SansSerifBoldItalic, '\u{03F1}') => c as u32 + 0x1D3D7,
        (Font::SansSerifBoldItalic, '\u{03D6}') => c as u32 + 0x1D3F3,

        (Font::SansSerifItalic, 'A'..='Z') => c as u32 + 0x1D5D7,
        (Font::SansSerifItalic, 'a'..='z') => c as u32 + 0x1D5C1,

        (Font::BoldSansSerif, 'A'..='Z') => c as u32 + 0x1D593,
        (Font::BoldSansSerif, 'a'..='z') => c as u32 + 0x1D58D,
        (Font::BoldSansSerif, '\u{0391}'..='\u{03A1}' | '\u{03A3}'..='\u{03A9}') => {
            c as u32 + 0x1D3C5
        }
        (Font::BoldSansSerif, '\u{03F4}') => c as u32 + 0x1D373,
        (Font::BoldSansSerif, '\u{2207}') => c as u32 + 0x1B568,
        (Font::BoldSansSerif, '\u{03B1}'..='\u{03C9}') => c as u32 + 0x1D3BF,
        (Font::BoldSansSerif, '\u{2202}') => c as u32 + 0x1B587,
        (Font::BoldSansSerif, '\u{03F5}') => c as u32 + 0x1D395,
        (Font::BoldSansSerif, '\u{03D1}') => c as u32 + 0x1D3BA,
        (Font::BoldSansSerif, '\u{03F0}') => c as u32 + 0x1D39C,
        (Font::BoldSansSerif, '\u{03D5}') => c as u32 + 0x1D3B8,
        (Font::BoldSansSerif, '\u{03F1}') => c as u32 + 0x1D39D,
        (Font::BoldSansSerif, '\u{03D6}') => c as u32 + 0x1D3B9,
        (Font::BoldSansSerif, '0'..='9') => c as u32 + 0x1D7BC,

        _ => c as u32,
    };
    char::from_u32(code).unwrap_or(c)
}

fn push_escaped_char(out: &mut String, c: char) {
    match c {
        '&' => out.push_str("&amp;"),
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        _ => out.push(c),
    }
}

fn push_escaped_text(out: &mut String, text: &str) {
    for c in text.chars() {
        push_escaped_char(out, c);
    }
}

/// `text` escaped for HTML, in elements and attributes.
fn escape(text: &str) -> String {
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
fn sanitize_html(input: &str) -> String {
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
                    if val_end > val_start && bytes.get(val_end) == Some(&b'>') && bytes[val_end - 1] == b'/' {
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
    for (name, raw_value) in attrs {
        let decoded = decode_entities(raw_value, true);
        let validated: Option<String> = match (tag, name.as_str()) {
            ("a", "href") => {
                if is_safe_href(&decoded) {
                    let trimmed = decoded.trim_matches(|c: char| c.is_ascii_whitespace());
                    if let Some(fragment) = trimmed.strip_prefix('#') {
                        if fragment.is_empty() {
                            Some("#".to_string())
                        } else if fragment.starts_with("fn-") {
                            Some(trimmed.to_string())
                        } else {
                            Some(format!("#fn-{fragment}"))
                        }
                    } else {
                        Some(trimmed.to_string())
                    }
                } else {
                    Some("#".to_string())
                }
            }
            ("a" | "img", "title") | ("img", "alt") => Some(decoded),
            ("img", "src") => {
                if is_safe_image_src(&decoded) {
                    Some(decoded.trim_matches(|c: char| c.is_ascii_whitespace()).to_string())
                } else {
                    Some(String::new())
                }
            }
            ("code", "data-lang") => {
                let valid = decoded.len() <= 64
                    && decoded
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'+' | b'#' | b'.'));
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

/// The slides of the reveal.js Markdown `source`, as HTML, in columns: a `---` line starts the
/// next column, and a `--` line the next slide in it. Speaker notes, from a `Note:` line on, do
/// not show.
pub fn slides(source: &str) -> Vec<Vec<String>> {
    split(source, "---")
        .iter()
        .map(|column| {
            split(column, "--")
                .iter()
                .map(|slide| markdown(without_notes(slide)))
                .collect()
        })
        .collect()
}

/// `source` cut at each line that is `separator`.
fn split(source: &str, separator: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    for line in source.lines() {
        if line.trim_end() == separator {
            parts.push(String::new());
        } else {
            let part = parts.last_mut().expect("never empty");
            part.push_str(line);
            part.push('\n');
        }
    }
    parts
}

/// `slide` without its speaker notes.
fn without_notes(slide: &str) -> &str {
    let mut start = 0;
    for line in slide.split_inclusive('\n') {
        let lower = line.trim_start().to_lowercase();
        if lower.starts_with("note:") || lower.starts_with("notes:") {
            return &slide[..start];
        }
        start += line.len();
    }
    slide
}

/// The CSV `text`, separated by `delimiter`, as a table bounded by [`ROWS_MAX`], [`COLS_MAX`],
/// and [`CELLS_MAX`].
fn table(text: &str, delimiter: u8) -> Kind {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut rows = vec![];
    let mut more = false;
    let mut truncated_columns = false;
    let mut truncated_cells = false;
    let mut total_cells = 0usize;
    for record in reader.records() {
        let Ok(record) = record else { break };
        if rows.len() == ROWS_MAX {
            more = true;
            break;
        }
        let mut row: Vec<String> = record.iter().take(COLS_MAX).map(str::to_string).collect();
        if record.len() > COLS_MAX {
            let extra = record.len() - COLS_MAX;
            let suffix = if extra == 1 { "column" } else { "columns" };
            row.push(format!("… (+{extra} more {suffix})"));
            truncated_columns = true;
            more = true;
        }
        if !rows.is_empty() && total_cells.saturating_add(row.len()) > CELLS_MAX {
            truncated_cells = true;
            more = true;
            break;
        }
        total_cells = total_cells.saturating_add(row.len());
        rows.push(row);
    }
    Kind::Table(Table {
        rows,
        more,
        truncated_columns,
        truncated_cells,
    })
}

/// The lines of the unified diff `text`, each with its kind.
fn diff(text: &str) -> Vec<(DiffLine, String)> {
    let mut in_hunk = false;
    text.lines()
        .map(|line| {
            let kind = if line.starts_with("@@") {
                in_hunk = true;
                DiffLine::Hunk
            } else if line.starts_with("diff ") || line.starts_with("--- ") && !in_hunk {
                in_hunk = false;
                DiffLine::File
            } else if !in_hunk {
                DiffLine::File
            } else if line.starts_with('+') {
                DiffLine::Added
            } else if line.starts_with('-') {
                DiffLine::Removed
            } else {
                DiffLine::Context
            };
            (kind, line.to_string())
        })
        .collect()
}

/// The content lines of a vCard or iCalendar file: unfolded, each as its name, upper case, and
/// its value, unescaped.
fn content_lines(text: &str) -> Vec<(String, String)> {
    let mut lines: Vec<String> = vec![];
    for line in text.lines() {
        match (line.strip_prefix([' ', '\t']), lines.last_mut()) {
            (Some(rest), Some(last)) => last.push_str(rest),
            _ => lines.push(line.to_string()),
        }
    }
    lines
        .iter()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            let name = name.split(';').next()?.trim().to_uppercase();
            let value = value
                .replace("\\n", "\n")
                .replace("\\N", "\n")
                .replace("\\,", ",")
                .replace("\\;", ";")
                .replace("\\\\", "\\");
            Some((name, value))
        })
        .collect()
}

/// The contacts of the vCard file `text`.
fn contacts(text: &str) -> Vec<Card> {
    let mut cards = vec![];
    let mut card: Option<Card> = None;
    for (name, value) in content_lines(text) {
        match (name.as_str(), &mut card) {
            ("BEGIN", None) if value.eq_ignore_ascii_case("VCARD") => {
                card = Some(Card {
                    title: String::new(),
                    fields: vec![],
                });
            }
            ("END", Some(_)) if value.eq_ignore_ascii_case("VCARD") => cards.extend(card.take()),
            ("FN", Some(card)) => card.title = value,
            // The structured name, if there is no formatted one: given then family name.
            ("N", Some(card)) if card.title.is_empty() => {
                let mut parts = value.split(';');
                let family = parts.next().unwrap_or_default();
                let given = parts.next().unwrap_or_default();
                card.title = format!("{given} {family}").trim().to_string();
            }
            (name, Some(card)) => {
                let label = match name {
                    "TEL" => "Phone",
                    "EMAIL" => "Email",
                    "ORG" => "Organization",
                    "TITLE" => "Title",
                    "ADR" => "Address",
                    "URL" => "Web",
                    "BDAY" => "Birthday",
                    "NOTE" => "Note",
                    _ => continue,
                };
                let value = match name {
                    "ADR" | "ORG" => joined(&value),
                    "BDAY" => date(&value),
                    _ => value,
                };
                card.fields.push((label, value));
            }
            _ => {}
        }
    }
    cards
}

/// The events of the iCalendar file `text`, without their alarms.
fn events(text: &str) -> Vec<Card> {
    let mut cards = vec![];
    let mut card: Option<Card> = None;
    let mut nested = 0;
    for (name, value) in content_lines(text) {
        match (name.as_str(), &mut card) {
            ("BEGIN", None) if value.eq_ignore_ascii_case("VEVENT") => {
                card = Some(Card {
                    title: String::new(),
                    fields: vec![],
                });
            }
            ("BEGIN", Some(_)) => nested += 1,
            ("END", Some(_)) if nested > 0 => nested -= 1,
            ("END", Some(_)) if value.eq_ignore_ascii_case("VEVENT") => cards.extend(card.take()),
            (_, Some(_)) if nested > 0 => {}
            ("SUMMARY", Some(card)) => card.title = value,
            (name, Some(card)) => {
                let label = match name {
                    "DTSTART" => "Starts",
                    "DTEND" => "Ends",
                    "LOCATION" => "Where",
                    "ORGANIZER" => "Organizer",
                    "ATTENDEE" => "Attendee",
                    "RRULE" => "Repeats",
                    "DESCRIPTION" => "Description",
                    _ => continue,
                };
                let value = match name {
                    "DTSTART" | "DTEND" => date(&value),
                    "ORGANIZER" | "ATTENDEE" => value
                        .trim_start_matches("mailto:")
                        .trim_start_matches("MAILTO:")
                        .to_string(),
                    _ => value,
                };
                card.fields.push((label, value));
            }
            _ => {}
        }
    }
    cards
}

/// A structured value's parts, such as an address's, joined by commas, the empty ones left out.
fn joined(value: &str) -> String {
    value
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A date or date-time such as `20261025T090000Z` as `2026-10-25 09:00 UTC`; any other as is.
fn date(value: &str) -> String {
    let digits = |range: std::ops::Range<usize>| {
        value
            .get(range)
            .filter(|part| part.bytes().all(|b| b.is_ascii_digit()))
    };
    let (Some(year), Some(month), Some(day)) = (digits(0..4), digits(4..6), digits(6..8)) else {
        return value.to_string();
    };
    let date = format!("{year}-{month}-{day}");
    match (value.get(8..9), digits(9..11), digits(11..13)) {
        (Some("T"), Some(hour), Some(minute)) => {
            let zone = if value.ends_with('Z') { " UTC" } else { "" };
            format!("{date} {hour}:{minute}{zone}")
        }
        _ => date,
    }
}

#[cfg(test)]
mod test {
    use std::io::Write;

    use super::*;

    #[test]
    fn files_sort_by_content_then_name_then_type() {
        // By content, whatever the name.
        assert_eq!(sort("notes.txt", "", b"\x89PNG\r\n\x1a\n...."), Sort::Image);
        assert_eq!(sort("photo", "", b"\x89PNG\r\n\x1a\n...."), Sort::Image);
        assert_eq!(sort("clip", "", b"\x1aE\xdf\xa3....webm"), Sort::Video);
        assert_eq!(sort("x.bin", "", b"%PDF-1.7\n..."), Sort::Document);
        assert_eq!(sort("backup", "", b"7z\xbc\xaf\x27\x1c...."), Sort::Archive);
        // An office document is a ZIP archive.
        assert_eq!(sort("report.docx", "", b"PK\x03\x04...."), Sort::Document);
        // By name, as an attachment's content is not here.
        assert_eq!(sort("main.rs", "", b""), Sort::Code);
        assert_eq!(sort("README.md", "", b""), Sort::Document);
        assert_eq!(sort("song.FLAC", "", b""), Sort::Audio);
        assert_eq!(sort("site.tar.gz", "", b""), Sort::Archive);
        // Then by the type its sender gave, then as text or not.
        assert_eq!(sort("clip", "video/mp4", b""), Sort::Video);
        assert_eq!(sort("letter", "", b"Dear Bob"), Sort::Document);
        assert_eq!(
            sort("blob", "application/octet-stream", b"\0\x01"),
            Sort::Other
        );
        assert_eq!(sort("blob", "", b""), Sort::Other);
    }

    #[test]
    fn kinds_come_from_contents_first() {
        let kind_of = |name, data: &[u8]| kind(name, "", data);
        assert_eq!(kind_of("x.bin", b"%PDF-1.7\n..."), Kind::Pdf);
        assert_eq!(
            kind_of("photo.txt", b"\x89PNG\r\n\x1a\n...."),
            Kind::Image("image/png")
        );
        assert_eq!(
            kind_of("a", b"\0\0\0\x1cftypavif\0\0\0\0"),
            Kind::Image("image/avif")
        );
        assert_eq!(
            kind_of("clip", b"\0\0\0\x14ftypqt  \0\0\0\0"),
            Kind::Video("video/quicktime")
        );
        assert_eq!(
            kind_of("voice", b"\0\0\0\x1cftypM4A \0\0\0\0"),
            Kind::Audio("audio/mp4")
        );
        assert_eq!(
            kind_of("photo.heic", b"\0\0\0\x18ftypheic\0\0\0\0"),
            Kind::None
        );
        assert_eq!(
            kind_of("a.opus", b"OggS\0\x02....OpusHead"),
            Kind::Audio("audio/ogg")
        );
        assert_eq!(kind_of("song", b"ID3\x04\0\0"), Kind::Audio("audio/mpeg"));
        assert_eq!(
            kind_of("logo.svg", b"<?xml version=\"1.0\"?><svg xmlns=\"\"></svg>"),
            Kind::Image("image/svg+xml")
        );
        // Office documents are archives, but show nothing.
        assert_eq!(kind_of("report.docx", b"PK\x03\x04...."), Kind::None);
        assert_eq!(kind_of("blob", &[0xC3, 0x28, 0x00]), Kind::None);
        // Text, highlighted as its name says, unless too long.
        assert_eq!(
            kind_of("main.rs", b"fn main() {}"),
            Kind::Code {
                text: "fn main() {}".into(),
                language: Some("rust")
            }
        );
        let long = vec![b'a'; HIGHLIGHT_MAX + 1];
        assert!(matches!(
            kind_of("a.rs", &long),
            Kind::Code { language: None, .. }
        ));
        assert_eq!(
            kind_of("a.json", br#"{"a":[1,2]}"#),
            Kind::Code {
                text: "{\n  \"a\": [\n    1,\n    2\n  ]\n}".into(),
                language: Some("json")
            }
        );
    }

    #[test]
    fn markdown_keeps_to_itself() {
        let html = markdown(
            "# Title\n\n<script>alert(1)</script>\n\n<!-- .slide: data-x -->\n\n\
             [web](https://example.com) [script](javascript:alert(1)) [file](notes.md)\n\n\
             ![tracker](https://example.com/pixel.png) ![inline](data:image/png;base64,AAAA)\n\n\
             ```rust\nfn main() {}\n```\n\n$a^2$\n",
        );
        assert!(html.contains("<h1>Title</h1>"), "{html}");
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "{html}"
        );
        assert!(!html.contains("<script"), "{html}");
        assert!(!html.contains("slide:"), "{html}");
        assert!(
            html.contains(r#"<a href="https://example.com">web</a>"#),
            "{html}"
        );
        assert!(html.contains(r##"<a href="#">script</a>"##), "{html}");
        assert!(html.contains(r##"<a href="#">file</a>"##), "{html}");
        assert!(html.contains(r#"<img src="" alt="tracker" />"#), "{html}");
        assert!(
            html.contains(r#"src="data:image/png;base64,AAAA""#),
            "{html}"
        );
        assert!(
            html.contains("<pre><code data-lang=\"rust\">fn main() {}\n</code></pre>"),
            "{html}"
        );
        assert!(html.contains("<math"), "{html}");
        // Maths keeps to itself too.
        assert!(!markdown(r"$\text{<script>}$").contains("<script"));
    }

    #[test]
    fn mathml_escapes_operator_names_errors_and_relations() {
        // 1. \operatorname{...} unescaped HTML injection vector.
        let op_img = markdown(r"$\operatorname{<img src=x onerror=alert(1)>}$");
        assert!(!op_img.contains("<img"), "{op_img}");
        assert!(
            op_img.contains("<mi>&lt;img src=x onerror=alert(1)&gt;</mi>"),
            "{op_img}"
        );

        // 2. \mathop{...} unescaped HTML injection vector.
        let op_iframe = markdown(r#"$\mathop{<iframe src="/">}$"#);
        assert!(!op_iframe.contains("<iframe"), "{op_iframe}");
        assert!(op_iframe.contains("&lt;iframe"), "{op_iframe}");

        // 3. Broken LaTeX syntax errors containing <script>alert(1)</script> must bail out to
        // escaped raw TeX rather than emitting raw <merror><mtext>...</mtext></merror>.
        for broken in [
            r"$\frac{1}{<script>alert(1)</script>$",
            r"$\unknowncommand{<script>alert(1)</script>}$",
            r"$\begin{matrix} <script>alert(1)</script>$",
            r"$a^^<script>alert(1)</script>$",
            r"$\left<script>alert(1)</script>$",
        ] {
            let html = markdown(broken);
            assert!(!html.contains("<script"), "input={broken} html={html}");
            assert!(!html.contains("<merror"), "input={broken} html={html}");
            assert!(
                html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
                "input={broken} html={html}"
            );
        }

        // 4. <, >, and & in math relations, delimiters, and environments must be HTML-escaped.
        let rel = markdown(r"$a < b > c$");
        assert!(rel.contains("<mo>&lt;</mo>"), "{rel}");
        assert!(rel.contains("<mo>&gt;</mo>"), "{rel}");
        assert!(!rel.contains("<mo><</mo>"), "{rel}");
        assert!(!rel.contains("<mo>></mo>"), "{rel}");

        let invalid_delim = markdown(r"$\left< x \right>$");
        assert!(!invalid_delim.contains("<merror"), "{invalid_delim}");
        assert!(invalid_delim.contains(r"\left&lt; x \right&gt;"), "{invalid_delim}");

        let angle_delim = markdown(r"$\left\langle x \right\rangle$");
        assert!(angle_delim.contains("<math"), "{angle_delim}");
        assert!(angle_delim.contains("stretchy=\"true\""), "{angle_delim}");

        // Direct MathmlRenderer escaping test for raw `<`, `>`, `&` in delimiters, ops, and ordinaries.
        let synthetic_events = [
            LatexEvent::Begin(Grouping::LeftRight(Some('<'), Some('>'))),
            LatexEvent::Content(Content::Ordinary {
                content: '<',
                stretchy: false,
            }),
            LatexEvent::Content(Content::BinaryOp {
                content: '&',
                small: false,
            }),
            LatexEvent::Content(Content::Delimiter {
                content: '>',
                size: Some(DelimiterSize::Big),
                ty: DelimiterType::Close,
            }),
            LatexEvent::End,
        ];
        let synthetic_html = MathmlRenderer::new(&synthetic_events, DisplayMode::Inline)
            .render()
            .expect("valid synthetic events");
        assert!(
            synthetic_html.contains("<mo stretchy=\"true\">&lt;</mo>"),
            "{synthetic_html}"
        );
        assert!(
            synthetic_html.contains("<mo stretchy=\"true\">&gt;</mo>"),
            "{synthetic_html}"
        );
        assert!(synthetic_html.contains("<mi>&lt;</mi>"), "{synthetic_html}");
        assert!(synthetic_html.contains("&amp;"), "{synthetic_html}");
        assert!(
            synthetic_html.contains("minsize=\"1.2em\" maxsize=\"1.2em\">&gt;</mo>"),
            "{synthetic_html}"
        );

        let mat = markdown(r"$$\begin{pmatrix} a & b \\ c & d \end{pmatrix}$$");
        assert!(mat.contains("<math display=\"block\">"), "{mat}");
        assert!(mat.contains("<mtable"), "{mat}");
        assert!(mat.contains("<mi>a</mi>"), "{mat}");
        assert!(mat.contains("<mi>d</mi>"), "{mat}");

        // 5. No inline style="..." attributes anywhere (CSP style-src 'self' compliance).
        let styled_math = markdown(
            r"$\color{red}{x} + \colorbox{yellow}{y} + \fcolorbox{red}{yellow}{z} \kern -1em w$"
                .to_string()
                .as_str(),
        );
        assert!(!styled_math.contains("style="), "{styled_math}");
        assert!(styled_math.contains("class=\"ml-box\""), "{styled_math}");

        let spaced_align = markdown("$$\\begin{align} a &= b \\\\[1em] c &= d \\end{align}$$");
        assert!(!spaced_align.contains("style="), "{spaced_align}");
        assert!(spaced_align.contains("<mtable"), "{spaced_align}");
    }

    #[test]
    fn markdown_and_sanitizer_block_html_injection_and_unsafe_attributes() {
        // Raw HTML blocks and inline HTML in Markdown render as escaped text, never active tags.
        let raw = markdown(
            r#"<a ping="https://evil.example" href="https://ok.example">click</a>

<iframe src="/"></iframe>

<div class="slides full">phishing overlay</div>

<svg onload="alert(1)"><script>alert(1)</script></svg>

<form action="https://evil.example"><input type="password"></form>
"#,
        );
        assert!(!raw.contains("<a "), "{raw}");
        assert!(!raw.contains("<iframe"), "{raw}");
        assert!(!raw.contains("<div"), "{raw}");
        assert!(!raw.contains("<svg"), "{raw}");
        assert!(!raw.contains("<script"), "{raw}");
        assert!(!raw.contains("<form"), "{raw}");
        assert!(!raw.contains("<input"), "{raw}");
        assert!(raw.contains("&lt;a ping="), "{raw}");

        // Direct sanitizer checks (defense-in-depth if any upstream component ever emits raw HTML).
        let a_ping = sanitize_html(
            r#"<a href="https://example.com" ping="https://evil.example" onclick="alert(1)" style="position:fixed" target="_top">go</a>"#,
        );
        assert_eq!(a_ping, r#"<a href="https://example.com">go</a>"#);

        let entity_js = sanitize_html(
            r#"<a href="&#x6a;avascript:alert(1)">a</a><a href="javascript&colon;alert(1)">b</a><a href="java&#x09;script:alert(1)">c</a>"#,
        );
        assert_eq!(
            entity_js,
            r##"<a href="#">a</a><a href="#">b</a><a href="#">c</a>"##
        );

        let dangerous_tags = sanitize_html(
            r#"<p>ok</p><script>if (a < b) alert(1)</script><style>body{display:none}</style><iframe src="/">bad</iframe><object data="x">bad</object><embed src="x"><form><button>x</button></form><base href="https://evil.example"><meta http-equiv="refresh" content="0"><link rel="stylesheet" href="x"><svg onload=alert(1)><g>bad</g></svg>"#,
        );
        assert_eq!(dangerous_tags, "<p>ok</p>");

        // Non-allowlisted classes (such as app overlay `.slides.full`) are stripped.
        let overlay = sanitize_html(r#"<div class="slides full">overlay</div>"#);
        assert_eq!(overlay, "<div>overlay</div>");

        // Slash-separated attributes and duplicate attributes cannot bypass allowlists.
        let slash_img = sanitize_html(
            r#"<img/onerror=alert(1) src="https://tracker.example/x.png" alt="pic">"#,
        );
        assert_eq!(slash_img, r#"<img src="" alt="pic" />"#);

        // HTML tags injected inside <math> namespace are dropped; MathML tags outside <math> are dropped.
        let mxss = sanitize_html(
            r#"<math display="inline"><mtext><img src=x onerror=alert(1)><a href="https://evil.example">x</a></mtext><mi href="javascript:alert(1)" style="color:red">y</mi></math><mi>stray</mi>"#,
        );
        assert_eq!(
            mxss,
            r#"<math display="inline"><mtext>x</mtext><mi>y</mi></math>stray"#
        );

        // GFM aligned table emits no inline style="..." attribute under CSP style-src 'self'.
        let gfm_table = markdown("| a | b |\n| :--- | ---: |\n| 1 | 2 |\n");
        assert!(gfm_table.contains("<table>"), "{gfm_table}");
        assert!(gfm_table.contains("<th>a</th>"), "{gfm_table}");
        assert!(!gfm_table.contains("style="), "{gfm_table}");

        // Tasklists keep disabled checkbox inputs while arbitrary <input> is dropped.
        let tasklist = markdown("- [x] done\n- [ ] todo\n");
        assert!(
            tasklist.contains(r#"<input disabled="" type="checkbox" checked="" />"#),
            "{tasklist}"
        );
        assert!(
            tasklist.contains(r#"<input disabled="" type="checkbox" />"#),
            "{tasklist}"
        );
        assert_eq!(
            sanitize_html(r#"<input type="text" value="phish"><input type="checkbox" onclick="alert(1)">"#),
            r#"<input disabled="" type="checkbox" />"#
        );
    }

    #[test]
    fn valid_latex_mathml_and_markdown_render_cleanly() {
        let md = markdown(
            "## Euler\n\n\
             Inline $\\frac{\\sqrt{x^2 + 1}}{\\sin(x)}$ and $\\mathbf{v} \\neq 0$ and $\\bigl(a + b\\bigr)$.\n\n\
             $$\\sum_{i=1}^{n} i^2 = \\frac{n(n+1)(2n+1)}{6}$$\n\n\
             $$\\begin{cases} x & x \\ge 0 \\\\ -x & x < 0 \\end{cases}$$\n",
        );
        assert!(md.contains("<h2>Euler</h2>"), "{md}");
        assert!(md.contains("<mfrac>"), "{md}");
        assert!(md.contains("<msqrt>"), "{md}");
        assert!(md.contains("<msup>"), "{md}");
        assert!(md.contains("<munderover>"), "{md}");
        assert!(md.contains("<math display=\"inline\">"), "{md}");
        assert!(md.contains("<math display=\"block\">"), "{md}");
        assert!(md.contains("minsize=\"1.2em\" maxsize=\"1.2em\""), "{md}");
        assert!(md.contains("<mo>&lt;</mo>"), "{md}");
        assert!(!md.contains("style="), "{md}");
    }

    #[test]
    fn csv_table_bounds_columns_and_total_cells() {
        // Adversarial single row with many columns is capped to COLS_MAX + truncation cell.
        let wide_row = (0..COLS_MAX + 50)
            .map(|i| format!("c{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let Kind::Table(wide) = kind("wide.csv", "", wide_row.as_bytes()) else {
            panic!("expected table");
        };
        assert_eq!(wide.rows.len(), 1);
        assert_eq!(wide.rows[0].len(), COLS_MAX + 1);
        assert_eq!(wide.rows[0][0], "c0");
        assert_eq!(wide.rows[0][COLS_MAX - 1], format!("c{}", COLS_MAX - 1));
        assert_eq!(wide.rows[0][COLS_MAX], "… (+50 more columns)");
        assert!(wide.more);
        assert!(wide.truncated_columns);
        assert!(!wide.truncated_cells);
        assert!(wide.notice().unwrap().contains(&COLS_MAX.to_string()));

        // Adversarial grid with many rows x COLS_MAX columns stops at CELLS_MAX total cells.
        let row_line = (0..COLS_MAX).map(|_| "x").collect::<Vec<_>>().join(",");
        let many_rows = vec![row_line; 300].join("\n");
        let Kind::Table(grid) = kind("grid.csv", "", many_rows.as_bytes()) else {
            panic!("expected table");
        };
        let rendered_cells: usize = grid.rows.iter().map(Vec::len).sum();
        assert!(rendered_cells <= CELLS_MAX, "rendered_cells={rendered_cells}");
        assert_eq!(grid.rows.len(), CELLS_MAX / COLS_MAX);
        assert!(grid.more);
        assert!(!grid.truncated_columns);
        assert!(grid.truncated_cells);
        assert!(grid.notice().unwrap().contains(&CELLS_MAX.to_string()));

        // Tall narrow table stops at ROWS_MAX.
        let tall = vec!["a,b"; ROWS_MAX + 10].join("\n");
        let Kind::Table(tall_table) = kind("tall.csv", "", tall.as_bytes()) else {
            panic!("expected table");
        };
        assert_eq!(tall_table.rows.len(), ROWS_MAX);
        assert!(tall_table.more);
        assert!(!tall_table.truncated_columns);
        assert!(!tall_table.truncated_cells);
        assert!(tall_table.notice().unwrap().contains(&ROWS_MAX.to_string()));
    }

    #[test]
    fn slides_follow_reveal() {
        let deck =
            "# One\n\n---\n\n# Two\n\n--\n\n# Two, below\n\nNote: not shown\n\n---\n\n# Three\n";
        let deck = slides(deck);
        assert_eq!(deck.iter().map(Vec::len).collect::<Vec<_>>(), [1, 2, 1]);
        assert!(deck[1][1].contains("Two, below"));
        assert!(!deck[1][1].contains("not shown"));
    }

    #[test]
    fn tables_cards_and_diffs() {
        let Kind::Table(table) = kind("a.csv", "", b"name,age\n\"Doe, J\",30\n") else {
            panic!("a table");
        };
        assert_eq!(table.rows, [["name", "age"], ["Doe, J", "30"]]);
        assert!(!table.more);

        let vcard = "BEGIN:VCARD\r\nVERSION:4.0\r\nN:Doe;Jane;;;\r\nTEL;TYPE=cell:+1 555\r\n\
                     ADR:;;1 Main St;Springfield;;12345;\r\n  USA\r\nEND:VCARD\r\n";
        assert_eq!(
            contacts(vcard),
            [Card {
                title: "Jane Doe".into(),
                fields: vec![
                    ("Phone", "+1 555".into()),
                    ("Address", "1 Main St, Springfield, 12345, USA".into())
                ]
            }]
        );
        let ics = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:Lab meeting\nDTSTART:20261028T140000Z\n\
                   LOCATION:Room 2\\, east\nBEGIN:VALARM\nDESCRIPTION:reminder\nEND:VALARM\n\
                   END:VEVENT\nEND:VCALENDAR\n";
        assert_eq!(
            events(ics),
            [Card {
                title: "Lab meeting".into(),
                fields: vec![
                    ("Starts", "2026-10-28 14:00 UTC".into()),
                    ("Where", "Room 2, east".into())
                ]
            }]
        );

        let lines = diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n same\n");
        let kinds: Vec<_> = lines.iter().map(|(kind, _)| *kind).collect();
        use DiffLine::*;
        assert_eq!(kinds, [File, File, File, Hunk, Removed, Added, Context]);
    }

    #[test]
    fn archives_list_their_entries() {
        let mut zip = ::zip::ZipWriter::new(Cursor::new(vec![]));
        zip.add_directory("docs/", ::zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.start_file("docs/a.txt", ::zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"hello").unwrap();
        let data = zip.finish().unwrap().into_inner();
        assert_eq!(
            kind("a.zip", "", &data),
            Kind::Archive(Listing {
                entries: vec![
                    Entry {
                        path: "docs/".into(),
                        size: 0,
                        directory: true
                    },
                    Entry {
                        path: "docs/a.txt".into(),
                        size: 5,
                        directory: false
                    },
                ],
                complete: true,
            })
        );

        let mut tar = ::tar::Builder::new(vec![]);
        let mut header = ::tar::Header::new_gnu();
        header.set_size(5);
        header.set_cksum();
        tar.append_data(&mut header, "a.txt", &b"hello"[..])
            .unwrap();
        let tar = tar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
        gz.write_all(&tar).unwrap();
        let expected = Kind::Archive(Listing {
            entries: vec![Entry {
                path: "a.txt".into(),
                size: 5,
                directory: false,
            }],
            complete: true,
        });
        assert_eq!(kind("a.tar.gz", "", &gz.finish().unwrap()), expected);
        assert_eq!(kind("a.tar", "", &tar), expected);
    }

    #[test]
    fn listing_a_tar_stops_at_its_limit() {
        // A small file, one that unpacks to 4 MiB of zeros, and another after it.
        let mut builder = ::tar::Builder::new(vec![]);
        for (name, size) in [("a.txt", 5), ("zeros", 4 << 20), ("b.txt", 5)] {
            let mut header = ::tar::Header::new_gnu();
            header.set_size(size);
            header.set_cksum();
            builder
                .append_data(&mut header, name, std::io::repeat(0).take(size))
                .unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
        gz.write_all(&builder.into_inner().unwrap()).unwrap();
        let gz = gz.finish().unwrap();
        assert!(gz.len() < 64 << 10, "{} bytes", gz.len());
        let names = |listing: &Listing| -> Vec<String> {
            listing
                .entries
                .iter()
                .map(|entry| entry.path.clone())
                .collect()
        };

        // Within the limit, all of it.
        let whole = tar(GzDecoder::new(&gz[..]), 8 << 20).unwrap();
        assert_eq!(names(&whole), ["a.txt", "zeros", "b.txt"]);
        assert!(whole.complete);

        // Past it, what came before, and that there is more.
        let cut = tar(GzDecoder::new(&gz[..]), 1 << 20).unwrap();
        assert_eq!(names(&cut), ["a.txt", "zeros"]);
        assert!(!cut.complete);
    }

    #[test]
    fn gzip_that_is_not_a_tar_lists_nothing() {
        let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
        gz.write_all(&[0xFF; 4096]).unwrap();
        assert_eq!(
            tar(GzDecoder::new(&gz.finish().unwrap()[..]), UNPACKED_MAX),
            None
        );
    }

    #[test]
    fn markdown_footnotes_prefix_ids_and_hrefs_preventing_dom_clobbering() {
        let md = "Attach something[^file-picker].\n\n[^file-picker]: footnote body\n";
        let html = markdown(md);
        assert!(
            !html.contains(r#"id="file-picker""#),
            "footnote clobbered #file-picker: {html}"
        );
        assert!(
            !html.contains(r##"href="#file-picker""##),
            "footnote href missing fn- prefix: {html}"
        );
        assert!(
            html.contains(r#"id="fn-file-picker""#),
            "expected fn- prefixed id: {html}"
        );
        assert!(
            html.contains(r##"href="#fn-file-picker""##),
            "expected fn- prefixed href: {html}"
        );
        // Sanitizer must remain idempotent (re-sanitizing does not double-prefix).
        assert_eq!(sanitize_html(&html), html);

        // Max-length (64-char) footnote id remains idempotent after fn- prefixing.
        let long_id = "a".repeat(64);
        let long_html = sanitize_html(&format!(
            r##"<div class="footnote-definition" id="{long_id}"><a href="#{long_id}">1</a></div>"##
        ));
        assert!(long_html.contains(&format!(r#"id="fn-{long_id}""#)));
        assert!(long_html.contains(&format!(r##"href="#fn-{long_id}""##)));
        assert_eq!(sanitize_html(&long_html), long_html);
    }
}
