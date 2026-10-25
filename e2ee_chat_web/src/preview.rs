//! What the viewer shows of a file. Its kind comes from its content first, as the sender's name
//! and type are only hints, then from its name; for some kinds, Rust prepares what shows:
//! Markdown as HTML, slides, tables, listings of archives, and cards of contacts and events.
//!
//! Every file comes from a peer: Markdown's raw HTML shows as written text, its links go only to
//! the web or mail, and its images only come from `data:` URLs; the page's Content-Security-Policy
//! stops the rest.

use std::io::{Cursor, Read};

use e2ee_chat_preview::language::{self, Language};
use flate2::read::GzDecoder;
use pulldown_cmark::{CodeBlockKind, CowStr, Event, Options, Parser, Tag, TagEnd};
use pulldown_latex::{RenderConfig, Storage, config::DisplayMode};

/// The most bytes of text shown, ...
pub const TEXT_MAX: usize = 5_000_000;
/// ... and highlighted, which takes a while.
pub const HIGHLIGHT_MAX: usize = 1_000_000;
/// The most rows of a table shown, ...
pub const ROWS_MAX: usize = 1_000;
/// ... and entries of an archive.
pub const ENTRIES_MAX: usize = 10_000;

/// Office documents, which show no preview, not even as the archives some of them are.
const OFFICE: [&str; 13] = [
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "odg", "pages", "numbers",
    "key",
];

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
    Archive(Vec<Entry>),
    /// Contacts or events.
    Cards(Vec<Card>),
    Diff(Vec<(DiffLine, String)>),
    None,
}

/// The rows of a table, the first one as its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub rows: Vec<Vec<String>>,
    /// Whether there are more rows than [`ROWS_MAX`], which do not show.
    pub more: bool,
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
    if let Some(kind) = sniff(&lower, data) {
        return kind;
    }
    // Media without a signature known here, as the sender's browser named it.
    match mime.to_lowercase().as_str() {
        "video/mp4" => return Kind::Video("video/mp4"),
        "video/webm" => return Kind::Video("video/webm"),
        "audio/mpeg" => return Kind::Audio("audio/mpeg"),
        "audio/aac" => return Kind::Audio("audio/aac"),
        _ => {}
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
            code(pretty.unwrap_or_else(|_| text.to_string()), language::named("json"))
        }
        "diff" | "patch" => Kind::Diff(diff(text)),
        "vcf" | "vcard" => Kind::Cards(contacts(text)),
        "ics" | "ical" => Kind::Cards(events(text)),
        "svg" if text.contains("<svg") => Kind::Image("image/svg+xml"),
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
        [b'P', b'K', 3, 4, ..] | [b'P', b'K', 5, 6, ..] => Kind::Archive(zip(data)?),
        [0x1F, 0x8B, ..] => Kind::Archive(tar(GzDecoder::new(data))?),
        _ if data.get(257..262) == Some(b"ustar") => Kind::Archive(tar(data)?),
        _ => return None,
    })
}

/// The entries of the ZIP archive `data`, at most [`ENTRIES_MAX`].
fn zip(data: &[u8]) -> Option<Vec<Entry>> {
    let mut archive = ::zip::ZipArchive::new(Cursor::new(data)).ok()?;
    (0..archive.len().min(ENTRIES_MAX))
        .map(|index| {
            let file = archive.by_index_raw(index).ok()?;
            Some(Entry {
                path: file.name().ok()?.into_owned(),
                size: file.size(),
                directory: file.is_dir(),
            })
        })
        .collect()
}

/// The entries of the tar archive `reader` reads, at most [`ENTRIES_MAX`].
fn tar(reader: impl Read) -> Option<Vec<Entry>> {
    let mut archive = ::tar::Archive::new(reader);
    archive
        .entries()
        .ok()?
        .take(ENTRIES_MAX)
        .map(|entry| {
            let entry = entry.ok()?;
            Some(Entry {
                path: entry.path().ok()?.to_string_lossy().into_owned(),
                size: entry.header().size().ok()?,
                directory: entry.header().entry_type().is_dir(),
            })
        })
        .collect()
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
    html
}

/// A link to the web, to mail, or within the document; any other goes nowhere.
fn safe_link(url: CowStr<'_>) -> CowStr<'_> {
    let lower = url.to_lowercase();
    if ["http://", "https://", "mailto:", "#"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        url
    } else {
        "#".into()
    }
}

/// An image from a `data:` URL; any other shows none, rather than reach out.
fn safe_image(url: CowStr<'_>) -> CowStr<'_> {
    if url.to_lowercase().starts_with("data:image/") {
        url
    } else {
        "".into()
    }
}

/// The TeX `tex` as MathML, or as written if it does not render.
fn mathml(tex: &str, display_mode: DisplayMode) -> String {
    let storage = Storage::new();
    let parser = pulldown_latex::Parser::new(tex, &storage);
    let config = RenderConfig {
        display_mode,
        ..RenderConfig::default()
    };
    let mut mathml = String::new();
    match pulldown_latex::push_mathml(&mut mathml, parser, config) {
        Ok(()) => mathml,
        Err(_) => escape(tex),
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

/// The CSV `text`, separated by `delimiter`, as a table.
fn table(text: &str, delimiter: u8) -> Kind {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut rows = vec![];
    let mut more = false;
    for record in reader.records() {
        let Ok(record) = record else { break };
        if rows.len() == ROWS_MAX {
            more = true;
            break;
        }
        rows.push(record.iter().map(str::to_string).collect());
    }
    Kind::Table(Table { rows, more })
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
            Kind::Archive(vec![
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
            ])
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
        let expected = Kind::Archive(vec![Entry {
            path: "a.txt".into(),
            size: 5,
            directory: false,
        }]);
        assert_eq!(kind("a.tar.gz", "", &gz.finish().unwrap()), expected);
        assert_eq!(kind("a.tar", "", &tar), expected);
    }
}
