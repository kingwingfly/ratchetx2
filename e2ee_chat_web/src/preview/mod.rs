//! What the viewer shows of a file. Its kind comes from its content first, as the sender's name
//! and type are only hints, then from its name; for some kinds, Rust prepares what shows:
//! Markdown as HTML, slides, tables, listings of archives, and cards of contacts and events.
//!
//! Every file comes from a peer: Markdown's raw HTML shows as written text, its links go only to
//! the web or mail, and its images only come from `data:` URLs; the page's Content-Security-Policy
//! stops the rest.

mod archive;
mod markdown;
mod mathml;
mod sanitize;
mod structured;
#[cfg(test)]
mod tests;

pub use archive::{Entry, Listing};
pub use e2ee_chat_preview::audio::Tags;
use e2ee_chat_preview::language::{self, Language};
use flate2::read::GzDecoder;
pub use markdown::{markdown, slides};
pub use sanitize::validate_highlight_html;
pub use structured::{Card, Cards, Diff, DiffLine, Table};

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
/// The most bytes of ZIP central directory metadata indexed for a listing.
pub const ZIP_CENTRAL_DIR_MAX: u64 = 8 << 20;

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
    Cards(Cards),
    Diff(Diff),
    None,
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
        "csv" => Kind::Table(structured::table(text, b',')),
        "tsv" => Kind::Table(structured::table(text, b'\t')),
        "json" => code(
            pretty_json_bounded(text).unwrap_or_else(|| text.to_string()),
            language::named("json"),
        ),
        "diff" | "patch" => Kind::Diff(structured::diff(text)),
        "vcf" | "vcard" => Kind::Cards(structured::contacts(text)),
        "ics" | "ical" => Kind::Cards(structured::events(text)),
        // An SVG image showed already, as `sniff` found it; any other `.svg` shows as XML.
        _ => code(text.to_string(), language::of_file(name)),
    }
}

/// Maximum raw JSON input size pretty-printed on the main thread (keeps both the parsed DOM tree
/// and indented output strictly bounded).
const JSON_PRETTY_INPUT_MAX: usize = 256 * 1024;

/// Pretty-print `text` as JSON when small enough and when the indented output stays within
/// [`TEXT_MAX`], preventing deeply nested JSON from amplifying memory on the UI thread.
fn pretty_json_bounded(text: &str) -> Option<String> {
    use std::io::Write as _;

    struct BoundedVec {
        buf: Vec<u8>,
        max: usize,
    }

    impl std::io::Write for BoundedVec {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if self.buf.len().saturating_add(data.len()) > self.max {
                return Err(std::io::Error::other("pretty JSON exceeds TEXT_MAX"));
            }
            self.buf.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    if text.len() > JSON_PRETTY_INPUT_MAX {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut writer = BoundedVec {
        buf: Vec::with_capacity(text.len().min(64 * 1024)),
        max: TEXT_MAX,
    };
    serde_json::to_writer_pretty(&mut writer, &value).ok()?;
    writer.flush().ok()?;
    String::from_utf8(writer.buf).ok()
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
        [b'P', b'K', 3, 4, ..] | [b'P', b'K', 5, 6, ..] => Kind::Archive(archive::zip(data)?),
        [0x1F, 0x8B, ..] => Kind::Archive(archive::tar(GzDecoder::new(data), UNPACKED_MAX)?),
        // Already as large as it gets, and listed as fast as it is read.
        _ if data.get(257..262) == Some(b"ustar") => Kind::Archive(archive::tar(data, u64::MAX)?),
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
