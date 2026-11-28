//! Unified magic-byte content sniffing and RFC 9110 MIME parsing shared across `e2ee_chat_preview`
//! and `e2ee_chat_web`.
//!
//! Uses individual [`infer`] format matchers on a bounded header prefix (avoiding `infer::get`'s
//! global matcher shadowing and `infer::archive::{is_zst,is_lz4}`'s unchecked 32-bit `8 + data_len`
//! wrap on `wasm32`) together with strict structural guards for formats whose short magic prefixes
//! would otherwise false-positive on plain text or malformed headers (BMP, ID3v2, Ogg, FLAC, GIF,
//! WebP, ICO, ISOBMFF `ftyp` / HEIF, and SVG), plus [`mime::Mime`] for canonical MIME parsing and
//! parameter validation.

/// Raster image MIME types accepted for audio cover art and RPC wire decoding.
///
/// Explicitly excludes SVG (`image/svg+xml`) and ICO.
pub const RASTER_IMAGE_MIMES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
    "image/bmp",
];

/// Prefix length passed to [`infer`] matchers, keeping header inspection strictly O(1).
const INFER_PREFIX_MAX: usize = 512;

/// Prefix length inspected for UTF-8 text classification and `<svg` tag sniffing.
const SNIFF_PREFIX_MAX: usize = 8 * 1024;

/// Classified media format from magic-byte sniffing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Image(&'static str),
    Video(&'static str),
    Audio(&'static str),
    /// Recognized media container/format that browsers here cannot display (e.g. HEIF/HEIC).
    Unsupported,
}

/// Classified archive container from magic-byte sniffing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    Zip,
    Gzip,
    Tar,
    Other,
}

fn infer_prefix(data: &[u8]) -> &[u8] {
    &data[..data.len().min(INFER_PREFIX_MAX)]
}

/// Whether `mime` is in the strict raster cover-art MIME allowlist [`RASTER_IMAGE_MIMES`].
pub fn is_raster_image_mime(mime: &str) -> bool {
    RASTER_IMAGE_MIMES.contains(&mime)
}

/// Parse an RFC 9110 media type string with [`mime::Mime`], rejecting any ASCII control characters
/// (such as CR/LF/NUL header-injection attempts), empty type/subtype (e.g. `"video/"`), and
/// malformed parameter syntax without panicking.
pub fn parse_mime(raw: &str) -> Option<mime::Mime> {
    if raw.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7F) {
        return None;
    }
    let parsed = raw.trim_matches([' ', '\t']).parse::<mime::Mime>().ok()?;
    if parsed.type_().as_str().is_empty() || parsed.subtype().as_str().is_empty() {
        return None;
    }
    Some(parsed)
}

/// Extract the canonical lowercase MIME essence (`type/subtype`) from `raw`, stripping valid
/// parameters and returning `None` if `raw` is empty or malformed.
pub fn mime_essence(raw: &str) -> Option<String> {
    parse_mime(raw).map(|parsed| parsed.essence_str().to_string())
}

/// Validate a streaming media MIME type for same-origin service-worker responses: accepts only
/// valid `video/*` or `audio/*` types (with optional RFC 9110 parameters such as `; codecs=...`)
/// whose subtype uses only ASCII alphanumeric, `+`, `-`, or `.` characters, returning the bare
/// lowercase essence; otherwise falls back to `"application/octet-stream"`.
pub fn stream_media_mime(raw: &str) -> String {
    if let Some(parsed) = parse_mime(raw)
        && matches!(parsed.type_(), mime::VIDEO | mime::AUDIO)
        && parsed
            .subtype()
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte))
    {
        parsed.essence_str().to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

/// Check whether `data` starts with valid NUL-free UTF-8 text within its first 8 KiB, tolerating
/// a multi-byte character split cleanly across the prefix boundary.
pub fn is_utf8_text_prefix(data: &[u8]) -> bool {
    utf8_prefix(data).is_some()
}

/// Decode the valid UTF-8 prefix of `data` (up to 8 KiB), returning `None` if `data` is empty,
/// contains NUL bytes, or has invalid UTF-8 within that prefix.
pub fn utf8_prefix(data: &[u8]) -> Option<&str> {
    if data.is_empty() {
        return None;
    }
    let sample = &data[..data.len().min(SNIFF_PREFIX_MAX)];
    if sample.contains(&0) {
        return None;
    }
    match std::str::from_utf8(sample) {
        Ok(text) => Some(text),
        Err(err) if sample.len() < data.len() && err.error_len().is_none() => {
            std::str::from_utf8(&sample[..err.valid_up_to()]).ok()
        }
        Err(_) => None,
    }
}

/// Validate a Windows/OS2 BMP header (14-byte file header + recognized DIB header size, zeroed
/// reserved fields, valid non-zero dimensions, single color plane, valid bits-per-pixel, and
/// consistent file size / pixel data offset) so plain text starting with `"BM"` or malformed
/// headers are never misclassified as BMP images.
pub fn is_valid_bmp(data: &[u8]) -> bool {
    if data.len() < 26 || !infer::image::is_bmp(data) {
        return false;
    }
    let file_size = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
    let reserved = &data[6..10];
    let pixel_offset = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
    let dib_size = u32::from_le_bytes([data[14], data[15], data[16], data[17]]);
    if reserved != [0, 0, 0, 0] {
        return false;
    }
    if !matches!(dib_size, 12 | 40 | 52 | 56 | 64 | 108 | 124) {
        return false;
    }
    let header_end = 14u32.saturating_add(dib_size);
    if data.len() < header_end as usize || file_size < header_end || pixel_offset < header_end {
        return false;
    }
    if pixel_offset > file_size {
        return false;
    }
    if dib_size == 12 {
        let width = u16::from_le_bytes([data[18], data[19]]);
        let height = u16::from_le_bytes([data[20], data[21]]);
        let planes = u16::from_le_bytes([data[22], data[23]]);
        let bpp = u16::from_le_bytes([data[24], data[25]]);
        width > 0 && height > 0 && planes == 1 && matches!(bpp, 1 | 2 | 4 | 8 | 16 | 24 | 32)
    } else {
        let width = i32::from_le_bytes([data[18], data[19], data[20], data[21]]);
        let height = i32::from_le_bytes([data[22], data[23], data[24], data[25]]);
        let planes = u16::from_le_bytes([data[26], data[27]]);
        let bpp = u16::from_le_bytes([data[28], data[29]]);
        width > 0
            && height != 0
            && height != i32::MIN
            && planes == 1
            && matches!(bpp, 1 | 2 | 4 | 8 | 16 | 24 | 32)
    }
}

/// Validate an ID3v2 header (10 bytes: `"ID3"`, version `2..=4`, non-0xFF revision, valid
/// version-specific flags, and 4 synchsafe size bytes `< 0x80`) so text starting with `"ID3"` is
/// never misclassified as MP3 audio.
pub fn is_valid_id3v2(data: &[u8]) -> bool {
    if data.len() < 10 || !data.starts_with(b"ID3") {
        return false;
    }
    let version = data[3];
    let revision = data[4];
    let flags = data[5];
    let valid_flags = match version {
        2 => flags & 0x3F == 0,
        3 => flags & 0x1F == 0,
        4 => flags & 0x0F == 0,
        _ => return false,
    };
    revision != 0xFF && valid_flags && data[6..10].iter().all(|&b| b < 0x80)
}

/// Validate an Ogg BOS page header (version `0`, valid `header_type` with BOS flag set on page 0,
/// and complete segment lacing table) so text starting with `"OggS"` is never misclassified.
pub fn is_valid_ogg(data: &[u8]) -> bool {
    if data.len() < 28 || !infer::audio::is_ogg(data) {
        return false;
    }
    let version = data[4];
    let header_type = data[5];
    let page_segments = usize::from(data[26]);
    version == 0
        && header_type & !0x07 == 0
        && header_type & 0x02 != 0
        && page_segments > 0
        && data.len() >= 27 + page_segments
}

/// Validate a FLAC stream marker followed by the mandatory 34-byte STREAMINFO metadata block so
/// text starting with `"fLaC"` is never misclassified.
pub fn is_valid_flac(data: &[u8]) -> bool {
    if data.len() < 42 || !infer::audio::is_flac(data) {
        return false;
    }
    let block_type = data[4] & 0x7F;
    let block_len =
        (usize::from(data[5]) << 16) | (usize::from(data[6]) << 8) | usize::from(data[7]);
    block_type == 0 && block_len == 34
}

/// Whether `data` begins with a PDF header (`"%PDF-"`).
pub fn is_pdf(data: &[u8]) -> bool {
    infer::archive::is_pdf(infer_prefix(data)) && data.starts_with(b"%PDF-")
}

/// Discriminate ISO Base Media File Format (`ftyp`) containers by major and compatible brands,
/// separating AVIF (`image/avif`), QuickTime (`video/quicktime`), M4A/M4B/M4P (`audio/mp4`),
/// unsupported HEIF/HEIC (`MediaKind::Unsupported`), and generic MP4 (`video/mp4`).
pub fn sniff_isobmff(data: &[u8]) -> Option<MediaKind> {
    if data.len() < 12 || &data[4..8] != b"ftyp" {
        return None;
    }
    let prefix = infer_prefix(data);
    let major = &data[8..12];
    if matches!(major, b"avif" | b"avis") || infer::image::is_avif(prefix) {
        return Some(MediaKind::Image("image/avif"));
    }
    if major == b"qt  " {
        return Some(MediaKind::Video("video/quicktime"));
    }
    if matches!(major, b"M4A " | b"M4B " | b"M4P ") {
        return Some(MediaKind::Audio("audio/mp4"));
    }
    if matches!(
        major,
        b"heic"
            | b"heix"
            | b"hevc"
            | b"hevx"
            | b"heim"
            | b"heis"
            | b"hevm"
            | b"hevs"
            | b"mif1"
            | b"msf1"
    ) || infer::image::is_heif(prefix)
    {
        return Some(MediaKind::Unsupported);
    }
    Some(MediaKind::Video("video/mp4"))
}

/// Sniff a basic web raster image (PNG, JPEG, GIF, WebP) from magic bytes. Never classifies SVG.
pub fn sniff_basic_image(data: &[u8]) -> Option<&'static str> {
    let prefix = infer_prefix(data);
    if infer::image::is_png(prefix) {
        Some("image/png")
    } else if infer::image::is_jpeg(prefix) {
        Some("image/jpeg")
    } else if infer::image::is_gif(prefix) && data.starts_with(b"GIF8") {
        // Guard `infer`'s 3-byte `"GIF"` check so plain text starting with `"GIF"` is rejected.
        Some("image/gif")
    } else if infer::image::is_webp(prefix) && data.starts_with(b"RIFF") {
        // Guard `infer`'s offset-8 `"WEBP"` check so non-RIFF buffers are rejected.
        Some("image/webp")
    } else {
        None
    }
}

/// Sniff a safe raster image suitable for embedded audio cover art (PNG, JPEG, GIF, WebP, AVIF,
/// strict BMP). Never classifies SVG or ICO.
pub fn sniff_cover_image(data: &[u8]) -> Option<&'static str> {
    if let Some(mime) = sniff_basic_image(data) {
        return Some(mime);
    }
    if matches!(sniff_isobmff(data), Some(MediaKind::Image("image/avif"))) {
        return Some("image/avif");
    }
    if is_valid_bmp(data) {
        return Some("image/bmp");
    }
    None
}

/// Sniff any safe raster image displayed by browsers (PNG, JPEG, GIF, WebP, AVIF, strict BMP, or
/// non-empty ICO). Never classifies SVG.
pub fn sniff_raster_image(data: &[u8]) -> Option<&'static str> {
    if let Some(mime) = sniff_cover_image(data) {
        return Some(mime);
    }
    if infer::image::is_ico(infer_prefix(data)) && data.get(4).is_some_and(|&count| count > 0) {
        return Some("image/x-icon");
    }
    None
}

/// Sniff a browser-displayable preview image: any safe raster image from [`sniff_raster_image`],
/// or a bounded `.svg` file (<= `svg_max` bytes) whose valid UTF-8 8 KiB prefix contains `"<svg"`.
///
/// Callers displaying `"image/svg+xml"` MUST render it strictly inside an `<img>` element where
/// scripts cannot execute.
pub fn sniff_preview_image(name: &str, data: &[u8], svg_max: usize) -> Option<&'static str> {
    if let Some(mime) = sniff_raster_image(data) {
        return Some(mime);
    }
    if data.len() <= svg_max
        && name.to_ascii_lowercase().ends_with(".svg")
        && utf8_prefix(data).is_some_and(|prefix| prefix.contains("<svg"))
    {
        return Some("image/svg+xml");
    }
    None
}

/// Sniff a media file (image, video, audio, or recognized unsupported media such as HEIF) from its
/// magic bytes and (for bounded SVG only) filename `name`.
pub fn sniff_media(name: &str, data: &[u8], svg_max: usize) -> Option<MediaKind> {
    if let Some(mime) = sniff_preview_image(name, data, svg_max) {
        return Some(MediaKind::Image(mime));
    }
    if let Some(iso) = sniff_isobmff(data) {
        return Some(iso);
    }
    let prefix = infer_prefix(data);
    let window = &data[..data.len().min(64)];
    let has = |needle: &[u8]| window.windows(needle.len()).any(|bytes| bytes == needle);
    if infer::video::is_webm(prefix) {
        return Some(if has(b"webm") {
            MediaKind::Video("video/webm")
        } else {
            MediaKind::Video("video/x-matroska")
        });
    }
    if is_valid_ogg(data) {
        return Some(if has(b"theora") {
            MediaKind::Video("video/ogg")
        } else {
            MediaKind::Audio("audio/ogg")
        });
    }
    if is_valid_flac(data) {
        return Some(MediaKind::Audio("audio/flac"));
    }
    if infer::audio::is_wav(prefix) {
        return Some(MediaKind::Audio("audio/wav"));
    }
    if is_valid_id3v2(data) {
        return Some(MediaKind::Audio("audio/mpeg"));
    }
    match data {
        // ADTS AAC frames, then MPEG audio frames.
        [0xFF, second, ..] if second & 0xF6 == 0xF0 => Some(MediaKind::Audio("audio/aac")),
        [0xFF, second, ..] if second & 0xE0 == 0xE0 && second & 0x06 != 0 => {
            Some(MediaKind::Audio("audio/mpeg"))
        }
        _ => None,
    }
}

/// Iterative Zstandard frame detector (standard magic `0xFD2FB528` plus bounded skippable-frame
/// walking with overflow-checked `usize` arithmetic, avoiding `infer::archive::is_zst`'s unchecked
/// `8 + data_len` wrap and recursion on 32-bit `wasm32`).
fn is_valid_zstd(mut buf: &[u8]) -> bool {
    const ZSTD_MAGIC: &[u8; 4] = &[0x28, 0xB5, 0x2F, 0xFD];
    const ZSTD_SKIP_START: u32 = 0x184D_2A50;
    const ZSTD_SKIP_MASK: u32 = 0xFFFF_FFF0;
    const MAX_SKIPPABLE_FRAMES: usize = 64;

    for _ in 0..=MAX_SKIPPABLE_FRAMES {
        if buf.starts_with(ZSTD_MAGIC) {
            return true;
        }
        if buf.len() < 8 {
            return false;
        }
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if (magic & ZSTD_SKIP_MASK) != ZSTD_SKIP_START {
            return false;
        }
        let Ok(data_len) = usize::try_from(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]))
        else {
            return false;
        };
        let Some(next_offset) = 8usize.checked_add(data_len) else {
            return false;
        };
        let Some(rest) = buf.get(next_offset..) else {
            return false;
        };
        buf = rest;
    }
    false
}

/// Sniff an archive container from its magic bytes using targeted [`infer::archive`] matchers
/// (avoiding global matcher shadowing and unsafe recursive Zstd/LZ4 matchers).
pub fn sniff_archive(data: &[u8]) -> Option<ArchiveKind> {
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        return Some(ArchiveKind::Zip);
    }
    let prefix = infer_prefix(data);
    if infer::archive::is_gz(prefix) || data.starts_with(&[0x1F, 0x8B]) {
        return Some(ArchiveKind::Gzip);
    }
    if infer::archive::is_tar(prefix) {
        return Some(ArchiveKind::Tar);
    }
    if infer::archive::is_7z(prefix)
        || infer::archive::is_rar(prefix)
        || data.starts_with(b"Rar!\x1A\x07")
        || infer::archive::is_xz(prefix)
        || infer::archive::is_bz2(prefix)
        || is_valid_zstd(prefix)
    {
        return Some(ArchiveKind::Other);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SVG_MAX: usize = 2 << 20;

    fn valid_bmp_info(width: i32, height: i32, planes: u16, bpp: u16) -> Vec<u8> {
        let mut bmp = vec![0u8; 58];
        bmp[0..2].copy_from_slice(b"BM");
        bmp[2..6].copy_from_slice(&58u32.to_le_bytes());
        bmp[10..14].copy_from_slice(&54u32.to_le_bytes());
        bmp[14..18].copy_from_slice(&40u32.to_le_bytes());
        bmp[18..22].copy_from_slice(&width.to_le_bytes());
        bmp[22..26].copy_from_slice(&height.to_le_bytes());
        bmp[26..28].copy_from_slice(&planes.to_le_bytes());
        bmp[28..30].copy_from_slice(&bpp.to_le_bytes());
        bmp
    }

    fn valid_bmp_core(width: u16, height: u16, planes: u16, bpp: u16) -> Vec<u8> {
        let mut bmp = vec![0u8; 30];
        bmp[0..2].copy_from_slice(b"BM");
        bmp[2..6].copy_from_slice(&30u32.to_le_bytes());
        bmp[10..14].copy_from_slice(&26u32.to_le_bytes());
        bmp[14..18].copy_from_slice(&12u32.to_le_bytes());
        bmp[18..20].copy_from_slice(&width.to_le_bytes());
        bmp[20..22].copy_from_slice(&height.to_le_bytes());
        bmp[22..24].copy_from_slice(&planes.to_le_bytes());
        bmp[24..26].copy_from_slice(&bpp.to_le_bytes());
        bmp
    }

    fn minimal_ogg(payload: &[u8]) -> Vec<u8> {
        let mut ogg = Vec::with_capacity(28 + payload.len());
        ogg.extend_from_slice(b"OggS");
        ogg.push(0); // version
        ogg.push(0x02); // BOS
        ogg.extend_from_slice(&[0u8; 8]); // granule
        ogg.extend_from_slice(&1u32.to_le_bytes()); // serial
        ogg.extend_from_slice(&0u32.to_le_bytes()); // sequence
        ogg.extend_from_slice(&0u32.to_le_bytes()); // crc
        ogg.push(1); // 1 segment
        ogg.push(payload.len() as u8);
        ogg.extend_from_slice(payload);
        ogg
    }

    fn minimal_flac() -> Vec<u8> {
        let mut flac = vec![0u8; 42];
        flac[0..4].copy_from_slice(b"fLaC");
        flac[4] = 0x80; // last metadata block, type 0 = STREAMINFO
        flac[5..8].copy_from_slice(&[0, 0, 34]);
        flac
    }

    #[test]
    fn sniffs_supported_raster_images_and_rejects_svg_and_false_positives() {
        assert_eq!(
            sniff_basic_image(b"\x89PNG\r\n\x1a\n...."),
            Some("image/png")
        );
        assert_eq!(
            sniff_basic_image(b"\xFF\xD8\xFF\xE0...."),
            Some("image/jpeg")
        );
        assert_eq!(sniff_basic_image(b"GIF89a...."), Some("image/gif"));
        assert_eq!(sniff_basic_image(b"GIF87a...."), Some("image/gif"));
        assert_eq!(sniff_basic_image(b"RIFF\x24\0\0\0WEBP"), Some("image/webp"));

        // Plain-text / forged prefixes must NOT false-positive.
        assert_eq!(sniff_basic_image(b"GIF image documentation"), None);
        assert_eq!(sniff_basic_image(b"12345678WEBP trailing"), None);

        // Cover & raster image sniffing include AVIF & strict BMP (and ICO for raster only).
        let avif = b"\0\0\0\x1cftypavif\0\0\0\0";
        assert_eq!(sniff_basic_image(avif), None);
        assert_eq!(sniff_cover_image(avif), Some("image/avif"));
        assert_eq!(sniff_raster_image(avif), Some("image/avif"));

        // `mif1` with `avif` compatible brand is AVIF.
        let mut mif1_avif = Vec::new();
        mif1_avif.extend_from_slice(&24u32.to_be_bytes());
        mif1_avif.extend_from_slice(b"ftypmif1\0\0\0\0avif\0\0\0\0");
        assert_eq!(sniff_cover_image(&mif1_avif), Some("image/avif"));

        let ico = b"\x00\x00\x01\x00\x01\x00\x10\x10";
        assert_eq!(sniff_cover_image(ico), None);
        assert_eq!(sniff_raster_image(ico), Some("image/x-icon"));
        assert_eq!(sniff_raster_image(b"\x00\x00\x01\x00\x00\x00"), None);

        // SVG MUST NEVER be classified as a raster/basic/cover image.
        let svg = b"<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"></svg>";
        assert_eq!(sniff_basic_image(svg), None);
        assert_eq!(sniff_cover_image(svg), None);
        assert_eq!(sniff_raster_image(svg), None);
        assert_eq!(sniff_preview_image("icon.txt", svg, TEST_SVG_MAX), None);
        assert_eq!(
            sniff_preview_image("icon.SVG", svg, TEST_SVG_MAX),
            Some("image/svg+xml")
        );
        assert_eq!(sniff_preview_image("icon.svg", svg, svg.len() - 1), None);
    }

    #[test]
    fn bmp_strict_validation_checks_dib_dimensions_planes_bpp_and_bounds() {
        // Valid bottom-up and top-down BITMAPINFOHEADER and OS/2 BITMAPCOREHEADER.
        assert!(is_valid_bmp(&valid_bmp_info(1, 1, 1, 24)));
        assert!(is_valid_bmp(&valid_bmp_info(16, -16, 1, 32)));
        assert!(is_valid_bmp(&valid_bmp_core(4, 4, 1, 8)));

        // Short / plain text / malformed headers rejected.
        assert!(!is_valid_bmp(b"BM"));
        assert!(!is_valid_bmp(
            b"BM is an abbreviation in a plain text file exceeding 54 bytes."
        ));
        assert!(!is_valid_bmp(&valid_bmp_info(0, 1, 1, 24)));
        assert!(!is_valid_bmp(&valid_bmp_info(-1, 1, 1, 24)));
        assert!(!is_valid_bmp(&valid_bmp_info(1, 0, 1, 24)));
        assert!(!is_valid_bmp(&valid_bmp_info(1, i32::MIN, 1, 24)));
        assert!(!is_valid_bmp(&valid_bmp_info(1, 1, 0, 24)));
        assert!(!is_valid_bmp(&valid_bmp_info(1, 1, 2, 24)));
        assert!(!is_valid_bmp(&valid_bmp_info(1, 1, 1, 0)));
        assert!(!is_valid_bmp(&valid_bmp_info(1, 1, 1, 15)));
        assert!(!is_valid_bmp(&valid_bmp_core(0, 4, 1, 8)));
        assert!(!is_valid_bmp(&valid_bmp_core(4, 0, 1, 8)));
        assert!(!is_valid_bmp(&valid_bmp_core(4, 4, 0, 8)));

        // Non-zero reserved bytes, bad DIB size, and out-of-range pixel offset rejected.
        let mut bad_reserved = valid_bmp_info(1, 1, 1, 24);
        bad_reserved[6] = 1;
        assert!(!is_valid_bmp(&bad_reserved));

        let mut bad_dib = valid_bmp_info(1, 1, 1, 24);
        bad_dib[14..18].copy_from_slice(&99u32.to_le_bytes());
        assert!(!is_valid_bmp(&bad_dib));

        let mut bad_offset = valid_bmp_info(1, 1, 1, 24);
        bad_offset[10..14].copy_from_slice(&20u32.to_le_bytes());
        assert!(!is_valid_bmp(&bad_offset));

        let mut offset_gt_size = valid_bmp_info(1, 1, 1, 24);
        offset_gt_size[10..14].copy_from_slice(&100u32.to_le_bytes());
        assert!(!is_valid_bmp(&offset_gt_size));
    }

    #[test]
    fn isobmff_discriminates_mp4_mov_m4a_avif_and_heif() {
        assert_eq!(
            sniff_media("a", b"\0\0\0\x1cftypavif\0\0\0\0", TEST_SVG_MAX),
            Some(MediaKind::Image("image/avif"))
        );
        assert_eq!(
            sniff_media("a", b"\0\0\0\x1cftypavis\0\0\0\0", TEST_SVG_MAX),
            Some(MediaKind::Image("image/avif"))
        );
        assert_eq!(
            sniff_media("clip", b"\0\0\0\x14ftypqt  \0\0\0\0", TEST_SVG_MAX),
            Some(MediaKind::Video("video/quicktime"))
        );
        for brand in [b"M4A ", b"M4B ", b"M4P "] {
            let mut buf = b"\0\0\0\x14ftyp".to_vec();
            buf.extend_from_slice(brand);
            buf.extend_from_slice(&[0; 4]);
            assert_eq!(
                sniff_media("voice", &buf, TEST_SVG_MAX),
                Some(MediaKind::Audio("audio/mp4"))
            );
        }
        for brand in [
            b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"hevm", b"hevs", b"mif1",
            b"msf1",
        ] {
            let mut buf = b"\0\0\0\x18ftyp".to_vec();
            buf.extend_from_slice(brand);
            buf.extend_from_slice(&[0; 4]);
            assert_eq!(
                sniff_media("photo.heic", &buf, TEST_SVG_MAX),
                Some(MediaKind::Unsupported),
                "HEIF brand {brand:?} must be Unsupported"
            );
        }
        assert_eq!(
            sniff_media("v.mp4", b"\0\0\0\x18ftypisom\0\0\0\0", TEST_SVG_MAX),
            Some(MediaKind::Video("video/mp4"))
        );
        assert_eq!(
            sniff_media("v.mp4", b"\0\0\0\x18ftypmp42\0\0\0\0", TEST_SVG_MAX),
            Some(MediaKind::Video("video/mp4"))
        );
        // Plain text starting with "M4A " or containing "moov"/"mdat" must not false-positive.
        assert_eq!(
            sniff_media("notes.txt", b"M4A audio format description", TEST_SVG_MAX),
            None
        );
        assert_eq!(
            sniff_media("notes.txt", b"xxxxmoovyyyyyyyyyyyyyyyy", TEST_SVG_MAX),
            None
        );
    }

    #[test]
    fn sniffs_audio_video_pdf_and_archives_without_text_false_positives() {
        assert_eq!(
            sniff_media("clip", b"\x1a\x45\xdf\xa3....webm", TEST_SVG_MAX),
            Some(MediaKind::Video("video/webm"))
        );
        assert_eq!(
            sniff_media("clip", b"\x1a\x45\xdf\xa3....matroska", TEST_SVG_MAX),
            Some(MediaKind::Video("video/x-matroska"))
        );
        assert_eq!(
            sniff_media("a.opus", &minimal_ogg(b"OpusHead"), TEST_SVG_MAX),
            Some(MediaKind::Audio("audio/ogg"))
        );
        assert_eq!(
            sniff_media("v.ogv", &minimal_ogg(b"\x80theora"), TEST_SVG_MAX),
            Some(MediaKind::Video("video/ogg"))
        );
        assert_eq!(
            sniff_media("track", &minimal_flac(), TEST_SVG_MAX),
            Some(MediaKind::Audio("audio/flac"))
        );
        assert_eq!(
            sniff_media("sound", b"RIFF\x24\0\0\0WAVEfmt ", TEST_SVG_MAX),
            Some(MediaKind::Audio("audio/wav"))
        );
        assert_eq!(
            sniff_media("song", b"ID3\x04\0\0\0\0\0\x10", TEST_SVG_MAX),
            Some(MediaKind::Audio("audio/mpeg"))
        );
        assert_eq!(
            sniff_media("raw.aac", &[0xFF, 0xF1, 0x50, 0x80], TEST_SVG_MAX),
            Some(MediaKind::Audio("audio/aac"))
        );
        assert_eq!(
            sniff_media("raw.mp3", &[0xFF, 0xFB, 0x90, 0x00], TEST_SVG_MAX),
            Some(MediaKind::Audio("audio/mpeg"))
        );

        // Plain-text false positives rejected for ID3, Ogg, FLAC.
        assert_eq!(
            sniff_media("t.txt", b"ID3 tags store audio metadata.", TEST_SVG_MAX),
            None
        );
        assert_eq!(
            sniff_media(
                "t.txt",
                b"OggS is the page capture pattern of Ogg.",
                TEST_SVG_MAX
            ),
            None
        );
        assert_eq!(
            sniff_media(
                "t.txt",
                b"fLaC is a lossless audio codec with 34-byte STREAMINFO headers.",
                TEST_SVG_MAX
            ),
            None
        );
        assert!(!is_valid_id3v2(b"ID3\x04\0\x01\0\0\0\x10"));
        assert!(!is_valid_id3v2(b"ID3\x04\0\0\x80\0\0\x10"));

        // PDF requires "%PDF-".
        assert!(is_pdf(b"%PDF-1.7\n"));
        assert!(!is_pdf(b"%PDF without dash"));

        // Archives.
        assert_eq!(sniff_archive(b"PK\x03\x04...."), Some(ArchiveKind::Zip));
        assert_eq!(sniff_archive(b"PK\x05\x06...."), Some(ArchiveKind::Zip));
        assert_eq!(sniff_archive(b"\x1F\x8B\x08\0"), Some(ArchiveKind::Gzip));
        let mut tar = vec![0u8; 300];
        tar[257..262].copy_from_slice(b"ustar");
        assert_eq!(sniff_archive(&tar), Some(ArchiveKind::Tar));
        assert_eq!(
            sniff_archive(b"7z\xBC\xAF\x27\x1C...."),
            Some(ArchiveKind::Other)
        );
        assert_eq!(
            sniff_archive(b"Rar!\x1A\x07\x01\x00"),
            Some(ArchiveKind::Other)
        );
        assert_eq!(sniff_archive(b"\xFD7zXZ\x00...."), Some(ArchiveKind::Other));
        assert_eq!(sniff_archive(b"BZh91AY&SY"), Some(ArchiveKind::Other));
        assert_eq!(
            sniff_archive(b"\x28\xB5\x2F\xFD...."),
            Some(ArchiveKind::Other)
        );
        // Non-archive infer MatcherType::Archive entries (RTF, PostScript, SQLite) are not archives.
        assert_eq!(sniff_archive(b"{\\rtf1\\ansi hello}"), None);
        assert_eq!(sniff_archive(b"%!PS-Adobe-3.0"), None);
        assert_eq!(sniff_archive(b"SQLite format 3\0"), None);

        // Deeply chained Zstd skippable frames and 32-bit `8 + data_len` overflow payloads must
        // never panic or recurse unboundedly, while valid skippable + Zstd frames still match.
        let zstd_skip_bomb = b"\x50\x2A\x4D\x18\x00\x00\x00\x00".repeat(4096);
        assert_eq!(sniff_archive(&zstd_skip_bomb), None);
        for overflow_payload in [
            b"\x50\x2A\x4D\x18\xF8\xFF\xFF\xFF".as_slice(),
            b"\x50\x2A\x4D\x18\xFF\xFF\xFF\xFF".as_slice(),
        ] {
            assert_eq!(sniff_basic_image(overflow_payload), None);
            assert_eq!(
                sniff_media("probe.bin", overflow_payload, TEST_SVG_MAX),
                None
            );
            assert_eq!(sniff_archive(overflow_payload), None);
        }
        assert_eq!(
            sniff_archive(b"\x50\x2A\x4D\x18\x02\x00\x00\x00ab\x28\xB5\x2F\xFD"),
            Some(ArchiveKind::Other)
        );

        // Archive headers whose bytes 8..12 contain "WEBP" or 12..16 contain "mdat" must not be
        // shadowed by image/video matchers.
        for magic in [
            b"7z\xBC\xAF\x27\x1C\x00\x04".as_slice(),
            b"BZh91AY&".as_slice(),
            b"\xFD7zXZ\x00\x00\x04".as_slice(),
            b"\x28\xB5\x2F\xFD\x00\x00\x00\x00".as_slice(),
            b"Rar!\x1A\x07\x01\x00".as_slice(),
        ] {
            let mut shadowed = magic.to_vec();
            shadowed.extend_from_slice(b"WEBPmdat");
            assert_eq!(
                sniff_archive(&shadowed),
                Some(ArchiveKind::Other),
                "archive with embedded WEBP/mdat must not be shadowed: {magic:?}"
            );
        }
    }

    #[test]
    fn mime_parsing_and_stream_validation_handle_params_case_and_malformed_inputs() {
        assert_eq!(
            mime_essence("  TEXT/PLAIN; charset=UTF-8  ").as_deref(),
            Some("text/plain")
        );
        assert_eq!(
            mime_essence("application/pdf; name=report.pdf").as_deref(),
            Some("application/pdf")
        );
        assert_eq!(
            mime_essence(r#"video/mp4; codecs="avc1.42E01E""#).as_deref(),
            Some("video/mp4")
        );
        assert_eq!(mime_essence(""), None);
        assert_eq!(mime_essence("not-a-mime"), None);
        assert_eq!(mime_essence("video/mp4; badparam"), None);
        assert_eq!(mime_essence("video/mp4\r\nX-Injected: 1"), None);
        assert_eq!(mime_essence("video/mp4; codecs=\"a\r\nX-Bad: 1\""), None);

        assert_eq!(stream_media_mime("VIDEO/MP4"), "video/mp4");
        assert_eq!(stream_media_mime("audio/x-matroska"), "audio/x-matroska");
        assert_eq!(stream_media_mime("video/mp4; codecs=avc1"), "video/mp4");
        assert_eq!(stream_media_mime("audio/webm; codecs=opus"), "audio/webm");
        assert_eq!(
            stream_media_mime(r#"video/mp4; codecs="avc1.42E01E, mp4a.40.2""#),
            "video/mp4"
        );
        for rejected in [
            "",
            "video/",
            "audio/",
            "video/a/b",
            "video/mp4!bad",
            "text/html",
            "text/html; codecs=avc1",
            "image/svg+xml",
            "application/javascript",
            "video/mp4; badparam",
            "video/mp4; codecs=\"unterminated",
            "video/mp4; codecs=\"a\r\nX-Bad: 1\"",
            "video/mp4\0",
        ] {
            assert_eq!(
                stream_media_mime(rejected),
                "application/octet-stream",
                "expected fallback for {rejected:?}"
            );
        }
    }
}
