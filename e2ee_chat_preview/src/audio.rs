//! What an audio file's tags say of it, as lofty reads them: its title, artist, album and year,
//! and its cover.

/// What an audio file's tags say of it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tags {
    pub title: Option<String>,
    pub artist: Option<String>,
    pub album: Option<String>,
    pub year: Option<u16>,
    /// The cover's MIME type and bytes.
    pub cover: Option<(String, Vec<u8>)>,
}

/// Maximum cover art payload kept from an audio tag (4 MiB).
pub const COVER_MAX: usize = 4 << 20;
/// Maximum audio input byte length accepted for tag extraction (64 MiB).
pub const MAX_AUDIO_BYTES: usize = 64 << 20;
/// Raster image MIME types accepted for audio cover art and RPC wire decoding.
pub const IMAGE_MIMES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
    "image/bmp",
];

/// Whether `mime` is in the raster image MIME allowlist [`IMAGE_MIMES`].
pub fn is_image_mime(mime: &str) -> bool {
    IMAGE_MIMES.contains(&mime)
}

/// Maximum byte length kept for a single audio text tag (title, artist, album).
#[cfg(feature = "audio")]
const TAG_TEXT_MAX: usize = 1024;
/// Maximum single-item allocation limit passed to `lofty` (cover budget + 256 KiB metadata slack).
#[cfg(feature = "audio")]
const LOFTY_ALLOCATION_LIMIT: usize = COVER_MAX + 256 * 1024;
/// Maximum nested `CHAP`/`CTOC` recursion depth allowed in an ID3v2 tag before rejecting.
#[cfg(feature = "audio")]
const ID3V2_MAX_DEPTH: usize = 4;
/// Maximum Vorbis comment items allowed in a FLAC or Ogg comment block before rejecting
/// (`lofty 0.25.5` calls infallible `Vec::with_capacity(number_of_items)`).
#[cfg(feature = "audio")]
const VORBIS_COMMENTS_MAX: u32 = 4096;
/// Maximum Ogg pages inspected while locating the identification and comment header packets.
#[cfg(feature = "audio")]
const OGG_MAX_HEADER_PAGES: usize = 4096;
/// Maximum MP4 atoms visited during container-boundary preflight.
#[cfg(feature = "audio")]
const MP4_MAX_ATOMS: usize = 16_384;

/// Decode a 4-byte ID3v2 synchsafe integer (matching `lofty`'s `SynchsafeInteger::unsynch`).
#[cfg(feature = "audio")]
fn unsynch_u32(bytes: &[u8]) -> u32 {
    let raw = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    ((raw & 0x7F00_0000) >> 3)
        | ((raw & 0x007F_0000) >> 2)
        | ((raw & 0x0000_7F00) >> 1)
        | (raw & 0x0000_007F)
}

/// Remove ID3v2 unsynchronisation (`0xFF 0x00` -> `0xFF`) from `input`.
#[cfg(feature = "audio")]
fn unsynchronise(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let byte = input[i];
        out.push(byte);
        if byte == 0xFF && input.get(i + 1) == Some(&0x00) {
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

/// Whether `bytes` is a valid 4-byte ID3v2.3/2.4 frame ID or a 3-byte ID padded with a trailing
/// NUL (which `lofty 0.25.5` accepts as `FrameId::Outdated` via `utf8_decode_str` in both ID3v2.3
/// and ID3v2.4).
#[cfg(feature = "audio")]
fn is_id3v2_frame_id(bytes: &[u8]) -> bool {
    let valid_char = |b: u8| b.is_ascii_uppercase() || b.is_ascii_digit();
    if bytes[3] == 0 {
        bytes[..3].iter().copied().all(valid_char)
    } else {
        bytes.iter().copied().all(valid_char)
    }
}

#[cfg(feature = "audio")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Id3v2ScanResult {
    Clean,
    /// Padding (`0x00`) ended frame parsing early while non-zero bytes remained in the slice.
    EarlyPaddingWithTrailingData,
    /// Compressed frame, excessive `CHAP`/`CTOC` recursion, or parser-desync hazard detected.
    Unsafe,
}

#[cfg(feature = "audio")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Id3v2ExtHeader {
    /// Truncated or invalid size that `lofty 0.25.5` rejects directly.
    Invalid,
    /// Valid to the spec or `lofty`, but `lofty 0.25.5`'s reader cursor would desync from the
    /// actual frame start (e.g., ID3v2.4 `0x40` update flag, ID3v2.3 4-byte `padding_size` /
    /// `0x80` CRC, or extra extended-header bytes).
    Desync,
    /// Extended header whose spec frame start matches `lofty 0.25.5`'s reader cursor.
    Valid { frame_start: usize, ext_size: u32 },
}

/// Parse an ID3v2.3 or ID3v2.4 extended header at `pos + 10`, checking both the ID3v2 spec
/// layout (v2.4 `0x40`/`0x20`/`0x10`, v2.3 `padding_size` + `ext_hdr[0] & 0x80` CRC) and
/// `lofty 0.25.5`'s actual cursor advancement.
#[cfg(feature = "audio")]
fn parse_id3v2_ext_header(data: &[u8], pos: usize, major: u8, tag_size: u32) -> Id3v2ExtHeader {
    let Some(size_bytes) = data.get(pos + 10..pos + 14) else {
        return Id3v2ExtHeader::Invalid;
    };
    let ext_size = if major == 4 {
        unsynch_u32(size_bytes)
    } else {
        u32::from_be_bytes([size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]])
    };
    if ext_size < 6 || ext_size >= tag_size {
        return Id3v2ExtHeader::Invalid;
    }
    let Some(ext_hdr) = data.get(pos + 14..pos + 16) else {
        return Id3v2ExtHeader::Invalid;
    };
    let lofty_len = 6usize
        + if ext_hdr[1] & 0x20 != 0 { 6 } else { 0 }
        + if ext_hdr[1] & 0x10 != 0 { 2 } else { 0 };
    if pos + 10 + lofty_len > data.len() {
        return Id3v2ExtHeader::Invalid;
    }

    if major == 3 {
        // ID3v2.3 §3.2: 4-byte size (excluding itself, 6 or 10), 2-byte flags (`ext_hdr[0] & 0x80`
        // indicates 4-byte CRC), 4-byte `padding_size`, optional 4-byte CRC. `lofty 0.25.5`
        // runs its v2.4 extended-header parser on v2.3 and never skips `padding_size` or the v2.3
        // CRC, so any v2.3 extended header that passes `lofty`'s size check desyncs the reader.
        return Id3v2ExtHeader::Desync;
    }

    // ID3v2.4 §3.2: 4-byte synchsafe `ext_size` (including itself), 1-byte `num_flag_bytes` (1),
    // 1-byte flags: 0x40 ("Tag is an update", 1-byte 0x00 length), 0x20 (CRC, 6 B), 0x10
    // (restrictions, 2 B). `lofty 0.25.5` omits 0x40 and never skips to `pos + 10 + ext_size`.
    let num_flag_bytes = ext_hdr[0];
    let ext_flags = ext_hdr[1];
    let spec_len = 6usize
        + if ext_flags & 0x40 != 0 { 1 } else { 0 }
        + if ext_flags & 0x20 != 0 { 6 } else { 0 }
        + if ext_flags & 0x10 != 0 { 2 } else { 0 };
    if num_flag_bytes != 1
        || (ext_flags & !0x70) != 0
        || spec_len > ext_size as usize
        || lofty_len != ext_size as usize
    {
        return Id3v2ExtHeader::Desync;
    }
    let Some(frame_start) = (pos + 10).checked_add(ext_size as usize) else {
        return Id3v2ExtHeader::Invalid;
    };
    if frame_start > data.len() {
        return Id3v2ExtHeader::Invalid;
    }
    Id3v2ExtHeader::Valid {
        frame_start,
        ext_size,
    }
}

/// Inspect a slice of ID3v2.3/2.4 frames (at `depth`) for compressed frames, deep `CHAP`/`CTOC`
/// recursion, or `lofty 0.25.5` partial-read `Take` desynchronisation vectors.
#[cfg(feature = "audio")]
fn scan_id3v2_frames(frames: &[u8], major: u8, tag_unsynch: bool, depth: usize) -> Id3v2ScanResult {
    if depth > ID3V2_MAX_DEPTH {
        return Id3v2ScanResult::Unsafe;
    }
    let mut offset = 0;
    while offset + 10 <= frames.len() {
        let hdr = &frames[offset..offset + 10];
        if hdr[0] == 0 {
            return if (depth > 0 && offset + 10 < frames.len())
                || frames[offset + 1..].iter().any(|&b| b != 0)
            {
                Id3v2ScanResult::EarlyPaddingWithTrailingData
            } else {
                Id3v2ScanResult::Clean
            };
        }
        let frame_size = if major == 4 {
            unsynch_u32(&hdr[4..8])
        } else {
            u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]])
        };
        let flags = u16::from_be_bytes([hdr[8], hdr[9]]);
        let compressed = if major == 4 {
            (flags & 0x0008) != 0
        } else {
            (flags & 0x0080) != 0
        };
        let valid_id = is_id3v2_frame_id(&hdr[..4]);
        if compressed && frame_size > 0 && valid_id {
            return Id3v2ScanResult::Unsafe;
        }
        let body_start = offset + 10;
        let next = body_start.checked_add(frame_size as usize);
        let truncated = next.is_none_or(|n| n > frames.len());
        let body_end = next.unwrap_or(frames.len()).min(frames.len());
        let body = &frames[body_start..body_end];

        let encrypted = if major == 4 {
            (flags & 0x0004) != 0
        } else {
            (flags & 0x0040) != 0
        };
        if valid_id && !encrypted && !body.is_empty() {
            let skip = if major == 4 {
                usize::from((flags & 0x0040) != 0) + if (flags & 0x0001) != 0 { 4 } else { 0 }
            } else {
                usize::from((flags & 0x0020) != 0)
            };
            if skip <= body.len() {
                let raw_content = &body[skip..];
                let decoded_content;
                let content: &[u8] = if major == 4 && (tag_unsynch || (flags & 0x0002) != 0) {
                    decoded_content = unsynchronise(raw_content);
                    &decoded_content
                } else {
                    raw_content
                };

                let id = &hdr[..4];
                if id == b"CHAP" {
                    let Some(nul) = content.iter().position(|&b| b == 0) else {
                        return Id3v2ScanResult::Unsafe;
                    };
                    let Some(sub_start) = nul.checked_add(17) else {
                        return Id3v2ScanResult::Unsafe;
                    };
                    if sub_start > content.len() {
                        return Id3v2ScanResult::Unsafe;
                    }
                    if scan_id3v2_frames(&content[sub_start..], major, false, depth + 1)
                        != Id3v2ScanResult::Clean
                    {
                        return Id3v2ScanResult::Unsafe;
                    }
                } else if id == b"CTOC" {
                    let Some(nul) = content.iter().position(|&b| b == 0) else {
                        return Id3v2ScanResult::Unsafe;
                    };
                    let Some(&entry_count) = content.get(nul + 2) else {
                        return Id3v2ScanResult::Unsafe;
                    };
                    let mut pos = nul + 3;
                    for _ in 0..entry_count {
                        let Some(rel) = content
                            .get(pos..)
                            .and_then(|s| s.iter().position(|&b| b == 0))
                        else {
                            return Id3v2ScanResult::Unsafe;
                        };
                        pos += rel + 1;
                    }
                    if scan_id3v2_frames(&content[pos..], major, false, depth + 1)
                        != Id3v2ScanResult::Clean
                    {
                        return Id3v2ScanResult::Unsafe;
                    }
                } else if id[0] == b'W' && id != b"WXXX" && !(major == 3 && id == b"WXX\0") {
                    // `UrlLinkFrame::parse` stops at the first NUL without draining `Take`.
                    // At top level, trailing non-zero bytes would be reparsed as a frame; inside
                    // `CHAP`/`CTOC` (`depth > 0`), even a single trailing `0x00` exits the child
                    // loop early without draining `CHAP`/`CTOC`'s `Take`.
                    if let Some(nul) = content.iter().position(|&b| b == 0)
                        && ((depth > 0 && nul + 1 < content.len())
                            || content[nul + 1..].iter().any(|&b| b != 0))
                    {
                        return Id3v2ScanResult::Unsafe;
                    }
                } else if id == b"TIPL" || id == b"TMCL" || (major == 3 && id == b"IPL\0") {
                    // `KeyValueFrame::parse` returns `Ok(None)` immediately on an empty first key
                    // without draining `Take`.
                    let empty_tail = match content.first() {
                        Some(0 | 3) if content.get(1) == Some(&0) => Some(&content[2..]),
                        Some(1 | 2) if content.get(1..3) == Some(&[0, 0]) => Some(&content[3..]),
                        _ => None,
                    };
                    if let Some(tail) = empty_tail
                        && ((depth > 0 && !tail.is_empty()) || tail.iter().any(|&b| b != 0))
                    {
                        return Id3v2ScanResult::Unsafe;
                    }
                } else if id == b"COMM"
                    || id == b"USLT"
                    || (major == 3 && (id == b"COM\0" || id == b"ULT\0"))
                {
                    // `LanguageFrame::parse` uses terminated UTF-16 decoding on encodings 1/2,
                    // which can stop early at an aligned `[0, 0]` without draining `Take`.
                    if matches!(content.first(), Some(1 | 2)) && content.len() > 4 {
                        let rest = &content[4..];
                        if let Some(desc_end) =
                            rest.as_chunks::<2>().0.iter().position(|c| *c == [0, 0])
                        {
                            let text = &rest[(desc_end + 1) * 2..];
                            if let Some(text_end) =
                                text.as_chunks::<2>().0.iter().position(|c| *c == [0, 0])
                            {
                                let tail = &text[(text_end + 1) * 2..];
                                if (depth > 0 && !tail.is_empty()) || tail.iter().any(|&b| b != 0) {
                                    return Id3v2ScanResult::Unsafe;
                                }
                            }
                        }
                    }
                }
            }
        }
        if truncated {
            break;
        }
        offset = next.unwrap();
    }
    Id3v2ScanResult::Clean
}

/// Preflight check rejecting any audio file containing a compressed ID3v2.3 or ID3v2.4 frame,
/// deeply nested `CHAP`/`CTOC` frames, or ID3v2 parser-desynchronisation hazards.
#[cfg(feature = "audio")]
fn has_compressed_id3v2(data: &[u8]) -> bool {
    if matches!(
        lofty::file::FileType::from_buffer(&data[..data.len().min(36)]),
        Some(
            lofty::file::FileType::Mp4
                | lofty::file::FileType::Vorbis
                | lofty::file::FileType::Opus
                | lofty::file::FileType::Speex
                | lofty::file::FileType::WavPack
        )
    ) {
        return false;
    }
    let max_work = data.len().saturating_mul(2).max(64 * 1024);
    let mut scanned = 0usize;
    let mut start = 0;
    while start + 10 <= data.len() {
        let Some(rel) = data[start..].windows(3).position(|w| w == b"ID3") else {
            break;
        };
        let pos = start + rel;
        start = pos + 3;
        if pos + 10 > data.len() {
            break;
        }
        let major = data[pos + 3];
        if major != 3 && major != 4 {
            continue;
        }
        let tag_flags = data[pos + 5];
        let unsynch = (tag_flags & 0x80) != 0;
        let has_ext = (tag_flags & 0x40) != 0;
        if major == 3 && unsynch && has_ext {
            return true;
        }
        let tag_size = unsynch_u32(&data[pos + 6..pos + 10]);

        let (cursor, ext_size) = if has_ext {
            match parse_id3v2_ext_header(data, pos, major, tag_size) {
                Id3v2ExtHeader::Invalid => continue,
                Id3v2ExtHeader::Desync => return true,
                Id3v2ExtHeader::Valid {
                    frame_start,
                    ext_size,
                } => (frame_start, ext_size),
            }
        } else {
            (pos + 10, 0u32)
        };

        let body_len = (tag_size - ext_size) as usize;
        let body_end = cursor.saturating_add(body_len).min(data.len());
        let raw_body = &data[cursor..body_end];
        scanned = scanned.saturating_add(raw_body.len().max(1));
        if scanned > max_work {
            return true;
        }
        let decoded_body;
        let frames: &[u8] = if major == 3 && unsynch {
            decoded_body = unsynchronise(raw_body);
            &decoded_body
        } else {
            raw_body
        };

        if scan_id3v2_frames(frames, major, unsynch, 0) != Id3v2ScanResult::Clean {
            return true;
        }
    }
    false
}

#[cfg(feature = "audio")]
#[derive(Debug, Clone, Copy)]
struct Mp4Atom {
    fourcc: [u8; 4],
    len_raw: u32,
    payload_start: usize,
    /// Declared end of this atom (may exceed `data.len()` if truncated).
    end: usize,
}

/// Read one MP4 atom header at exact offset `pos` within `parent_end`, returning `Err(())` when a
/// `lofty 0.25.5` panic vector is found (`----`/`mean`/`name`/`data` extended or undersized, or
/// truncated extended header).
#[cfg(feature = "audio")]
fn read_mp4_atom(data: &[u8], pos: usize, parent_end: usize) -> Result<Option<Mp4Atom>, ()> {
    if pos + 8 > parent_end || pos + 8 > data.len() {
        return Ok(None);
    }
    let len_raw = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    let fourcc = [data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]];

    // Reject extended (`len_raw == 1`), EOF-extending (`len_raw == 0`), or undersized freeform /
    // data atoms at actual container boundaries (prevents `lofty 0.25.5` underflows).
    if &fourcc == b"----" && (len_raw == 0 || len_raw == 1 || len_raw < 16) {
        return Err(());
    }
    if (&fourcc == b"mean" || &fourcc == b"name") && (len_raw == 0 || len_raw == 1 || len_raw < 12)
    {
        return Err(());
    }
    if &fourcc == b"data" && (len_raw == 0 || len_raw == 1 || len_raw < 16) {
        return Err(());
    }

    let (payload_start, end) = match len_raw {
        0 => (pos + 8, parent_end),
        1 => {
            let Some(ext_bytes) = data.get(pos + 8..pos + 16) else {
                return Ok(None);
            };
            let ext_len = u64::from_be_bytes([
                ext_bytes[0],
                ext_bytes[1],
                ext_bytes[2],
                ext_bytes[3],
                ext_bytes[4],
                ext_bytes[5],
                ext_bytes[6],
                ext_bytes[7],
            ]);
            if ext_len < 16 {
                return Ok(None);
            }
            let Ok(ext_len) = usize::try_from(ext_len) else {
                return Ok(None);
            };
            let Some(end) = pos.checked_add(ext_len) else {
                return Ok(None);
            };
            (pos + 16, end)
        }
        n if n < 8 => return Ok(None),
        n => {
            let Some(end) = pos.checked_add(n as usize) else {
                return Ok(None);
            };
            (pos + 8, end)
        }
    };

    Ok(Some(Mp4Atom {
        fourcc,
        len_raw,
        payload_start,
        end,
    }))
}

#[cfg(feature = "audio")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mp4Context {
    TopLevel,
    Moov,
    Udta,
    Meta,
    Ilst,
    IlstItem,
    Freeform,
}

#[cfg(feature = "audio")]
fn scan_mp4_children(
    data: &[u8],
    mut pos: usize,
    end: usize,
    ctx: Mp4Context,
    visited: &mut usize,
) -> bool {
    let limit = end.min(data.len());
    while pos + 8 <= limit {
        *visited += 1;
        if *visited > MP4_MAX_ATOMS {
            return true;
        }
        let atom = match read_mp4_atom(data, pos, limit) {
            Ok(Some(atom)) => atom,
            Ok(None) => break,
            Err(()) => return true,
        };
        if ctx == Mp4Context::Meta && atom.len_raw == 0 {
            return true;
        }

        let child_limit = atom.end.min(data.len());
        let unsafe_child = match (ctx, &atom.fourcc) {
            (Mp4Context::TopLevel, b"moov") => scan_mp4_children(
                data,
                atom.payload_start,
                child_limit,
                Mp4Context::Moov,
                visited,
            ),
            (Mp4Context::TopLevel | Mp4Context::Moov | Mp4Context::Udta, b"meta") => {
                scan_mp4_meta(data, atom.payload_start, atom.end, visited)
            }
            (Mp4Context::Moov, b"udta") => scan_mp4_children(
                data,
                atom.payload_start,
                child_limit,
                Mp4Context::Udta,
                visited,
            ),
            (Mp4Context::Meta, b"ilst") => scan_mp4_children(
                data,
                atom.payload_start,
                child_limit,
                Mp4Context::Ilst,
                visited,
            ),
            (Mp4Context::Ilst, b"----") => scan_mp4_children(
                data,
                atom.payload_start,
                child_limit,
                Mp4Context::Freeform,
                visited,
            ),
            (Mp4Context::Ilst, fourcc) if fourcc != b"free" && fourcc != b"skip" => {
                scan_mp4_children(
                    data,
                    atom.payload_start,
                    child_limit,
                    Mp4Context::IlstItem,
                    visited,
                )
            }
            _ => {
                // Skip payloads of non-container atoms (`mdat`, `ftyp`, `free`, `data`, `mean`,
                // `name`, `trak`, etc.) so audio samples and cover artwork never cause false
                // positives.
                false
            }
        };
        if unsafe_child {
            return true;
        }

        if atom.end <= pos {
            break;
        }
        pos = atom.end;
    }
    false
}

/// Inspect a `meta` atom matching `lofty 0.25.5`'s `meta_is_full` heuristic and catching
/// EOF-extending (`len_raw == 0`) children even when `meta`'s declared end overshoots `moov`.
#[cfg(feature = "audio")]
fn scan_mp4_meta(data: &[u8], payload_start: usize, meta_end: usize, visited: &mut usize) -> bool {
    let is_meta_child_ident =
        |ident: &[u8]| matches!(ident, b"hdlr" | b"ilst" | b"mhdr" | b"ctry" | b"lang");
    let children_start = match data.get(payload_start + 4..payload_start + 8) {
        Some(ident) if is_meta_child_ident(ident) => payload_start,
        Some(_) => payload_start + 4,
        None => return false,
    };
    // Check the first child against `data.len()` directly in case `meta` overshot `moov`'s end
    // (the exact condition that triggers `end - pos` underflow in `lofty 0.25.5`).
    if let Some(first_hdr) = data.get(children_start..children_start + 8)
        && &first_hdr[0..4] == b"\x00\x00\x00\x00"
        && is_meta_child_ident(&first_hdr[4..8])
    {
        return true;
    }
    scan_mp4_children(
        data,
        children_start,
        meta_end.min(data.len()),
        Mp4Context::Meta,
        visited,
    )
}

/// Reject MP4 extended-size or undersized freeform/data atoms (`----`, `mean`, `name`, `data`)
/// and EOF-extending `meta` child atoms by traversing actual MP4 atom boundaries rather than
/// raw byte windows over media/artwork payloads.
#[cfg(feature = "audio")]
fn has_mp4_extended_freeform_atom(data: &[u8]) -> bool {
    if lofty::file::FileType::from_buffer(&data[..data.len().min(36)])
        != Some(lofty::file::FileType::Mp4)
    {
        return false;
    }
    let mut visited = 0usize;
    scan_mp4_children(data, 0, data.len(), Mp4Context::TopLevel, &mut visited)
}

/// Mirror `lofty 0.25.5` `Id3v2Header::parse` + `full_tag_size()` for a leading ID3v2 tag at
/// offset 0, returning `None` if `lofty` would reject or ignore the header.
#[cfg(feature = "audio")]
fn leading_id3v2_full_tag_size(data: &[u8]) -> Option<u64> {
    if !data.starts_with(b"ID3") || data.len() < 10 {
        return None;
    }
    let major = data[3];
    if !matches!(major, 2..=4) {
        return None;
    }
    let flags = data[5];
    if major == 2 && (flags & 0x40) != 0 {
        return None;
    }
    let size = unsynch_u32(&data[6..10]);
    let has_footer = (major == 3 || major == 4) && (flags & 0x10) != 0;
    let has_ext = (major == 3 || major == 4) && (flags & 0x40) != 0;
    let mut ext_size = 0u32;
    if has_ext {
        if major == 3 && (flags & 0x80) != 0 {
            return None;
        }
        match parse_id3v2_ext_header(data, 0, major, size) {
            Id3v2ExtHeader::Valid {
                ext_size: parsed_ext,
                ..
            } => ext_size = parsed_ext,
            Id3v2ExtHeader::Invalid | Id3v2ExtHeader::Desync => return None,
        }
    }
    let footer_len = if has_footer { 10u64 } else { 0u64 };
    Some(u64::from(size) + 10 + u64::from(ext_size) + footer_len)
}

/// Reject WavPack/APE files whose trailing `APETAGEX` footer declares a total tag size larger than
/// the bytes remaining after subtracting an optional trailing 128-byte ID3v1 tag and (for APE
/// streams containing `MAC `) an optional leading ID3v2 tag (`lofty 0.25.5` `wavpack/read.rs:63`
/// and `ape/read.rs:48,157` perform unchecked `stream_length -= header.size`).
#[cfg(feature = "audio")]
fn has_oversized_ape_footer(data: &[u8]) -> bool {
    let tail_end = if data.len() >= 128 && &data[data.len() - 128..data.len() - 125] == b"TAG" {
        data.len() - 128
    } else {
        data.len()
    };
    if tail_end < 32 {
        return false;
    }
    let footer = &data[tail_end - 32..tail_end];
    if &footer[0..8] != b"APETAGEX" {
        return false;
    }
    let version = u32::from_le_bytes([footer[8], footer[9], footer[10], footer[11]]);
    let size = u32::from_le_bytes([footer[12], footer[13], footer[14], footer[15]]);
    if size < 32 {
        return false;
    }
    let total = if version == 2000 {
        u64::from(size) + 32
    } else {
        u64::from(size)
    };
    let mut remaining = tail_end as u64;
    if data.starts_with(b"ID3")
        && data.windows(4).any(|w| w == b"MAC ")
        && let Some(id3v2_full) = leading_id3v2_full_tag_size(data)
    {
        remaining = remaining.saturating_sub(id3v2_full);
    }
    total > remaining
}

/// Check whether a raw VorbisComment payload (`vendor_len || vendor || item_count || ...`) declares
/// more than [`VORBIS_COMMENTS_MAX`] items (`lofty 0.25.5` does an infallible `Vec::with_capacity`)
/// OR contains a deprecated `COVERART=` entry decoding to `< 8` bytes (which panics
/// `Picture::mimetype_from_bin` on `&bytes[..8]` in `lofty 0.25.5`).
#[cfg(feature = "audio")]
fn vorbis_comment_is_unsafe(payload: &[u8]) -> bool {
    if payload.len() < 4 {
        return false;
    }
    let vendor_len = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    let Some(count_off) = 4usize.checked_add(vendor_len) else {
        return true;
    };
    let Some(count_end) = count_off.checked_add(4) else {
        return false;
    };
    let Some(count_bytes) = payload.get(count_off..count_end) else {
        return false;
    };
    let count = u32::from_le_bytes([
        count_bytes[0],
        count_bytes[1],
        count_bytes[2],
        count_bytes[3],
    ]);
    if count > VORBIS_COMMENTS_MAX {
        return true;
    }
    let mut cursor = count_end;
    for _ in 0..count {
        let Some(len_end) = cursor.checked_add(4) else {
            break;
        };
        let Some(len_bytes) = payload.get(cursor..len_end) else {
            break;
        };
        let item_len =
            u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        let Some(item_end) = len_end.checked_add(item_len) else {
            break;
        };
        let Some(item) = payload.get(len_end..item_end) else {
            break;
        };
        if item.len() >= 9 && item[..9].eq_ignore_ascii_case(b"COVERART=") && item.len() - 9 < 16 {
            return true;
        }
        cursor = item_end;
    }
    false
}

/// O(1)-memory streaming scanner for an Ogg Vorbis/Opus/Speex comment packet (packet #1).
#[cfg(feature = "audio")]
#[derive(Default)]
struct OggCommentScanner {
    magic: [u8; 8],
    magic_len: usize,
    prefix_stripped: bool,
    vendor_len_buf: [u8; 4],
    vendor_len_have: usize,
    vendor_remaining: usize,
    count_buf: [u8; 4],
    count_have: usize,
    items_remaining: u32,
    item_len_buf: [u8; 4],
    item_len_have: usize,
    item_total_len: usize,
    item_remaining: usize,
    item_prefix: [u8; 9],
    item_prefix_have: usize,
}

#[cfg(feature = "audio")]
impl OggCommentScanner {
    fn feed_body(&mut self, mut bytes: &[u8]) -> Option<bool> {
        while !bytes.is_empty() {
            if self.vendor_len_have < 4 {
                let take = (4 - self.vendor_len_have).min(bytes.len());
                self.vendor_len_buf[self.vendor_len_have..self.vendor_len_have + take]
                    .copy_from_slice(&bytes[..take]);
                self.vendor_len_have += take;
                bytes = &bytes[take..];
                if self.vendor_len_have == 4 {
                    self.vendor_remaining = u32::from_le_bytes(self.vendor_len_buf) as usize;
                }
            } else if self.vendor_remaining > 0 {
                let skip = self.vendor_remaining.min(bytes.len());
                self.vendor_remaining -= skip;
                bytes = &bytes[skip..];
            } else if self.count_have < 4 {
                let take = (4 - self.count_have).min(bytes.len());
                self.count_buf[self.count_have..self.count_have + take]
                    .copy_from_slice(&bytes[..take]);
                self.count_have += take;
                bytes = &bytes[take..];
                if self.count_have == 4 {
                    let count = u32::from_le_bytes(self.count_buf);
                    if count > VORBIS_COMMENTS_MAX {
                        return Some(true);
                    }
                    self.items_remaining = count;
                    if self.items_remaining == 0 {
                        return Some(false);
                    }
                }
            } else if self.items_remaining > 0 {
                if self.item_len_have < 4 {
                    let take = (4 - self.item_len_have).min(bytes.len());
                    self.item_len_buf[self.item_len_have..self.item_len_have + take]
                        .copy_from_slice(&bytes[..take]);
                    self.item_len_have += take;
                    bytes = &bytes[take..];
                    if self.item_len_have == 4 {
                        self.item_total_len = u32::from_le_bytes(self.item_len_buf) as usize;
                        self.item_remaining = self.item_total_len;
                        self.item_prefix_have = 0;
                        if self.item_remaining == 0 {
                            self.items_remaining -= 1;
                            self.item_len_have = 0;
                            if self.items_remaining == 0 {
                                return Some(false);
                            }
                        }
                    }
                } else {
                    if self.item_prefix_have < 9 {
                        let need = (9 - self.item_prefix_have).min(self.item_remaining);
                        let take = need.min(bytes.len());
                        self.item_prefix[self.item_prefix_have..self.item_prefix_have + take]
                            .copy_from_slice(&bytes[..take]);
                        self.item_prefix_have += take;
                        self.item_remaining -= take;
                        bytes = &bytes[take..];
                        if self.item_prefix_have == 9
                            && self.item_prefix.eq_ignore_ascii_case(b"COVERART=")
                            && self.item_total_len < 25
                        {
                            return Some(true);
                        }
                    } else {
                        let skip = self.item_remaining.min(bytes.len());
                        self.item_remaining -= skip;
                        bytes = &bytes[skip..];
                    }
                    if self.item_remaining == 0 {
                        self.items_remaining -= 1;
                        self.item_len_have = 0;
                        if self.items_remaining == 0 {
                            return Some(false);
                        }
                    }
                }
            } else {
                return Some(false);
            }
        }
        None
    }

    fn feed_packet(&mut self, mut bytes: &[u8]) -> Option<bool> {
        // Buffer up to 8 bytes first to detect `\x03vorbis` (7 B) or `OpusTags` (8 B) magic
        // (Speex comment packets have no magic prefix).
        if !self.prefix_stripped {
            while self.magic_len < 8 && !bytes.is_empty() {
                self.magic[self.magic_len] = bytes[0];
                self.magic_len += 1;
                bytes = &bytes[1..];
            }
            if self.magic_len < 8 {
                return None;
            }
            self.prefix_stripped = true;
            let magic = self.magic;
            let leftover: &[u8] = if &magic[..7] == b"\x03vorbis" {
                &magic[7..8]
            } else if &magic == b"OpusTags" {
                &[]
            } else {
                &magic[..]
            };
            if let Some(res) = self.feed_body(leftover) {
                return Some(res);
            }
        }
        self.feed_body(bytes)
    }
}

/// Scan an Ogg container's first two packets in O(1) memory.
///
/// When `track_serial` is `true`, tracks the primary logical stream's `serial_number` from page 0,
/// skips pages belonging to interleaved foreign serials, and resyncs forward on `b"OggS"` within
/// a bounded work budget. When `track_serial` is `false`, mirrors `ogg_pager 0.8.0`'s contiguous
/// serial-blind `Packets::read_count` so a malicious comment packet placed on a foreign serial
/// page immediately after BOS cannot slip through either.
#[cfg(feature = "audio")]
fn scan_ogg_comments(data: &[u8], track_serial: bool) -> bool {
    if data.len() < 27 || !data.starts_with(b"OggS") {
        return false;
    }
    let primary_serial = u32::from_le_bytes([data[14], data[15], data[16], data[17]]);
    let max_resync_bytes = data.len().min(64 * 1024);
    let mut resync_bytes = 0usize;
    let mut pages_seen = 0usize;
    let mut header_bytes = 0usize;
    let mut packet_index = 0usize;
    let mut scanner = OggCommentScanner::default();
    let mut pos = 0usize;

    while pos + 27 <= data.len() {
        if &data[pos..pos + 4] != b"OggS" {
            if !track_serial {
                break;
            }
            let Some(rel) = data[pos..].windows(4).position(|w| w == b"OggS") else {
                break;
            };
            resync_bytes = resync_bytes.saturating_add(rel);
            if resync_bytes > max_resync_bytes {
                return true;
            }
            pos += rel;
            if pos + 27 > data.len() {
                break;
            }
        }

        pages_seen += 1;
        if pages_seen > OGG_MAX_HEADER_PAGES {
            return true;
        }

        let version = data[pos + 4];
        let serial = u32::from_le_bytes([
            data[pos + 14],
            data[pos + 15],
            data[pos + 16],
            data[pos + 17],
        ]);
        let num_segments = data[pos + 26] as usize;
        let table_start = pos + 27;
        let body_start = table_start + num_segments;
        if version != 0 || num_segments == 0 || body_start > data.len() {
            if !track_serial {
                break;
            }
            pos += 4;
            continue;
        }

        let payload_len: usize = data[table_start..body_start]
            .iter()
            .map(|&s| usize::from(s))
            .sum();
        let Some(page_end) = body_start.checked_add(payload_len) else {
            return false;
        };
        if page_end > data.len() {
            return false;
        }

        if track_serial && serial != primary_serial {
            pos = page_end;
            continue;
        }

        let mut seg_cursor = body_start;
        for &seg_len in &data[table_start..body_start] {
            let len = usize::from(seg_len);
            let seg_end = seg_cursor + len;
            header_bytes = header_bytes.saturating_add(len);
            if header_bytes > LOFTY_ALLOCATION_LIMIT {
                return true;
            }
            if packet_index == 1
                && let Some(is_unsafe) = scanner.feed_packet(&data[seg_cursor..seg_end])
            {
                return is_unsafe;
            }
            seg_cursor = seg_end;
            if seg_len < 255 {
                packet_index += 1;
                if packet_index > 1 {
                    return false;
                }
            }
        }
        pos = page_end;
    }
    false
}

/// Inspect FLAC `VORBIS_COMMENT` metadata blocks and Ogg comment packets (Vorbis, Opus, Speex)
/// without allocating, rejecting oversized `number_of_items` counts and `< 8`-byte `COVERART=`
/// entries before `lofty` reads them.
#[cfg(feature = "audio")]
fn has_oversized_vorbis_comments(data: &[u8]) -> bool {
    if data.starts_with(b"ID3") || data.starts_with(b"fLaC") {
        let mut total_blocks = 0usize;
        for flac_pos in data
            .windows(4)
            .enumerate()
            .filter_map(|(i, w)| (w == b"fLaC").then_some(i))
        {
            let mut cursor = flac_pos + 4;
            let Some(first_hdr) = data.get(cursor..cursor + 4) else {
                continue;
            };
            let first_type = first_hdr[0] & 0x7F;
            let first_len =
                u32::from_be_bytes([0, first_hdr[1], first_hdr[2], first_hdr[3]]) as usize;
            if first_type != 0 || first_len < 14 {
                continue;
            }
            while cursor + 4 <= data.len() {
                total_blocks += 1;
                if total_blocks > 4096 {
                    return true;
                }
                let hdr = &data[cursor..cursor + 4];
                let is_last = (hdr[0] & 0x80) != 0;
                let block_type = hdr[0] & 0x7F;
                let block_len = u32::from_be_bytes([0, hdr[1], hdr[2], hdr[3]]) as usize;
                cursor += 4;
                let Some(end) = cursor.checked_add(block_len) else {
                    break;
                };
                if end > data.len() {
                    break;
                }
                if block_type == 4 && vorbis_comment_is_unsafe(&data[cursor..end]) {
                    return true;
                }
                cursor = end;
                if is_last {
                    break;
                }
            }
        }
    }

    data.starts_with(b"OggS") && (scan_ogg_comments(data, true) || scan_ogg_comments(data, false))
}

/// Truncate `text` to at most `max_bytes` bytes on a UTF-8 character boundary.
#[cfg(feature = "audio")]
fn bound_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// The tags of the audio file `data`, if it has any: ID3, MP4, FLAC or Vorbis comments. Its
/// main tag first, then the others, as an MP3's ID3v1 after its ID3v2; the front cover, or else
/// its first picture, only if it is an image a page shows, whatever its tag calls it.
#[cfg(feature = "audio")]
pub fn tags(data: &[u8]) -> Option<Tags> {
    use std::{borrow::Cow, io::Cursor};

    use lofty::{
        config::{GlobalOptions, ParseOptions, ParsingMode, apply_global_options},
        picture::PictureType,
        prelude::{Accessor, TaggedFileExt},
        probe::Probe,
        tag::Tag,
    };

    if data.len() > MAX_AUDIO_BYTES {
        return None;
    }

    if has_compressed_id3v2(data)
        || has_mp4_extended_freeform_atom(data)
        || has_oversized_ape_footer(data)
        || has_oversized_vorbis_comments(data)
    {
        return None;
    }

    apply_global_options(
        GlobalOptions::new()
            .allocation_limit(LOFTY_ALLOCATION_LIMIT)
            .preserve_format_specific_items(false),
    );

    let file = Probe::new(Cursor::new(data))
        .options(
            ParseOptions::new()
                .read_properties(false)
                .parsing_mode(ParsingMode::Strict),
        )
        .guess_file_type()
        .ok()?
        .read()
        .ok()?;
    let all: Vec<&Tag> = file.primary_tag().into_iter().chain(file.tags()).collect();
    let text = |field: fn(&Tag) -> Option<Cow<'_, str>>| {
        all.iter().find_map(|tag| {
            let value = field(tag)?;
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| bound_text(trimmed, TAG_TEXT_MAX))
        })
    };
    let valid_pictures = || {
        all.iter()
            .flat_map(|tag| tag.pictures())
            .filter_map(|picture| {
                let bytes = picture.data();
                if bytes.len() > COVER_MAX {
                    return None;
                }
                let mime = picture_type(bytes)?;
                Some((picture.pic_type(), mime, bytes))
            })
    };
    let cover = valid_pictures()
        .find(|(pic_type, _, _)| *pic_type == PictureType::CoverFront)
        .or_else(|| valid_pictures().next())
        .map(|(_, mime, bytes)| (mime.to_string(), bytes.to_vec()));
    let tags = Tags {
        title: text(|tag| tag.title()),
        artist: text(|tag| tag.artist()),
        album: text(|tag| tag.album()),
        year: all.iter().find_map(|tag| tag.date()).map(|date| date.year),
        cover,
    };
    (tags != Tags::default()).then_some(tags)
}

/// Stateless [`WorkerService`](crate::rpc::WorkerService) for audio tag extraction.
#[cfg(feature = "audio")]
#[derive(Debug, Default, Clone, Copy)]
pub struct AudioService;

#[cfg(feature = "audio")]
impl crate::rpc::WorkerService for AudioService {
    fn accepts(&self, method: crate::rpc::Method) -> bool {
        method.is_served_by(crate::Worker::Audio)
    }

    fn handle(&mut self, req: crate::rpc::Request) -> Result<crate::rpc::Response, String> {
        match req {
            crate::rpc::Request::Tags(bytes) => Ok(crate::rpc::Response::Tags(tags(&bytes))),
            other => Err(format!("no method {}", other.method().as_str())),
        }
    }
}

/// The MIME type of the picture `data`, by its first bytes, if a page shows it as an image:
/// PNG, JPEG, GIF, WebP, AVIF or BMP.
#[cfg(feature = "audio")]
fn picture_type(data: &[u8]) -> Option<&'static str> {
    match data {
        [0x89, b'P', b'N', b'G', ..] => Some("image/png"),
        [0xFF, 0xD8, 0xFF, ..] => Some("image/jpeg"),
        [b'G', b'I', b'F', b'8', ..] => Some("image/gif"),
        _ if data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP") => Some("image/webp"),
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
        [b'B', b'M', ..] if is_valid_bmp_header(data) => Some("image/bmp"),
        _ => None,
    }
}

/// Require a full BMP file header (14 B) + recognized DIB header size (>= 12 B, total >= 26 B)
/// so arbitrary 2-byte `"BM"` prefixes are never misclassified as BMP images.
#[cfg(feature = "audio")]
fn is_valid_bmp_header(data: &[u8]) -> bool {
    if data.len() < 26 {
        return false;
    }
    let file_size = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
    let dib_size = u32::from_le_bytes([data[14], data[15], data[16], data[17]]);
    file_size >= 26 && matches!(dib_size, 12 | 40 | 52 | 56 | 64 | 108 | 124)
}

#[cfg(all(test, feature = "audio"))]
mod tests {
    use lofty::{
        config::WriteOptions,
        id3::v2::Id3v2Tag,
        picture::{MimeType, Picture, PictureType},
        prelude::{Accessor, TagExt},
    };

    use super::*;
    use crate::rpc::{Method, Request, Response, WorkerService};

    /// A one-pixel PNG.
    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\x1f\x15\xc4\x89\0\0\0\rIDATx\x9cc\xf8\x0f\0\x01\x01\x01\0\x18\xdd\x8d\xb0\0\0\0\0IEND\xaeB`\x82";

    fn mp3(tag: &Id3v2Tag) -> Vec<u8> {
        let mut mp3 = vec![];
        tag.dump_to(&mut mp3, WriteOptions::default()).unwrap();
        for _ in 0..4 {
            mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
            mp3.extend_from_slice(&[0; 413]);
        }
        mp3
    }

    fn cover(data: &[u8]) -> Picture {
        Picture::unchecked(data.to_vec())
            .pic_type(PictureType::CoverFront)
            .mime_type(MimeType::Png)
            .build()
    }

    fn synchsafe(v: u32) -> [u8; 4] {
        [
            ((v >> 21) & 0x7F) as u8,
            ((v >> 14) & 0x7F) as u8,
            ((v >> 7) & 0x7F) as u8,
            (v & 0x7F) as u8,
        ]
    }

    fn append_mp3_silence(out: &mut Vec<u8>) {
        for _ in 0..4 {
            out.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
            out.extend_from_slice(&[0; 413]);
        }
    }

    fn wrap_id3v24(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"ID3");
        out.extend_from_slice(&[4, 0, 0]);
        out.extend_from_slice(&synchsafe(body.len() as u32));
        out.extend_from_slice(body);
        append_mp3_silence(&mut out);
        out
    }

    fn v24_frame(id: &[u8; 4], flags: u16, body: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(id);
        f.extend_from_slice(&synchsafe(body.len() as u32));
        f.extend_from_slice(&flags.to_be_bytes());
        f.extend_from_slice(body);
        f
    }

    fn compressed_apic() -> Vec<u8> {
        v24_frame(
            b"APIC",
            0x0009,
            &[0, 0, 0, 16, 0x78, 0x9c, 0x03, 0, 0, 0, 0, 1],
        )
    }

    fn mp4_atom(ident: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = ((8 + payload.len()) as u32).to_be_bytes().to_vec();
        out.extend_from_slice(ident);
        out.extend_from_slice(payload);
        out
    }

    fn wrap_m4a_with_ilst(ilst_payload: &[u8], extra_top_level: &[u8]) -> Vec<u8> {
        let ilst = mp4_atom(b"ilst", ilst_payload);
        let mut hdlr_payload = vec![0u8; 25];
        hdlr_payload[8..12].copy_from_slice(b"mdir");
        let hdlr = mp4_atom(b"hdlr", &hdlr_payload);
        let mut meta_payload = vec![0u8; 4]; // full meta version/flags
        meta_payload.extend_from_slice(&hdlr);
        meta_payload.extend_from_slice(&ilst);
        let meta = mp4_atom(b"meta", &meta_payload);
        let udta = mp4_atom(b"udta", &meta);
        let moov = mp4_atom(b"moov", &udta);
        let mut m4a = mp4_atom(b"ftyp", b"M4A \x00\x00\x00\x00M4A ");
        m4a.extend_from_slice(&moov);
        m4a.extend_from_slice(extra_top_level);
        m4a
    }

    fn ogg_page(header_type: u8, serial: u32, seq: u32, payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() < 255);
        let mut page = Vec::with_capacity(28 + payload.len());
        page.extend_from_slice(b"OggS");
        page.push(0); // version
        page.push(header_type);
        page.extend_from_slice(&0u64.to_le_bytes()); // granule position
        page.extend_from_slice(&serial.to_le_bytes());
        page.extend_from_slice(&seq.to_le_bytes());
        page.extend_from_slice(&0u32.to_le_bytes()); // checksum (ignored by preflight)
        page.push(1); // 1 segment
        page.push(payload.len() as u8);
        page.extend_from_slice(payload);
        page
    }

    fn oversized_flac_stream() -> Vec<u8> {
        let mut flac = b"fLaC".to_vec();
        flac.extend_from_slice(&[0x00, 0x00, 0x00, 34]); // STREAMINFO (non-last, 34 B)
        flac.extend_from_slice(&[0u8; 34]);
        flac.extend_from_slice(&[0x7F, 0x00, 0x00, 0x00]); // block_type 127 (non-last, 0 B)
        let mut vc = Vec::new();
        vc.extend_from_slice(&0u32.to_le_bytes());
        vc.extend_from_slice(&(VORBIS_COMMENTS_MAX + 1).to_le_bytes());
        let vc_len = vc.len() as u32;
        flac.push(0x80 | 4);
        flac.extend_from_slice(&vc_len.to_be_bytes()[1..]);
        flac.extend_from_slice(&vc);
        flac
    }

    #[test]
    fn titles_artists_albums_and_covers() {
        let mut tag = Id3v2Tag::new();
        tag.set_title("Song".into());
        tag.set_artist("Singer".into());
        tag.set_album("Album".into());
        tag.insert_picture(cover(PNG));
        let read = tags(&mp3(&tag)).expect("tags");
        assert_eq!(read.title.as_deref(), Some("Song"));
        assert_eq!(read.artist.as_deref(), Some("Singer"));
        assert_eq!(read.album.as_deref(), Some("Album"));
        assert_eq!(read.cover, Some(("image/png".to_string(), PNG.to_vec())));
    }

    #[test]
    fn a_cover_that_is_no_image_is_left_out() {
        let mut tag = Id3v2Tag::new();
        tag.set_title("Song".into());
        tag.insert_picture(cover(b"<svg onload=alert(1)>"));
        assert_eq!(tags(&mp3(&tag)).expect("tags").cover, None);
    }

    #[test]
    fn bmp_sniff_rejects_short_and_malformed_headers_and_accepts_valid_bmp() {
        assert_eq!(picture_type(b"BM"), None);
        assert_eq!(picture_type(b"BMnot_a_real_bmp_header_123456"), None);
        let mut valid_bmp = vec![0u8; 58];
        valid_bmp[0..2].copy_from_slice(b"BM");
        valid_bmp[2..6].copy_from_slice(&58u32.to_le_bytes());
        valid_bmp[10..14].copy_from_slice(&54u32.to_le_bytes());
        valid_bmp[14..18].copy_from_slice(&40u32.to_le_bytes()); // BITMAPINFOHEADER
        assert_eq!(picture_type(&valid_bmp), Some("image/bmp"));
        assert!(is_image_mime("image/bmp"));
        assert!(!is_image_mime("image/svg+xml"));
        assert!(!is_image_mime("text/html"));
    }

    #[test]
    fn no_tags_say_nothing() {
        assert_eq!(tags(b"RIFF....WAVEfmt "), None);
    }

    #[test]
    fn oversized_cover_and_text_tags_are_bounded() {
        let mut huge_png = PNG.to_vec();
        huge_png.resize(COVER_MAX + 1, 0);
        let mut tag = Id3v2Tag::new();
        tag.set_title("A".repeat(TAG_TEXT_MAX + 200));
        tag.insert_picture(cover(&huge_png));
        let read = tags(&mp3(&tag)).expect("tags");
        assert_eq!(read.cover, None);
        assert_eq!(read.title.as_deref().map(str::len), Some(TAG_TEXT_MAX));
    }

    #[test]
    fn compressed_id3v2_frames_are_rejected_before_decompression() {
        let apic = compressed_apic();
        let v24 = wrap_id3v24(&apic);
        assert!(has_compressed_id3v2(&v24));
        assert_eq!(tags(&v24), None);

        // Synthetic ID3v2.3 tag with a compressed APIC frame (flag bit 0x0080 set).
        let mut v23 = v24.clone();
        let fsize = (apic.len() - 10) as u32;
        v23[3] = 3;
        v23[14..18].copy_from_slice(&fsize.to_be_bytes());
        v23[18..20].copy_from_slice(&0x0080u16.to_be_bytes());
        assert!(has_compressed_id3v2(&v23));
        assert_eq!(tags(&v23), None);
    }

    #[test]
    fn id3v2_woaf_and_wxx_nul_desync_is_rejected() {
        let mut woaf_smuggle_body = b"https://example.test\0".to_vec();
        woaf_smuggle_body.extend_from_slice(&compressed_apic());
        let woaf_smuggle = wrap_id3v24(&v24_frame(b"WOAF", 0, &woaf_smuggle_body));
        assert!(has_compressed_id3v2(&woaf_smuggle));
        assert_eq!(tags(&woaf_smuggle), None);

        let clean_woaf = wrap_id3v24(&v24_frame(b"WOAF", 0, b"https://example.test\0\0"));
        assert!(!has_compressed_id3v2(&clean_woaf));

        let v24_outdated_compressed = wrap_id3v24(&v24_frame(
            b"PIC\0",
            0x0009,
            &[0, 0, 0, 16, 0x78, 0x9c, 0x03, 0, 0, 0, 0, 1],
        ));
        assert!(has_compressed_id3v2(&v24_outdated_compressed));

        let mut wxx_desync_body = b"https://example.test\0".to_vec();
        wxx_desync_body.extend_from_slice(&compressed_apic());
        let v24_wxx_desync = wrap_id3v24(&v24_frame(b"WXX\0", 0, &wxx_desync_body));
        assert!(has_compressed_id3v2(&v24_wxx_desync));
    }

    #[test]
    fn id3v2_chap_compression_desync_and_recursion_are_rejected() {
        let apic = compressed_apic();

        // Compressed frame inside CHAP child.
        let mut chap_body = b"ch1\0".to_vec();
        chap_body.extend_from_slice(&[0u8; 16]);
        chap_body.extend_from_slice(&apic);
        let chap_compressed = wrap_id3v24(&v24_frame(b"CHAP", 0, &chap_body));
        assert!(has_compressed_id3v2(&chap_compressed));
        assert_eq!(tags(&chap_compressed), None);

        // CHAP with early NUL padding + trailing non-zero bytes.
        let mut chap_desync_body = b"ch1\0".to_vec();
        chap_desync_body.extend_from_slice(&[0u8; 16]);
        chap_desync_body.push(0x00);
        chap_desync_body.extend_from_slice(&apic);
        assert!(has_compressed_id3v2(&wrap_id3v24(&v24_frame(
            b"CHAP",
            0,
            &chap_desync_body
        ))));

        // Deeply nested CHAP recursion (> ID3V2_MAX_DEPTH).
        let mut nested = Vec::new();
        for _ in 0..=ID3V2_MAX_DEPTH + 1 {
            let mut inner = b"c\0".to_vec();
            inner.extend_from_slice(&[0u8; 16]);
            inner.extend_from_slice(&nested);
            nested = v24_frame(b"CHAP", 0, &inner);
        }
        assert!(has_compressed_id3v2(&wrap_id3v24(&nested)));

        // Child WOAF with trailing NUL inside CHAP.
        let mut chap_woaf_pad = b"ch1\0".to_vec();
        chap_woaf_pad.extend_from_slice(&[0u8; 16]);
        chap_woaf_pad.extend_from_slice(&v24_frame(b"WOAF", 0, b"x\0\0"));
        assert!(has_compressed_id3v2(&wrap_id3v24(&v24_frame(
            b"CHAP",
            0,
            &chap_woaf_pad
        ))));

        // Nested CHAP with >= 11 bytes of zero padding.
        let mut inner_chap_body = b"c2\0".to_vec();
        inner_chap_body.extend_from_slice(&[0u8; 16]);
        inner_chap_body.extend_from_slice(&[0u8; 11]);
        let mut outer_chap_body = b"c1\0".to_vec();
        outer_chap_body.extend_from_slice(&[0u8; 16]);
        outer_chap_body.extend_from_slice(&v24_frame(b"CHAP", 0, &inner_chap_body));
        assert!(has_compressed_id3v2(&wrap_id3v24(&v24_frame(
            b"CHAP",
            0,
            &outer_chap_body
        ))));
    }

    #[test]
    fn id3v2_extended_header_desync_and_early_padding_are_rejected() {
        let apic = compressed_apic();

        // 1. ID3v2.3 with BOTH unsynchronisation (0x80) and extended header (0x40).
        let mut v23_ext_unsynch = b"ID3\x03\x00\xC0".to_vec();
        v23_ext_unsynch.extend_from_slice(&synchsafe(100));
        v23_ext_unsynch.extend_from_slice(&[0u8; 100]);
        assert!(has_compressed_id3v2(&v23_ext_unsynch));

        // 2. ID3v2.4 extended header with flag 0x40 ("Tag is an update", 1-byte 0x00 payload)
        //    followed by a compressed APIC frame. Previously `cursor` stayed on `0x00`, returning
        //    `EarlyPaddingWithTrailingData` which bypassed the preflight!
        let mut v24_update_ext = b"ID3\x04\x00\x40".to_vec();
        let body_len = 7 + apic.len();
        v24_update_ext.extend_from_slice(&synchsafe(body_len as u32));
        v24_update_ext.extend_from_slice(&synchsafe(7)); // ext_size = 7
        v24_update_ext.extend_from_slice(&[0x01, 0x40, 0x00]); // num_flag_bytes=1, update flag, 0x00 len
        v24_update_ext.extend_from_slice(&apic);
        append_mp3_silence(&mut v24_update_ext);
        assert!(has_compressed_id3v2(&v24_update_ext));
        assert_eq!(tags(&v24_update_ext), None);

        // 3. ID3v2.3 extended header (4-byte padding_size + CRC flag 0x80) followed by compressed APIC.
        let mut v23_ext = b"ID3\x03\x00\x40".to_vec();
        let v23_body_len = 14 + apic.len();
        v23_ext.extend_from_slice(&synchsafe(v23_body_len as u32));
        v23_ext.extend_from_slice(&10u32.to_be_bytes()); // ext_size = 10 (excludes 4-byte size)
        v23_ext.extend_from_slice(&[0x80, 0x00]); // CRC present
        v23_ext.extend_from_slice(&0u32.to_be_bytes()); // padding_size
        v23_ext.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // 4-byte CRC
        v23_ext.extend_from_slice(&apic);
        append_mp3_silence(&mut v23_ext);
        assert!(has_compressed_id3v2(&v23_ext));
        assert_eq!(tags(&v23_ext), None);

        // 4. Top-level early 0x00 padding followed by non-zero trailing data is rejected (`!= Clean`).
        let mut early_pad = vec![0x00; 10];
        early_pad.extend_from_slice(&apic);
        let early_pad_tag = wrap_id3v24(&early_pad);
        assert!(has_compressed_id3v2(&early_pad_tag));
        assert_eq!(tags(&early_pad_tag), None);

        // 5. Clean ID3v2.4 extended header (`ext_size = 6`, no flags) with clean TIT2 passes preflight.
        let tit2 = v24_frame(b"TIT2", 0, b"\x03Clean");
        let mut clean_ext = b"ID3\x04\x00\x40".to_vec();
        clean_ext.extend_from_slice(&synchsafe((6 + tit2.len()) as u32));
        clean_ext.extend_from_slice(&synchsafe(6));
        clean_ext.extend_from_slice(&[0x01, 0x00]);
        clean_ext.extend_from_slice(&tit2);
        append_mp3_silence(&mut clean_ext);
        assert!(!has_compressed_id3v2(&clean_ext));
    }

    #[test]
    fn id3v2_overlapping_headers_trip_work_budget() {
        let mut id3_dos = Vec::with_capacity(20_000 * 10);
        for _ in 0..20_000 {
            id3_dos.extend_from_slice(b"ID3\x03\x00\x80\x7F\x7F\x7F\x7F");
        }
        assert!(has_compressed_id3v2(&id3_dos));
        assert_eq!(tags(&id3_dos), None);
    }

    #[test]
    fn id3v2_polyglot_prefixes_do_not_bypass_preflight() {
        let apic = compressed_apic();
        let mut compressed_id3_tag = b"ID3\x04\x00\x00".to_vec();
        compressed_id3_tag.extend_from_slice(&synchsafe(apic.len() as u32));
        compressed_id3_tag.extend_from_slice(&apic);

        let mut wav_ftyp = b"RIFFftypWAVEID3 ".to_vec();
        wav_ftyp.extend_from_slice(&(compressed_id3_tag.len() as u32).to_le_bytes());
        wav_ftyp.extend_from_slice(&compressed_id3_tag);
        assert!(has_compressed_id3v2(&wav_ftyp));
        assert_eq!(tags(&wav_ftyp), None);

        let mut aiff_ftyp = b"FORMftypAIFFID3 ".to_vec();
        aiff_ftyp.extend_from_slice(&(compressed_id3_tag.len() as u32).to_be_bytes());
        aiff_ftyp.extend_from_slice(&compressed_id3_tag);
        assert!(has_compressed_id3v2(&aiff_ftyp));
        assert_eq!(tags(&aiff_ftyp), None);

        let mut ogg_fake_mpeg = b"OggS".to_vec();
        ogg_fake_mpeg.extend_from_slice(&compressed_id3_tag);
        append_mp3_silence(&mut ogg_fake_mpeg);
        assert!(has_compressed_id3v2(&ogg_fake_mpeg));
        assert_eq!(tags(&ogg_fake_mpeg), None);

        let mut mpeg_ftyp = b"\xFF\xFB\x0C\x00ftyp".to_vec();
        mpeg_ftyp.extend_from_slice(&compressed_id3_tag);
        append_mp3_silence(&mut mpeg_ftyp);
        assert!(has_compressed_id3v2(&mpeg_ftyp));
        assert_eq!(tags(&mpeg_ftyp), None);
    }

    #[test]
    fn flac_vorbis_comment_caps_and_short_coverart_are_rejected() {
        let flac = oversized_flac_stream();
        assert!(has_oversized_vorbis_comments(&flac));
        assert_eq!(tags(&flac), None);

        // Short `COVERART=` VorbisComment with minimal 14-byte STREAMINFO.
        let mut coverart_flac = b"fLaC".to_vec();
        coverart_flac.extend_from_slice(&[0x00, 0x00, 0x00, 14]);
        coverart_flac.extend_from_slice(&[0u8; 14]);
        let mut short_vc = Vec::new();
        short_vc.extend_from_slice(&0u32.to_le_bytes());
        short_vc.extend_from_slice(&1u32.to_le_bytes());
        short_vc.extend_from_slice(&9u32.to_le_bytes());
        short_vc.extend_from_slice(b"COVERART=");
        let short_vc_len = short_vc.len() as u32;
        coverart_flac.push(0x80 | 4);
        coverart_flac.extend_from_slice(&short_vc_len.to_be_bytes()[1..]);
        coverart_flac.extend_from_slice(&short_vc);
        assert!(has_oversized_vorbis_comments(&coverart_flac));
        assert_eq!(tags(&coverart_flac), None);

        // Literal `"fLaC"` inside MP3 ID3v2 padding must NOT false-positive.
        let mut mp3_with_flac_text = b"ID3\x04\x00\x00".to_vec();
        let mut body = b"fLaC".to_vec();
        body.extend_from_slice(&[0u8; 20_000]);
        mp3_with_flac_text.extend_from_slice(&synchsafe(body.len() as u32));
        mp3_with_flac_text.extend_from_slice(&body);
        assert!(!has_oversized_vorbis_comments(&mp3_with_flac_text));

        // ID3v2.2 with footer flag 0x10 followed immediately by FLAC.
        let mut v22_flac = b"ID3\x02\x00\x10\x00\x00\x00\x00".to_vec();
        v22_flac.extend_from_slice(&flac);
        assert!(has_oversized_vorbis_comments(&v22_flac));
        assert_eq!(tags(&v22_flac), None);

        // ID3v2.4 with extended header + decoy `fLaC` + real `fLaC`.
        let mut v24_split_flac = b"ID3\x04\x00\x40\x00\x00\x00\x10".to_vec();
        v24_split_flac.extend_from_slice(&[0u8; 16]);
        v24_split_flac.extend_from_slice(b"fLaC\x80\x00\x00\x00");
        v24_split_flac.extend_from_slice(&[0u8; 6]);
        v24_split_flac.extend_from_slice(&flac);
        assert!(has_oversized_vorbis_comments(&v24_split_flac));
        assert_eq!(tags(&v24_split_flac), None);
    }

    #[test]
    fn ogg_multi_serial_interleaved_bos_and_resync_junk_are_rejected() {
        let mut opus_ident = b"OpusHead".to_vec();
        opus_ident.extend_from_slice(&[1, 2, 0, 0, 0x80, 0xBB, 0, 0, 0, 0, 0]);

        let mut evil_tags = b"OpusTags".to_vec();
        evil_tags.extend_from_slice(&0u32.to_le_bytes()); // vendor len = 0
        evil_tags.extend_from_slice(&(VORBIS_COMMENTS_MAX + 1).to_le_bytes());

        // 1. Interleaved foreign-serial BOS page before stream 1's malicious comment packet.
        let mut interleaved = ogg_page(0x02, 1, 0, &opus_ident);
        interleaved.extend_from_slice(&ogg_page(0x02, 2, 0, b"decoy-bos"));
        interleaved.extend_from_slice(&ogg_page(0x00, 1, 1, &evil_tags));
        assert!(has_oversized_vorbis_comments(&interleaved));
        assert_eq!(tags(&interleaved), None);

        // 2. Non-`OggS` resync junk inserted between page 0 and page 1.
        let mut resynced = ogg_page(0x02, 1, 0, &opus_ident);
        resynced.extend_from_slice(b"JUNK_BYTES_BETWEEN_PAGES");
        resynced.extend_from_slice(&ogg_page(0x00, 1, 1, &evil_tags));
        assert!(has_oversized_vorbis_comments(&resynced));
        assert_eq!(tags(&resynced), None);

        // 3. Malicious comment packet placed on a foreign serial right after BOS (targets
        //    serial-blind `ogg_pager 0.8.0`).
        let mut foreign_evil = ogg_page(0x02, 1, 0, &opus_ident);
        foreign_evil.extend_from_slice(&ogg_page(0x00, 99, 1, &evil_tags));
        assert!(has_oversized_vorbis_comments(&foreign_evil));
        assert_eq!(tags(&foreign_evil), None);

        // 4. Clean Opus stream passes preflight.
        let mut clean_tags = b"OpusTags".to_vec();
        clean_tags.extend_from_slice(&0u32.to_le_bytes());
        clean_tags.extend_from_slice(&1u32.to_le_bytes());
        let comment = b"TITLE=Clean";
        clean_tags.extend_from_slice(&(comment.len() as u32).to_le_bytes());
        clean_tags.extend_from_slice(comment);
        let mut clean_ogg = ogg_page(0x02, 1, 0, &opus_ident);
        clean_ogg.extend_from_slice(&ogg_page(0x00, 1, 1, &clean_tags));
        assert!(!has_oversized_vorbis_comments(&clean_ogg));
    }

    #[test]
    fn mp4_atom_boundary_rejects_malformed_atoms_without_payload_false_positives() {
        // 1. Extended / undersized freeform `----` at top level and inside `ilst`.
        for bad_freeform in [
            b"\x00\x00\x00\x01----".as_slice(),
            b"\x00\x00\x00\x08----".as_slice(),
        ] {
            let mut top = mp4_atom(b"ftyp", b"M4A \x00\x00\x00\x00M4A ");
            top.extend_from_slice(bad_freeform);
            assert!(has_mp4_extended_freeform_atom(&top));
            assert_eq!(tags(&top), None);
        }

        // 2. Extended and undersized (2..12) `mean` / `name` and (2..16) `data` inside `ilst -> ----`.
        let good_mean = mp4_atom(b"mean", b"\0\0\0\0com.apple.iTunes");
        let good_name = mp4_atom(b"name", b"\0\0\0\0CUSTOM");
        for bad_inner in [
            // Extended `mean`
            b"\x00\x00\x00\x01mean\x00\x00\x00\x00\x00\x00\x00\x14\0\0\0\0".to_vec(),
            // Undersized `mean` (len = 8, in 2..12)
            b"\x00\x00\x00\x08mean".to_vec(),
            // Undersized `name` (len = 10, in 2..12)
            [good_mean.as_slice(), b"\x00\x00\x00\x0aname\0\0"].concat(),
            // Extended `name`
            [
                good_mean.as_slice(),
                b"\x00\x00\x00\x01name\x00\x00\x00\x00\x00\x00\x00\x14\0\0\0\0",
            ]
            .concat(),
            // Undersized `data` (len = 12, in 2..16)
            [
                good_mean.as_slice(),
                good_name.as_slice(),
                b"\x00\x00\x00\x0cdata\0\0\0\0",
            ]
            .concat(),
            // Extended `data`
            [
                good_mean.as_slice(),
                good_name.as_slice(),
                b"\x00\x00\x00\x01data\x00\x00\x00\x00\x00\x00\x00\x18\0\0\0\x01\0\0\0\0",
            ]
            .concat(),
        ] {
            let freeform = mp4_atom(b"----", &bad_inner);
            let m4a = wrap_m4a_with_ilst(&freeform, &[]);
            assert!(has_mp4_extended_freeform_atom(&m4a));
            assert_eq!(tags(&m4a), None);
        }

        // 3. 44-byte MP4 `meta` `end - pos` underflow (`len_raw == 0` `hdlr` inside `meta`).
        let mut mp4_meta_eof = Vec::new();
        mp4_meta_eof.extend_from_slice(b"\x00\x00\x00\x0cftypM4A ");
        mp4_meta_eof.extend_from_slice(b"\x00\x00\x00\x1dmoov");
        mp4_meta_eof.extend_from_slice(b"\x00\x00\x00\x15udta");
        mp4_meta_eof.extend_from_slice(b"\x00\x00\x00\x15meta");
        mp4_meta_eof.extend_from_slice(b"\x00\x00\x00\x00hdlr");
        assert!(has_mp4_extended_freeform_atom(&mp4_meta_eof));
        assert_eq!(tags(&mp4_meta_eof), None);

        // 4. Legitimate M4A whose `mdat` media bytes AND `data` tag payload contain raw marker
        //    sequences (`\0\0\0\x01----`, `\0\0\0\x01data`, `meta\0\0\0\0hdlr`, `\0\0\0\0lang`)
        //    must NOT be false-positive rejected!
        let mut title_data = vec![0, 0, 0, 1, 0, 0, 0, 0];
        title_data.extend_from_slice(b"language");
        let nam = mp4_atom(b"\xA9nam", &mp4_atom(b"data", &title_data));
        let mut fake_media = b"\x00\x00\x00\x01----\x00\x00\x00\x01data".to_vec();
        fake_media.extend_from_slice(b"meta\x00\x00\x00\x00hdlr\x00\x00\x00\x08mean");
        let mdat = mp4_atom(b"mdat", &fake_media);
        let valid_m4a = wrap_m4a_with_ilst(&nam, &mdat);
        assert!(!has_mp4_extended_freeform_atom(&valid_m4a));
        assert_eq!(
            tags(&valid_m4a).and_then(|t| t.title),
            Some("language".to_string())
        );

        let mut aiff_with_dashes = b"FORM\x00\x00\x00\x20AIFF".to_vec();
        aiff_with_dashes.extend_from_slice(b"NAME\x00\x00\x00\x08\x00\x00\x00\x08----");
        assert!(!has_mp4_extended_freeform_atom(&aiff_with_dashes));
    }

    #[test]
    fn ape_and_wavpack_oversized_footer_and_u32_max_are_rejected() {
        for magic in [b"wvpk", b"MAC "] {
            let mut ape_underflow = Vec::new();
            ape_underflow.extend_from_slice(magic);
            ape_underflow.extend_from_slice(b"APETAGEX");
            ape_underflow.extend_from_slice(&2000u32.to_le_bytes());
            ape_underflow.extend_from_slice(&32u32.to_le_bytes());
            ape_underflow.extend_from_slice(&0u32.to_le_bytes());
            ape_underflow.extend_from_slice(&[0u8; 12]);
            ape_underflow.extend_from_slice(b"TAG");
            ape_underflow.extend_from_slice(&[0u8; 125]);
            assert!(has_oversized_ape_footer(&ape_underflow));
            assert_eq!(tags(&ape_underflow), None);
        }

        // 78-byte APE `ID3 + MAC + APETAGEX` underflow after subtracting leading ID3v2 size.
        let mut ape_id3_underflow = b"ID3\x04\x00\x00\x00\x00\x00\x20".to_vec();
        ape_id3_underflow.extend_from_slice(&[0u8; 32]);
        ape_id3_underflow.extend_from_slice(b"MAC ");
        ape_id3_underflow.extend_from_slice(b"APETAGEX");
        ape_id3_underflow.extend_from_slice(&2000u32.to_le_bytes());
        ape_id3_underflow.extend_from_slice(&32u32.to_le_bytes());
        ape_id3_underflow.extend_from_slice(&0u32.to_le_bytes());
        ape_id3_underflow.extend_from_slice(&[0u8; 12]);
        assert_eq!(ape_id3_underflow.len(), 78);
        assert!(has_oversized_ape_footer(&ape_id3_underflow));
        assert_eq!(tags(&ape_id3_underflow), None);

        // Version 2000 with `size == u32::MAX` must widen to u64 before `+ 32`.
        let mut ape_max = b"MAC APETAGEX".to_vec();
        ape_max.extend_from_slice(&2000u32.to_le_bytes());
        ape_max.extend_from_slice(&u32::MAX.to_le_bytes());
        ape_max.extend_from_slice(&0u32.to_le_bytes());
        ape_max.extend_from_slice(&[0u8; 12]);
        assert!(has_oversized_ape_footer(&ape_max));
    }

    #[test]
    fn audio_service_dispatches_and_rejects_other_methods() {
        let mut service = AudioService;
        assert!(service.accepts(Method::Tags));
        assert!(!service.accepts(Method::Find));

        let mut tag = Id3v2Tag::new();
        tag.set_title("Hello".into());
        let Response::Tags(Some(read)) = service.handle(Request::Tags(mp3(&tag))).unwrap() else {
            panic!("expected Tags");
        };
        assert_eq!(read.title.as_deref(), Some("Hello"));
        assert!(service.handle(Request::Close { doc_id: 1 }).is_err());
    }

    #[test]
    fn deterministic_adversarial_audio_fuzz_never_panics() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let chunks: &[&[u8]] = &[
            b"ID3\x02\x00\x00\x00\x00\x00\x20",
            b"ID3\x02\x00\x10\x00\x00\x00\x00",
            b"ID3\x03\x00\x40\x00\x00\x00\x40",
            b"ID3\x03\x00\xC0\x00\x00\x00\x40",
            b"ID3\x04\x00\x40\x00\x00\x00\x40",
            b"ID3\x04\x00\x80\x00\x00\x00\x40",
            b"CHAP\x00\x00\x00\x20\x00\x00ch1\0",
            b"CTOC\x00\x00\x00\x20\x00\x00toc\0\x03\x01c\0",
            b"WOAF\x00\x00\x00\x10\x00\x00http\0",
            b"WXX\0\x00\x00\x00\x10\x00\x00http\0",
            b"PIC\0\x00\x00\x00\x10\x00\x09",
            b"APIC\x00\x00\x00\x10\x00\x09",
            b"TIPL\x00\x00\x00\x10\x00\x00\x01\xFF\xFEa\0\0\0",
            b"COMM\x00\x00\x00\x10\x00\x00\x01eng\xFF\xFE\0\0",
            b"\x00\x00\x00\x14ftypM4A \x00\x00\x00\x00M4A ",
            b"\x00\x00\x00\x40moov\x00\x00\x00\x38udta\x00\x00\x00\x30meta\x00\x00\x00\x00\x00\x00\x00\x24ilst",
            b"\x00\x00\x00\x28----\x00\x00\x00\x10mean\x00\x00\x00\x00aaaa",
            b"\x00\x00\x00\x01----\x00\x00\x00\x00\x00\x00\x00\x10",
            b"\x00\x00\x00\x08----",
            b"\x00\x00\x00\x01mean\x00\x00\x00\x00\x00\x00\x00\x10",
            b"\x00\x00\x00\x01name\x00\x00\x00\x00\x00\x00\x00\x10",
            b"\x00\x00\x00\x01data\x00\x00\x00\x00\x00\x00\x00\x10",
            b"\x00\x00\x00\x00\xA9nam\x00\x00\x00\x14data\x00\x00\x00\x01\x00\x00\x00\x00hi",
            b"fLaC\x00\x00\x00\x22",
            b"\x84\x00\x00\x08\x00\x00\x00\x00\xFF\xFF\x00\x00",
            b"OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1E\x01vorbis",
            b"OggS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x10\x03vorbis\x00\x00\x00\x00\xFF\xFF\x00\x00",
            b"OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x13OpusHead",
            b"OpusTags\x00\x00\x00\x00\xFF\xFF\x00\x00",
            b"RIFF\x24\x00\x00\x00WAVEfmt ",
            b"FORM\x00\x00\x00\x20AIFF",
            b"APETAGEX\xD0\x07\x00\x00\x20\x00\x00\x00\x01\x00\x00\x00",
            b"\xFF\xFB\x90\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
        ];
        let mut buf = Vec::with_capacity(512);
        for _ in 0..1_200 {
            buf.clear();
            let pieces = 1 + (next_u64() as usize % 8);
            for _ in 0..pieces {
                let piece = chunks[next_u64() as usize % chunks.len()];
                buf.extend_from_slice(piece);
                let pad = (next_u64() as usize) % 16;
                for _ in 0..pad {
                    buf.push((next_u64() & 0xFF) as u8);
                }
            }
            if !buf.is_empty() && (next_u64() & 1) == 0 {
                let idx = next_u64() as usize % buf.len();
                buf[idx] ^= (1u8) << (next_u64() as u8 & 7);
            }
            let _ = tags(&buf);
        }
    }
}
