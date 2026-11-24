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
#[cfg(feature = "audio")]
const COVER_MAX: usize = 4 << 20;
/// Maximum byte length kept for a single audio text tag (title, artist, album).
#[cfg(feature = "audio")]
const TAG_TEXT_MAX: usize = 1024;

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

/// Maximum nested `CHAP`/`CTOC` recursion depth allowed in an ID3v2 tag before rejecting.
#[cfg(feature = "audio")]
const ID3V2_MAX_DEPTH: usize = 4;
/// Maximum Vorbis comment items allowed in a FLAC or Ogg comment block before rejecting
/// (`lofty 0.25.5` calls infallible `Vec::with_capacity(number_of_items)`).
#[cfg(feature = "audio")]
const VORBIS_COMMENTS_MAX: u32 = 4096;

#[cfg(feature = "audio")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Id3v2ScanResult {
    Clean,
    /// Padding (`0x00`) ended frame parsing early while non-zero bytes remained in the slice.
    EarlyPaddingWithTrailingData,
    /// Compressed frame, excessive `CHAP`/`CTOC` recursion, or parser-desync hazard detected.
    Unsafe,
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
///
/// `lofty 0.25.5` wraps compressed ID3v2 frames in an unbounded `flate2::read::ZlibDecoder`
/// (and its `default-features = false` build does not compile upstream), does not drain `Take`
/// after early-returning frame parsers, skips up to 8 KiB via `UnsynchronizedStream` on ID3v2.3
/// tags with both unsynchronisation and extended headers, and parses `CHAP`/`CTOC` children
/// recursively without a depth bound.
#[cfg(feature = "audio")]
fn has_compressed_id3v2(data: &[u8]) -> bool {
    // Formats that `lofty 0.25.5` unambiguously routes to a non-ID3v2 parser on the exact 36-byte
    // probe prefix (`Probe::guess_inner` calls `FileType::from_buffer_inner(&buf[..36])`) need no
    // ID3v2 preflight scan. Ambiguous or earlier-matching prefixes (`RIFFftypWAVE`, `FORMftypAIFF`,
    // non-Vorbis/Opus/Speex `OggS`, MPEG sync + `ftyp`, etc.) return `None` or an ID3-capable type
    // and still run the full ID3v2 preflight.
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
    // Bound cumulative ID3 body bytes scanned across repeated `ID3` markers so adversarial inputs
    // with thousands of overlapping headers cannot cause quadratic CPU/allocation amplification.
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

        let mut cursor = pos + 10;
        let mut ext_size = 0u32;
        if has_ext {
            let mut read_ext = |dst: &mut [u8]| -> bool {
                if cursor + dst.len() <= data.len() {
                    dst.copy_from_slice(&data[cursor..cursor + dst.len()]);
                    cursor += dst.len();
                    true
                } else {
                    false
                }
            };
            let mut size_buf = [0u8; 4];
            if !read_ext(&mut size_buf) {
                continue;
            }
            ext_size = if major == 4 {
                unsynch_u32(&size_buf)
            } else {
                u32::from_be_bytes(size_buf)
            };
            if ext_size < 6 || ext_size >= tag_size {
                continue;
            }
            let mut ext_hdr = [0u8; 2];
            if !read_ext(&mut ext_hdr) {
                continue;
            }
            let ext_flags = ext_hdr[1];
            if ext_flags & 0x20 != 0 {
                let mut crc = [0u8; 6];
                if !read_ext(&mut crc) {
                    continue;
                }
            }
            if ext_flags & 0x10 != 0 {
                let mut restrictions = [0u8; 2];
                if !read_ext(&mut restrictions) {
                    continue;
                }
            }
        }

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

        if scan_id3v2_frames(frames, major, unsynch, 0) == Id3v2ScanResult::Unsafe {
            return true;
        }
    }
    false
}

/// Reject MP4 extended-size freeform atoms (`----`, `mean`, `name`, `data` with `len_raw == 1`,
/// `header_len == 16`), undersized `----` atoms (`2..16`, which can underflow
/// `reader_size -= header_len` in `mp4/atom_info.rs:245`), and EOF-extending `meta` child atoms
/// (`len_raw == 0` for `hdlr`/`ilst`/`mhdr`/`ctry`/`lang` immediately after a normal or extended
/// `meta` header, which trigger `end - pos` underflow in `mp4/atom_info.rs:203` after
/// `meta_is_full` rewinds), preventing panics in `lofty 0.25.5`.
#[cfg(feature = "audio")]
fn has_mp4_extended_freeform_atom(data: &[u8]) -> bool {
    if lofty::file::FileType::from_buffer(&data[..data.len().min(36)])
        != Some(lofty::file::FileType::Mp4)
    {
        return false;
    }
    if data.windows(8).any(|w| {
        if &w[4..8] == b"----" {
            let len_raw = u32::from_be_bytes([w[0], w[1], w[2], w[3]]);
            return len_raw == 1 || (2..16).contains(&len_raw);
        }
        w == b"\x00\x00\x00\x01mean" || w == b"\x00\x00\x00\x01name" || w == b"\x00\x00\x00\x01data"
    }) {
        return true;
    }
    let is_meta_eof_child = |bytes: &[u8]| {
        bytes.len() >= 8
            && &bytes[0..4] == b"\x00\x00\x00\x00"
            && matches!(
                &bytes[4..8],
                b"hdlr" | b"ilst" | b"mhdr" | b"ctry" | b"lang"
            )
    };
    data.windows(4).enumerate().any(|(i, w)| {
        if w != b"meta" {
            return false;
        }
        // Normal 8-byte `meta` header (non-full or full + 4-byte version/flags).
        if data.get(i + 4..).is_some_and(is_meta_eof_child)
            || data.get(i + 8..).is_some_and(is_meta_eof_child)
        {
            return true;
        }
        // Extended 16-byte `meta` header (`\x00\x00\x00\x01meta` + 8-byte size, non-full or full).
        i >= 4
            && &data[i - 4..i] == b"\x00\x00\x00\x01"
            && (data.get(i + 12..).is_some_and(is_meta_eof_child)
                || data.get(i + 16..).is_some_and(is_meta_eof_child))
    })
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
        let ext_bytes = data.get(10..14)?;
        ext_size = if major == 4 {
            unsynch_u32(ext_bytes)
        } else {
            u32::from_be_bytes([ext_bytes[0], ext_bytes[1], ext_bytes[2], ext_bytes[3]])
        };
        if ext_size < 6 || ext_size >= size {
            return None;
        }
        let ext_hdr = data.get(14..16)?;
        let ext_flags = ext_hdr[1];
        let mut cursor = 16usize;
        if ext_flags & 0x20 != 0 {
            cursor = cursor.checked_add(6)?;
        }
        if ext_flags & 0x10 != 0 {
            cursor = cursor.checked_add(2)?;
        }
        if cursor > data.len() {
            return None;
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
        u64::from(size.saturating_add(32))
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

/// Inspect FLAC `VORBIS_COMMENT` metadata blocks and Ogg comment packets (Vorbis, Opus, Speex)
/// without allocating, rejecting oversized `number_of_items` counts and `< 8`-byte `COVERART=`
/// entries before `lofty` reads them.
#[cfg(feature = "audio")]
fn has_oversized_vorbis_comments(data: &[u8]) -> bool {
    // 1. FLAC stream (optionally preceded by an ID3v2 tag — scan every `fLaC` marker whose
    // initial block is a valid `STREAMINFO` with `first_len + 4 >= 18`, i.e. `first_len >= 14`,
    // matching `lofty-0.25.5` `flac/block.rs:55` & `flac/read.rs:76-80`, so neither ID3v2 offset
    // quirks nor `block_type == 127` skip the real metadata chain and literal `"fLaC"` inside MP3
    // ID3v2 text + padding causes no false positive).
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

    // 2. Ogg container (`OggS`): stream packet #1 (0-indexed: packet #0 is identification header,
    // packet #1 is the Vorbis/Opus/Speex comment header) in O(1) memory to check `number_of_items`
    // and short `COVERART=` entries.
    if data.starts_with(b"OggS") {
        let mut pos = 0usize;
        let mut packet_index = 0usize;
        let mut pkt1_magic = [0u8; 8];
        let mut pkt1_magic_len = 0usize;
        let mut pkt1_prefix_stripped = false;
        let mut vendor_len_buf = [0u8; 4];
        let mut vendor_len_have = 0usize;
        let mut vendor_remaining = 0usize;
        let mut count_buf = [0u8; 4];
        let mut count_have = 0usize;
        let mut items_remaining = 0u32;
        let mut item_len_buf = [0u8; 4];
        let mut item_len_have = 0usize;
        let mut item_total_len = 0usize;
        let mut item_remaining = 0usize;
        let mut item_prefix = [0u8; 9];
        let mut item_prefix_have = 0usize;

        let mut feed_body = |mut bytes: &[u8]| -> Option<bool> {
            while !bytes.is_empty() {
                if vendor_len_have < 4 {
                    let take = (4 - vendor_len_have).min(bytes.len());
                    vendor_len_buf[vendor_len_have..vendor_len_have + take]
                        .copy_from_slice(&bytes[..take]);
                    vendor_len_have += take;
                    bytes = &bytes[take..];
                    if vendor_len_have == 4 {
                        vendor_remaining = u32::from_le_bytes(vendor_len_buf) as usize;
                    }
                } else if vendor_remaining > 0 {
                    let skip = vendor_remaining.min(bytes.len());
                    vendor_remaining -= skip;
                    bytes = &bytes[skip..];
                } else if count_have < 4 {
                    let take = (4 - count_have).min(bytes.len());
                    count_buf[count_have..count_have + take].copy_from_slice(&bytes[..take]);
                    count_have += take;
                    bytes = &bytes[take..];
                    if count_have == 4 {
                        let count = u32::from_le_bytes(count_buf);
                        if count > VORBIS_COMMENTS_MAX {
                            return Some(true);
                        }
                        items_remaining = count;
                        if items_remaining == 0 {
                            return Some(false);
                        }
                    }
                } else if items_remaining > 0 {
                    if item_len_have < 4 {
                        let take = (4 - item_len_have).min(bytes.len());
                        item_len_buf[item_len_have..item_len_have + take]
                            .copy_from_slice(&bytes[..take]);
                        item_len_have += take;
                        bytes = &bytes[take..];
                        if item_len_have == 4 {
                            item_total_len = u32::from_le_bytes(item_len_buf) as usize;
                            item_remaining = item_total_len;
                            item_prefix_have = 0;
                            if item_remaining == 0 {
                                items_remaining -= 1;
                                item_len_have = 0;
                                if items_remaining == 0 {
                                    return Some(false);
                                }
                            }
                        }
                    } else {
                        if item_prefix_have < 9 {
                            let need = (9 - item_prefix_have).min(item_remaining);
                            let take = need.min(bytes.len());
                            item_prefix[item_prefix_have..item_prefix_have + take]
                                .copy_from_slice(&bytes[..take]);
                            item_prefix_have += take;
                            item_remaining -= take;
                            bytes = &bytes[take..];
                            if item_prefix_have == 9
                                && item_prefix.eq_ignore_ascii_case(b"COVERART=")
                                && item_total_len < 25
                            {
                                return Some(true);
                            }
                        } else {
                            let skip = item_remaining.min(bytes.len());
                            item_remaining -= skip;
                            bytes = &bytes[skip..];
                        }
                        if item_remaining == 0 {
                            items_remaining -= 1;
                            item_len_have = 0;
                            if items_remaining == 0 {
                                return Some(false);
                            }
                        }
                    }
                } else {
                    return Some(false);
                }
            }
            None
        };

        let mut feed_pkt1 = |mut bytes: &[u8]| -> Option<bool> {
            // Buffer up to 8 bytes first to detect `\x03vorbis` (7 B) or `OpusTags` (8 B) magic
            // (Speex comment packets have no magic prefix).
            if !pkt1_prefix_stripped {
                while pkt1_magic_len < 8 && !bytes.is_empty() {
                    pkt1_magic[pkt1_magic_len] = bytes[0];
                    pkt1_magic_len += 1;
                    bytes = &bytes[1..];
                }
                if pkt1_magic_len < 8 {
                    return None;
                }
                pkt1_prefix_stripped = true;
                let leftover: &[u8] = if &pkt1_magic[..7] == b"\x03vorbis" {
                    &pkt1_magic[7..8]
                } else if &pkt1_magic == b"OpusTags" {
                    &[]
                } else {
                    &pkt1_magic[..]
                };
                if let Some(res) = feed_body(leftover) {
                    return Some(res);
                }
            }
            feed_body(bytes)
        };

        while pos + 27 <= data.len() && &data[pos..pos + 4] == b"OggS" {
            let num_segments = data[pos + 26] as usize;
            let table_start = pos + 27;
            let body_start = table_start + num_segments;
            if body_start > data.len() {
                break;
            }
            let mut seg_cursor = body_start;
            for &seg_len in &data[table_start..body_start] {
                let len = seg_len as usize;
                let Some(seg_end) = seg_cursor.checked_add(len) else {
                    return false;
                };
                if seg_end > data.len() {
                    return false;
                }
                if packet_index == 1
                    && let Some(exceeded) = feed_pkt1(&data[seg_cursor..seg_end])
                {
                    return exceeded;
                }
                seg_cursor = seg_end;
                if seg_len < 255 {
                    packet_index += 1;
                    if packet_index > 1 {
                        return false;
                    }
                }
            }
            pos = seg_cursor;
        }
    }

    false
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
        config::ParseOptions,
        picture::PictureType,
        prelude::{Accessor, TaggedFileExt},
        probe::Probe,
        tag::Tag,
    };

    if has_compressed_id3v2(data)
        || has_mp4_extended_freeform_atom(data)
        || has_oversized_ape_footer(data)
        || has_oversized_vorbis_comments(data)
    {
        return None;
    }

    let file = Probe::new(Cursor::new(data))
        .options(ParseOptions::new().read_properties(false))
        .guess_file_type()
        .ok()?
        .read()
        .ok()?;
    let all: Vec<&Tag> = file.primary_tag().into_iter().chain(file.tags()).collect();
    let text = |field: fn(&Tag) -> Option<Cow<'_, str>>| {
        all.iter().find_map(|tag| {
            let trimmed = field(tag)?.trim().to_string();
            (!trimmed.is_empty()).then(|| bound_text(&trimmed, TAG_TEXT_MAX))
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
        [b'B', b'M', ..] => Some("image/bmp"),
        _ => None,
    }
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

    /// A one-pixel PNG.
    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\x1f\x15\xc4\x89\0\0\0\rIDATx\x9cc\xf8\x0f\0\x01\x01\x01\0\x18\xdd\x8d\xb0\0\0\0\0IEND\xaeB`\x82";

    /// An MP3 of `tag` and a few frames of silence: MPEG-1 layer III, 128 kbit/s at 44.1 kHz.
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
        // Synthetic ID3v2.4 tag with a compressed APIC frame (flag bit 0x0008 set) + valid MP3 frames.
        let mut v24 = Vec::new();
        let frame_body = [
            0u8, 0, 0, 16, 0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let tag_size = (10 + frame_body.len()) as u32;
        v24.extend_from_slice(b"ID3");
        v24.extend_from_slice(&[4, 0, 0]);
        v24.extend_from_slice(&[
            ((tag_size >> 21) & 0x7F) as u8,
            ((tag_size >> 14) & 0x7F) as u8,
            ((tag_size >> 7) & 0x7F) as u8,
            (tag_size & 0x7F) as u8,
        ]);
        v24.extend_from_slice(b"APIC");
        let fsize = frame_body.len() as u32;
        v24.extend_from_slice(&[
            ((fsize >> 21) & 0x7F) as u8,
            ((fsize >> 14) & 0x7F) as u8,
            ((fsize >> 7) & 0x7F) as u8,
            (fsize & 0x7F) as u8,
        ]);
        v24.extend_from_slice(&0x0009u16.to_be_bytes()); // compression | data_length_indicator
        v24.extend_from_slice(&frame_body);
        for _ in 0..4 {
            v24.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
            v24.extend_from_slice(&[0; 413]);
        }
        assert!(has_compressed_id3v2(&v24));
        assert_eq!(tags(&v24), None);

        // Synthetic ID3v2.3 tag with a compressed APIC frame (flag bit 0x0080 set).
        let mut v23 = v24.clone();
        v23[3] = 3;
        v23[14..18].copy_from_slice(&fsize.to_be_bytes());
        v23[18..20].copy_from_slice(&0x0080u16.to_be_bytes());
        assert!(has_compressed_id3v2(&v23));
        assert_eq!(tags(&v23), None);
    }

    #[test]
    fn id3v2_preflight_blocks_desync_chap_recursion_and_v23_ext_unsynch() {
        fn synchsafe(v: u32) -> [u8; 4] {
            [
                ((v >> 21) & 0x7F) as u8,
                ((v >> 14) & 0x7F) as u8,
                ((v >> 7) & 0x7F) as u8,
                (v & 0x7F) as u8,
            ]
        }
        fn wrap_id3v24(body: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(b"ID3");
            out.extend_from_slice(&[4, 0, 0]);
            out.extend_from_slice(&synchsafe(body.len() as u32));
            out.extend_from_slice(body);
            for _ in 0..4 {
                out.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
                out.extend_from_slice(&[0; 413]);
            }
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

        let compressed_apic = v24_frame(
            b"APIC",
            0x0009,
            &[0, 0, 0, 16, 0x78, 0x9c, 0x03, 0, 0, 0, 0, 1],
        );

        // 1. WOAF NUL-desync smuggling a compressed frame after an internal NUL byte.
        let mut woaf_smuggle_body = b"https://example.test\0".to_vec();
        woaf_smuggle_body.extend_from_slice(&compressed_apic);
        let woaf_smuggle = wrap_id3v24(&v24_frame(b"WOAF", 0, &woaf_smuggle_body));
        assert!(has_compressed_id3v2(&woaf_smuggle));
        assert_eq!(tags(&woaf_smuggle), None);

        // Clean WOAF with only trailing NUL padding still passes preflight.
        let clean_woaf = wrap_id3v24(&v24_frame(b"WOAF", 0, b"https://example.test\0\0"));
        assert!(!has_compressed_id3v2(&clean_woaf));

        // 2. Compressed frame nested inside a CHAP child frame.
        let mut chap_body = b"ch1\0".to_vec();
        chap_body.extend_from_slice(&[0u8; 16]);
        chap_body.extend_from_slice(&compressed_apic);
        let chap_compressed = wrap_id3v24(&v24_frame(b"CHAP", 0, &chap_body));
        assert!(has_compressed_id3v2(&chap_compressed));
        assert_eq!(tags(&chap_compressed), None);

        // 3. CHAP frame with early NUL padding + trailing non-zero bytes (Take desync).
        let mut chap_desync_body = b"ch1\0".to_vec();
        chap_desync_body.extend_from_slice(&[0u8; 16]);
        chap_desync_body.push(0x00);
        chap_desync_body.extend_from_slice(&compressed_apic);
        let chap_desync = wrap_id3v24(&v24_frame(b"CHAP", 0, &chap_desync_body));
        assert!(has_compressed_id3v2(&chap_desync));

        // 4. Deeply nested CHAP recursion (> ID3V2_MAX_DEPTH).
        let mut nested = Vec::new();
        for _ in 0..=ID3V2_MAX_DEPTH + 1 {
            let mut inner = b"c\0".to_vec();
            inner.extend_from_slice(&[0u8; 16]);
            inner.extend_from_slice(&nested);
            nested = v24_frame(b"CHAP", 0, &inner);
        }
        assert!(has_compressed_id3v2(&wrap_id3v24(&nested)));

        // 5. ID3v2.3 with BOTH unsynchronisation (0x80) and extended header (0x40) flags set.
        let mut v23_ext_unsynch = Vec::new();
        v23_ext_unsynch.extend_from_slice(b"ID3");
        v23_ext_unsynch.extend_from_slice(&[3, 0, 0xC0]);
        v23_ext_unsynch.extend_from_slice(&synchsafe(100));
        v23_ext_unsynch.extend_from_slice(&[0u8; 100]);
        assert!(has_compressed_id3v2(&v23_ext_unsynch));

        // 6. ID3v2.4 3-char + NUL frame IDs (`PIC\0` compressed & `WAF\0` / `WXX\0` NUL-desync).
        let v24_outdated_compressed = wrap_id3v24(&v24_frame(
            b"PIC\0",
            0x0009,
            &[0, 0, 0, 16, 0x78, 0x9c, 0x03, 0, 0, 0, 0, 1],
        ));
        assert!(has_compressed_id3v2(&v24_outdated_compressed));
        let mut wxx_desync_body = b"https://example.test\0".to_vec();
        wxx_desync_body.extend_from_slice(&compressed_apic);
        let v24_wxx_desync = wrap_id3v24(&v24_frame(b"WXX\0", 0, &wxx_desync_body));
        assert!(has_compressed_id3v2(&v24_wxx_desync));

        // 7. Child WOAF with trailing `0x00` inside CHAP (Take desync exiting CHAP early).
        let mut chap_woaf_pad = b"ch1\0".to_vec();
        chap_woaf_pad.extend_from_slice(&[0u8; 16]);
        chap_woaf_pad.extend_from_slice(&v24_frame(b"WOAF", 0, b"x\0\0"));
        assert!(has_compressed_id3v2(&wrap_id3v24(&v24_frame(
            b"CHAP",
            0,
            &chap_woaf_pad
        ))));

        // 8. MP4 extended freeform `----`, `mean`, `name`, `data` atom headers & FLAC/Ogg
        //    oversized VorbisComments (including ID3v2.2 footer-flag & ID3v2.4 ext-header bypasses).
        for ext_atom in [
            b"\x00\x00\x00\x01----",
            b"\x00\x00\x00\x08----",
            b"\x00\x00\x00\x01mean",
            b"\x00\x00\x00\x01name",
            b"\x00\x00\x00\x01data",
        ] {
            let mut mp4_ext = b"\x00\x00\x00\x14ftypM4A \x00\x00\x00\x00M4A ".to_vec();
            mp4_ext.extend_from_slice(ext_atom);
            assert!(has_mp4_extended_freeform_atom(&mp4_ext));
            assert_eq!(tags(&mp4_ext), None);
        }

        // 9. Nested CHAP with >= 11 bytes of zero padding (Take desync into outer CHAP).
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

        // Build a valid FLAC prefix (STREAMINFO + optional block_type 127 + VORBIS_COMMENT).
        let mut flac = b"fLaC".to_vec();
        flac.extend_from_slice(&[0x00, 0x00, 0x00, 34]); // STREAMINFO (non-last, 34 B)
        flac.extend_from_slice(&[0u8; 34]);
        flac.extend_from_slice(&[0x7F, 0x00, 0x00, 0x00]); // block_type 127 (non-last, 0 B)
        let mut vc = Vec::new();
        vc.extend_from_slice(&0u32.to_le_bytes()); // vendor_len = 0
        vc.extend_from_slice(&(VORBIS_COMMENTS_MAX + 1).to_le_bytes());
        let vc_len = vc.len() as u32;
        flac.push(0x80 | 4); // last block, VORBIS_COMMENT
        flac.extend_from_slice(&vc_len.to_be_bytes()[1..]);
        flac.extend_from_slice(&vc);
        assert!(has_oversized_vorbis_comments(&flac));
        assert_eq!(tags(&flac), None);

        // Short `COVERART=` VorbisComment (decodes to < 8 bytes -> lofty mimetype_from_bin panic),
        // tested with minimal `STREAMINFO` payload length 14 (`14 + 4 == 18`, accepted by lofty).
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

        // 44-byte MP4 `meta` `end - pos` underflow (`len_raw == 0` `hdlr` inside `meta`).
        let mut mp4_meta_eof = Vec::new();
        mp4_meta_eof.extend_from_slice(b"\x00\x00\x00\x0cftypM4A ");
        mp4_meta_eof.extend_from_slice(b"\x00\x00\x00\x1dmoov");
        mp4_meta_eof.extend_from_slice(b"\x00\x00\x00\x15udta");
        mp4_meta_eof.extend_from_slice(b"\x00\x00\x00\x15meta");
        mp4_meta_eof.extend_from_slice(b"\x00\x00\x00\x00hdlr");
        assert!(has_mp4_extended_freeform_atom(&mp4_meta_eof));
        assert_eq!(tags(&mp4_meta_eof), None);

        // 164-byte WavPack / APE `stream_length -= header.size` underflow (`APETAGEX` + ID3v1).
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

        // Legitimate M4A titled `"language"` (contains `\0\0\0\0lang` inside `data` atom) and
        // legitimate AIFF with `"----"` text must NOT be false-positive rejected.
        fn atom(ident: &[u8; 4], payload: &[u8]) -> Vec<u8> {
            let mut out = ((8 + payload.len()) as u32).to_be_bytes().to_vec();
            out.extend_from_slice(ident);
            out.extend_from_slice(payload);
            out
        }
        let mut data_payload = vec![0, 0, 0, 1, 0, 0, 0, 0]; // UTF-8 type + locale
        data_payload.extend_from_slice(b"language");
        let nam = atom(b"\xA9nam", &atom(b"data", &data_payload));
        let ilst = atom(b"ilst", &nam);
        let mut hdlr_payload = vec![0u8; 25];
        hdlr_payload[8..12].copy_from_slice(b"mdir");
        let hdlr = atom(b"hdlr", &hdlr_payload);
        let mut meta_payload = vec![0u8; 4]; // full meta version/flags
        meta_payload.extend_from_slice(&hdlr);
        meta_payload.extend_from_slice(&ilst);
        let meta = atom(b"meta", &meta_payload);
        let udta = atom(b"udta", &meta);
        let moov = atom(b"moov", &udta);
        let mut valid_m4a = atom(b"ftyp", b"M4A \x00\x00\x00\x00M4A ");
        valid_m4a.extend_from_slice(&moov);
        assert!(!has_mp4_extended_freeform_atom(&valid_m4a));
        assert_eq!(
            tags(&valid_m4a).and_then(|t| t.title),
            Some("language".to_string())
        );

        let mut aiff_with_dashes = b"FORM\x00\x00\x00\x20AIFF".to_vec();
        aiff_with_dashes.extend_from_slice(b"NAME\x00\x00\x00\x08\x00\x00\x00\x08----");
        assert!(!has_mp4_extended_freeform_atom(&aiff_with_dashes));

        // Repeated overlapping `ID3` headers must trip the cumulative byte-work budget in O(N).
        let mut id3_dos = Vec::with_capacity(20_000 * 10);
        for _ in 0..20_000 {
            id3_dos.extend_from_slice(b"ID3\x03\x00\x80\x7F\x7F\x7F\x7F");
        }
        assert!(has_compressed_id3v2(&id3_dos));
        assert_eq!(tags(&id3_dos), None);

        // Polyglot prefixes where `lofty` matches WAV/AIFF/MPEG before `ftyp` or falls back from
        // non-Vorbis/Opus/Speex `OggS` to MPEG must NEVER bypass `has_compressed_id3v2`.
        let mut compressed_id3_tag = b"ID3\x04\x00\x00".to_vec();
        compressed_id3_tag.extend_from_slice(&synchsafe(compressed_apic.len() as u32));
        compressed_id3_tag.extend_from_slice(&compressed_apic);

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
        for _ in 0..2 {
            ogg_fake_mpeg.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
            ogg_fake_mpeg.extend_from_slice(&[0u8; 413]);
        }
        assert!(has_compressed_id3v2(&ogg_fake_mpeg));
        assert_eq!(tags(&ogg_fake_mpeg), None);

        let mut mpeg_ftyp = b"\xFF\xFB\x0C\x00ftyp".to_vec();
        mpeg_ftyp.extend_from_slice(&compressed_id3_tag);
        for _ in 0..2 {
            mpeg_ftyp.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
            mpeg_ftyp.extend_from_slice(&[0u8; 413]);
        }
        assert!(has_compressed_id3v2(&mpeg_ftyp));
        assert_eq!(tags(&mpeg_ftyp), None);

        // Literal `"fLaC"` inside MP3 ID3v2 padding must NOT false-positive on `total_blocks`.
        let mut mp3_with_flac_text = b"ID3\x04\x00\x00".to_vec();
        let mut body = b"fLaC".to_vec();
        body.extend_from_slice(&[0u8; 20_000]);
        mp3_with_flac_text.extend_from_slice(&synchsafe(body.len() as u32));
        mp3_with_flac_text.extend_from_slice(&body);
        assert!(!has_oversized_vorbis_comments(&mp3_with_flac_text));

        // ID3v2.2 with footer flag 0x10 set (ignored by lofty on v2.2) followed immediately by FLAC.
        let mut v22_flac = b"ID3\x02\x00\x10\x00\x00\x00\x00".to_vec();
        v22_flac.extend_from_slice(&flac);
        assert!(has_oversized_vorbis_comments(&v22_flac));
        assert_eq!(tags(&v22_flac), None);

        // ID3v2.4 with extended header + decoy `fLaC` at `10 + tag_size` + real `fLaC` after ext.
        let mut v24_split_flac = b"ID3\x04\x00\x40\x00\x00\x00\x10".to_vec();
        v24_split_flac.extend_from_slice(&[0u8; 16]);
        v24_split_flac.extend_from_slice(b"fLaC\x80\x00\x00\x00");
        v24_split_flac.extend_from_slice(&[0u8; 6]);
        v24_split_flac.extend_from_slice(&flac);
        assert!(has_oversized_vorbis_comments(&v24_split_flac));
        assert_eq!(tags(&v24_split_flac), None);
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
            // Random bit flip / truncation mutation.
            if !buf.is_empty() && (next_u64() & 1) == 0 {
                let idx = next_u64() as usize % buf.len();
                buf[idx] ^= (1u8) << (next_u64() as u8 & 7);
            }
            let _ = tags(&buf);
        }
    }
}
