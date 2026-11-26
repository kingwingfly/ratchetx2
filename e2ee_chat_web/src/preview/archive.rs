use std::io::{self, Cursor, Read, Seek, SeekFrom};

use unicode_general_category::{GeneralCategory, get_general_category};

use super::{ENTRIES_MAX, PreviewBudget, ZIP_CENTRAL_DIR_MAX};

const EOCD_LEN: usize = 22;
const ZIP64_EOCD_LEN: usize = 56;
const ZIP64_LOCATOR_LEN: usize = 20;
const ZIP64_FOOTER_LEN: usize = ZIP64_EOCD_LEN + ZIP64_LOCATOR_LEN + EOCD_LEN;

/// Maximum byte length allowed for a single TAR GNU LongName/LongLink or PAX extension header.
const TAR_EXT_HEADER_MAX: u64 = 4 * 1024;
/// Maximum byte length retained for a single displayed archive entry path.
const ARCHIVE_SINGLE_PATH_MAX: usize = 4 * 1024;
/// Maximum cumulative path bytes across all listed entries in one archive.
const ARCHIVE_PATH_BYTES_MAX: usize = 4 * 1024 * 1024;
/// Maximum byte length shown for a sanitized link target in [`Entry::note`].
const ARCHIVE_LINK_TARGET_MAX: usize = 256;

/// The entries of an archive, all of them, or the first, if listing more would take too long.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub entries: Vec<super::Entry>,
    pub complete: bool,
}

/// A file or directory in an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub size: u64,
    pub directory: bool,
    /// Optional security/metadata indicator (e.g. symlink, hardlink, path traversal).
    pub note: Option<String>,
}

/// Sanitize a peer-supplied archive entry path for display: strips Unicode format/BiDi (`Cf`)
/// and control (`Cc`) characters while preserving relative `/` path separators, caps length, and
/// detects path traversal patterns (`..`, leading `/` or `\`, backslash separators, or Windows
/// drive prefixes).
fn sanitize_entry_path(raw: &str, max_bytes: usize) -> (String, bool) {
    let mut cleaned = String::with_capacity(raw.len().min(max_bytes));
    let mut truncated = false;
    for ch in raw.chars() {
        let cat = get_general_category(ch);
        if matches!(cat, GeneralCategory::Control | GeneralCategory::Format) {
            continue;
        }
        let mapped = if ch.is_whitespace() { ' ' } else { ch };
        if cleaned.len().saturating_add(mapped.len_utf8()) > max_bytes {
            truncated = true;
            break;
        }
        cleaned.push(mapped);
    }
    if truncated {
        cleaned.push('…');
    }
    let has_traversal = is_traversal_path(raw) || is_traversal_path(&cleaned);
    (cleaned, has_traversal)
}

fn is_traversal_path(path: &str) -> bool {
    if path.starts_with('/') || path.starts_with('\\') || path.contains('\\') {
        return true;
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return true;
    }
    path.split(['/', '\\']).any(|segment| segment == "..")
}

fn build_entry_note(
    symlink_target: Option<&str>,
    hardlink_target: Option<&str>,
    has_traversal: bool,
) -> Option<String> {
    let mut notes = Vec::new();
    if let Some(target) = symlink_target {
        let (clean_target, _) = sanitize_entry_path(target, ARCHIVE_LINK_TARGET_MAX);
        if clean_target.is_empty() {
            notes.push("symlink".to_string());
        } else {
            notes.push(format!("symlink -> {clean_target}"));
        }
    }
    if let Some(target) = hardlink_target {
        let (clean_target, _) = sanitize_entry_path(target, ARCHIVE_LINK_TARGET_MAX);
        if clean_target.is_empty() {
            notes.push("hardlink".to_string());
        } else {
            notes.push(format!("hardlink -> {clean_target}"));
        }
    }
    if has_traversal {
        notes.push("path traversal".to_string());
    }
    (!notes.is_empty()).then(|| notes.join("; "))
}

struct CentralDirectory {
    entries: u64,
    size: u64,
    offset: u64,
    /// Start of the end record, immediately after the directory in an ordinary ZIP.
    limit: u64,
}

pub(super) struct ZipFooter<'a> {
    directory_end: usize,
    end: &'a [u8; EOCD_LEN],
    zip64: Option<(&'a [u8; ZIP64_EOCD_LEN], &'a [u8; ZIP64_LOCATOR_LEN])>,
}

fn field<const N: usize>(record: &[u8], offset: usize) -> Option<[u8; N]> {
    record.get(offset..)?.first_chunk().copied()
}

fn zip64_directory<'a>(
    before_locator: &'a [u8],
    locator: &[u8; ZIP64_LOCATOR_LEN],
) -> Option<(CentralDirectory, &'a [u8; ZIP64_EOCD_LEN])> {
    let disk = u32::from_le_bytes(field(locator, 4)?);
    let record_offset = u64::from_le_bytes(field(locator, 8)?);
    let total_disks = u32::from_le_bytes(field(locator, 16)?);
    if disk != 0 || total_disks > 1 {
        return None;
    }

    let record = before_locator.get(usize::try_from(record_offset).ok()?..)?;
    let header = record.first_chunk::<ZIP64_EOCD_LEN>()?;
    let record_size = u64::from_le_bytes(field(header, 4)?);
    if !header.starts_with(b"PK\x06\x06")
        || record_size < 44
        || usize::try_from(record_size).ok()?.checked_add(12)? > record.len()
    {
        return None;
    }

    let disk_number = u32::from_le_bytes(field(header, 16)?);
    let cd_start_disk = u32::from_le_bytes(field(header, 20)?);
    let entries_on_disk = u64::from_le_bytes(field(header, 24)?);
    let entries = u64::from_le_bytes(field(header, 32)?);
    if disk_number != 0 || cd_start_disk != 0 || entries_on_disk != entries {
        return None;
    }
    let directory = CentralDirectory {
        entries,
        size: u64::from_le_bytes(field(header, 40)?),
        offset: u64::from_le_bytes(field(header, 48)?),
        limit: record_offset,
    };
    Some((directory, header))
}

/// Bound the work of indexing peer-supplied bytes before the ZIP reader allocates its index.
pub(super) fn validate_zip_central_directory(data: &[u8]) -> Option<ZipFooter<'_>> {
    let last = data.len().checked_sub(EOCD_LEN)?;
    let first = last.saturating_sub(usize::from(u16::MAX));
    let pos = (first..=last).rev().find(|&offset| {
        let end = &data[offset..];
        end.starts_with(b"PK\x05\x06")
            && usize::from(u16::from_le_bytes([end[20], end[21]])) == last - offset
    })?;
    let (before_end, end) = data.split_at(pos);
    let disk_number = u16::from_le_bytes(field(end, 4)?);
    let cd_start_disk = u16::from_le_bytes(field(end, 6)?);
    let entries_on_disk = u16::from_le_bytes(field(end, 8)?);
    let entries_total = u16::from_le_bytes(field(end, 10)?);
    let cd_size = u32::from_le_bytes(field(end, 12)?);
    let cd_offset = u32::from_le_bytes(field(end, 16)?);

    let (directory, zip64) = if let Some(locator) = before_end
        .last_chunk::<ZIP64_LOCATOR_LEN>()
        .filter(|locator| locator.starts_with(b"PK\x06\x07"))
    {
        let (directory, header) = zip64_directory(&before_end[..pos - locator.len()], locator)?;
        // Standard fields may defer to ZIP64. Every concrete value must agree with it.
        if !matches!(disk_number, 0 | u16::MAX)
            || !matches!(cd_start_disk, 0 | u16::MAX)
            || (entries_on_disk != u16::MAX && u64::from(entries_on_disk) != directory.entries)
            || (entries_total != u16::MAX && u64::from(entries_total) != directory.entries)
            || (cd_size != u32::MAX && u64::from(cd_size) != directory.size)
            || (cd_offset != u32::MAX && u64::from(cd_offset) != directory.offset)
        {
            return None;
        }
        (directory, Some((header, locator)))
    } else {
        if disk_number != 0
            || cd_start_disk != 0
            || entries_on_disk != entries_total
            || entries_total == u16::MAX
            || cd_size == u32::MAX
            || cd_offset == u32::MAX
        {
            return None;
        }
        let directory = CentralDirectory {
            entries: u64::from(entries_total),
            size: u64::from(cd_size),
            offset: u64::from(cd_offset),
            limit: pos as u64,
        };
        (directory, None)
    };

    let CentralDirectory {
        entries,
        size,
        offset,
        limit,
    } = directory;
    let directory_end = offset.checked_add(size)?;
    if entries > ENTRIES_MAX as u64
        || size > ZIP_CENTRAL_DIR_MAX
        || directory_end > limit
        || limit.checked_sub(offset)? > ZIP_CENTRAL_DIR_MAX
    {
        return None;
    }
    if entries == 0 && size != 0 {
        return None;
    }
    // Each central directory file header has a 46-byte fixed part.
    let start = usize::try_from(offset).ok()?;
    if size < entries.saturating_mul(46)
        || (entries > 0 && !data.get(start..)?.starts_with(b"PK\x01\x02"))
    {
        return None;
    }
    Some(ZipFooter {
        directory_end: usize::try_from(directory_end).ok()?,
        end: end.first_chunk()?,
        zip64,
    })
}

impl ZipFooter<'_> {
    /// Put the checked end records directly after the directory. The ZIP reader accepts
    /// trailing data and can retry other signatures on error. An abutting footer with no
    /// comment pins it to the checked directory, including for ZIP64.
    fn for_indexing<'a>(&self, buffer: &'a mut [u8; ZIP64_FOOTER_LEN]) -> &'a [u8] {
        let (prefix, end) = buffer.split_at_mut(ZIP64_EOCD_LEN + ZIP64_LOCATOR_LEN);
        end.copy_from_slice(self.end);
        end[20..22].fill(0);
        let Some((header, locator)) = self.zip64 else {
            return &buffer[ZIP64_EOCD_LEN + ZIP64_LOCATOR_LEN..];
        };
        let (record, location) = prefix.split_at_mut(ZIP64_EOCD_LEN);
        record.copy_from_slice(header);
        record[4..12].copy_from_slice(&44u64.to_le_bytes()); // no extensible data sector
        location.copy_from_slice(locator);
        location[8..16].copy_from_slice(&(self.directory_end as u64).to_le_bytes());
        end[12..16].fill(0xff); // have the reader use the ZIP64 record
        buffer
    }
}

/// A seekable view of the original file bytes followed by the checked footer.
struct ZipFooterReader<'a> {
    cursor: Cursor<&'a [u8]>,
    footer: &'a [u8],
}

impl Read for ZipFooterReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let footer_start = self.cursor.get_ref().len() - self.footer.len();
        let pos = usize::try_from(self.cursor.position()).unwrap_or(usize::MAX);
        if pos < footer_start {
            let count = out.len().min(footer_start - pos);
            return self.cursor.read(&mut out[..count]);
        }
        let mut tail = self.footer.get(pos - footer_start..).unwrap_or_default();
        let count = tail.read(out)?;
        self.cursor
            .set_position(self.cursor.position() + count as u64);
        Ok(count)
    }
}

impl Seek for ZipFooterReader<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.cursor.seek(position)
    }
}

/// The entries of a ZIP whose central directory fits the preview limits, without unpacking files.
pub(super) fn zip(data: &[u8]) -> Option<Listing> {
    let checked = validate_zip_central_directory(data)?;
    let mut buffer = [0; ZIP64_FOOTER_LEN];
    let footer = checked.for_indexing(&mut buffer);
    if data.get(checked.directory_end..)? == footer {
        return list_zip(::zip::ZipArchive::new(Cursor::new(data)).ok()?);
    }
    let reader = ZipFooterReader {
        cursor: Cursor::new(data.get(..checked.directory_end.checked_add(footer.len())?)?),
        footer,
    };
    list_zip(::zip::ZipArchive::new(reader).ok()?)
}

fn list_zip(mut archive: ::zip::ZipArchive<impl Read + Seek>) -> Option<Listing> {
    if archive.len() > ENTRIES_MAX {
        return None;
    }
    let mut path_budget = PreviewBudget::new(ARCHIVE_PATH_BYTES_MAX);
    let mut entries = Vec::with_capacity(archive.len().min(1024));
    let mut complete = true;
    for index in 0..archive.len() {
        let file = archive.by_index_raw(index).ok()?;
        let raw_path = file.name().ok()?;
        let (path, has_traversal) = sanitize_entry_path(&raw_path, ARCHIVE_SINGLE_PATH_MAX);
        if !path_budget.take(path.len()) {
            complete = false;
            break;
        }
        let is_symlink = file.is_symlink()
            || file
                .unix_mode()
                .is_some_and(|mode| (mode & 0o170000) == 0o120000);
        let note = build_entry_note(is_symlink.then_some(""), None, has_traversal);
        entries.push(Entry {
            path,
            size: file.size(),
            directory: file.is_dir(),
            note,
        });
    }
    Some(Listing { entries, complete })
}

#[derive(Default)]
struct PaxOverrides {
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
    size: Option<u64>,
}

/// Parse bounded POSIX PAX extended-header records (`<len> <key>=<value>\n`).
fn parse_pax_records(mut data: &[u8]) -> PaxOverrides {
    let mut out = PaxOverrides::default();
    while !data.is_empty() {
        let Some(space) = data.iter().position(|&b| b == b' ') else {
            break;
        };
        let Ok(len_str) = std::str::from_utf8(&data[..space]) else {
            break;
        };
        let Ok(record_len) = len_str.parse::<usize>() else {
            break;
        };
        if record_len <= space + 1 || record_len > data.len() {
            break;
        }
        let body = &data[space + 1..record_len];
        let body = body.strip_suffix(b"\n").unwrap_or(body);
        if let Some(eq) = body.iter().position(|&b| b == b'=') {
            let key = &body[..eq];
            let val = &body[eq + 1..];
            match key {
                b"path" => out.path = Some(val.to_vec()),
                b"linkpath" => out.linkpath = Some(val.to_vec()),
                b"size" => {
                    if let Ok(s) = std::str::from_utf8(val)
                        && let Ok(parsed) = s.parse::<u64>()
                    {
                        out.size = Some(parsed);
                    }
                }
                _ => {}
            }
        }
        data = &data[record_len..];
    }
    out
}

struct TarScan {
    entries: Vec<Entry>,
    complete: bool,
    saw_valid_header: bool,
    max_file_end: u64,
}

/// Walk raw TAR entries so GNU LongName (`L`), GNU LongLink (`K`), and PAX (`x`/`g`) extension
/// headers are size-checked against [`TAR_EXT_HEADER_MAX`] *before* any payload bytes are read
/// into memory.
fn scan_raw_tar_entries<R: Read>(entries_iter: ::tar::Entries<'_, R>) -> TarScan {
    let mut entries = Vec::new();
    let mut entry_budget = PreviewBudget::new(ENTRIES_MAX);
    let mut path_budget = PreviewBudget::new(ARCHIVE_PATH_BYTES_MAX);
    let mut complete = true;
    let mut saw_valid_header = false;
    let mut max_file_end = 0u64;

    let mut pending_longname: Option<Vec<u8>> = None;
    let mut pending_longlink: Option<Vec<u8>> = None;
    let mut pending_pax = PaxOverrides::default();

    for raw in entries_iter {
        let Ok(mut entry) = raw else {
            complete = false;
            break;
        };
        saw_valid_header = true;
        let entry_type = entry.header().entry_type();
        let raw_size = entry.size();
        max_file_end = max_file_end.max(entry.raw_file_position().saturating_add(raw_size));

        if entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
            || entry_type.is_pax_local_extensions()
            || entry_type.is_pax_global_extensions()
        {
            if raw_size > TAR_EXT_HEADER_MAX {
                complete = false;
                break;
            }
            let mut buf = vec![0u8; raw_size as usize];
            if entry.read_exact(&mut buf).is_err() {
                complete = false;
                break;
            }
            if entry_type.is_gnu_longname() {
                while buf.last() == Some(&0) {
                    buf.pop();
                }
                pending_longname = Some(buf);
            } else if entry_type.is_gnu_longlink() {
                while buf.last() == Some(&0) {
                    buf.pop();
                }
                pending_longlink = Some(buf);
            } else if entry_type.is_pax_local_extensions() {
                let parsed = parse_pax_records(&buf);
                if parsed.path.is_some() {
                    pending_pax.path = parsed.path;
                }
                if parsed.linkpath.is_some() {
                    pending_pax.linkpath = parsed.linkpath;
                }
                if parsed.size.is_some() {
                    pending_pax.size = parsed.size;
                }
            }
            continue;
        }

        if !entry_budget.try_push() {
            complete = false;
            break;
        }

        let pax = std::mem::take(&mut pending_pax);
        let longname = pending_longname.take();
        let longlink = pending_longlink.take();

        let raw_path_bytes = pax
            .path
            .or(longname)
            .unwrap_or_else(|| entry.path_bytes().into_owned());
        let raw_path = String::from_utf8_lossy(&raw_path_bytes);
        let (path, has_traversal) = sanitize_entry_path(&raw_path, ARCHIVE_SINGLE_PATH_MAX);
        if !path_budget.take(path.len()) {
            complete = false;
            break;
        }

        let raw_link_bytes = pax
            .linkpath
            .or(longlink)
            .or_else(|| entry.link_name_bytes().map(|b| b.into_owned()));
        let raw_link = raw_link_bytes
            .as_deref()
            .map(|b| String::from_utf8_lossy(b).into_owned());

        let symlink_target = entry_type
            .is_symlink()
            .then(|| raw_link.as_deref().unwrap_or(""));
        let hardlink_target = entry_type
            .is_hard_link()
            .then(|| raw_link.as_deref().unwrap_or(""));
        let note = build_entry_note(symlink_target, hardlink_target, has_traversal);

        let size = pax.size.unwrap_or(raw_size);
        let pax_size_mismatch = pax.size.is_some_and(|ps| ps != raw_size);
        entries.push(Entry {
            path,
            size,
            directory: entry_type.is_dir(),
            note,
        });

        // Raw iteration advances by header size; if a PAX `size` differed from the header size,
        // stop cleanly here rather than risk misaligning subsequent headers.
        if pax_size_mismatch {
            complete = false;
            break;
        }
    }

    TarScan {
        entries,
        complete,
        saw_valid_header,
        max_file_end,
    }
}

/// The entries of the tar archive `reader` reads, at most [`ENTRIES_MAX`], from no more than
/// its first `limit` bytes. Listing an entry reads through the one before it, so the listing
/// stops at the entry that crosses the limit, or that is damaged. Not an archive if no valid
/// tar header is seen (preventing all-zero `.gz` files from reporting an empty tar listing).
pub(super) fn tar(reader: impl Read, limit: u64) -> Option<Listing> {
    let mut archive = ::tar::Archive::new(reader.take(limit));
    let TarScan {
        entries,
        mut complete,
        saw_valid_header,
        ..
    } = scan_raw_tar_entries(archive.entries().ok()?.raw(true));
    // Read up to the limit: what came after it went unread.
    complete &= archive.into_inner().limit() > 0;
    (saw_valid_header && (complete || !entries.is_empty())).then_some(Listing { entries, complete })
}

/// The entries of an uncompressed in-memory tar archive, using seekable iteration so entry
/// payloads are skipped in O(1) without linearly reading through them.
pub(super) fn tar_slice(data: &[u8]) -> Option<Listing> {
    let mut archive = ::tar::Archive::new(Cursor::new(data));
    let TarScan {
        entries,
        mut complete,
        saw_valid_header,
        max_file_end,
    } = scan_raw_tar_entries(archive.entries_with_seek().ok()?.raw(true));
    complete &= max_file_end <= data.len() as u64;
    (saw_valid_header && (complete || !entries.is_empty())).then_some(Listing { entries, complete })
}
