use std::io::{self, Cursor, Read, Seek, SeekFrom};

use super::{ENTRIES_MAX, ZIP_CENTRAL_DIR_MAX};

const EOCD_LEN: usize = 22;
const ZIP64_EOCD_LEN: usize = 56;
const ZIP64_LOCATOR_LEN: usize = 20;
const ZIP64_FOOTER_LEN: usize = ZIP64_EOCD_LEN + ZIP64_LOCATOR_LEN + EOCD_LEN;

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
    let entries = (0..archive.len())
        .map(|index| {
            let file = archive.by_index_raw(index).ok()?;
            Some(Entry {
                path: file.name().ok()?.into_owned(),
                size: file.size(),
                directory: file.is_dir(),
                note: None,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(Listing {
        complete: true,
        entries,
    })
}

/// The entries of the tar archive `reader` reads, at most [`ENTRIES_MAX`], from no more than
/// its first `limit` bytes. Listing an entry reads through the one before it, so the listing
/// stops at the entry that crosses the limit, or that is damaged. Not an archive, if not even
/// its first entry reads.
pub(super) fn tar(reader: impl Read, limit: u64) -> Option<Listing> {
    let mut archive = ::tar::Archive::new(reader.take(limit));
    let mut entries = Vec::new();
    let mut complete = true;
    for entry in archive.entries().ok()? {
        let entry = entry.ok().and_then(|entry| {
            Some(Entry {
                path: entry.path().ok()?.to_string_lossy().into_owned(),
                size: entry.size(),
                directory: entry.header().entry_type().is_dir(),
                note: None,
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
