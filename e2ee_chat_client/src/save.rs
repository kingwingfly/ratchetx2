//! Saving received files to the downloads directory.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

/// A new file in `dir` for one named `name` by its sender, created empty: only the name's last
/// component, so it stays in `dir`, with a number added if a file of that name is there already.
pub fn create(dir: &Path, name: &str) -> io::Result<(PathBuf, File)> {
    let name: String = Path::new(name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let name = if name.is_empty() { "file" } else { &name };
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem, Some(extension)),
        _ => (name, None),
    };
    for n in 0.. {
        let candidate = match (n, extension) {
            (0, _) => name.to_string(),
            (n, Some(extension)) => format!("{stem} ({n}).{extension}"),
            (n, None) => format!("{stem} ({n})"),
        };
        let path = dir.join(candidate);
        // Never replace a file, nor one being saved.
        if part(&path).exists() {
            continue;
        }
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    unreachable!("some number is free")
}

/// Save `data` in `dir` as a file named `name`. Returns where it went.
pub fn bytes(dir: &Path, name: &str, data: &[u8]) -> io::Result<PathBuf> {
    let (path, mut file) = create(dir, name)?;
    if let Err(e) = file.write_all(data).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&path);
        return Err(e);
    }
    Ok(path)
}

/// Where a file being saved to `path` grows until it is whole.
pub fn part(path: &Path) -> PathBuf {
    let mut part = path.as_os_str().to_owned();
    part.push(".part");
    PathBuf::from(part)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn names_stay_in_the_directory_and_never_replace() {
        let dir = std::env::temp_dir().join(format!("e2ee-chat-save-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let saved = |name, data: &[u8]| {
            let path = bytes(&dir, name, data).unwrap();
            assert_eq!(fs::read(&path).unwrap(), data);
            path.strip_prefix(&dir)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(saved("report.pdf", b"1"), "report.pdf");
        assert_eq!(saved("report.pdf", b"2"), "report (1).pdf");
        assert_eq!(saved("../../etc/passwd", b"3"), "passwd");
        assert_eq!(saved("..", b"4"), "file");
        assert_eq!(saved("notes", b"5"), "notes");
        assert_eq!(saved("notes", b"6"), "notes (1)");
        assert_eq!(saved("a\nb.txt", b"7"), "ab.txt");
        fs::remove_dir_all(&dir).unwrap();
    }
}
