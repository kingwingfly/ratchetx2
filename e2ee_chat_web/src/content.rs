//! What a message carries, encrypted: `protocol::content`, which the TUI client reads too, and
//! which drops the kinds it does not know.

#[cfg(test)]
pub use session::protocol::content::File;
pub use session::protocol::content::{
    AttachmentPointer, Contact, Content, Deleted, Events, Kind, place, stamp,
};

/// The MIME type of a PNG, JPEG, GIF or WebP image, by its first bytes.
pub fn image_type(data: &[u8]) -> Option<&'static str> {
    match data {
        [0x89, b'P', b'N', b'G', ..] => Some("image/png"),
        [0xFF, 0xD8, 0xFF, ..] => Some("image/jpeg"),
        [b'G', b'I', b'F', b'8', ..] => Some("image/gif"),
        _ if data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP") => Some("image/webp"),
        _ => None,
    }
}
