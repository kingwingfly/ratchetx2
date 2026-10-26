//! What a chat message carries, defined in `proto/content.proto` (package `content.v1`): a
//! [`Content`], which a session encrypts, so the server never sees it. The web and TUI clients
//! both read it, and drop the kinds they do not show.

use core::fmt;

use prost::Message as _;

#[allow(missing_docs)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/content.v1.rs"));
}

pub use proto::{content::Kind, *};

impl fmt::Debug for AttachmentPointer {
    /// Shows no key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentPointer")
            .field("size", &self.size)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Kind {
    /// Same bytes as encoding `Content { kind: Some(self) }`, without cloning `self`, which may
    /// be a file of megabytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf);
        buf
    }

    /// `None` if the bytes do not parse, or carry a kind this version does not know.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Content::decode(bytes).ok()?.kind
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn content_goes_without_its_wrapper() {
        let text = Kind::Text("hi".to_string());
        let wrapped = Content {
            kind: Some(text.clone()),
        };
        assert_eq!(text.to_bytes(), wrapped.encode_to_vec());
        assert_eq!(Kind::from_bytes(&text.to_bytes()), Some(text));
        // A kind of a later version, field 15, is dropped.
        assert_eq!(Kind::from_bytes(&[0x7a, 0]), None);
    }
}
