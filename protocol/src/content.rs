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

impl Content {
    /// The content `bytes` encode; empty if they do not parse, as a kind this version does not
    /// know.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::decode(bytes).unwrap_or_default()
    }
}

/// Give `content`, the bytes of a [`Content`], the clock `clock`, replacing any it had: the field
/// goes last, and a field that comes again replaces the one before when the message decodes.
pub fn stamp(content: &mut Vec<u8>, clock: u64) {
    prost::encoding::uint64::encode(7, &clock, content);
}

/// How far past a chat's highest place a peer's clock may go. An honest peer is ahead only by
/// the messages of its that have not come yet, never this many; so a lying one cannot pin the
/// chat's clock at its end, where every message would tie.
pub const MAX_AHEAD: u64 = 1 << 20;

/// The place in a chat of the peer's message whose clock is `clock`, which both clients show it
/// by: its clock, unless that would put it at or before `floor`, the later of the places of the
/// peer's previous message and of the last message the peer said it read, which an honest
/// peer's clock is past already; so the peer cannot slip a message far up the history, nor start
/// over below it, e.g. after deleting the chat. Nor can it go more than [`MAX_AHEAD`] past
/// `highest`, the chat's highest place. A message without a clock, of a client that gives none,
/// goes right after `highest`, where it came.
pub fn place(clock: u64, floor: u64, highest: u64) -> u64 {
    if clock == 0 {
        return highest.saturating_add(1);
    }
    clock
        .min(highest.saturating_add(MAX_AHEAD))
        .max(floor.saturating_add(1))
}

impl Events {
    /// Whether there is nothing to tell.
    pub fn is_empty(&self) -> bool {
        self.read.is_empty() && self.downloaded.is_empty()
    }

    /// The bytes of a message telling these events only.
    pub fn to_bytes(&self) -> Vec<u8> {
        Content {
            events: Some(self.clone()),
            ..Content::default()
        }
        .encode_to_vec()
    }
}

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
    /// Same bytes as encoding `Content { kind: Some(self), .. }`, without cloning `self`, which
    /// may be a file of megabytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf);
        buf
    }

    /// `None` if the bytes do not parse, or carry a kind this version does not know.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Content::decode(bytes).ok()?.kind
    }

    /// Whether it is something to read, which its sender waits to hear was read: not a greeting,
    /// nor that the sender deleted the chat.
    pub fn is_readable(&self) -> bool {
        matches!(
            self,
            Self::Text(_) | Self::Image(_) | Self::File(_) | Self::Attachment(_)
        )
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
            ..Content::default()
        };
        assert_eq!(text.to_bytes(), wrapped.encode_to_vec());
        assert_eq!(Kind::from_bytes(&text.to_bytes()), Some(text.clone()));
        // With its clock, given again.
        let mut bytes = text.to_bytes();
        stamp(&mut bytes, 3);
        stamp(&mut bytes, 4);
        let content = Content::decode(bytes.as_slice()).unwrap();
        assert_eq!(
            content,
            Content {
                clock: 4,
                ..wrapped
            }
        );
        // Events alone.
        let events = Events {
            read: vec![4],
            downloaded: vec![],
        };
        let content = Content::decode(events.to_bytes().as_slice()).unwrap();
        assert_eq!((content.kind, content.events), (None, Some(events)));
        // A kind of a later version, field 15, is dropped.
        assert_eq!(Kind::from_bytes(&[0x7a, 0]), None);
    }
}
