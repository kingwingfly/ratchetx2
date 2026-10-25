//! What a message carries, encrypted: the TUI client's format, with files, greetings and
//! attachments added.
//!
//! A message's plaintext is a `WireContent`. Text and images have the TUI client's tags, so the
//! clients can read each other's; it drops the kinds it does not know.

use prost::Message as _;

/// What a message carries.
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Content {
    /// Text.
    #[prost(string, tag = "1")]
    Text(String),
    /// An image, in a format the TUI client can show (PNG, JPEG, GIF or WebP).
    #[prost(bytes = "vec", tag = "2")]
    Image(Vec<u8>),
    /// Any file.
    #[prost(message, tag = "3")]
    File(File),
    /// The first message of a session, which Bob needs before he can send: the sender's name.
    #[prost(message, tag = "4")]
    Hello(Hello),
    /// A file too large for its message, uploaded encrypted as an attachment.
    #[prost(message, tag = "5")]
    Attachment(AttachmentPointer),
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct File {
    #[prost(string, tag = "1")]
    pub name: String,
    /// The MIME type the sender gave; only a hint.
    #[prost(string, tag = "2")]
    pub mime: String,
    #[prost(bytes = "vec", tag = "3")]
    pub data: Vec<u8>,
}

/// Where an attachment is, and its key.
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct AttachmentPointer {
    /// Its ID at the server.
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    /// The key its chunks are encrypted under.
    #[prost(bytes = "vec", tag = "2")]
    pub key: Vec<u8>,
    /// Its size, in bytes, decrypted.
    #[prost(uint64, tag = "3")]
    pub size: u64,
    #[prost(string, tag = "4")]
    pub name: String,
    /// The MIME type the sender gave; only a hint.
    #[prost(string, tag = "5")]
    pub mime: String,
}

impl std::fmt::Debug for AttachmentPointer {
    /// Shows no key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentPointer")
            .field("size", &self.size)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Hello {
    /// The name the sender goes by.
    #[prost(string, tag = "1")]
    pub name: String,
}

/// A oneof cannot be a top-level protobuf message, so [`Content`] travels inside this.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WireContent {
    #[prost(oneof = "Content", tags = "1, 2, 3, 4, 5")]
    pub content: Option<Content>,
}

impl Content {
    /// Same bytes as encoding `WireContent { content: Some(self) }`, without cloning `self`,
    /// which may be a file of megabytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf);
        buf
    }

    /// `None` if the bytes do not parse, or carry a kind this client does not know.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        WireContent::decode(bytes).ok()?.content
    }

    /// The content of a file someone chose to send: an image the TUI client can show goes as an
    /// [`Content::Image`], anything else as a [`Content::File`].
    pub fn from_file(name: String, mime: String, data: Vec<u8>) -> Self {
        if image_type(&data).is_some() {
            Self::Image(data)
        } else {
            Self::File(File { name, mime, data })
        }
    }
}

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
