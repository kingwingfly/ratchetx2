use prost::Message as _;
use unicode_width::UnicodeWidthStr;

#[derive(Debug)]
pub struct Message {
    pub content: MessageContent,
    pub state: MessageState,
}

#[derive(Debug)]
pub enum MessageState {
    Sent,
    Received,
    Error(String),
}

/// What a message carries, in the web client's format, whose other kinds this client drops.
#[derive(prost::Oneof)]
pub enum MessageContent {
    #[prost(string, tag = "1")]
    Text(String),
    #[prost(bytes = "vec", tag = "2")]
    Image(Vec<u8>),
    /// A file small enough for its message.
    #[prost(message, tag = "3")]
    File(File),
    /// A file uploaded as an attachment, which saving downloads.
    #[prost(message, tag = "5")]
    Attachment(AttachmentPointer),
}

#[derive(Clone, prost::Message)]
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
#[derive(Clone, prost::Message)]
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

/// A oneof can't be a top-level protobuf message, so [`MessageContent`] travels inside this.
#[derive(prost::Message)]
struct WireContent {
    #[prost(oneof = "MessageContent", tags = "1, 2, 3, 5")]
    content: Option<MessageContent>,
}

impl MessageContent {
    /// Same bytes as encoding `WireContent { content: Some(self) }`, without cloning `self`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        WireContent::decode(bytes).ok()?.content
    }
}

/// The greeting that starts a session, as the web client sends it: field 4 of the content's
/// oneof, which this client drops when it receives one. It is the session's first message,
/// which shows the peer that the initial message is this client's, and lets the peer write
/// back.
#[derive(prost::Message)]
struct Greeting {
    #[prost(message, optional, tag = "4")]
    hello: Option<Hello>,
}

#[derive(prost::Message)]
struct Hello {
    /// The name the sender goes by; this client has none.
    #[prost(string, tag = "1")]
    name: String,
}

/// The bytes of a greeting.
pub fn greeting() -> Vec<u8> {
    Greeting {
        hello: Some(Hello::default()),
    }
    .encode_to_vec()
}

impl Message {
    pub fn line_num(&self, width: u16) -> u16 {
        let mut lines = 0;
        match &self.content {
            MessageContent::Text(text) => {
                for line in text.lines() {
                    lines += line.width_cjk() as u16 / width + 1;
                }
            }
            MessageContent::Image(_) => lines += 16,
            // Its name, then its size.
            MessageContent::File(_) | MessageContent::Attachment(_) => lines += 2,
        }
        if let MessageState::Error(err) = &self.state {
            lines += err.width_cjk() as u16 / width + 1;
        }
        lines
    }
}
