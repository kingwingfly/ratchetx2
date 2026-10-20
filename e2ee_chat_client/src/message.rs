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
    Recved,
    Error(String),
}

#[derive(prost::Oneof)]
pub enum MessageContent {
    #[prost(string, tag = "1")]
    Text(String),
    #[prost(bytes = "vec", tag = "2")]
    Image(Vec<u8>),
}

/// A oneof can't be a top-level protobuf message, so [`MessageContent`] travels inside this.
#[derive(prost::Message)]
struct WireContent {
    #[prost(oneof = "MessageContent", tags = "1, 2")]
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
        }
        if let MessageState::Error(err) = &self.state {
            lines += err.width_cjk() as u16 / width + 1;
        }
        lines
    }
}
