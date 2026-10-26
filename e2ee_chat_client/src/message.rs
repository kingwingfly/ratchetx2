/// What a message carries: `protocol::content`, which the web client writes too.
pub use session::protocol::content::{AttachmentPointer, File, Hello, Kind};
use unicode_width::UnicodeWidthStr;

#[derive(Debug)]
pub struct Message {
    pub content: Kind,
    pub state: MessageState,
}

#[derive(Debug)]
pub enum MessageState {
    Sent,
    Received,
    Error(String),
}

/// The content `bytes` carry, if it is a kind this client shows: not a greeting, which starts a
/// session, and not a kind it does not know.
pub fn shown(bytes: &[u8]) -> Option<Kind> {
    Kind::from_bytes(bytes).filter(|kind| !matches!(kind, Kind::Hello(_)))
}

/// The bytes of a greeting, the session's first message, which shows the peer that the initial
/// message is this client's, and lets the peer write back. This client goes by no name.
pub fn greeting() -> Vec<u8> {
    Kind::Hello(Hello::default()).to_bytes()
}

impl Message {
    pub fn line_num(&self, width: u16) -> u16 {
        let mut lines = 0;
        match &self.content {
            Kind::Text(text) => {
                for line in text.lines() {
                    lines += line.width_cjk() as u16 / width + 1;
                }
            }
            Kind::Hello(_) => lines += 1,
            Kind::Image(_) => lines += 16,
            // Its name, then its size.
            Kind::File(_) | Kind::Attachment(_) => lines += 2,
        }
        if let MessageState::Error(err) = &self.state {
            lines += err.width_cjk() as u16 / width + 1;
        }
        lines
    }
}
