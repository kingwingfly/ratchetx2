use bincode::{Decode, Encode};
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

#[derive(Debug, Decode, Encode)]
pub enum MessageContent {
    Text(String),
    Image(Vec<u8>),
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
            MessageContent::Image(_) => todo!(),
        }
        if let MessageState::Error(err) = &self.state {
            lines += err.width_cjk() as u16 / width + 1;
        }
        lines
    }
}
