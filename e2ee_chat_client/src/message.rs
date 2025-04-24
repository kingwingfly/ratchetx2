use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug)]
pub struct Message {
    pub content: MessageContent,
    pub state: Arc<RwLock<MessageState>>,
}

#[derive(Debug)]
pub enum MessageState {
    Sending,
    Sent,
    Recved,
    Error(String),
}

#[derive(Debug)]
pub enum MessageContent {
    Text(String),
    Image(Vec<u8>),
}
