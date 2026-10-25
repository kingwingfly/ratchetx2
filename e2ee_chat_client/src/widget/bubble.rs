use image::load_from_memory;
use lru::LruCache;
use ratatui::{
    prelude::*,
    widgets::{Block, Padding, Paragraph, Wrap},
};
use ratatui_image::{
    FilterType, Resize, ResizeEncodeRender, StatefulImage, picker::Picker,
    protocol::StatefulProtocol,
};
use sha2::{Digest, Sha256};

use crate::message::{File, Message, MessageContent, MessageState};

pub struct Bubble<'a> {
    pub picker: &'a Picker,
    pub message: &'a Message,
}

impl StatefulWidget for Bubble<'_> {
    type State = LruCache<Vec<u8>, Option<StatefulProtocol>>;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let chunk = match self.message.state {
            MessageState::Sent => {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(40), Constraint::Fill(1)])
                    .split(area);
                chunks[1]
            }
            MessageState::Received => {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Fill(1), Constraint::Percentage(40)])
                    .split(area);
                chunks[0]
            }
            MessageState::Error(_) => {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Percentage(20),
                        Constraint::Fill(1),
                        Constraint::Percentage(20),
                    ])
                    .split(area);
                chunks[1]
            }
        };
        let block = Block::bordered()
            .padding(Padding::horizontal(2))
            .border_style(Style::default().fg(Color::Gray));
        let inner = block.inner(chunk);
        block.render(chunk, buf);
        match &self.message.content {
            MessageContent::Text(text) => {
                let mut lines = text
                    .lines()
                    .map(|line| Line::default().spans([Span::raw(line)]))
                    .collect::<Vec<_>>();
                if let MessageState::Error(e) = &self.message.state {
                    lines.push(Line::default().spans([Span::raw(e)]).yellow());
                }
                let mut p = Paragraph::new(lines).wrap(Wrap::default());
                p = match self.message.state {
                    MessageState::Sent => p.left_aligned(),
                    MessageState::Received => p.left_aligned(),
                    MessageState::Error(_) => p.centered(),
                };
                p.render(inner, buf);
            }
            MessageContent::File(File { name, data, .. }) => {
                file_card(name, data.len() as u64).render(inner, buf);
            }
            MessageContent::Attachment(pointer) => {
                file_card(&pointer.name, pointer.size).render(inner, buf);
            }
            MessageContent::Image(bytes) => {
                if let Some(image) = state.get_or_insert_mut(Sha256::digest(bytes).to_vec(), || {
                    load_from_memory(bytes).ok().map(|image| {
                        let mut image = self.picker.new_resize_protocol(image);
                        image.resize_encode(
                            &Resize::Fit(Some(FilterType::CatmullRom)),
                            inner.as_size(),
                        );
                        image
                    })
                }) {
                    StatefulImage::default().render(inner, buf, image);
                }
            }
        }
    }
}

/// A file's name, then its size and how to save it.
fn file_card(name: &str, size: u64) -> Paragraph<'_> {
    Paragraph::new(vec![
        Line::raw(name).bold(),
        Line::raw(format!("{} · s to save", human_size(size))).gray(),
    ])
    .wrap(Wrap::default())
}

/// A size in bytes, for people.
fn human_size(bytes: u64) -> String {
    match bytes {
        0..1_000 => format!("{bytes} B"),
        1_000..1_000_000 => format!("{:.0} KB", bytes as f64 / 1e3),
        _ => format!("{:.1} MB", bytes as f64 / 1e6),
    }
}
