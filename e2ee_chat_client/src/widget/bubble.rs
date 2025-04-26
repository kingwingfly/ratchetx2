use image::load_from_memory;
use ratatui::{
    prelude::*,
    widgets::{Block, Padding, Paragraph, Wrap},
};
use ratatui_image::{FilterType, Resize, StatefulImage, picker::Picker};

use crate::message::{Message, MessageContent, MessageState};

pub struct Bubble<'a> {
    pub picker: &'a Picker,
    pub message: &'a Message,
}

impl Widget for Bubble<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chunk = match self.message.state {
            MessageState::Sent => {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(40), Constraint::Fill(1)])
                    .split(area);
                chunks[1]
            }
            MessageState::Recved => {
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
                    MessageState::Recved => p.left_aligned(),
                    MessageState::Error(_) => p.centered(),
                };
                p.render(inner, buf);
            }
            MessageContent::Image(bytes) => {
                if let Ok(image) = load_from_memory(bytes) {
                    let mut image = self.picker.new_resize_protocol(image);
                    image.resize_encode(&Resize::Fit(Some(FilterType::CatmullRom)), inner);
                    StatefulImage::default().render(inner, buf, &mut image);
                }
            }
        }
    }
}
