use ratatui::{
    prelude::*,
    widgets::{Block, Padding, Paragraph, Wrap},
};

use crate::message::{Message, MessageContent, MessageState};

impl Widget for &Message {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chunk = match self.state {
            MessageState::Sent => {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(20), Constraint::Fill(1)])
                    .split(area);
                chunks[1]
            }
            MessageState::Recved => {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Fill(1), Constraint::Percentage(20)])
                    .split(area);
                chunks[0]
            }
            MessageState::Error(_) => {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Percentage(10),
                        Constraint::Fill(1),
                        Constraint::Percentage(10),
                    ])
                    .split(area);
                chunks[1]
            }
        };
        match &self.content {
            MessageContent::Text(text) => {
                let mut lines = text
                    .lines()
                    .map(|line| Line::default().spans([Span::raw(line)]))
                    .collect::<Vec<_>>();
                if let MessageState::Error(e) = &self.state {
                    lines.push(Line::default().spans([Span::raw(e)]).yellow());
                }
                let mut p = Paragraph::new(lines)
                    .block(Block::bordered().padding(Padding::horizontal(2)))
                    .wrap(Wrap::default());
                p = match self.state {
                    MessageState::Sent => p.right_aligned(),
                    MessageState::Recved => p.left_aligned(),
                    MessageState::Error(_) => p.centered(),
                };
                p.render(chunk, buf);
            }
            MessageContent::Image(_) => todo!(),
        }
    }
}
