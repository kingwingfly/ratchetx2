use ratatui::{
    prelude::*,
    widgets::{Scrollbar, ScrollbarState},
};
use ratatui_image::picker::Picker;

use crate::message::Message;

use super::bubble::Bubble;

pub struct Conversation<'a> {
    pub messages: &'a Vec<Message>,
    pub picker: &'a Picker,
}

impl StatefulWidget for Conversation<'_> {
    type State = usize;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Fill(1), Constraint::Length(1)])
            .split(area);
        Scrollbar::default().render(
            chunks[1],
            buf,
            &mut ScrollbarState::new(self.messages.len()).position(*state),
        );
        let lines = chunks[0].height;
        let mut used = 0;
        for message in self.messages[..=*state].iter().rev() {
            let line_num = message.line_num((chunks[0].width * 3 / 5).max(7) - 6) + 2; // border and padding
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Fill(1),
                    Constraint::Length(line_num),
                    Constraint::Length(used),
                ])
                .split(chunks[0]);
            Bubble {
                message,
                picker: self.picker,
            }
            .render(chunks[1], buf);
            used += line_num;
            if used >= lines {
                break;
            }
        }
    }
}
