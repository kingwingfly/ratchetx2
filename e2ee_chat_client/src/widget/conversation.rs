use std::num::NonZero;

use lru::LruCache;
use ratatui::{
    prelude::*,
    widgets::{Scrollbar, ScrollbarState},
};
use ratatui_image::{picker::Picker, protocol::StatefulProtocol};

use crate::message::Message;

use super::bubble::Bubble;

pub struct ConversationState {
    lru_image: LruCache<Vec<u8>, Option<StatefulProtocol>>,
}

impl Default for ConversationState {
    fn default() -> Self {
        Self {
            lru_image: LruCache::new(NonZero::new(16).unwrap()),
        }
    }
}

pub struct Conversation<'a> {
    pub messages: &'a Vec<Message>,
    pub current: usize,
    pub picker: &'a Picker,
}

impl StatefulWidget for Conversation<'_> {
    type State = ConversationState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Fill(1), Constraint::Length(1)])
            .split(area);
        Scrollbar::default().render(
            chunks[1],
            buf,
            &mut ScrollbarState::new(self.messages.len()).position(self.current),
        );
        let lines = chunks[0].height;
        let mut used = 0;
        for message in self.messages[..=self.current].iter().rev() {
            let line_num = message.line_num((chunks[0].width * 3 / 5).max(7) - 6) + 2; // border and padding
            if used + line_num >= lines {
                break;
            }
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
            .render(chunks[1], buf, &mut state.lru_image);
            used += line_num;
        }
    }
}
