use ratatui::{
    prelude::*,
    widgets::{Block, Paragraph},
};

pub struct Hint {
    pub hint: String,
}

impl Widget for Hint {
    fn render(self, area: Rect, buf: &mut Buffer) {
        Paragraph::new(self.hint)
            .centered()
            .block(Block::bordered().style(Style::default().yellow()))
            .render(area, buf);
    }
}
