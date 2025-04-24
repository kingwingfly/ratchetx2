use ratatui::{prelude::*, widgets::Paragraph};

pub struct Footer {
    pub hint: String,
}

impl Widget for Footer {
    fn render(self, area: Rect, buf: &mut Buffer) {
        Paragraph::new(self.hint).render(area, buf);
    }
}
