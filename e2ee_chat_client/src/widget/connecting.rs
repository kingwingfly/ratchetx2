use ratatui::prelude::*;
use ratatui::widgets::Widget;

pub struct Connecting {
    pub server_addr: String,
}

impl Widget for Connecting {
    fn render(self, area: Rect, buf: &mut Buffer)
    where
        Self: Sized,
    {
        Text::from(format!("Connecting {}...", self.server_addr))
            .centered()
            .render(area, buf);
    }
}
