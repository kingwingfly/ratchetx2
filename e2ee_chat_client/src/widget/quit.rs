use ratatui::{
    prelude::*,
    widgets::{Block, Padding, Paragraph},
};

pub struct Quite {}

impl Widget for Quite {
    fn render(self, area: Rect, buf: &mut Buffer)
    where
        Self: Sized,
    {
        let block = Block::bordered()
            .style(Style::default().red())
            .padding(Padding::proportional(2));
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Fill(1)])
            .split(block.inner(area));
        block.render(area, buf);
        Paragraph::new("Quite?[y/*]")
            .centered()
            .render(chunks[0], buf);
        Paragraph::new("WARNING: All data won't be saved and will be lost.")
            .centered()
            .render(chunks[1], buf);
    }
}
