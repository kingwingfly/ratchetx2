use ratatui::{
    prelude::*,
    widgets::{Block, Padding},
};
use tui_textarea::TextArea;

pub struct Form<'a> {
    pub fields: &'a Vec<(String, TextArea<'static>)>,
}

impl StatefulWidget for Form<'_> {
    type State = usize;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let block = Block::bordered()
            .border_style(Style::default().green())
            .padding(Padding::proportional(2));
        let inner = block.inner(area);
        block.render(area, buf);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Fill(1), Constraint::Length(2)])
            .split(inner);

        Text::from("Tab/↓ | BackTab/↑ | Enter(Submit)")
            .centered()
            .render(chunks[1], buf);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![Constraint::Length(2); self.fields.len()])
            .split(chunks[0]);

        for (i, (label, textarea)) in self.fields.iter().enumerate() {
            let line_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(vec![Constraint::Fill(1), Constraint::Min(48)])
                .split(chunks[i]);

            let mut text = Text::from(label.as_str()).bold();
            if i == *state {
                text = text.fg(Color::Green);
            }
            text.render(line_chunks[0], buf);
            textarea.render(line_chunks[1], buf);
        }
    }
}
