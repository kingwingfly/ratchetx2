use ratatui::{
    prelude::*,
    widgets::{Scrollbar, ScrollbarState},
};

pub struct Contacts<'a> {
    pub contacts: &'a Vec<String>,
}

impl StatefulWidget for Contacts<'_> {
    type State = usize;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Fill(1), Constraint::Length(1)])
            .split(area);
        Scrollbar::default().render(
            chunks[1],
            buf,
            &mut ScrollbarState::new(self.contacts.len()).position(*state),
        );
        let lines = chunks[0].height as usize;
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![Constraint::Length(1); lines])
            .split(chunks[0]);
        let page = *state / lines;
        for (i, contact) in self
            .contacts
            .iter()
            .skip(page * lines)
            .take(lines)
            .enumerate()
        {
            let mut text = Text::from(contact.as_str());
            if i == (*state % lines) {
                text = text.fg(Color::Green).underlined();
            }
            text.render(chunks[i], buf);
        }
    }
}
