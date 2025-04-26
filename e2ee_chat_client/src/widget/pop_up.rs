use ratatui::{prelude::*, widgets::Clear};

pub struct PopUp<W: Widget> {
    pub inner: W,
}

impl<W: Widget> Widget for PopUp<W> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let pop_up = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(15),
                Constraint::Fill(1),
                Constraint::Percentage(5),
            ])
            .split(
                Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Fill(1),
                        Constraint::Fill(4),
                        Constraint::Percentage(30),
                    ])
                    .split(area)[1],
            )[1];
        Clear.render(pop_up, buf);
        self.inner.render(pop_up, buf);
    }
}

pub struct PopUpStateful<W: StatefulWidget> {
    pub inner: W,
}

impl<W: StatefulWidget> StatefulWidget for PopUpStateful<W> {
    type State = W::State;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let pop_up = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(15),
                Constraint::Fill(1),
                Constraint::Percentage(5),
            ])
            .split(
                Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Fill(1),
                        Constraint::Fill(4),
                        Constraint::Percentage(30),
                    ])
                    .split(area)[1],
            )[1];
        Clear.render(pop_up, buf);
        self.inner.render(pop_up, buf, state);
    }
}
