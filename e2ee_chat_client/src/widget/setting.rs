use base64::prelude::*;
use ratatui::{
    prelude::*,
    widgets::{Block, Cell, Padding, Paragraph, Row, Table},
};

pub struct Setting {}

pub struct SettingState {
    pub server_addr: String,
    pub public_identity_key: Vec<u8>,
}

impl StatefulWidget for Setting {
    type State = SettingState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let block = Block::bordered()
            .style(Style::default().green())
            .padding(Padding::proportional(2));
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Fill(1), Constraint::Length(2)])
            .split(block.inner(area));
        block.render(area, buf);
        Widget::render(
            Table::default()
                .widths([Constraint::Fill(1), Constraint::Min(44)])
                .header(Row::new([Cell::from("Setting"), Cell::from("value")]).bottom_margin(1))
                .rows([
                    Row::new([
                        Cell::from("Server Address"),
                        Cell::from(state.server_addr.as_str()),
                    ]),
                    Row::new([
                        Cell::from("Public Identity Key"),
                        Cell::from(BASE64_STANDARD.encode(&state.public_identity_key).as_str()),
                    ]),
                ]),
            chunks[0],
            buf,
        );
        Paragraph::new("(P)ublish keys | (R)efresh keys | (S)end/(H)anle initial message")
            .centered()
            .render(chunks[1], buf);
    }
}
