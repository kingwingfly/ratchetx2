use base64::prelude::*;
use ratatui::{
    prelude::*,
    widgets::{Block, Cell, Padding, Row, Table},
};
use ratchetx2::Uri;

pub struct Setting {}

pub struct SettingState {
    pub server_addr: Uri,
    pub public_identity_key: Vec<u8>,
}

impl StatefulWidget for Setting {
    type State = SettingState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let block = Block::bordered()
            .border_style(Style::default().green())
            .padding(Padding::proportional(2));
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Fill(1), Constraint::Length(1)])
            .split(block.inner(area));
        block.render(area, buf);
        Widget::render(
            Table::default()
                .widths([Constraint::Max(32), Constraint::Min(44)])
                .header(
                    Row::new([Cell::from("Setting"), Cell::from("Value")])
                        .bottom_margin(1)
                        .bold(),
                )
                .rows([
                    Row::new([
                        {
                            if state.server_addr.scheme_str() == Some("http") {
                                Cell::from("Server Addr (HTTP⚠️)").red()
                            } else if state.server_addr.scheme_str() == Some("https") {
                                Cell::from("Server Addr (HTTPS)")
                            } else {
                                Cell::from("Server Addr (Unknown Type)").yellow()
                            }
                        },
                        Cell::from(state.server_addr.to_string()),
                    ]),
                    Row::new([
                        Cell::from("Public Identity Key"),
                        Cell::from(BASE64_STANDARD.encode(&state.public_identity_key).as_str()),
                    ]),
                ]),
            chunks[0],
            buf,
        );
        Line::default()
            .spans([
                Span::raw("P").underlined(),
                Span::raw("ublish Keys | "),
                Span::raw("R").underlined(),
                Span::raw("efresh Keys | "),
                Span::raw("S").underlined(),
                Span::raw("end/"),
                Span::raw("H").underlined(),
                Span::raw("andle/"),
                Span::raw("L").underlined(),
                Span::raw("ist InitialMessage"),
            ])
            .centered()
            .gray()
            .left_aligned()
            .render(chunks[1], buf);
    }
}
