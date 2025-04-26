use ratatui::prelude::*;

use crate::navi::Navigation;

pub struct Footer {}

impl StatefulWidget for Footer {
    type State = Navigation;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        match state {
            Navigation::Contacts => {
                Line::default().spans([Span::raw("Tab").underlined(), Span::raw("(Settings)")])
            }
            Navigation::Conversation => Line::default().spans([Span::raw("↑"), Span::raw("↓ ")]),
            Navigation::Input => Line::default().spans([
                Span::raw("^S").underlined(),
                Span::raw("end | "),
                Span::raw("^E").underlined(),
                Span::raw("xplore"),
            ]),
        }
        .gray()
        .right_aligned()
        .render(area, buf)
    }
}
