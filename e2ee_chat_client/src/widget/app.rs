use std::collections::HashMap;

use anyhow::Result;
use ratatui::{
    prelude::*,
    widgets::{Block, Padding},
};
use ratchetx2::{Party, X3DHClient, transport::RpcTransport};
use std::sync::Arc;
use tokio::sync::RwLock;
use tui_textarea::TextArea;

use crate::{
    message::Message,
    navi::{Navigation, Navigator},
    screen::Screen,
};

use super::{
    hint::Hint,
    pop_up::{PopUp, PopUpStateful},
    quit::Quite,
    setting::{Setting, SettingState},
};

pub struct AppState {
    pub x3dh_client: X3DHClient,
    pub parties: HashMap<String, Arc<RwLock<Party<RpcTransport>>>>,
    pub server_addr: String,
    pub navi: Navigator,
    pub chat_textarea: TextArea<'static>,
    pub textarea: TextArea<'static>,
    /// Current activated conversation
    pub current: Option<String>,
    pub conversation: HashMap<String, Vec<Message>>,
    pub screen: Screen,
}

impl AppState {
    pub async fn connect(server_addr: impl AsRef<str>) -> Result<Self> {
        let mut text_area = TextArea::default();
        text_area.set_line_number_style(Style::default().gray());
        Ok(Self {
            x3dh_client: X3DHClient::connect(&server_addr).await,
            parties: HashMap::default(),
            server_addr: server_addr.as_ref().to_owned(),
            navi: Navigator::default(),
            chat_textarea: text_area,
            textarea: TextArea::default(),
            current: None,
            conversation: HashMap::default(),
            screen: Screen::default(),
        })
    }
}

pub struct App {}

impl StatefulWidget for App {
    type State = AppState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Fill(1),
                Constraint::Length(4),
            ])
            .split(area);

        let header_block = Block::bordered();
        let header = header_block.inner(chunks[0]);
        header_block.render(chunks[0], buf);

        let footer_block = Block::bordered();
        let footer = footer_block.inner(chunks[2]);
        footer_block.render(chunks[2], buf);

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(20), Constraint::Fill(1)])
            .split(chunks[1]);

        let mut contacts_block = Block::bordered().title("Contacts");
        if state.navi.current == Navigation::Contacts {
            contacts_block = contacts_block.border_style(Style::default().light_green());
        }
        let contacts = contacts_block.inner(chunks[0]);
        contacts_block.render(chunks[0], buf);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Fill(1), Constraint::Percentage(25)])
            .split(chunks[1]);

        let mut conversation_block = Block::bordered();
        if state.navi.current == Navigation::Conversation {
            conversation_block = conversation_block.border_style(Style::default().light_green());
        }
        let conversation = conversation_block.inner(chunks[0]);
        conversation_block.render(chunks[0], buf);

        let mut input_block = Block::bordered().padding(Padding::proportional(2));
        if state.navi.current == Navigation::Input {
            input_block = input_block.border_style(Style::default().light_green());
        }
        let input = input_block.inner(chunks[1]);
        input_block.render(chunks[1], buf);
        state.chat_textarea.render(input, buf);

        match &state.screen {
            Screen::Main => {}
            Screen::Settings => PopUpStateful { inner: Setting {} }.render(
                area,
                buf,
                &mut SettingState {
                    server_addr: state.server_addr.to_owned(),
                    public_identity_key: state.x3dh_client.public_identity_key(),
                },
            ),
            Screen::Quit => PopUp { inner: Quite {} }.render(area, buf),
            Screen::Hint(hint) => PopUp {
                inner: Hint {
                    hint: hint.to_owned(),
                },
            }
            .render(area, buf),
            Screen::PushInitMsg | Screen::HandleInitMsg => {
                state.textarea.set_block(
                    Block::bordered()
                        .title(state.screen.to_string())
                        .padding(Padding::proportional(2)),
                );
                PopUp {
                    inner: &state.textarea,
                }
                .render(area, buf);
            }
        }
    }
}
