use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use base64::prelude::*;
use parking_lot::RwLock;
use ratatui::{
    prelude::*,
    widgets::{Block, List, ListState, Padding},
};
use ratatui_image::picker::Picker;
use session::protocol::grpc::{Certificate, Channel, GrpcHandshake, GrpcMailbox, Uri, connect};
use session::{Client, Introduction, Session};
use tokio::sync::Mutex as AsyncMutex;
use tui_textarea::TextArea;

use crate::{
    message::Message,
    navi::{Navigation, Navigator},
    screen::Screen,
};

use super::{
    contacts::Contacts,
    conversation::{Conversation, ConversationState},
    explore::{Explore, ExploreState},
    footer::Footer,
    form::Form,
    hint::Hint,
    pop_up::{PopUp, PopUpStateful},
    quit::Quite,
    setting::{Setting, SettingState},
};

pub use session::PublicKey;
/// A session, locked on its own so using one never waits for the others.
pub type SharedSession = Arc<AsyncMutex<Session<GrpcMailbox>>>;

pub struct AppState {
    pub client: Client<GrpcHandshake>,
    pub channel: Channel,

    /// (Name, PublicKey)
    pub contacts: Vec<(String, PublicKey)>,
    /// Only locked to look sessions up, never across an `await`.
    pub sessions: Arc<RwLock<HashMap<PublicKey, SharedSession>>>,
    pub current_activated_contact: usize,
    pub conversations: Arc<RwLock<HashMap<PublicKey, Vec<Message>>>>,
    pub current_activated_message: usize,

    pub server_addr: Uri,
    pub navi: Navigator,
    pub chat_textarea: TextArea<'static>,
    pub textareas: Vec<(String, TextArea<'static>)>,
    pub current_activated_textarea: usize,
    /// Initial messages taken from the server but not accepted yet.
    pub introductions: Vec<Introduction>,
    pub current_selected_introduction: usize,
    pub screen: Screen,

    pub explore_state: ExploreState,
    conversation_state: ConversationState,

    picker: Picker,
}

impl AppState {
    pub async fn connect(server_addr: impl TryInto<Uri>, ca: Option<Certificate>) -> Result<Self> {
        let server_addr = server_addr
            .try_into()
            .unwrap_or_else(|_| panic!("Invalid server address."));
        let mut text_area = TextArea::default();
        text_area.set_line_number_style(Style::default().gray());
        let channel = connect(server_addr.clone(), ca).await?;
        Ok(Self {
            client: Client::new(GrpcHandshake::new(channel.clone())),
            channel,
            contacts: vec![],
            sessions: Default::default(),
            current_activated_contact: 0,
            conversations: Default::default(),
            current_activated_message: 0,
            server_addr,
            navi: Navigator::default(),
            chat_textarea: text_area,
            textareas: vec![],
            current_activated_textarea: 0,
            introductions: vec![],
            current_selected_introduction: 0,
            screen: Screen::default(),
            explore_state: Default::default(),
            conversation_state: Default::default(),
            #[cfg(not(windows))]
            picker: Picker::from_query_stdio()?,
            #[cfg(windows)]
            picker: {
                // Deprecated, but the only way to pair iTerm2 with a fixed font size.
                #[allow(deprecated)]
                let mut picker = Picker::from_fontsize(ratatui_image::FontSize::new(7, 14));
                picker.set_protocol_type(ratatui_image::picker::ProtocolType::Iterm2);
                picker
            },
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
                Constraint::Length(1),
                Constraint::Fill(1),
                Constraint::Length(1),
            ])
            .split(area);

        Text::from("E2EE Chat").centered().render(chunks[0], buf);

        Footer {}.render(chunks[2], buf, &mut state.navi.current);

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(10), Constraint::Fill(1)])
            .split(chunks[1]);

        let mut contacts_block = Block::bordered().title("Contacts");
        if state.navi.current == Navigation::Contacts {
            contacts_block = contacts_block.border_style(Style::default().light_green());
        }
        let contacts = contacts_block.inner(chunks[0]);
        contacts_block.render(chunks[0], buf);
        Contacts {
            contacts: &state.contacts,
        }
        .render(contacts, buf, &mut state.current_activated_contact);

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
        {
            let conversations_r = state.conversations.read();
            if let Some(messages) = state
                .contacts
                .get(state.current_activated_contact)
                .and_then(|c| conversations_r.get(&c.1))
            {
                Conversation {
                    messages,
                    current: state.current_activated_message,
                    picker: &state.picker,
                }
                .render(conversation, buf, &mut state.conversation_state);
            }
        }

        let mut textarea_block = Block::bordered().padding(Padding::proportional(1));
        if state.navi.current == Navigation::Input {
            textarea_block = textarea_block.border_style(Style::default().light_green());
        }
        let textarea = textarea_block.inner(chunks[1]);
        textarea_block.render(chunks[1], buf);
        state.chat_textarea.render(textarea, buf);

        match &state.screen {
            Screen::Main => {}
            Screen::Settings => PopUpStateful { inner: Setting {} }.render(
                area,
                buf,
                &mut SettingState {
                    server_addr: state.server_addr.clone(),
                    public_identity_key: state.client.identity_key(),
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
                PopUpStateful {
                    inner: Form {
                        fields: &state.textareas,
                    },
                }
                .render(area, buf, &mut state.current_activated_textarea);
            }
            Screen::ListInitMsg => {
                PopUpStateful {
                    inner: List::new(
                        state
                            .introductions
                            .iter()
                            .map(|introduction| BASE64_STANDARD.encode(introduction.identity_key)),
                    )
                    .highlight_style(Style::default().green())
                    .block(Block::bordered().padding(Padding::proportional(2))),
                }
                .render(
                    area,
                    buf,
                    &mut ListState::default()
                        .with_selected(Some(state.current_selected_introduction)),
                );
            }
            Screen::SelectFile => {
                PopUpStateful {
                    inner: Explore {
                        picker: &state.picker,
                    },
                }
                .render(area, buf, &mut state.explore_state);
            }
        }
    }
}
