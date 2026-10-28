use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::Result;
use base64::prelude::*;
use parking_lot::RwLock;
use ratatui::{
    prelude::*,
    widgets::{Block, List, ListState, Padding},
};
use ratatui_image::picker::Picker;
pub use session::PublicKey;
use session::{
    Client, InitialMessage, Session,
    protocol::{
        ErrorKind,
        handshake::{FetchBundleRequest, LocalHandshake as _},
    },
};
use tokio::sync::Mutex as AsyncMutex;
use tui_textarea::TextArea;

use super::{
    contacts::Contacts,
    conversation::{Conversation, ConversationState},
    explore::{Explore, ExploreState},
    footer::Footer,
    form::Form,
    hint::Hint,
    pop_up::{PopUp, PopUpStateful},
    quit::Quit,
    setting::{Setting, SettingState},
};
use crate::{
    message::Chat,
    navi::{Navigation, Navigator},
    screen::Screen,
    transport::{Connect, Http},
};
/// A session, locked on its own so using one never waits for the others.
pub type SharedSession = Arc<AsyncMutex<Session<Connect>>>;

pub struct AppState {
    /// Shared with the task that receives, which takes the initial messages first.
    pub client: Arc<AsyncMutex<Client<Connect>>>,
    /// The client's identity key.
    pub identity_key: PublicKey,
    /// The server, for new handshake and mailbox clients.
    pub http: Http,
    /// Where saved files go.
    pub downloads: PathBuf,

    /// (Name, PublicKey)
    pub contacts: Vec<(String, PublicKey)>,
    /// Only locked to look sessions up, never across an `await`.
    pub sessions: Arc<RwLock<HashMap<PublicKey, SharedSession>>>,
    pub current_activated_contact: usize,
    /// Only locked to read or change a chat, never across an `await`.
    pub conversations: Arc<RwLock<HashMap<PublicKey, Chat>>>,
    pub current_activated_message: usize,

    pub navi: Navigator,
    pub chat_textarea: TextArea<'static>,
    pub textareas: Vec<(String, TextArea<'static>)>,
    pub current_activated_textarea: usize,
    /// New peers' initial messages, taken from the server but not accepted yet; shared with
    /// the task that receives, which takes them.
    pub initial_messages: Arc<RwLock<Vec<InitialMessage>>>,
    pub current_selected_initial_message: usize,
    pub screen: Screen,

    pub explore_state: ExploreState,
    conversation_state: ConversationState,

    picker: Picker,
}

impl AppState {
    pub async fn connect(server_addr: &str, downloads: PathBuf) -> Result<Self> {
        let mut text_area = TextArea::default();
        text_area.set_line_number_style(Style::default().gray());
        let http = Http::new(server_addr)?;
        let client = Client::new(http.connect());
        // Fail now if nothing speaks the protocol there: the new identity has no bundle yet, so
        // the server answers "not found".
        let probe = http
            .connect()
            .fetch_bundle(FetchBundleRequest {
                identity_key: client.identity_key().to_vec().into(),
            })
            .await;
        if let Err(e) = probe
            && e.kind() != ErrorKind::NotFound
        {
            return Err(anyhow::Error::new(e).context(format!("cannot reach {server_addr}")));
        }
        Ok(Self {
            identity_key: client.identity_key(),
            client: Arc::new(AsyncMutex::new(client)),
            http,
            downloads,
            contacts: vec![],
            sessions: Default::default(),
            current_activated_contact: 0,
            conversations: Default::default(),
            current_activated_message: 0,
            navi: Navigator::default(),
            chat_textarea: text_area,
            textareas: vec![],
            current_activated_textarea: 0,
            initial_messages: Default::default(),
            current_selected_initial_message: 0,
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
            if let Some(chat) = state
                .contacts
                .get(state.current_activated_contact)
                .and_then(|c| conversations_r.get(&c.1))
            {
                Conversation {
                    messages: &chat.messages,
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
                    server_addr: state.http.server().to_string(),
                    public_identity_key: state.identity_key,
                    signed_in: state.http.signed_in(),
                },
            ),
            Screen::Quit => PopUp { inner: Quit {} }.render(area, buf),
            Screen::Hint(hint) => PopUp {
                inner: Hint {
                    hint: hint.to_owned(),
                },
            }
            .render(area, buf),
            Screen::PushInitMsg | Screen::HandleInitMsg | Screen::SignIn => {
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
                            .initial_messages
                            .read()
                            .iter()
                            .map(|initial_message| {
                                BASE64_STANDARD.encode(initial_message.x3dh.identity_key)
                            })
                            .collect::<Vec<_>>(),
                    )
                    .highlight_style(Style::default().green())
                    .block(Block::bordered().padding(Padding::proportional(2))),
                }
                .render(
                    area,
                    buf,
                    &mut ListState::default()
                        .with_selected(Some(state.current_selected_initial_message)),
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
