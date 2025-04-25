use anyhow::Result;
use base64::prelude::*;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, prelude::*};
use ratchetx2::X3DHClient;
use tui_textarea::TextArea;

use std::io::Stderr;

use crate::{
    message::{Message, MessageContent, MessageState},
    navi::Navigation,
    screen::Screen,
    widget::{
        app::{App, AppState},
        connecting::Connecting,
        hint::Hint,
        pop_up::PopUp,
    },
};

const CONTROL: KeyModifiers = KeyModifiers::CONTROL;

pub struct Client {
    terminal: Terminal<CrosstermBackend<Stderr>>,
}

impl Client {
    pub fn new() -> Result<Self> {
        enable_raw_mode()?;
        let mut stderr = std::io::stderr();
        #[cfg(windows)]
        execute!(stderr, EnableMouseCapture)?; // for Windows, enable first or it cannot disable
        execute!(stderr, EnterAlternateScreen, DisableMouseCapture)?;
        let backend = CrosstermBackend::new(stderr);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub async fn run(&mut self, server_addr: impl AsRef<str>) -> Result<()> {
        self.terminal.draw(|f| {
            f.render_widget(
                PopUp {
                    inner: Connecting {
                        server_addr: server_addr.as_ref().to_owned(),
                    },
                },
                f.area(),
            )
        })?;
        let mut state = match AppState::connect(server_addr).await {
            Ok(state) => state,
            Err(e) => {
                self.terminal.draw(|f| {
                    f.render_widget(
                        PopUp {
                            inner: Hint {
                                hint: e.to_string(),
                            },
                        },
                        f.area(),
                    )
                })?;
                event::read()?;
                return Ok(());
            }
        };
        loop {
            self.terminal.draw(|f| {
                f.render_stateful_widget(App {}, f.area(), &mut state);
            })?;
            match &state.screen {
                Screen::Quit => {
                    if matches!(
                        event::read()?,
                        Event::Key(KeyEvent {
                            code: KeyCode::Char('y') | KeyCode::Char('Y'),
                            kind: KeyEventKind::Press,
                            ..
                        })
                    ) {
                        break;
                    }
                    state.screen = Screen::default();
                    continue;
                }
                Screen::Hint(_) => {
                    if matches!(
                        event::read()?,
                        Event::Key(KeyEvent {
                            kind: KeyEventKind::Press,
                            ..
                        })
                    ) {
                        state.screen = Screen::default();
                        continue;
                    }
                }
                Screen::Settings => match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Char('p') => {
                            state.screen = match state.x3dh_client.publish_keys().await {
                                Ok(_) => Screen::Hint("Keys published".to_string()),
                                Err(err) => Screen::Hint(err.to_string()),
                            };
                        }
                        KeyCode::Char('r') => {
                            state.screen = match X3DHClient::connect(&state.server_addr).await {
                                Ok(client) => {
                                    state.x3dh_client = client;
                                    Screen::Hint("Keys refreshed".to_string())
                                }
                                Err(e) => Screen::Hint(e.to_string()),
                            }
                        }
                        KeyCode::Char('s') => {
                            state.textareas = vec![
                                ("Name".to_string(), TextArea::default()),
                                ("Public IndentityKey (Bob)".to_string(), TextArea::default()),
                            ];
                            state.current_activated_textarea = 0;
                            state.screen = Screen::PushInitMsg;
                        }
                        KeyCode::Char('h') => {
                            state.textareas = vec![
                                ("Name".to_string(), TextArea::default()),
                                (
                                    "Public IndentityKey (Alice)".to_string(),
                                    TextArea::default(),
                                ),
                            ];
                            state.current_activated_textarea = 0;
                            state.screen = Screen::HandleInitMsg;
                        }
                        KeyCode::Esc | KeyCode::Tab => state.screen = Screen::Main,
                        _ => {}
                    },
                    _ => {}
                },
                Screen::PushInitMsg | Screen::HandleInitMsg => match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Esc => state.screen = Screen::Main,
                        KeyCode::Tab | KeyCode::Down => {
                            state.current_activated_textarea += 1;
                            state.current_activated_textarea %= state.textareas.len();
                        }
                        KeyCode::BackTab | KeyCode::Up => {
                            state.current_activated_textarea += state.textareas.len() - 1;
                            state.current_activated_textarea %= state.textareas.len();
                        }
                        KeyCode::Enter => {
                            let name = state.textareas[0].1.lines().join("\n");
                            let content = state.textareas[1].1.lines().join("\n");
                            match BASE64_STANDARD.decode(&content) {
                                Ok(identity_key) => {
                                    state.textareas = vec![];
                                    match &state.screen {
                                        Screen::PushInitMsg => match state
                                            .x3dh_client
                                            .push_initial_message(&identity_key, &state.server_addr)
                                            .await
                                        {
                                            Ok(party) => {
                                                state.parties.insert(name.to_owned(), party);
                                                state.contacts.push(name);
                                                state.current_activated_contact =
                                                    state.contacts.len() - 1;
                                                state.screen = Screen::Main;
                                            }
                                            Err(e) => state.screen = Screen::Hint(e.to_string()),
                                        },
                                        Screen::HandleInitMsg => match state
                                            .x3dh_client
                                            .handle_initial_message(
                                                &identity_key,
                                                &state.server_addr,
                                            )
                                            .await
                                        {
                                            Ok(party) => {
                                                state.parties.insert(name.to_owned(), party);
                                                state.contacts.push(name);
                                                state.current_activated_contact =
                                                    state.contacts.len() - 1;
                                                state.screen = Screen::Main;
                                            }
                                            Err(e) => state.screen = Screen::Hint(e.to_string()),
                                        },
                                        _ => unreachable!(),
                                    }
                                }
                                Err(e) => state.screen = Screen::Hint(e.to_string()),
                            }
                        }
                        _ => {
                            state.textareas[state.current_activated_textarea]
                                .1
                                .input(key);
                        }
                    },
                    _ => {}
                },
                Screen::Main => match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Tab if state.navi.current == Navigation::Contacts => {
                            state.screen = Screen::Settings;
                        }
                        KeyCode::Up if key.modifiers == CONTROL => state.navi.up(),
                        KeyCode::Down if key.modifiers == CONTROL => state.navi.down(),
                        KeyCode::Left if key.modifiers == CONTROL => state.navi.left(),
                        KeyCode::Right if key.modifiers == CONTROL => state.navi.right(),
                        KeyCode::Up if state.navi.current == Navigation::Contacts => {
                            state.current_activated_contact =
                                state.current_activated_contact.saturating_sub(1);
                        }
                        KeyCode::Down if state.navi.current == Navigation::Contacts => {
                            state.current_activated_contact =
                                (state.contacts.len().saturating_sub(1))
                                    .min(state.current_activated_contact + 1);
                        }
                        KeyCode::Enter if state.navi.current == Navigation::Contacts => {
                            state.navi.down();
                        }
                        KeyCode::Up if state.navi.current == Navigation::Conversation => {
                            state.current_activated_message =
                                state.current_activated_message.saturating_sub(1);
                        }
                        KeyCode::Down if state.navi.current == Navigation::Conversation => {
                            if let Some(messages) = state
                                .contacts
                                .get(state.current_activated_contact)
                                .and_then(|c| state.conversation.get(c))
                            {
                                state.current_activated_message =
                                    (messages.len().saturating_sub(1))
                                        .min(state.current_activated_message + 1);
                            }
                        }
                        KeyCode::Char('s')
                            if key.modifiers == CONTROL
                                && state.navi.current == Navigation::Input =>
                        {
                            if let Some(name) = state.contacts.get(state.current_activated_contact)
                            {
                                if let Some(party) = state.parties.get_mut(name) {
                                    let content = state.chat_textarea.lines().join("\n");
                                    let mut textarea = TextArea::default();
                                    textarea.set_line_number_style(Style::default().gray());
                                    state.chat_textarea = textarea;
                                    let message = Message {
                                        content: MessageContent::Text(content.clone()),
                                        state: match party.push(content.to_owned()).await {
                                            Ok(_) => MessageState::Sent,
                                            Err(e) => MessageState::Error(e.to_string()),
                                        },
                                    };
                                    state
                                        .conversation
                                        .entry(name.to_owned())
                                        .or_default()
                                        .push(message);
                                    state.current_activated_message =
                                        state.conversation[name].len() - 1;
                                }
                            }
                        }
                        KeyCode::Esc if state.navi.current != Navigation::Contacts => {
                            state.navi.left()
                        }
                        KeyCode::Esc => state.screen = Screen::Quit,
                        _ if state.navi.current == Navigation::Input => {
                            state.chat_textarea.input(key);
                        }
                        _ => {}
                    },
                    _ => {}
                },
            }
        }
        Ok(())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        disable_raw_mode().ok();
        execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            EnableMouseCapture
        )
        .ok();
    }
}
