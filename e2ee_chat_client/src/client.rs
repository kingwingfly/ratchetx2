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
use tokio::sync::RwLock;
use tui_textarea::TextArea;

use std::{io::Stderr, sync::Arc};

use crate::{
    message::{Message, MessageContent, MessageState},
    navi::Navigation,
    screen::Screen,
    widget::{
        app::{App, AppState},
        connecting::Connecting,
    },
};

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
                Connecting {
                    server_addr: server_addr.as_ref().to_owned(),
                },
                f.area(),
            )
        })?;
        let mut state = AppState::connect(server_addr).await?;
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
                            state.x3dh_client = X3DHClient::connect(&state.server_addr).await;
                            state.screen = Screen::Hint("Keys refreshed".to_string());
                        }
                        KeyCode::Char('s') => state.screen = Screen::PushInitMsg,
                        KeyCode::Char('h') => state.screen = Screen::HandleInitMsg,
                        KeyCode::Esc => state.screen = Screen::Main,
                        _ => {}
                    },
                    _ => {}
                },
                Screen::PushInitMsg | Screen::HandleInitMsg => match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Esc => state.screen = Screen::Main,
                        KeyCode::Enter => {
                            let content = state.textarea.lines().join("\n");
                            match BASE64_STANDARD.decode(&content) {
                                Ok(identity_key) => {
                                    let mut textarea = TextArea::default();
                                    textarea.set_line_number_style(Style::default().gray());
                                    state.textarea = textarea;
                                    match &state.screen {
                                        Screen::PushInitMsg => match state
                                            .x3dh_client
                                            .push_initial_message(&identity_key, &state.server_addr)
                                            .await
                                        {
                                            Ok(party) => {
                                                state
                                                    .parties
                                                    .insert(content, Arc::new(RwLock::new(party)));
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
                                                state
                                                    .parties
                                                    .insert(content, Arc::new(RwLock::new(party)));
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
                            state.textarea.input(key);
                        }
                    },
                    _ => {}
                },
                Screen::Main => match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Char(',') if key.modifiers == KeyModifiers::ALT => {
                            state.screen = Screen::Settings;
                        }
                        KeyCode::Up if key.modifiers == KeyModifiers::ALT => state.navi.up(),
                        KeyCode::Down if key.modifiers == KeyModifiers::ALT => state.navi.down(),
                        KeyCode::Left if key.modifiers == KeyModifiers::ALT => state.navi.left(),
                        KeyCode::Right if key.modifiers == KeyModifiers::ALT => state.navi.right(),
                        KeyCode::Enter
                            if key.modifiers == KeyModifiers::ALT
                                && state.navi.current == Navigation::Input =>
                        {
                            if let Some(current) = state.current.as_ref() {
                                if let Some(party) = state.parties.get(current).cloned() {
                                    let content = state.chat_textarea.lines().join("\n");
                                    let mut textarea = TextArea::default();
                                    textarea.set_line_number_style(Style::default().gray());
                                    state.chat_textarea = textarea;
                                    let message_state =
                                        Arc::new(RwLock::new(MessageState::Sending));
                                    let message = Message {
                                        content: MessageContent::Text(content.clone()),
                                        state: message_state.clone(),
                                    };
                                    state
                                        .conversation
                                        .entry(current.to_owned())
                                        .or_default()
                                        .push(message);
                                    tokio::spawn(async move {
                                        if party.write().await.push(content).await.is_ok() {
                                            *message_state.write().await = MessageState::Sent;
                                        } else {
                                            *message_state.write().await =
                                                MessageState::Error("Failed to send.".to_string());
                                        }
                                    });
                                }
                            }
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
