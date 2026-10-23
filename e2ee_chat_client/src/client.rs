use std::{io::Stderr, sync::Arc, time::Duration};

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
use session::protocol::grpc::{Certificate, GrpcHandshake, GrpcMailbox, Uri};
use tui_textarea::TextArea;

use crate::{
    message::{Message, MessageContent, MessageState},
    navi::Navigation,
    screen::Screen,
    widget::{
        app::{App, AppState, PublicKey},
        connecting::Connecting,
        hint::Hint,
        pop_up::PopUp,
    },
};

const CONTROL: KeyModifiers = KeyModifiers::CONTROL;
/// How many one-time prekeys to publish.
const ONE_TIME_PREKEYS: usize = 16;

pub struct Client {
    terminal: Terminal<CrosstermBackend<Stderr>>,
}

impl Client {
    pub fn new() -> Result<Self> {
        let original_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic| {
            disable_raw_mode().unwrap();
            execute!(std::io::stderr(), LeaveAlternateScreen).unwrap();
            original_hook(panic);
        }));
        enable_raw_mode()?;
        let mut stderr = std::io::stderr();
        #[cfg(windows)]
        execute!(stderr, EnableMouseCapture)?; // for Windows, enable first or it cannot disable
        execute!(stderr, EnterAlternateScreen, DisableMouseCapture)?;
        let backend = CrosstermBackend::new(stderr);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub async fn run(
        &mut self,
        server_addr: impl TryInto<Uri>,
        ca: Option<Certificate>,
    ) -> Result<()> {
        let server_addr: Uri = server_addr
            .try_into()
            .unwrap_or_else(|_| panic!("Invalid server address."));
        self.terminal.draw(|f| {
            f.render_widget(
                PopUp {
                    inner: Connecting {
                        server_addr: server_addr.to_string(),
                    },
                },
                f.area(),
            )
        })?;
        let mut state = match AppState::connect(server_addr, ca.clone()).await {
            Ok(state) => state,
            Err(e) => {
                self.terminal.draw(|f| {
                    f.render_widget(
                        PopUp {
                            inner: Hint {
                                hint: format!("{e:#}"),
                            },
                        },
                        f.area(),
                    )
                })?;
                event::read()?;
                return Ok(());
            }
        };

        let sessions = state.sessions.clone();
        let conversations = state.conversations.clone();
        tokio::spawn(async move {
            let mut sync = true;
            loop {
                tokio::select! {
                    _ = async {
                        let sessions: Vec<_> = sessions
                            .read()
                            .iter()
                            .map(|(key, session)| (*key, session.clone()))
                            .collect();
                        for (key, session) in sessions {
                            // Lock the session for one page at a time, so sending to this peer
                            // waits for one fetch at most.
                            loop {
                                let page = session.lock().await.receive().await;
                                let Ok(page) = page else { break };
                                if page.is_empty() {
                                    break;
                                }
                                for message in page.into_iter().filter_map(|m| m.ok()) {
                                    if let Some(content) = MessageContent::from_bytes(&message) {
                                        conversations.write().entry(key).or_default().push(
                                            Message {
                                                content,
                                                state: MessageState::Received,
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    }, if sync => sync = false,
                    _ = tokio::time::sleep(Duration::from_secs(8)), if !sync => sync = true,
                }
            }
        });

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
                            state.screen = match state.client.publish_keys(ONE_TIME_PREKEYS).await {
                                Ok(_) => Screen::Hint("Keys published".to_string()),
                                Err(err) => Screen::Hint(describe(err)),
                            };
                        }
                        KeyCode::Char('r') => {
                            state.client =
                                session::Client::new(GrpcHandshake::new(state.channel.clone()));
                            // They were sent to the old identity, whose prekeys are gone.
                            state.introductions.clear();
                            state.screen = Screen::Hint(
                                "New identity created, publish its keys to be reachable"
                                    .to_string(),
                            );
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
                        KeyCode::Char('l') => match state.client.take_introductions().await {
                            // Taken introductions are gone from the server, so keep them
                            // until accepted.
                            Ok(introductions) => {
                                state.introductions.extend(introductions);
                                state.screen = if state.introductions.is_empty() {
                                    Screen::Hint("No init message.".to_string())
                                } else {
                                    state.current_selected_introduction = 0;
                                    Screen::ListInitMsg
                                };
                            }
                            Err(e) => state.screen = Screen::Hint(describe(e)),
                        },
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
                            let Some(identity_key) = BASE64_STANDARD
                                .decode(content.trim())
                                .ok()
                                .and_then(|key| PublicKey::try_from(key).ok())
                            else {
                                state.screen = Screen::Hint("Invalid identity key".to_string());
                                continue;
                            };
                            state.textareas = vec![];
                            let mailbox = GrpcMailbox::new(state.channel.clone());
                            let session = match &state.screen {
                                Screen::PushInitMsg => state
                                    .client
                                    .initiate(&identity_key, mailbox)
                                    .await
                                    .map_err(describe),
                                // The newest one from this key: a peer who started again
                                // only keeps the session of the last.
                                Screen::HandleInitMsg => match state
                                    .introductions
                                    .iter()
                                    .rposition(|i| i.identity_key == identity_key)
                                {
                                    // Accepting fails for good or not at all, so remove it.
                                    Some(index) => state
                                        .client
                                        .accept(
                                            &identity_key,
                                            &state.introductions.remove(index),
                                            mailbox,
                                        )
                                        .map_err(describe),
                                    None => Err("No init message from this key, list them first"
                                        .to_string()),
                                },
                                _ => unreachable!(),
                            };
                            match session {
                                Ok(session) => {
                                    state.sessions.write().insert(
                                        identity_key,
                                        Arc::new(tokio::sync::Mutex::new(session)),
                                    );
                                    // A new session with a known contact replaces its old one.
                                    state.current_activated_contact = match state
                                        .contacts
                                        .iter()
                                        .position(|(_, key)| *key == identity_key)
                                    {
                                        Some(index) => index,
                                        None => {
                                            state.contacts.push((name, identity_key));
                                            state.contacts.len() - 1
                                        }
                                    };
                                    state.screen = Screen::Main;
                                }
                                Err(e) => state.screen = Screen::Hint(e),
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
                Screen::ListInitMsg => match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Esc => state.screen = Screen::Main,
                        KeyCode::Tab | KeyCode::Down => {
                            state.current_selected_introduction += 1;
                            state.current_selected_introduction %= state.introductions.len();
                        }
                        KeyCode::BackTab | KeyCode::Up => {
                            state.current_selected_introduction += state.introductions.len() - 1;
                            state.current_selected_introduction %= state.introductions.len();
                        }
                        KeyCode::Enter => {
                            state.textareas = vec![
                                ("Name".to_string(), TextArea::default()),
                                (
                                    "Public IndentityKey (Alice)".to_string(),
                                    TextArea::new(vec![
                                        BASE64_STANDARD.encode(
                                            state.introductions
                                                [state.current_selected_introduction]
                                                .identity_key,
                                        ),
                                    ]),
                                ),
                            ];
                            state.current_activated_textarea = 0;
                            state.screen = Screen::HandleInitMsg;
                        }
                        _ => {}
                    },
                    _ => {}
                },
                Screen::SelectFile => match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Esc => state.screen = Screen::Main,
                        KeyCode::Up => {
                            state.explore_state.selected =
                                state.explore_state.selected.saturating_sub(1);
                        }
                        KeyCode::Down => {
                            state.explore_state.selected = (state.explore_state.selected + 1)
                                .min(state.explore_state.paths.len().saturating_sub(1));
                        }
                        KeyCode::Right => state.explore_state.forward(),
                        KeyCode::Left => state.explore_state.back(),
                        KeyCode::Enter => {
                            if let Some(content) = state.explore_state.message() {
                                let _ = self.send(&mut state, content).await;
                                state.screen = Screen::Main;
                            }
                        }
                        _ => {
                            state.explore_state.input(key);
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
                            if let Some(len) = state
                                .contacts
                                .get(state.current_activated_contact)
                                .and_then(|c| state.conversations.read().get(&c.1).map(|m| m.len()))
                            {
                                state.current_activated_message = len.saturating_sub(1);
                            }
                        }
                        KeyCode::Down if state.navi.current == Navigation::Contacts => {
                            state.current_activated_contact =
                                (state.contacts.len().saturating_sub(1))
                                    .min(state.current_activated_contact + 1);
                            if let Some(len) = state
                                .contacts
                                .get(state.current_activated_contact)
                                .and_then(|c| state.conversations.read().get(&c.1).map(|m| m.len()))
                            {
                                state.current_activated_message = len.saturating_sub(1);
                            }
                        }
                        KeyCode::Enter if state.navi.current != Navigation::Input => {
                            state.navi.down();
                        }
                        KeyCode::Up if state.navi.current == Navigation::Conversation => {
                            state.current_activated_message =
                                state.current_activated_message.saturating_sub(1);
                        }
                        KeyCode::Down if state.navi.current == Navigation::Conversation => {
                            if let Some(len) = state
                                .contacts
                                .get(state.current_activated_contact)
                                .and_then(|c| state.conversations.read().get(&c.1).map(|m| m.len()))
                            {
                                state.current_activated_message = (len.saturating_sub(1))
                                    .min(state.current_activated_message + 1);
                            }
                        }
                        KeyCode::Char('s')
                            if key.modifiers == CONTROL
                                && state.navi.current == Navigation::Input =>
                        {
                            let content = state.chat_textarea.lines().join("\n");
                            if content.trim().is_empty() {
                                continue;
                            }
                            let content = MessageContent::Text(content);
                            if self.send(&mut state, content).await {
                                let mut textarea = TextArea::default();
                                textarea.set_line_number_style(Style::default().gray());
                                state.chat_textarea = textarea;
                            }
                        }
                        KeyCode::Char('e')
                            if key.modifiers == CONTROL
                                && state.navi.current == Navigation::Input =>
                        {
                            state.screen = Screen::SelectFile;
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

    /// true: tried sending
    /// false: did not send at all
    #[must_use = "Clean textarea according to the result."]
    async fn send(&mut self, state: &mut AppState, content: MessageContent) -> bool {
        let Some(&(_, key)) = state.contacts.get(state.current_activated_contact) else {
            return false;
        };
        // A statement of its own, so the map's lock is released before the `await`.
        let Some(session) = state.sessions.read().get(&key).cloned() else {
            return false;
        };
        let message = Message {
            state: match session.lock().await.send(&content.to_bytes()).await {
                Ok(_) => MessageState::Sent,
                Err(e) => MessageState::Error(describe(e)),
            },
            content,
        };
        state
            .conversations
            .write()
            .entry(key)
            .or_default()
            .push(message);
        state.current_activated_message = state.conversations.read()[&key].len().saturating_sub(1);
        true
    }
}

/// An error and its sources, e.g. "server error: status: Unavailable, ...", since an error's
/// kind alone rarely says what to do.
fn describe(error: session::Error) -> String {
    format!("{:#}", anyhow::Error::new(error))
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
