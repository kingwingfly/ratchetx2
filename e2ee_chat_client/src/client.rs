use std::{
    fs,
    io::{Stderr, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
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
use session::{
    ErrorKind, Session,
    attachment::{self, KEY_LENGTH},
    protocol::attachment::ID_LENGTH,
};
use tui_textarea::TextArea;

use crate::{
    message::{self, AttachmentPointer, Kind, Message, MessageState, greeting},
    navi::Navigation,
    save,
    screen::Screen,
    transport::{Connect, Http},
    widget::{
        app::{App, AppState, PublicKey},
        connecting::Connecting,
        hint::Hint,
        pop_up::PopUp,
    },
};

const CONTROL: KeyModifiers = KeyModifiers::CONTROL;
/// How long to wait before asking for a chunk not uploaded yet, doubling up to the second...
const POLL_CHUNK_MIN: Duration = Duration::from_millis(500);
const POLL_CHUNK_MAX: Duration = Duration::from_secs(4);
/// ... until none came for this long, as the sender may have stopped.
const STALLED: Duration = Duration::from_secs(60);
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

    pub async fn run(&mut self, server_addr: String, downloads: PathBuf) -> Result<()> {
        self.terminal.draw(|f| {
            f.render_widget(
                PopUp {
                    inner: Connecting {
                        server_addr: server_addr.clone(),
                    },
                },
                f.area(),
            )
        })?;
        let mut state = match AppState::connect(&server_addr, downloads).await {
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
                                    if let Some(content) = message::shown(&message) {
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
                            state.client = session::Client::new(state.http.connect());
                            // They were sent to the old identity, whose prekeys are gone.
                            state.initial_messages.clear();
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
                        KeyCode::Char('l') => match state.client.take_initial_messages().await {
                            // Taken initial messages are gone from the server, so keep them
                            // until accepted.
                            Ok(initial_messages) => {
                                state.initial_messages.extend(initial_messages);
                                state.screen = if state.initial_messages.is_empty() {
                                    Screen::Hint("No init message.".to_string())
                                } else {
                                    state.current_selected_initial_message = 0;
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
                            let mailbox = state.http.connect();
                            let session = match &state.screen {
                                // The greeting, the session's first message, shows the peer
                                // that the initial message is this client's, and lets the peer
                                // write back.
                                Screen::PushInitMsg => state
                                    .client
                                    .initiate(&identity_key, &greeting(), mailbox)
                                    .await
                                    .map_err(describe),
                                // The newest one from this key: a peer who started again
                                // only keeps the session of the last.
                                Screen::HandleInitMsg => match state
                                    .initial_messages
                                    .iter()
                                    .rposition(|i| i.x3dh.identity_key == identity_key)
                                {
                                    // Accepting fails for good, e.g. as the first message does
                                    // not decrypt, or not at all, so remove it.
                                    Some(index) => match state.client.accept(
                                        &identity_key,
                                        &state.initial_messages.remove(index),
                                        mailbox,
                                    ) {
                                        Ok((session, first)) => {
                                            if let Some(content) = message::shown(&first) {
                                                state
                                                    .conversations
                                                    .write()
                                                    .entry(identity_key)
                                                    .or_default()
                                                    .push(Message {
                                                        content,
                                                        state: MessageState::Received,
                                                    });
                                            }
                                            Ok(session)
                                        }
                                        Err(e) => Err(describe(e)),
                                    },
                                    None => Err("No init message from this key, list them first"
                                        .to_string()),
                                },
                                _ => unreachable!(),
                            };
                            match session {
                                Ok(session) => {
                                    // A new session with a known contact joins the old one,
                                    // kept only to decrypt the messages sent on it.
                                    let known = state.sessions.read().get(&identity_key).cloned();
                                    match known {
                                        Some(known) => {
                                            let mut known = known.lock().await;
                                            let old = std::mem::replace(&mut *known, session);
                                            if let Err(e) = known.keep(old) {
                                                state.screen = Screen::Hint(describe(e));
                                                continue;
                                            }
                                        }
                                        None => {
                                            state.sessions.write().insert(
                                                identity_key,
                                                Arc::new(tokio::sync::Mutex::new(session)),
                                            );
                                        }
                                    }
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
                            state.current_selected_initial_message += 1;
                            state.current_selected_initial_message %= state.initial_messages.len();
                        }
                        KeyCode::BackTab | KeyCode::Up => {
                            state.current_selected_initial_message +=
                                state.initial_messages.len() - 1;
                            state.current_selected_initial_message %= state.initial_messages.len();
                        }
                        KeyCode::Enter => {
                            state.textareas = vec![
                                ("Name".to_string(), TextArea::default()),
                                (
                                    "Public IndentityKey (Alice)".to_string(),
                                    TextArea::new(vec![
                                        BASE64_STANDARD.encode(
                                            state.initial_messages
                                                [state.current_selected_initial_message]
                                                .x3dh
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
                        KeyCode::Char('s') if state.navi.current == Navigation::Conversation => {
                            state.screen = Screen::Hint(match self.save(&state).await {
                                Ok(path) => format!("Saved to {}", path.display()),
                                Err(e) => format!("{e:#}"),
                            });
                        }
                        KeyCode::Char('s')
                            if key.modifiers == CONTROL
                                && state.navi.current == Navigation::Input =>
                        {
                            let content = state.chat_textarea.lines().join("\n");
                            if content.trim().is_empty() {
                                continue;
                            }
                            let content = Kind::Text(content);
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

    /// Save the selected message's file or image in the downloads directory. An attachment is
    /// downloaded now, and only now, chunk by chunk, showing how far it got. Returns where it
    /// went.
    async fn save(&mut self, state: &AppState) -> Result<PathBuf> {
        let content = {
            let &(_, key) = state
                .contacts
                .get(state.current_activated_contact)
                .context("No chat open")?;
            let conversations = state.conversations.read();
            let message = conversations
                .get(&key)
                .and_then(|messages| messages.get(state.current_activated_message))
                .context("No message selected")?;
            match &message.content {
                Kind::Text(_) | Kind::Hello(_) => bail!("Only files and images can be saved"),
                Kind::Image(data) => {
                    let extension = image::guess_format(data)
                        .ok()
                        .and_then(|format| format.extensions_str().first().copied())
                        .unwrap_or("img");
                    Ok((format!("image.{extension}"), data.clone()))
                }
                Kind::File(file) => Ok((file.name.clone(), file.data.clone())),
                Kind::Attachment(pointer) => Err(pointer.clone()),
            }
        };
        match content {
            Ok((name, data)) => save::bytes(&state.downloads, &name, &data)
                .with_context(|| format!("Cannot save {name}")),
            Err(pointer) => self.download(state, &pointer).await,
        }
    }

    /// Download the attachment `pointer`, decrypt it, and save it. Its chunks go to a `.part`
    /// file, which takes the file's name once whole.
    async fn download(&mut self, state: &AppState, pointer: &AttachmentPointer) -> Result<PathBuf> {
        let name = &pointer.name;
        let malformed = || anyhow!("{name} is a malformed attachment");
        let id = <[u8; ID_LENGTH]>::try_from(pointer.id.as_slice()).map_err(|_| malformed())?;
        let key = <[u8; KEY_LENGTH]>::try_from(pointer.key.as_slice()).map_err(|_| malformed())?;
        let chunks =
            u32::try_from(attachment::chunk_count(pointer.size)).map_err(|_| malformed())?;
        // The name is taken now, empty, so nothing else saves there meanwhile.
        let (path, _) =
            save::create(&state.downloads, name).with_context(|| format!("Cannot save {name}"))?;
        let part = save::part(&path);
        let downloaded = async {
            let mut file = fs::File::create(&part)?;
            let attachments = state.http.connect();
            let mut size = 0;
            for index in 0..chunks {
                let progress = format!("Saving {name}: {}%", index * 100 / chunks);
                self.show(&progress)?;
                let chunk = self
                    .await_chunk(&attachments, name, &id, index, &progress)
                    .await?;
                let plaintext = attachment::decrypt_chunk(&key, index, index + 1 == chunks, &chunk)
                    .map_err(|_| anyhow!("{name} does not decrypt"))?;
                size += plaintext.len() as u64;
                file.write_all(&plaintext)?;
            }
            if size != pointer.size {
                bail!("{name} is not the size it should be");
            }
            file.sync_all()?;
            fs::rename(&part, &path)?;
            Ok(())
        }
        .await;
        if let Err(e) = downloaded {
            let _ = fs::remove_file(&part);
            let _ = fs::remove_file(&path);
            return Err(e);
        }
        Ok(path)
    }

    /// Chunk `index` of the attachment `id`, named `name`, waiting for it while it is uploaded,
    /// unless none comes for [`STALLED`]. `progress` says how far the saving got.
    async fn await_chunk(
        &mut self,
        attachments: &Connect,
        name: &str,
        id: &[u8; ID_LENGTH],
        index: u32,
        progress: &str,
    ) -> Result<Vec<u8>> {
        let (mut waited, mut wait) = (Duration::ZERO, POLL_CHUNK_MIN);
        loop {
            match attachment::download_chunk(attachments, id, index).await {
                Ok(Some(chunk)) => return Ok(chunk),
                Ok(None) if waited < STALLED => {
                    self.show(&format!("{progress}, as the sender uploads it"))?;
                    tokio::time::sleep(wait).await;
                    waited += wait;
                    wait = (wait * 2).min(POLL_CHUNK_MAX);
                }
                Ok(None) => bail!(
                    "{name} is still being uploaded, but nothing came for a while; save it again \
                     later"
                ),
                Err(e) if e.kind() == ErrorKind::NotFound => bail!(
                    "{name} is no longer on the server: its sender cancelled it, or it expired, as \
                     the server keeps attachments for a while only"
                ),
                Err(e) => bail!(describe(e)),
            }
        }
    }

    /// Show `hint` over the screen, e.g. what is going on.
    fn show(&mut self, hint: &str) -> Result<()> {
        self.terminal.draw(|f| {
            f.render_widget(
                PopUp {
                    inner: Hint {
                        hint: hint.to_string(),
                    },
                },
                f.area(),
            )
        })?;
        Ok(())
    }

    /// true: tried sending
    /// false: did not send at all
    #[must_use = "Clean textarea according to the result."]
    async fn send(&mut self, state: &mut AppState, content: Kind) -> bool {
        let Some(&(_, key)) = state.contacts.get(state.current_activated_contact) else {
            return false;
        };
        // A statement of its own, so the map's lock is released before the `await`.
        let Some(session) = state.sessions.read().get(&key).cloned() else {
            return false;
        };
        let sent = send_on(
            &mut state.client,
            &state.http,
            &mut *session.lock().await,
            &key,
            &content.to_bytes(),
        )
        .await;
        let message = Message {
            state: match sent {
                Ok(()) => MessageState::Sent,
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

/// Send `content` to `peer` on `session`; if it has none to send on, as the two kept missing
/// each other, a new session starts first, greeting the peer, and the content goes on it.
async fn send_on(
    client: &mut session::Client<Connect>,
    http: &Http,
    session: &mut Session<Connect>,
    peer: &PublicKey,
    content: &[u8],
) -> session::Result<()> {
    if session.needs_new_session() {
        let started = client.initiate(peer, &greeting(), http.connect()).await?;
        let older = std::mem::replace(session, started);
        session.keep(older)?;
    }
    session.send(content).await
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
