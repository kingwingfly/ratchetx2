use std::{
    collections::HashMap,
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
use parking_lot::RwLock;
use ratatui::{Terminal, prelude::*};
use session::{
    ErrorKind, InitialMessage, Session,
    attachment::{self, KEY_LENGTH},
    protocol::attachment::ID_LENGTH,
};
use tokio::sync::Mutex as AsyncMutex;
use tui_textarea::TextArea;

use crate::{
    message::{
        AttachmentPointer, Chat, Content, Events, Kind, Message, MessageState, greeting, stamp,
    },
    navi::Navigation,
    save,
    screen::Screen,
    transport::{Connect, Http},
    widget::{
        app::{App, AppState, PublicKey, SharedSession},
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
        let (client, initial_messages, http) = (
            state.client.clone(),
            state.initial_messages.clone(),
            state.http.clone(),
        );
        tokio::spawn(async move {
            let mut sync = true;
            loop {
                tokio::select! {
                    _ = async {
                        // A known contact's new session joins its chat first, see `take`; if
                        // taking fails, what does not decrypt meanwhile waits, see below.
                        let _ = take(&client, &sessions, &conversations, &initial_messages, &http)
                            .await;
                        let chats: Vec<_> = sessions
                            .read()
                            .iter()
                            .map(|(key, session)| (*key, session.clone()))
                            .collect();
                        for (key, session) in chats {
                            // Lock the session for one page at a time, so sending to this peer
                            // waits for one fetch at most.
                            loop {
                                let (page, mine_first, deleted) = {
                                    let mut session = session.lock().await;
                                    // Each content decoded once, as it may be an image.
                                    let page = session.receive().await.map(|page| {
                                        page.into_iter()
                                            .map(|received| {
                                                let content = received
                                                    .content
                                                    .map(|content| Content::from_bytes(&content));
                                                (content, received.earlier, received.initial_messages)
                                            })
                                            .collect::<Vec<_>>()
                                    });
                                    // The peer deleted the chat, and its sessions: the next
                                    // message goes on a new one. Under the same lock, so that no
                                    // session joined meanwhile is retired. Unless it said so on
                                    // an earlier session: then it started the chat again since,
                                    // on the active one.
                                    let deletions: Vec<_> = page
                                        .iter()
                                        .flatten()
                                        .filter(|(content, ..)| {
                                            matches!(
                                                content,
                                                Ok(Content {
                                                    kind: Some(Kind::Deleted(_)),
                                                    ..
                                                })
                                            )
                                        })
                                        .map(|(_, earlier, _)| *earlier)
                                        .collect();
                                    if deletions.contains(&false) {
                                        session.retire();
                                    }
                                    let deleted = !deletions.is_empty();
                                    (page, session.me() < session.peer(), deleted)
                                };
                                let Ok(page) = page else { break };
                                if page.is_empty() {
                                    break;
                                }
                                // Where it stopped, with the initial messages that came with the
                                // rest of the page.
                                let stalled = page
                                    .last()
                                    .filter(|(content, ..)| {
                                        content
                                            .as_ref()
                                            .is_err_and(|e| e.kind() == ErrorKind::Stalled)
                                    })
                                    .map(|(.., initial_messages)| initial_messages.clone());
                                for (content, ..) in page {
                                    if let Ok(content) = content {
                                        conversations
                                            .write()
                                            .entry(key)
                                            .or_default()
                                            .receive(content, mine_first);
                                    }
                                }
                                // What the peer never read goes again, on a new session, or on
                                // the one it started again.
                                if deleted {
                                    resend(&client, &session, &conversations, &key).await;
                                }
                                // Stopped at a message that may be on a session whose initial
                                // message came since they were taken, or with the page, as the
                                // one in the inbox was lost: once they are taken, and those are
                                // accepted, receiving goes on, past what still does not decrypt.
                                if let Some(offered) = stalled {
                                    if take(
                                        &client,
                                        &sessions,
                                        &conversations,
                                        &initial_messages,
                                        &http,
                                    )
                                    .await
                                    .is_err()
                                    {
                                        break;
                                    }
                                    for initial_message in &offered {
                                        let chats = &conversations;
                                        join(&client, &session, chats, initial_message, &http)
                                            .await;
                                    }
                                    session.lock().await.skip_stalled();
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
            tell_read(&state).await;
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
                            state.screen = match state
                                .client
                                .lock()
                                .await
                                .publish_keys(ONE_TIME_PREKEYS)
                                .await
                            {
                                Ok(_) => Screen::Hint("Keys published".to_string()),
                                Err(err) => Screen::Hint(describe(err)),
                            };
                        }
                        KeyCode::Char('r') => {
                            let client = session::Client::new(state.http.connect());
                            state.identity_key = client.identity_key();
                            *state.client.lock().await = client;
                            // They were sent to the old identity, whose prekeys are gone.
                            state.initial_messages.write().clear();
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
                        KeyCode::Char('i') => {
                            let mut password = TextArea::default();
                            password.set_mask_char('•');
                            state.textareas = vec![("Server Password".to_string(), password)];
                            state.current_activated_textarea = 0;
                            state.screen = Screen::SignIn;
                        }
                        KeyCode::Char('l') => match take(
                            &state.client,
                            &state.sessions,
                            &state.conversations,
                            &state.initial_messages,
                            &state.http,
                        )
                        .await
                        {
                            Ok(()) => {
                                state.screen = if state.initial_messages.read().is_empty() {
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
                                Screen::PushInitMsg => {
                                    let clock = state
                                        .conversations
                                        .write()
                                        .entry(identity_key)
                                        .or_default()
                                        .tick();
                                    state
                                        .client
                                        .lock()
                                        .await
                                        .initiate(&identity_key, &greeting(clock), mailbox)
                                        .await
                                        .map_err(describe)
                                }
                                Screen::HandleInitMsg => {
                                    match newest_waiting(&state.initial_messages, &identity_key) {
                                        // Accepting fails for good, e.g. as the first message does
                                        // not decrypt, or not at all, so it is removed.
                                        Some(initial_message) => match state
                                            .client
                                            .lock()
                                            .await
                                            .accept(&identity_key, &initial_message, mailbox)
                                        {
                                            Ok((session, first)) => {
                                                let mine_first = state.identity_key < identity_key;
                                                state
                                                    .conversations
                                                    .write()
                                                    .entry(identity_key)
                                                    .or_default()
                                                    .receive(
                                                        Content::from_bytes(&first),
                                                        mine_first,
                                                    );
                                                Ok(session)
                                            }
                                            Err(e) => Err(describe(e)),
                                        },
                                        None => {
                                            Err("No init message from this key, list them first"
                                                .to_string())
                                        }
                                    }
                                }
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
                Screen::SignIn => match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Esc => state.screen = Screen::Main,
                        KeyCode::Enter => {
                            let password = state.textareas[0].1.lines().join("\n");
                            state.textareas = vec![];
                            state.screen =
                                Screen::Hint(match state.http.sign_in(&password).await {
                                    Ok(()) => {
                                        "Signed in: publish your keys (p), then chat".to_string()
                                    }
                                    Err(e) => format!("{e:#}"),
                                });
                        }
                        _ => {
                            state.textareas[0].1.input(key);
                        }
                    },
                    _ => {}
                },
                Screen::ListInitMsg => match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Esc => state.screen = Screen::Main,
                        KeyCode::Tab | KeyCode::Down => {
                            state.current_selected_initial_message += 1;
                            state.current_selected_initial_message %=
                                state.initial_messages.read().len();
                        }
                        KeyCode::BackTab | KeyCode::Up => {
                            let waiting = state.initial_messages.read().len();
                            state.current_selected_initial_message += waiting - 1;
                            state.current_selected_initial_message %= waiting;
                        }
                        KeyCode::Enter => {
                            state.textareas = vec![
                                ("Name".to_string(), TextArea::default()),
                                (
                                    "Public IndentityKey (Alice)".to_string(),
                                    TextArea::new(vec![
                                        BASE64_STANDARD.encode(
                                            state.initial_messages.read()
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
                                .and_then(|c| {
                                    state
                                        .conversations
                                        .read()
                                        .get(&c.1)
                                        .map(|chat| chat.messages.len())
                                })
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
                                .and_then(|c| {
                                    state
                                        .conversations
                                        .read()
                                        .get(&c.1)
                                        .map(|chat| chat.messages.len())
                                })
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
                                .and_then(|c| {
                                    state
                                        .conversations
                                        .read()
                                        .get(&c.1)
                                        .map(|chat| chat.messages.len())
                                })
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
    /// downloaded now, and only now, chunk by chunk, showing how far it got; then, if it is the
    /// peer's, the peer is told. Returns where it went.
    async fn save(&mut self, state: &AppState) -> Result<PathBuf> {
        let &(_, key) = state
            .contacts
            .get(state.current_activated_contact)
            .context("No chat open")?;
        let content = {
            let conversations = state.conversations.read();
            let message = conversations
                .get(&key)
                .and_then(|chat| chat.messages.get(state.current_activated_message))
                .context("No message selected")?;
            // The clock the peer named it by, to tell it once downloaded.
            let clock = match message.state {
                MessageState::Received { .. } => message.clock,
                _ => 0,
            };
            match &message.content {
                Kind::Text(_) | Kind::Hello(_) | Kind::Deleted(_) => {
                    bail!("Only files and images can be saved")
                }
                Kind::Image(data) => {
                    let extension = image::guess_format(data)
                        .ok()
                        .and_then(|format| format.extensions_str().first().copied())
                        .unwrap_or("img");
                    Ok((format!("image.{extension}"), data.clone()))
                }
                Kind::File(file) => Ok((file.name.clone(), file.data.clone())),
                Kind::Attachment(pointer) => Err((pointer.clone(), clock)),
            }
        };
        match content {
            Ok((name, data)) => save::bytes(&state.downloads, &name, &data)
                .with_context(|| format!("Cannot save {name}")),
            Err((pointer, clock)) => {
                let path = self.download(state, &pointer).await?;
                // A statement of its own, so the map's lock is released before the `await`.
                let session = state.sessions.read().get(&key).cloned();
                if clock > 0
                    && let Some(session) = session
                {
                    let events = Events {
                        read: vec![],
                        downloaded: vec![clock],
                    };
                    tell(&session, &state.conversations, &key, events).await;
                }
                Ok(path)
            }
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
        // The client first, then the session, as `take` locks them.
        let mut client = state.client.lock().await;
        let chats = &state.conversations;
        let sent = send_on(&mut client, &mut *session.lock().await, chats, &content).await;
        drop(client);
        let (state_of, place) = match sent {
            Ok(clock) => (MessageState::Sent, clock),
            Err(e) if e.kind() == ErrorKind::SignInRequired => (
                MessageState::Error(format!("{SIGN_IN_FIRST}, and send it again")),
                0,
            ),
            Err(e) => (MessageState::Error(describe(e)), 0),
        };
        let message = Message {
            state: state_of,
            content,
            place,
            clock: place,
        };
        let mine_first = state.identity_key < key;
        let mut conversations = state.conversations.write();
        let chat = conversations.entry(key).or_default();
        chat.insert(message, mine_first);
        state.current_activated_message = chat.messages.len().saturating_sub(1);
        true
    }
}

/// Send `content` on `session`, at the next place of its chat in `chats`; if it has none to send
/// on, as the two kept missing each other or the peer deleted the chat, a new session starts
/// first, greeting the peer, and the content goes on it. Returns its place.
async fn send_on(
    client: &mut session::Client<Connect>,
    session: &mut Session<Connect>,
    chats: &RwLock<HashMap<PublicKey, Chat>>,
    content: &Kind,
) -> session::Result<u64> {
    let peer = *session.peer();
    let tick = || chats.write().entry(peer).or_default().tick();
    if session.needs_new_session() {
        client.start_again(session, &greeting(tick())).await?;
    }
    let clock = tick();
    let mut bytes = content.to_bytes();
    stamp(&mut bytes, clock);
    session.send(&bytes).await?;
    Ok(clock)
}

/// Send again, on a new session, this client's messages to `peer` that the peer never read, as
/// it deleted the chat: each at a new place, as in a new chat.
async fn resend(
    client: &AsyncMutex<session::Client<Connect>>,
    session: &SharedSession,
    chats: &RwLock<HashMap<PublicKey, Chat>>,
    peer: &PublicKey,
) {
    let unread: Vec<_> = {
        let mut chats = chats.write();
        let Some(chat) = chats.get_mut(peer) else {
            return;
        };
        let (unread, others) = std::mem::take(&mut chat.messages)
            .into_iter()
            .partition(|message| matches!(message.state, MessageState::Sent));
        chat.messages = others;
        unread
    };
    // The client first, then the session, as `take` locks them.
    let mut client = client.lock().await;
    let mut session = session.lock().await;
    let mine_first = session.me() < session.peer();
    for mut message in unread {
        let sent = send_on(&mut client, &mut session, chats, &message.content).await;
        (message.state, message.place) = match sent {
            Ok(clock) => (MessageState::Sent, clock),
            Err(e) => (MessageState::Error(describe(e)), 0),
        };
        message.clock = message.place;
        chats
            .write()
            .entry(*peer)
            .or_default()
            .insert(message, mine_first);
    }
}

/// Tell the peer of the open chat which of its messages are read, as they show now.
async fn tell_read(state: &AppState) {
    let Some(&(_, key)) = state.contacts.get(state.current_activated_contact) else {
        return;
    };
    let Some(session) = state.sessions.read().get(&key).cloned() else {
        return;
    };
    let read = match state.conversations.write().get_mut(&key) {
        Some(chat) => chat.read(),
        None => return,
    };
    if !read.is_empty() {
        let events = Events {
            read,
            downloaded: vec![],
        };
        tell(&session, &state.conversations, &key, events).await;
    }
}

/// Tell `events` of the chat in `chats` with `peer` on `session`, in one message, never starting
/// a new session for them. Reads that cannot go are told again later.
async fn tell(
    session: &SharedSession,
    chats: &RwLock<HashMap<PublicKey, Chat>>,
    peer: &PublicKey,
    events: Events,
) {
    let mut session = session.lock().await;
    let told = !session.needs_new_session() && session.send(&events.to_bytes()).await.is_ok();
    if !told && let Some(chat) = chats.write().get_mut(peer) {
        chat.untold(&events.read);
    }
}

/// The newest of the initial messages from `peer` that wait, taken from them: a peer who
/// started again only keeps the session of the last.
fn newest_waiting(
    waiting: &RwLock<Vec<InitialMessage>>,
    peer: &PublicKey,
) -> Option<InitialMessage> {
    let mut waiting = waiting.write();
    let index = waiting
        .iter()
        .rposition(|initial_message| initial_message.x3dh.identity_key == *peer)?;
    Some(waiting.remove(index))
}

/// Accept `initial_message`, of the peer of `session`, which came with one of its messages
/// rather than through the inbox, where it was lost: its session joins `session`, the chat so
/// far, and its greeting moves the chat's clock in `chats`. One accepted already, or not from
/// the peer, changes nothing.
async fn join(
    client: &AsyncMutex<session::Client<Connect>>,
    session: &SharedSession,
    chats: &RwLock<HashMap<PublicKey, Chat>>,
    initial_message: &InitialMessage,
    http: &Http,
) {
    // The client first, then the session, as `take` locks them.
    let mut client = client.lock().await;
    let mut session = session.lock().await;
    let peer = *session.peer();
    if let Ok((accepted, greeting)) = client.accept(&peer, initial_message, http.connect()) {
        let older = std::mem::replace(&mut *session, accepted);
        let _ = session.keep(older);
        let mine_first = session.me() < session.peer();
        chats
            .write()
            .entry(peer)
            .or_default()
            .receive(Content::from_bytes(&greeting), mine_first);
    }
}

/// Take the initial messages waiting. A known contact's session joins its chat at once, as the
/// messages on it only decrypt once it has, and receiving would skip them for good; so nothing
/// is received until this succeeds. Its greeting moves the chat's clock in `chats`. A new peer's
/// waits for the user to accept it.
async fn take(
    client: &AsyncMutex<session::Client<Connect>>,
    sessions: &RwLock<HashMap<PublicKey, SharedSession>>,
    chats: &RwLock<HashMap<PublicKey, Chat>>,
    waiting: &RwLock<Vec<InitialMessage>>,
    http: &Http,
) -> session::Result<()> {
    let mut client = client.lock().await;
    // The server deleted them all: one that cannot join its chat must not lose the others.
    let mut failure = None;
    for initial_message in client.take_initial_messages().await? {
        let peer = initial_message.x3dh.identity_key;
        let known = sessions.read().get(&peer).cloned();
        let Some(known) = known else {
            waiting.write().push(initial_message);
            continue;
        };
        // One whose first message does not decrypt is not from whom it claims: dropped.
        if let Ok((session, greeting)) = client.accept(&peer, &initial_message, http.connect()) {
            let mut known = known.lock().await;
            let older = std::mem::replace(&mut *known, session);
            if let Err(e) = known.keep(older) {
                failure.get_or_insert(e);
            }
            let mine_first = known.me() < known.peer();
            chats
                .write()
                .entry(peer)
                .or_default()
                .receive(Content::from_bytes(&greeting), mine_first);
        }
    }
    failure.map_or(Ok(()), Err)
}

/// An error and its sources, e.g. "server error: status: Unavailable, ...", since an error's
/// kind alone rarely says what to do.
fn describe(error: session::Error) -> String {
    if error.kind() == ErrorKind::SignInRequired {
        return SIGN_IN_FIRST.to_string();
    }
    format!("{:#}", anyhow::Error::new(error))
}

/// What a call the server refused for the sign-in tells.
const SIGN_IN_FIRST: &str =
    "The server is only for those signed in to it: sign in from the settings (Tab, then i)";

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
