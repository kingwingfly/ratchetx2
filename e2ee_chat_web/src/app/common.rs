use std::time::Duration;

use leptos::{ev, html, prelude::*, task::spawn_local};
use session::PublicKey;
use web_sys::{FileList, HtmlInputElement};
use zeroize::Zeroizing;

use crate::{
    content,
    engine::{Sending, build_invitation_link, invitation, origin},
    glue::copy,
    icon::{Icon, icon},
    state::{ClassicalPrompt, Dialog, Me, ServerPqStatus, Ui},
    util::sleep,
};

use super::{engine, ui};

pub(super) fn strict_pq_enabled(ui: Ui) -> bool {
    ui.me
        .with(|me| me.as_ref().is_some_and(|me| me.pq_config.strict_pq))
}

pub(super) fn can_allow_classical(prompt: ClassicalPrompt, strict_pq: bool) -> bool {
    !strict_pq && prompt != ClassicalPrompt::None
}

pub(super) fn pq_available(ui: Ui) -> bool {
    ui.me.with(|me| {
        me.as_ref()
            .is_some_and(|me| me.pq_config.pq_enabled && !me.pq_config.offered_suites().is_empty())
    })
}

pub(super) fn server_pq_disabled(ui: Ui) -> bool {
    ui.me.with(|me| {
        me.as_ref()
            .is_some_and(|me| me.server_pq == ServerPqStatus::Disabled)
    })
}

pub(super) fn pq_retry_ready(ui: Ui) -> bool {
    pq_available(ui) && !server_pq_disabled(ui)
}

pub(super) fn upgrade_disabled_tip(ui: Ui) -> Option<&'static str> {
    server_pq_disabled(ui).then_some("This server does not have post-quantum encryption enabled.")
}

#[component]
pub(super) fn AllowClassical(peer: PublicKey, busy: RwSignal<bool>) -> impl IntoView {
    view! {
        <button
            type="button"
            class="btn small"
            disabled=move || busy.get()
            on:click=move |_| act_while(busy, async move { engine().approve_classical(peer).await })
        >
            "Allow classical"
        </button>
    }
}

/// An avatar's letters: the initials of a name.
pub(super) fn initials(label: &str) -> String {
    label
        .split_whitespace()
        .take(2)
        .filter_map(|word| word.chars().next())
        .collect()
}

/// A file's extension, lowercase, for its card; `file` if it has none.
pub(super) fn extension(name: &str) -> String {
    name.rsplit_once('.')
        .map_or("file".to_string(), |(_, extension)| {
            extension.to_lowercase()
        })
}

/// Run `action`, telling what went wrong.
pub(super) fn act(action: impl Future<Output = Result<(), String>> + 'static) {
    let ui = ui();
    spawn_local(async move {
        if let Err(e) = action.await {
            ui.notify(e);
        }
    });
}

/// Run `action` as [`act`] does, unless `busy` says one runs already, which it says meanwhile:
/// the buttons it disables, pressed again, start nothing twice.
pub(super) fn act_while(
    busy: RwSignal<bool>,
    action: impl Future<Output = Result<(), String>> + 'static,
) {
    if busy.get_untracked() {
        return;
    }
    busy.set(true);
    act(async move {
        let done = action.await;
        busy.try_set(false);
        done
    });
}

pub(super) fn open_chat(peer: Option<PublicKey>) {
    let engine = engine();
    spawn_local(async move { engine.open(peer).await });
}

pub(super) fn new_chat() {
    ui().dialog.set(Some(Dialog::NewChat {
        key: String::new(),
        name: String::new(),
        server: None,
        pq_pinned: false,
    }));
}

/// Lock the vault: the page starts over, keeping nothing in memory.
pub(super) fn lock() {
    let _ = window().location().reload();
}

/// How long a copy button shows that it copied, in milliseconds.
const COPIED_SHOWN: i32 = 1_500;

/// `text` in a box, with a button beside it that copies it, `what` it is, e.g. "your key": a
/// tick shows for a moment once it did, and a notice says if the browser would not.
#[component]
pub(super) fn Copyable(text: String, what: &'static str) -> impl IntoView {
    let copied = RwSignal::new(false);
    let value = text.clone();
    let on_click = move |_| {
        let text = value.clone();
        spawn_local(async move {
            if !copy(&text).await {
                ui().notify(format!(
                    "The browser would not copy {what}; select it and copy it instead."
                ));
                return;
            }
            copied.set(true);
            sleep(COPIED_SHOWN).await;
            copied.try_set(false);
        });
    };
    let label = move || {
        if copied.get() {
            "Copied".to_string()
        } else {
            format!("Copy {what}")
        }
    };
    view! {
        <div class="copyable">
            <div class="key">{text}</div>
            <button
                type="button"
                class="btn icon"
                class:done=move || copied.get()
                title=label
                aria-label=label
                on:click=on_click
            >
                {move || icon(if copied.get() { Icon::Tick } else { Icon::Copy })}
            </button>
        </div>
    }
}

/// A link that opens a chat with `me`, with the name filled in, the server if it is not the
/// page's own, and `&pq=1` when post-quantum encryption is enabled.
pub(super) fn invitation_link(me: &Me) -> String {
    build_invitation_link(&origin(), me)
}

/// The server an invitation link in the page's address names, to create the vault on.
pub(super) fn invited_server() -> Option<String> {
    match invitation()? {
        Dialog::NewChat { server, .. } => server,
        _ => None,
    }
}

/// Send `content` to `peer`, after what was sent before it.
pub(super) fn send(peer: PublicKey, content: content::Kind) {
    engine().queue(Sending::Content(peer, content));
}

/// Send `files` to the open chat, in their order, after what was sent before them: the small
/// ones in their messages, the others as attachments.
pub(super) fn send_files(files: FileList) {
    let Some(peer) = ui().open.get_untracked() else {
        return;
    };
    let engine = engine();
    for file in (0..files.length()).filter_map(|i| files.get(i)) {
        engine.queue(Sending::File(peer, file));
    }
}

/// Closes the page's dialog.
pub(super) fn close_dialog() {
    ui().dialog.set(None);
}

/// Keeps the password in the DOM until submission. Cache the element so cleanup can clear it
/// even after the node reference is detached.
#[derive(Clone, Copy)]
pub(super) struct SecretInput {
    pub(super) node: NodeRef<html::Input>,
    mounted: StoredValue<Option<HtmlInputElement>, LocalStorage>,
}

impl SecretInput {
    pub(super) fn new() -> Self {
        let node = NodeRef::<html::Input>::new();
        let mounted = StoredValue::new_local(None);
        Effect::new(move || {
            if let Some(input) = node.get() {
                // Native autofocus only runs when the shared dialog first opens.
                if input.has_attribute("autofocus") {
                    let _ = input.focus();
                }
                mounted.set_value(Some(input));
            }
        });
        Self { node, mounted }
    }

    fn element(&self) -> Option<HtmlInputElement> {
        self.mounted
            .try_get_value()
            .flatten()
            .or_else(|| self.node.try_get_untracked().flatten())
    }

    pub(super) fn take(&self) -> Zeroizing<String> {
        let Some(input) = self.element() else {
            return Zeroizing::default();
        };
        let secret = Zeroizing::new(input.value());
        input.set_value("");
        secret
    }

    pub(super) fn clear(&self) {
        if let Some(input) = self.element() {
            input.set_value("");
        }
    }

    pub(super) fn focus(&self) {
        if let Some(input) = self.element() {
            let _ = input.focus();
        }
    }
}

/// A form's error line, or what it is busy with.
#[derive(Clone, Copy)]
pub(super) struct Progress {
    message: RwSignal<String>,
    pub(super) working: RwSignal<bool>,
}

impl Progress {
    pub(super) fn new() -> Self {
        Self {
            message: RwSignal::new(String::new()),
            working: RwSignal::new(false),
        }
    }

    pub(super) fn start(&self, message: &str) {
        self.working.set(true);
        self.message.set(message.to_string());
    }

    pub(super) fn try_start(&self, message: &str) {
        let _ = self.working.try_set(true);
        let _ = self.message.try_set(message.to_string());
    }

    pub(super) fn fail(&self, error: impl Into<String>) {
        self.working.set(false);
        self.message.set(error.into());
    }

    pub(super) fn try_fail(&self, error: impl Into<String>) {
        let _ = self.working.try_set(false);
        let _ = self.message.try_set(error.into());
    }

    pub(super) fn clear(&self) {
        let _ = self.working.try_set(false);
        let _ = self.message.try_set(String::new());
    }

    pub(super) fn view(self) -> impl IntoView {
        view! {
            <p class="error" class:working=move || self.working.get() role="alert">
                {move || self.message.get()}
            </p>
        }
    }
}

/// Accessible custom CSS pill toggle switch row.
#[component]
pub(super) fn ToggleSwitch(
    id: &'static str,
    title: &'static str,
    description: &'static str,
    checked: Signal<bool>,
    disabled: Signal<bool>,
    on_toggle: impl Fn(bool) + 'static,
) -> impl IntoView {
    view! {
        <label class="switch-row" class:disabled=move || disabled.get() for=id>
            <span class="switch-copy">
                <strong>{title}</strong>
                <small>{description}</small>
            </span>
            <span class="switch">
                <input
                    id=id
                    type="checkbox"
                    role="switch"
                    disabled=move || disabled.get()
                    prop:checked=move || checked.get()
                    on:change=move |ev: ev::Event| {
                        on_toggle(event_target_checked(&ev));
                    }
                />
                <span class="switch-track" aria-hidden="true">
                    <span class="switch-thumb"></span>
                </span>
            </span>
        </label>
    }
}

/// How long a button that asks to be pressed again, to be sure, waits for it.
pub(super) const ASKED_SHOWN: Duration = Duration::from_secs(6);

#[cfg(test)]
mod tests {
    use super::{ClassicalPrompt, can_allow_classical};

    #[test]
    fn classical_approval_requires_a_prompt_and_strict_mode_off() {
        for flag in [false, true] {
            for prompt in [
                ClassicalPrompt::InboundQuarantined {
                    peer_was_pq_pinned: flag,
                },
                ClassicalPrompt::Outbound {
                    peer_signed_off: flag,
                },
            ] {
                assert!(!can_allow_classical(prompt, true));
                assert!(can_allow_classical(prompt, false));
            }
        }
        assert!(!can_allow_classical(ClassicalPrompt::None, false));
        assert!(!can_allow_classical(ClassicalPrompt::None, true));
    }
}
