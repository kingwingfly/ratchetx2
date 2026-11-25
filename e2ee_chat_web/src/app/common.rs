use std::time::Duration;

use leptos::{ev, html, prelude::*, task::spawn_local};
use session::PublicKey;
use web_sys::{FileList, HtmlInputElement};
use zeroize::Zeroizing;

use crate::{
    content,
    engine::{Sending, build_invitation_link, invitation, origin, sanitize_shared_name},
    glue::copy,
    icon::{Icon, icon},
    state::{ClassicalPrompt, ContactView, Dialog, Me, ServerPqStatus, SharedContact, Ui},
    util::{key_to_text, sleep},
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
        .map(|(_, extension)| extension)
        .filter(|extension| !extension.is_empty())
        .map_or_else(|| "file".to_string(), str::to_lowercase)
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
    super::history::navigate(peer);
}

pub(super) fn reserve_chat_history() -> super::history::Reservation {
    super::history::reserve()
}

pub(super) fn is_chat_history_owned(reservation: Option<super::history::Reservation>) -> bool {
    super::history::is_reservation_owned(reservation)
}

pub(super) async fn commit_chat_history(
    reservation: Option<super::history::Reservation>,
    peer: PublicKey,
) {
    super::history::commit_reservation(reservation, peer).await;
}

pub(super) fn cancel_chat_history(reservation: Option<super::history::Reservation>) -> bool {
    super::history::cancel_reservation(reservation)
}

pub(super) fn retain_chat_history(reservation: Option<super::history::Reservation>) -> bool {
    super::history::retain_reservation(reservation)
}

pub(super) fn retain_active_chat_history_reservation() {
    super::history::retain_active_reservation();
}

pub(super) fn cancel_retained_chat_history_reservation() {
    super::history::cancel_retained_reservation();
}

pub(super) fn cancel_active_chat_history_reservation() {
    super::history::cancel_active_reservation();
}

pub(super) fn new_chat() {
    ui().dialog.set(Some(Dialog::NewChat {
        key: String::new(),
        name: String::new(),
        server: None,
        pq_pinned: false,
    }));
}

/// Open `NewChat` pre-filled from a shared contact card so the recipient can review and start.
/// Uses standard base64 (`key_to_text`) so the pre-filled key matches `Identity` and `ContactInfo`
/// verbatim if verified visually.
pub(super) fn open_new_chat_for_shared(card: &SharedContact) {
    ui().dialog.set(Some(Dialog::NewChat {
        key: key_to_text(&card.key),
        name: card.name.clone(),
        server: None,
        pq_pinned: card.pq_pinned,
    }));
}

/// Whether sharing `subject` should pin post-quantum encryption for the recipient.
pub(super) fn shared_contact_pq_pinned(subject: &ContactView, server_pq_disabled: bool) -> bool {
    !server_pq_disabled
        && (subject.pq_pinned
            || subject.peer_pq_capable
            || (subject.has_active_session && subject.security.is_pq))
}

/// Default editable display name when sharing `subject`: local nickname, or their greeting name.
pub(super) fn default_shared_contact_name(subject: &ContactView) -> String {
    let raw = if subject.name.is_empty() {
        &subject.hello_name
    } else {
        &subject.name
    };
    sanitize_shared_name(raw)
}

/// Accepted contacts eligible to be shared to another peer (excluding `exclude`).
pub(super) fn shareable_contacts(contacts: &[ContactView], exclude: PublicKey) -> Vec<ContactView> {
    contacts
        .iter()
        .filter(|contact| !contact.request && contact.peer != exclude)
        .cloned()
        .collect()
}

/// Accepted, unquarantined chats eligible to receive a shared contact (excluding `exclude`).
pub(super) fn writable_recipients(
    contacts: &[ContactView],
    exclude: PublicKey,
) -> Vec<ContactView> {
    contacts
        .iter()
        .filter(|contact| !contact.request && !contact.is_quarantined() && contact.peer != exclude)
        .cloned()
        .collect()
}

/// Lock the vault: the page starts over, keeping nothing in memory.
pub(super) fn lock() {
    let _ = window().location().reload();
}

/// How long a copy button shows that it copied, in milliseconds.
const COPIED_SHOWN: i32 = 1_500;

/// Flash a copied-tick generation signal for [`COPIED_SHOWN`] without panicking if the owning
/// component unmounts while the clipboard promise or timer is pending.
pub(super) async fn flash_copied(copied_gen: RwSignal<u32>) {
    let Some(next) = copied_gen.try_update(|slot| {
        let next = slot.wrapping_add(1).max(1);
        *slot = next;
        next
    }) else {
        return;
    };
    sleep(COPIED_SHOWN).await;
    let _ = copied_gen.try_update(|slot| {
        if *slot == next {
            *slot = 0;
        }
    });
}

/// `text` in a box, with a button beside it that copies it, `what` it is, e.g. "your key": a
/// tick shows for a moment once it did, and a notice says if the browser would not.
#[component]
pub(super) fn Copyable(text: String, what: &'static str) -> impl IntoView {
    let copied_gen = RwSignal::new(0u32);
    let copied = move || copied_gen.get() != 0;
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
            flash_copied(copied_gen).await;
        });
    };
    let label = move || {
        if copied() {
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
                class:done=copied
                title=label
                aria-label=label
                on:click=on_click
            >
                {move || icon(if copied() { Icon::Tick } else { Icon::Copy })}
            </button>
        </div>
    }
}

/// This client's invitation link, with buttons to copy it or open its scannable QR code.
#[component]
pub(super) fn InvitationLink(#[prop(default = false)] from_identity: bool) -> impl IntoView {
    let ui = ui();
    let link = Memo::new(move |_| {
        ui.me
            .with(|me| me.as_ref().map(invitation_link).unwrap_or_default())
    });
    let copied_gen = RwSignal::new(0u32);
    let copied = move || copied_gen.get() != 0;
    let on_copy = move |_| {
        let text = link.get_untracked();
        if text.is_empty() {
            return;
        }
        spawn_local(async move {
            if !copy(&text).await {
                ui.notify(
                    "The browser would not copy your invitation link; select it and copy it instead.",
                );
                return;
            }
            flash_copied(copied_gen).await;
        });
    };
    let copy_label = move || {
        if copied() {
            "Copied".to_string()
        } else {
            "Copy your invitation link".to_string()
        }
    };
    view! {
        <div class="copyable">
            <div class="key">{move || link.get()}</div>
            <div class="copyable-actions">
                <button
                    type="button"
                    class="btn icon"
                    class:done=copied
                    title=copy_label
                    aria-label=copy_label
                    disabled=move || link.with(String::is_empty)
                    on:click=on_copy
                >
                    {move || icon(if copied() { Icon::Tick } else { Icon::Copy })}
                </button>
                <button
                    type="button"
                    class="btn icon"
                    title="Share as QR code"
                    aria-label="Share your invitation link as a QR code"
                    disabled=move || link.with(String::is_empty)
                    on:click=move |_| ui.dialog.set(Some(Dialog::InviteQr { from_identity }))
                >
                    {icon(Icon::QrCode)}
                </button>
            </div>
        </div>
    }
}

/// A peer's identity key, with a button to copy it and (for accepted chats) share it to another chat.
#[component]
pub(super) fn ContactKey(peer: PublicKey, can_share: Signal<bool>) -> impl IntoView {
    let ui = ui();
    let text = key_to_text(&peer);
    let copied_gen = RwSignal::new(0u32);
    let copied = move || copied_gen.get() != 0;
    let value = text.clone();
    let on_copy = move |_| {
        let text = value.clone();
        spawn_local(async move {
            if !copy(&text).await {
                ui.notify("The browser would not copy their key; select it and copy it instead.");
                return;
            }
            flash_copied(copied_gen).await;
        });
    };
    let copy_label = move || {
        if copied() {
            "Copied".to_string()
        } else {
            "Copy their key".to_string()
        }
    };
    view! {
        <div class="copyable">
            <div class="key">{text}</div>
            <div class="copyable-actions">
                <button
                    type="button"
                    class="btn icon"
                    class:done=copied
                    title=copy_label
                    aria-label=copy_label
                    on:click=on_copy
                >
                    {move || icon(if copied() { Icon::Tick } else { Icon::Copy })}
                </button>
                <Show when=move || can_share.get()>
                    <button
                        type="button"
                        class="btn icon"
                        title="Share contact to another chat"
                        aria-label="Share this contact to another chat"
                        on:click=move |_| {
                            ui.dialog.set(Some(Dialog::ShareContact {
                                subject: Some(peer),
                                recipient: None,
                            }));
                        }
                    >
                        {icon(Icon::ShareContact)}
                    </button>
                </Show>
            </div>
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

/// Send `files` to `peer`, in their order, after what was sent before them: the small
/// ones in their messages, the others as attachments.
pub(super) fn send_files_to(peer: PublicKey, files: FileList) {
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
    use crate::state::{ContactView, SecurityAlert, SecurityView};

    use super::{
        ClassicalPrompt, can_allow_classical, default_shared_contact_name, shareable_contacts,
        shared_contact_pq_pinned, writable_recipients,
    };

    fn make_contact(byte: u8, name: &str) -> ContactView {
        ContactView {
            peer: [byte; 32],
            name: name.to_string(),
            request: false,
            hello_name: String::new(),
            unread: 0,
            last_activity: 0,
            security: SecurityView::default(),
            has_active_session: false,
            pq_pinned: false,
            peer_pq_capable: false,
            allow_classical_exception: false,
            downgrade_detected: false,
            alert: SecurityAlert::None,
            classical_prompt: ClassicalPrompt::None,
        }
    }

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

    #[test]
    fn shared_contact_helpers_enforce_pq_pinning_and_eligibility() {
        let mut alice = make_contact(1, "Alice");
        alice.pq_pinned = true;
        assert!(shared_contact_pq_pinned(&alice, false));
        assert!(!shared_contact_pq_pinned(&alice, true));

        let mut bob = make_contact(2, "");
        bob.hello_name = "  Bob\nSmith\x07  ".to_string();
        bob.has_active_session = true;
        bob.security.is_pq = true;
        assert!(shared_contact_pq_pinned(&bob, false));
        assert_eq!(default_shared_contact_name(&bob), "Bob Smith");

        let classical = make_contact(3, "Carol");
        assert!(!shared_contact_pq_pinned(&classical, false));

        let mut request = make_contact(4, "Dave");
        request.request = true;

        let mut quarantined = make_contact(5, "Eve");
        quarantined.classical_prompt = ClassicalPrompt::InboundQuarantined {
            peer_was_pq_pinned: true,
        };

        let all = vec![alice, bob, classical, request, quarantined];
        let subjects: Vec<u8> = shareable_contacts(&all, [1; 32])
            .into_iter()
            .map(|c| c.peer[0])
            .collect();
        assert_eq!(subjects, vec![2, 3, 5]);

        let recipients: Vec<u8> = writable_recipients(&all, [1; 32])
            .into_iter()
            .map(|c| c.peer[0])
            .collect();
        assert_eq!(recipients, vec![2, 3]);
    }
}
