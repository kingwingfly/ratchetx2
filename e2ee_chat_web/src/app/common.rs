use std::time::Duration;

use leptos::{ev, html, leptos_dom::helpers::TimeoutHandle, prelude::*, task::spawn_local};
use session::PublicKey;
use web_sys::{FileList, HtmlInputElement, Url};
use zeroize::Zeroizing;

use crate::{
    content,
    engine::{Sending, build_invitation_link, invitation, origin},
    glue::copy,
    icon::{Icon, icon},
    state::{ClassicalPrompt, ContactView, Dialog, Me, ServerPqStatus, SharedContact, Ui},
    util::{hex, key_to_text, sanitize_filename, sanitize_shared_name, sleep, validate_relay_url},
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

/// An avatar's letters for a contact or user: initials of `name`, or the first byte of `peer`
/// in hex when unnamed.
pub(super) fn avatar_letters(name: &str, peer: &PublicKey) -> String {
    let letters = initials(name);
    if letters.is_empty() {
        hex(&peer[..1])
    } else {
        letters
    }
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
        name: sanitize_shared_name(&card.name),
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

/// Trigger a browser download of `data` via `anchor`, sanitizing `filename` and revoking the
/// temporary blob URL after a grace period. Returns `false` if the anchor is unmounted or blob
/// creation fails.
pub(super) fn download_blob(
    data: &[u8],
    mime: &str,
    filename: &str,
    anchor: NodeRef<html::A>,
) -> bool {
    let Some(anchor) = anchor.try_get_untracked().flatten() else {
        return false;
    };
    let Some(url) = super::media::blob_url(data, mime) else {
        return false;
    };
    let safe_name = sanitize_filename(filename);
    anchor.set_href(&url);
    anchor.set_download(&safe_name);
    anchor.click();
    let _ = anchor.remove_attribute("href");
    let _ = anchor.remove_attribute("download");
    set_timeout(
        move || {
            let _ = Url::revoke_object_url(&url);
        },
        Duration::from_secs(60),
    );
    true
}

/// A copy button showing a tick while `copied_gen != 0`, rendered either icon-only (`label == None`)
/// or as a small labeled button (`label == Some((idle, done))`).
#[component]
pub(super) fn CopyFeedbackButton(
    copied_gen: RwSignal<u32>,
    #[prop(optional_no_strip)] title: Option<Signal<String>>,
    #[prop(optional_no_strip)] label: Option<(&'static str, &'static str)>,
    #[prop(optional_no_strip)] disabled: Option<Signal<bool>>,
    on_click: impl Fn(ev::MouseEvent) + 'static,
) -> impl IntoView {
    let copied = move || copied_gen.get() != 0;
    let class = if label.is_some() {
        "btn small"
    } else {
        "btn icon"
    };
    let is_disabled = move || disabled.is_some_and(|d| d.get());
    let tip = move || title.map(|t| t.get());
    view! {
        <button
            type="button"
            class=class
            class:done=copied
            title=tip
            aria-label=tip
            disabled=is_disabled
            on:click=on_click
        >
            {move || icon(if copied() { Icon::Tick } else { Icon::Copy })}
            {label.map(|(idle, done)| move || if copied() { done } else { idle })}
        </button>
    }
}

/// A button that copies `text` to the clipboard, flashing a tick for [`COPIED_SHOWN`] on success
/// and notifying on refusal.
#[component]
pub(super) fn CopyButton(
    text: Signal<String>,
    what: &'static str,
    #[prop(optional)] failure_notice: Option<&'static str>,
    #[prop(optional)] label: Option<(&'static str, &'static str)>,
    #[prop(optional_no_strip)] disabled: Option<Signal<bool>>,
) -> impl IntoView {
    let copied_gen = RwSignal::new(0u32);
    let on_click = move |_| {
        let value = text.get_untracked();
        if value.is_empty() {
            return;
        }
        spawn_local(async move {
            if !copy(&value).await {
                let notice = failure_notice.map_or_else(
                    || format!("The browser would not copy {what}; select it and copy it instead."),
                    str::to_string,
                );
                ui().notify(notice);
                return;
            }
            flash_copied(copied_gen).await;
        });
    };
    let title = label.is_none().then(|| {
        Signal::derive(move || {
            if copied_gen.get() != 0 {
                "Copied".to_string()
            } else {
                format!("Copy {what}")
            }
        })
    });
    view! {
        <CopyFeedbackButton copied_gen title label disabled on_click />
    }
}

/// `text` in a `.key` box with a copy button (and optional extra action buttons) beside it.
#[component]
pub(super) fn CopyableField(
    text: Signal<String>,
    what: &'static str,
    #[prop(optional)] disabled: Option<Signal<bool>>,
    #[prop(optional)] extra: Option<Children>,
) -> impl IntoView {
    view! {
        <div class="copyable">
            <div class="key">{move || text.get()}</div>
            {match extra {
                Some(extra) => view! {
                    <div class="copyable-actions">
                        <CopyButton text what disabled />
                        {extra()}
                    </div>
                }
                .into_any(),
                None => view! { <CopyButton text what disabled /> }.into_any(),
            }}
        </div>
    }
}

/// `text` in a box, with a button beside it that copies it, `what` it is, e.g. "your key": a
/// tick shows for a moment once it did, and a notice says if the browser would not.
#[component]
pub(super) fn Copyable(text: Signal<String>, what: &'static str) -> impl IntoView {
    view! { <CopyableField text what /> }
}

/// This client's invitation link, with buttons to copy it or open its scannable QR code.
#[component]
pub(super) fn InvitationLink(#[prop(default = false)] from_identity: bool) -> impl IntoView {
    let ui = ui();
    let link = Memo::new(move |_| {
        ui.me
            .with(|me| me.as_ref().map(invitation_link).unwrap_or_default())
    });
    let empty = Signal::derive(move || link.with(String::is_empty));
    view! {
        <CopyableField
            text=link.into()
            what="your invitation link"
            disabled=empty
            extra=Box::new(move || {
                view! {
                    <button
                        type="button"
                        class="btn icon"
                        title="Share as QR code"
                        aria-label="Share your invitation link as a QR code"
                        disabled=move || empty.get()
                        on:click=move |_| ui.dialog.set(Some(Dialog::InviteQr { from_identity }))
                    >
                        {icon(Icon::QrCode)}
                    </button>
                }
                .into_any()
            })
        />
    }
}

/// A peer's identity key, with a button to copy it and (for accepted chats) share it to another chat.
#[component]
pub(super) fn ContactKey(peer: PublicKey, can_share: Signal<bool>) -> impl IntoView {
    let ui = ui();
    let text = Signal::stored(key_to_text(&peer));
    view! {
        <CopyableField
            text
            what="their key"
            extra=Box::new(move || {
                view! {
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
                }
                .into_any()
            })
        />
    }
}

/// A link that opens a chat with `me`, with the name filled in, the server if it is not the
/// page's own, and `&pq=1` when post-quantum encryption is enabled.
pub(super) fn invitation_link(me: &Me) -> String {
    build_invitation_link(&origin(), me)
}

/// Validate an optional server URL from an invitation link (must be `https://` or
/// `http://localhost` / loopback with no credentials, path, query, or fragment).
pub(super) fn validate_invited_server(server: Option<&str>) -> Option<String> {
    validate_relay_url(server?).ok()
}

/// Extract and validate the server URL from an invitation `#chat=...&server=...` fragment.
#[cfg(test)]
pub(super) fn invited_server_from_hash(hash: &str) -> Option<String> {
    match crate::engine::parse_invitation_hash(hash)? {
        Dialog::NewChat { server, .. } => validate_invited_server(server.as_deref()),
        _ => None,
    }
}

/// The validated server an invitation link in the page's address names, to create the vault on.
pub(super) fn invited_server() -> Option<String> {
    match invitation()? {
        Dialog::NewChat { server, .. } => validate_invited_server(server.as_deref()),
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

/// Two-step confirmation guard that arms on the first click, auto-disarms after [`ASKED_SHOWN`],
/// and cancels its pending timeout on explicit disarm or component unmount.
#[derive(Clone, Copy)]
pub(super) struct ConfirmGuard {
    armed: RwSignal<bool>,
    timer: StoredValue<Option<TimeoutHandle>, LocalStorage>,
}

impl ConfirmGuard {
    pub(super) fn new() -> Self {
        let guard = Self {
            armed: RwSignal::new(false),
            timer: StoredValue::new_local(None),
        };
        on_cleanup(move || guard.clear_timer());
        guard
    }

    pub(super) fn is_armed(self) -> bool {
        self.armed.get()
    }

    fn clear_timer(self) {
        if let Some(handle) = self.timer.try_update_value(Option::take).flatten() {
            handle.clear();
        }
    }

    pub(super) fn disarm(self) {
        self.clear_timer();
        let _ = self.armed.try_set(false);
    }

    pub(super) fn arm(self) {
        self.clear_timer();
        let _ = self.armed.try_set(true);
        if let Ok(handle) = set_timeout_with_handle(
            move || {
                let _ = self.timer.try_set_value(None);
                let _ = self.armed.try_set(false);
            },
            ASKED_SHOWN,
        ) {
            let _ = self.timer.try_set_value(Some(handle));
        }
    }

    /// Arm on the first click and return `false`; disarm and return `true` when clicked while armed.
    pub(super) fn confirm_or_arm(self) -> bool {
        if self.armed.get_untracked() {
            self.disarm();
            true
        } else {
            self.arm();
            false
        }
    }
}

#[cfg(test)]
pub(super) fn make_contact(byte: u8, name: &str) -> ContactView {
    use crate::state::{SecurityAlert, SecurityView};

    ContactView {
        peer: [byte; 32],
        name: name.to_string(),
        request: false,
        hello_name: String::new(),
        unread: 0,
        last_activity: 0,
        last_message: None,
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

#[cfg(test)]
mod tests {
    use super::{
        ClassicalPrompt, can_allow_classical, default_shared_contact_name, make_contact,
        shareable_contacts, shared_contact_pq_pinned, writable_recipients,
    };

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
