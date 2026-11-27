use leptos::{ev, html, prelude::*, task::spawn_local};
use session::{PublicKey, safety_number};
use wasm_bindgen_futures::JsFuture;

use crate::{
    content,
    engine::{StartChatError, invitation_pins_pq, same_server},
    glue::start_copy_png,
    icon::{Icon, icon},
    qr::{QUIET_ZONE, QrCode},
    state::{ClassicalPrompt, ContactView, Dialog, PendingNewChat, Phase},
    util::{NAME_MAX, hex, key_from_text, key_to_text, sanitize_shared_name, short},
};

use super::{
    ActivityList, Toast,
    auth::{CreateVault, Elsewhere, IncompatibleVault, SignInDialog, Unavailable, UnlockVault},
    chat::{contact_can_upgrade_to_pq, security_badge},
    common::{
        AllowClassical, ConfirmGuard, ContactKey, CopyButton, CopyFeedbackButton, Copyable,
        InvitationLink, Progress, act_while, avatar_letters, can_allow_classical, close_dialog,
        default_shared_contact_name, download_blob, flash_copied, invitation_link, pq_available,
        send, server_pq_disabled, shared_contact_pq_pinned, strict_pq_enabled,
        upgrade_disabled_tip, writable_recipients,
    },
    engine,
    files::FileBrowser,
    history,
    settings::Settings,
    ui,
};

/// The modal dialog: the vault's while it is locked, then the one the page asks for.
#[component]
pub(super) fn VaultDialog() -> impl IntoView {
    let ui = ui();
    let dialog = NodeRef::<html::Dialog>::new();
    let shown = move || match ui.phase.get() {
        Phase::Create
        | Phase::Locked
        | Phase::IncompatibleVault(_)
        | Phase::Elsewhere
        | Phase::Unavailable(_, _) => true,
        Phase::Unlocked => ui.dialog.get().is_some(),
        Phase::Loading => false,
    };
    let restored_new_chat_non_cancelable = StoredValue::new(false);
    Effect::new(move || {
        let shown = shown();
        if let Some(dialog) = dialog.get() {
            if shown && !dialog.open() {
                restored_new_chat_non_cancelable.set_value(false);
                let _ = dialog.show_modal();
            } else if !shown && dialog.open() {
                restored_new_chat_non_cancelable.set_value(false);
                dialog.close();
            }
        }
    });
    let on_cancel = move |event: ev::Event| {
        restored_new_chat_non_cancelable.set_value(false);
        // The vault's dialog stays until the vault opens; Escape still cancels any active KDF.
        if ui.phase.get_untracked() != Phase::Unlocked {
            crate::kdf_worker::cancel_active();
            event.prevent_default();
        } else if ui
            .dialog
            .with_untracked(|dialog| matches!(dialog, Some(Dialog::SignIn)))
        {
            // Dismissed, e.g. with Escape, the sign-in is put off, as "Not now" puts it off:
            // cancel any in-flight auto-start submission; retain a pushed history slot if a
            // waiting NewChat draft is restored, otherwise unwind it back to the chat list.
            if engine().dismiss_sign_in() {
                history::retain_active_reservation();
                if !event.cancelable() {
                    restored_new_chat_non_cancelable.set_value(true);
                }
                event.prevent_default();
            } else {
                history::cancel_active_reservation();
            }
        } else if ui
            .dialog
            .with_untracked(|dialog| matches!(dialog, Some(Dialog::NewChat { .. })))
        {
            // Revoke any in-flight submission, draft, dialog state, and reservation synchronously
            // on `cancel` (before the queued `close` event runs) so a late 403 in that interval
            // cannot capture the dismissed draft or reopen SignIn.
            engine().cancel_active_startup_submission();
            history::cancel_active_reservation();
            ui.dialog.set(None);
        }
    };
    let on_close = move |_| {
        let reopen_restored_new_chat = restored_new_chat_non_cancelable.get_value();
        restored_new_chat_non_cancelable.set_value(false);
        // Ignore stale queued close events if a new modal dialog has already opened.
        if let Some(d) = dialog.get_untracked()
            && !d.open()
        {
            // Non-cancelable CloseWatcher dismissals ignore `prevent_default()` in `on_cancel`
            // and close `<dialog>` anyway. Re-open immediately for mandatory vault phases or a
            // restored `NewChat` draft so the modal cannot permanently vanish.
            if matches!(
                ui.phase.get_untracked(),
                Phase::Create
                    | Phase::Locked
                    | Phase::IncompatibleVault(_)
                    | Phase::Elsewhere
                    | Phase::Unavailable(_, _)
            ) {
                let _ = d.show_modal();
                return;
            }
            if reopen_restored_new_chat
                && ui
                    .dialog
                    .with_untracked(|current| matches!(current, Some(Dialog::NewChat { .. })))
            {
                let _ = d.show_modal();
                return;
            }
            // If a native Escape or system dialog-close request closed an active startup form
            // (`ui.dialog` is still set, unlike programmatic closes), cancel any in-flight
            // submission and unwind its reserved browser history entry synchronously.
            let (dismissed_startup, dismissed_sign_in) = ui.dialog.with_untracked(|current| {
                (
                    matches!(current, Some(Dialog::NewChat { .. } | Dialog::SignIn)),
                    matches!(current, Some(Dialog::SignIn)),
                )
            });
            if dismissed_startup {
                engine().cancel_active_startup_submission();
                if dismissed_sign_in {
                    engine().decline_sign_in_prompts();
                }
                history::cancel_active_reservation();
            }
            ui.dialog.set(None);
        }
    };
    view! {
        <dialog
            class="modal"
            class:wide=move || matches!(ui.dialog.get(), Some(Dialog::Files(_)))
            node_ref=dialog
            on:cancel=on_cancel
            on:close=on_close
        >
            {move || match (ui.phase.get(), ui.dialog.get()) {
                (Phase::Create, _) => view! { <CreateVault /> }.into_any(),
                (Phase::Locked, _) => view! { <UnlockVault /> }.into_any(),
                (Phase::IncompatibleVault(version), _) => {
                    view! { <IncompatibleVault version /> }.into_any()
                }
                (Phase::Elsewhere, _) => view! { <Elsewhere /> }.into_any(),
                (Phase::Unavailable(reason, error), _) => {
                    view! { <Unavailable reason error /> }.into_any()
                }
                (
                    Phase::Unlocked,
                    Some(Dialog::NewChat {
                        key,
                        name,
                        server,
                        pq_pinned,
                    }),
                ) => view! { <NewChat key name server pq_pinned /> }.into_any(),
                (Phase::Unlocked, Some(Dialog::Identity)) => view! { <Identity /> }.into_any(),
                (Phase::Unlocked, Some(Dialog::InviteQr { from_identity })) => {
                    view! { <InviteQr from_identity /> }.into_any()
                }
                (Phase::Unlocked, Some(Dialog::Settings)) => view! { <Settings /> }.into_any(),
                (Phase::Unlocked, Some(Dialog::Contact(peer))) => {
                    view! { <ContactInfo peer /> }.into_any()
                }
                (Phase::Unlocked, Some(Dialog::ShareContact(subject))) => {
                    view! { <ShareContact subject /> }.into_any()
                }
                (Phase::Unlocked, Some(Dialog::Files(peer))) => {
                    view! { <FileBrowser peer /> }.into_any()
                }
                (Phase::Unlocked, Some(Dialog::SignIn)) => view! { <SignInDialog /> }.into_any(),
                (Phase::Unlocked, Some(Dialog::Activity)) => {
                    view! { <ActivityDialog /> }.into_any()
                }
                _ => ().into_any(),
            }}
            <Toast />
        </dialog>
    }
}

fn apply_start_chat_error(
    err: StartChatError,
    classical_needed: RwSignal<bool>,
    progress: Progress,
) {
    match err {
        StartChatError::SignInRequired | StartChatError::Cancelled => progress.clear(),
        StartChatError::ClassicalApprovalRequired => {
            let _ = classical_needed.try_set(true);
            progress.try_fail(
                "This peer published a signed manifest disabling post-quantum encryption.",
            );
        }
        StartChatError::DowngradeDetected => {
            progress.try_fail(
                "Downgrade detected: this invitation pinned post-quantum encryption, but \
                 the server did not provide valid PQ prekeys.",
            );
        }
        StartChatError::PeerManifestExpired => {
            progress.try_fail(
                "This peer's signed post-quantum capability manifest has expired. Try \
                 again after they come online.",
            );
        }
        StartChatError::PqRequired => {
            progress.try_fail(
                "Require PQ (strict mode) is enabled, and a post-quantum session could not \
                 be established with this peer.",
            );
        }
        StartChatError::Other(e) => progress.try_fail(e),
    }
}

/// Compute the effective `(server, pq_pinned)` metadata for `NewChat` based on whether
/// `current_key` still matches the originally invited key (by trimmed text or decoded key bytes).
/// Replacing the invited key clears both `server` and `pq_pinned` so unrelated peers are never
/// falsely PQ-pinned or blocked by another invite's relay mismatch.
pub(super) fn effective_invite_context(
    invited_key: &str,
    current_key: &str,
    invited_server: Option<&str>,
    invited_pq_pinned: bool,
) -> (Option<String>, bool) {
    let invited_trimmed = invited_key.trim();
    let current_trimmed = current_key.trim();
    let matches_invited = if invited_trimmed.is_empty() {
        false
    } else if current_trimmed == invited_trimmed {
        true
    } else {
        match (
            key_from_text(invited_trimmed),
            key_from_text(current_trimmed),
        ) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    };
    if matches_invited {
        (invited_server.map(str::to_string), invited_pq_pinned)
    } else {
        (None, false)
    }
}

#[component]
fn NewChat(key: String, name: String, server: Option<String>, pq_pinned: bool) -> impl IntoView {
    let ui = ui();
    let initial_name = sanitize_shared_name(&name);
    let invited_key = StoredValue::new(key.clone());
    let invited_server = StoredValue::new(server);
    let (init_server, init_pq_pinned) = invited_server
        .with_value(|srv| effective_invite_context(&key, &key, srv.as_deref(), pq_pinned));
    engine().new_chat_mounted(
        key.clone(),
        initial_name.clone(),
        init_server,
        init_pq_pinned,
    );
    let last_key = StoredValue::new(key.clone());
    let key = RwSignal::new(key);
    let name = RwSignal::new(initial_name);
    let progress = Progress::new();
    let classical_needed = RwSignal::new(false);
    if let Some(feedback) = engine().take_new_chat_feedback() {
        apply_start_chat_error(feedback, classical_needed, progress);
    }
    let effective = Memo::new(move |_| {
        let current_key = key.get();
        invited_key.with_value(|orig_key| {
            invited_server.with_value(|orig_server| {
                effective_invite_context(orig_key, &current_key, orig_server.as_deref(), pq_pinned)
            })
        })
    });
    // An invitation for another server than the vault's: the inviter's keys are not on it.
    let elsewhere = Memo::new(move |_| {
        let (eff_server, _) = effective.get();
        let server = eff_server?;
        let my_server = ui.me.with(|me| me.as_ref().map(|me| me.server.clone()))?;
        (!same_server(&server, &my_server)).then_some((server, my_server))
    });
    Effect::new(move || {
        let current_key = key.get();
        let current_name = name.get();
        let (eff_server, eff_pq_pinned) = effective.get();
        let key_changed = last_key.with_value(|prev| *prev != current_key);
        if key_changed {
            last_key.set_value(current_key.clone());
            classical_needed.set(false);
            if !progress.working.get_untracked() {
                progress.clear();
            }
        }
        engine().new_chat_edited(current_key, current_name, eff_server, eff_pq_pinned);
    });
    let active_submit = StoredValue::new(None::<(u64, history::Reservation)>);
    on_cleanup(move || {
        engine().new_chat_unmounted();
        if let Some((submit_id, reservation)) =
            active_submit.try_update_value(Option::take).flatten()
        {
            let handed_to_sign_in = ui
                .dialog
                .with_untracked(|dialog| matches!(dialog, Some(Dialog::SignIn)));
            if !handed_to_sign_in {
                let _ = history::cancel_reservation(Some(reservation));
                engine().cancel_startup_submission(submit_id);
            }
        }
    });
    let start = move |allow_classical: bool| {
        if progress.working.get_untracked() {
            return;
        }
        if let Some((theirs, yours)) = elsewhere.get_untracked() {
            progress.fail(format!(
                "They are on {theirs}, and your vault is on {yours}: a chat cannot start here."
            ));
            return;
        }
        classical_needed.set(false);
        let raw_key = key.get_untracked();
        // Validate locally before reserving browser history so mistyped keys never push a history
        // entry or discard browser Forward history.
        let Some(peer) = key_from_text(&raw_key) else {
            progress.fail("that is not an identity key");
            return;
        };
        if ui
            .me
            .with_untracked(|me| me.as_ref().is_some_and(|me| me.key == peer))
        {
            progress.fail("You cannot start a chat with your own identity key.");
            return;
        }
        if allow_classical && strict_pq_enabled(ui) {
            apply_start_chat_error(StartChatError::PqRequired, classical_needed, progress);
            return;
        }
        let (eff_server, eff_pq_pinned) = effective.get_untracked();
        progress.start("Fetching their prekeys…");
        let engine = engine();
        let draft = PendingNewChat {
            key: raw_key,
            name: name.get_untracked(),
            server: eff_server,
            pq_pinned: eff_pq_pinned,
            allow_classical,
            auto_start: true,
        };
        let submit_id = engine.begin_new_chat_submit(draft.clone());
        let reservation = history::reserve();
        active_submit.set_value(Some((submit_id, reservation)));
        spawn_local(async move {
            let outcome = engine
                .start_chat(
                    submit_id,
                    &draft.key,
                    draft.name.clone(),
                    draft.server.as_deref(),
                    draft.pq_pinned,
                    draft.allow_classical,
                )
                .await;
            let _ = active_submit.try_update_value(|slot| {
                if slot.is_some_and(|(id, _)| id == submit_id) {
                    *slot = None;
                }
            });
            let cancelled = engine.is_submission_cancelled(submit_id);
            engine.finish_submission(submit_id);
            match outcome {
                Ok(peer) => {
                    if !cancelled && history::is_reservation_owned(Some(reservation)) {
                        engine.clear_pending_new_chat(submit_id);
                        engine.close_dialog_if_new_chat();
                        history::commit_reservation(Some(reservation), peer).await;
                    }
                }
                Err(StartChatError::Cancelled) => {
                    let _ = history::cancel_reservation(Some(reservation));
                    progress.clear();
                }
                Err(StartChatError::SignInRequired) => {
                    // Retain the gesture-pushed reserved slot across the `NewChat -> SignIn`
                    // handoff so submitting SignIn reuses it without a `history.back()` race.
                    let still_owned = !cancelled && history::retain_reservation(Some(reservation));
                    progress.clear();
                    if still_owned {
                        engine.require_sign_in_for_new_chat(submit_id, draft);
                    }
                }
                Err(err) => {
                    // Retain the gesture-pushed reserved slot while `NewChat` stays open for a
                    // retry (e.g. "Allow classical"); closing `NewChat` unwinds it cleanly.
                    let still_owned = !cancelled && history::retain_reservation(Some(reservation));
                    let key_unchanged = key
                        .try_get_untracked()
                        .is_some_and(|current| current == draft.key);
                    if still_owned && key_unchanged {
                        apply_start_chat_error(err, classical_needed, progress);
                    } else {
                        progress.clear();
                    }
                }
            }
        });
    };
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        start(false);
    };
    let local_pq_enabled = untrack(|| pq_available(ui));
    view! {
        <form on:submit=submit>
            <h2>"New chat"</h2>
            <p>
                "Paste their identity key. Their prekeys come from the server, and a chat request "
                "with your name starts the session; messages you send deliver once they accept."
            </p>
            {move || {
                let (_, eff_pq_pinned) = effective.get();
                eff_pq_pinned.then(|| {
                    if local_pq_enabled {
                        view! {
                            <p class="pq-pin-hint">
                                <span class="sec-badge pq">"PQ pinned"</span>
                                " This invitation expects post-quantum encryption and will refuse classical downgrades."
                            </p>
                        }
                        .into_any()
                    } else {
                        view! {
                            <p class="warning">
                                "This invitation expects post-quantum encryption, but post-quantum \
                                 encryption is disabled or not compiled into this client; starting a \
                                 chat here will use classical encryption only."
                            </p>
                        }
                        .into_any()
                    }
                })
            }}
            <label for="peer-key">"Their identity key"</label>
            <input
                id="peer-key"
                required
                autocomplete="off"
                spellcheck="false"
                disabled=move || progress.working.get()
                bind:value=key
            />
            <label for="peer-name">"Their name, for you"</label>
            <input
                id="peer-name"
                autocomplete="off"
                maxlength=NAME_MAX
                disabled=move || progress.working.get()
                bind:value=name
            />
            {move || {
                elsewhere.get().map(|(theirs, yours)| {
                    view! {
                        <p class="warning" role="alert">
                            "They are on " {theirs} ", and your vault on " {yours}
                            ": a chat needs both of you on one server, so it cannot start here."
                        </p>
                    }
                })
            }}
            {move || {
                classical_needed.get().then(|| {
                    let strict_pq = strict_pq_enabled(ui);
                    view! {
                        <div class="classical-box" role="alert">
                            <p>
                                {if strict_pq {
                                    "Require post-quantum (strict mode) blocks classical exceptions. To allow a classical chat, disable strict mode in Settings first."
                                } else {
                                    "The peer explicitly turned post-quantum encryption off. Only allow classical encryption if you expect that."
                                }}
                            </p>
                            {(!strict_pq).then(|| view! {
                                <button
                                    type="button"
                                    class="btn small"
                                    disabled=move || {
                                        progress.working.get() || elsewhere.with(Option::is_some)
                                    }
                                    on:click=move |_| start(true)
                                >
                                    "Allow classical"
                                </button>
                            })}
                        </div>
                    }
                })
            }}
            {progress.view()}
            <div class="actions">
                <button
                    type="button"
                    class="btn"
                    disabled=move || progress.working.get()
                    on:click=move |_| {
                        history::cancel_retained_reservation();
                        close_dialog();
                    }
                >
                    "Cancel"
                </button>
                <button
                    class="btn primary"
                    type="submit"
                    disabled=move || progress.working.get() || elsewhere.with(Option::is_some)
                >
                    "Start"
                </button>
            </div>
        </form>
    }
}

#[component]
fn Identity() -> impl IntoView {
    let ui = ui();
    let Some(me) = ui.me.get_untracked() else {
        return ().into_any();
    };
    let name = RwSignal::new(me.name.clone());
    // Saving or publishing prekeys, which its buttons wait for.
    let busy = RwSignal::new(false);
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        let engine = engine();
        let next_name = name.get_untracked();
        act_while(busy, async move {
            engine.set_name(next_name).await?;
            if !busy.is_disposed()
                && engine
                    .ui()
                    .dialog
                    .with_untracked(|dialog| *dialog == Some(Dialog::Identity))
            {
                engine.ui().dialog.set(None);
            }
            Ok(())
        });
    };
    let publish = move |_| {
        let engine = engine();
        act_while(busy, async move {
            engine.publish(true).await?;
            engine.ui().notify("Published new prekeys.");
            Ok(())
        });
    };
    view! {
        <form on:submit=submit>
            <h2>"Your identity"</h2>
            <p>
                "Others start a chat with your identity key, or by opening or scanning your "
                "invitation link. Both are public: only this browser can answer."
            </p>
            <label>"Identity key"</label>
            <Copyable text=Signal::stored(key_to_text(&me.key)) what="your key" />
            <label>"Invitation link"</label>
            <InvitationLink from_identity=true />
            <label for="my-name">"Your name, which new chats see"</label>
            <input id="my-name" autocomplete="nickname" maxlength=NAME_MAX bind:value=name />
            <div class="actions">
                <button
                    type="button"
                    class="btn aside"
                    title="publish a new signed prekey and one-time prekeys"
                    disabled=move || busy.get()
                    on:click=publish
                >
                    "New prekeys"
                </button>
                <button
                    type="button"
                    class="btn"
                    disabled=move || busy.get()
                    on:click=move |_| close_dialog()
                >
                    "Cancel"
                </button>
                <button type="submit" class="btn primary" disabled=move || busy.get()>
                    "Save"
                </button>
            </div>
        </form>
    }
    .into_any()
}

#[component]
fn ContactInfo(peer: PublicKey) -> impl IntoView {
    let ui = ui();
    let Some((contact, me)) = ui.contact(&peer).zip(ui.me.get_untracked()) else {
        return ().into_any();
    };
    let live_contact = move || ui.contact(&peer);
    let is_request = move || live_contact().is_some_and(|c| c.request);
    let is_quarantined = move || live_contact().is_some_and(|c| c.is_quarantined());
    let strict_pq = Memo::new(move |_| strict_pq_enabled(ui));
    let name = RwSignal::new(if contact.request {
        sanitize_shared_name(&contact.hello_name)
    } else {
        contact.name.clone()
    });
    let name_edited = RwSignal::new(false);
    // When approving classical encryption on a newly quarantined chat request unpacks the peer's
    // `Hello` inside this dialog, prefill the untouched name field with their `hello_name`.
    Effect::new(move |_| {
        if let Some(c) = live_contact()
            && c.request
            && !name_edited.get_untracked()
            && name.get_untracked().is_empty()
        {
            let clean = sanitize_shared_name(&c.hello_name);
            if !clean.is_empty() {
                name.set(clean);
            }
        }
    });
    let confirm_delete = ConfirmGuard::new();
    // Saving, accepting or deleting, which its buttons wait for.
    let busy = RwSignal::new(false);
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        confirm_delete.disarm();
        let req = is_request();
        if req && is_quarantined() {
            ui.notify(if strict_pq.get_untracked() {
                "Upgrade to PQ (or disable strict PQ mode in Settings) before accepting this request."
            } else {
                "Allow classical encryption or upgrade to PQ before accepting this request."
            });
            return;
        }
        let engine = engine();
        let next_name = name.get_untracked();
        act_while(busy, async move {
            if req {
                engine.accept(peer, next_name).await?;
            } else {
                engine.rename(peer, next_name).await?;
            }
            if !busy.is_disposed()
                && engine
                    .ui()
                    .dialog
                    .with_untracked(|dialog| *dialog == Some(Dialog::Contact(peer)))
            {
                engine.ui().dialog.set(None);
            }
            Ok(())
        });
    };
    let delete = move |_| {
        if !confirm_delete.confirm_or_arm() {
            return;
        }
        let engine = engine();
        act_while(busy, async move {
            engine.delete(peer).await?;
            history::forget_peer(peer);
            if !busy.is_disposed()
                && engine
                    .ui()
                    .dialog
                    .with_untracked(|dialog| *dialog == Some(Dialog::Contact(peer)))
            {
                engine.ui().dialog.set(None);
            }
            Ok(())
        });
    };
    let intro = move || match live_contact() {
        Some(c) if c.request => {
            let hello = sanitize_shared_name(&c.hello_name);
            if hello.is_empty() {
                format!("{} wants to chat.", short(&peer))
            } else {
                format!("{} wants to chat, and goes by “{hello}”.", short(&peer))
            }
        }
        Some(c) if c.awaiting_acceptance => format!(
            "Waiting for {} to accept your chat request. Messages will deliver once they accept.",
            c.label()
        ),
        Some(c) => format!("Your chat with {}.", c.label()),
        None => String::new(),
    };
    view! {
        <form on:submit=submit>
            <h2>{move || if is_request() { "Chat request" } else { "Chat" }}</h2>
            <p>
                {intro}
                " To be sure it is them, compare the safety number with them in person or over "
                "another channel: it is the same on both sides only if neither key was swapped."
            </p>
            <label>"Encryption"</label>
            {move || {
                live_contact().map(|c| {
                    let strict_pq = strict_pq.get();
                    let show_allow = can_allow_classical(c.classical_prompt, strict_pq);
                    let show_upgrade = pq_available(ui) && contact_can_upgrade_to_pq(&c);
                    let show_dismiss = c.has_downgrade() && !c.is_quarantined();
                    view! {
                        <div class="contact-security">
                            <div class="contact-security-row">
                                {security_badge(&c, true)}
                                {c.pq_pinned.then(|| view! { <span class="sec-meta">"PQ pinned"</span> })}
                                {(c.allow_classical_exception && !strict_pq).then(|| {
                                    view! { <span class="sec-meta">"Classical allowed"</span> }
                                })}
                                {(c.classical_prompt != ClassicalPrompt::None && strict_pq).then(|| {
                                    view! { <span class="sec-meta">"Strict PQ mode blocks classical exceptions"</span> }
                                })}
                            </div>
                            {(show_allow || show_upgrade || show_dismiss).then(|| {
                                view! {
                                    <div class="banner-actions">
                                        {show_allow.then(|| view! { <AllowClassical peer busy /> })}
                                        {show_upgrade.then(|| {
                                            view! {
                                                <button
                                                    type="button"
                                                    class="btn primary small"
                                                    title=move || upgrade_disabled_tip(ui)
                                                    disabled=move || {
                                                        busy.get() || server_pq_disabled(ui)
                                                    }
                                                    on:click=move |_| {
                                                        act_while(busy, async move {
                                                            engine().upgrade_to_pq(peer).await
                                                        });
                                                    }
                                                >
                                                    "Upgrade to PQ"
                                                </button>
                                            }
                                        })}
                                        {show_dismiss.then(|| {
                                            view! {
                                                <button
                                                    type="button"
                                                    class="btn small"
                                                    disabled=move || busy.get()
                                                    on:click=move |_| {
                                                        act_while(busy, async move {
                                                            engine().dismiss_downgrade(peer).await
                                                        });
                                                    }
                                                >
                                                    "Dismiss warning"
                                                </button>
                                            }
                                        })}
                                    </div>
                                }
                            })}
                        </div>
                    }
                })
            }}
            <label>"Safety number"</label>
            // Twelve groups of five digits, four to a row, as Signal shows them.
            <div class="key safety">
                {safety_number(&me.key, &peer)
                    .as_bytes()
                    .chunks(5)
                    .map(|group| view! { <span>{String::from_utf8_lossy(group).into_owned()}</span> })
                    .collect_view()}
            </div>
            <label>"Their identity key"</label>
            <ContactKey peer can_share=Signal::derive(move || !is_request()) />
            <label for="contact-name">"Their name, for you"</label>
            <input
                id="contact-name"
                autocomplete="off"
                maxlength=NAME_MAX
                bind:value=name
                on:input=move |_| name_edited.set(true)
            />
            <div class="actions">
                <button
                    type="button"
                    class="btn danger"
                    disabled=move || busy.get()
                    on:click=delete
                >
                    {move || match (confirm_delete.is_armed(), is_request()) {
                        (false, true) => "Delete request",
                        (false, false) => "Delete chat",
                        (true, _) => "Delete it and its history?",
                    }}
                </button>
                <button
                    type="button"
                    class="btn"
                    disabled=move || busy.get()
                    on:click=move |_| close_dialog()
                >
                    "Cancel"
                </button>
                <Show when=move || !(is_request() && is_quarantined())>
                    <button class="btn primary" type="submit" disabled=move || busy.get()>
                        {move || if is_request() { "Accept" } else { "Save" }}
                    </button>
                </Show>
            </div>
        </form>
    }
    .into_any()
}

#[component]
fn ShareContact(subject: PublicKey) -> impl IntoView {
    let ui = ui();
    let picked = RwSignal::new(None::<PublicKey>);
    let query = RwSignal::new(String::new());
    let initial_name = ui
        .contact(&subject)
        .map(|contact| default_shared_contact_name(&contact))
        .unwrap_or_default();
    let shared_name = RwSignal::new(initial_name);

    let candidates = Memo::new(move |_| {
        ui.contacts
            .with(|contacts| writable_recipients(contacts, subject))
    });
    let filtered_peers = Memo::new(move |_| {
        let needle = query.get().trim().to_lowercase();
        let list = candidates.get();
        list.into_iter()
            .filter(|contact| {
                needle.is_empty()
                    || contact.label().to_lowercase().contains(&needle)
                    || short(&contact.peer).to_lowercase().contains(&needle)
            })
            .map(|contact| contact.peer)
            .collect::<Vec<_>>()
    });
    // Only treat a picked peer as active while it remains visible in the current filtered list so
    // pressing Enter or clicking Share can never send to a hidden selection.
    let selected_recipient = Memo::new(move |_| {
        picked
            .get()
            .filter(|peer| filtered_peers.with(|list| list.contains(peer)))
    });
    let will_pin_pq = Memo::new(move |_| {
        ui.contact(&subject)
            .is_some_and(|contact| shared_contact_pq_pinned(&contact, server_pq_disabled(ui)))
    });
    let can_submit = move || {
        let Some(recipient_peer) = selected_recipient.get() else {
            return false;
        };
        subject != recipient_peer
            && ui.contact(&subject).is_some_and(|contact| !contact.request)
            && ui
                .contact(&recipient_peer)
                .is_some_and(|contact| !contact.request && !contact.is_quarantined())
    };

    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        let Some(recipient_peer) = selected_recipient.get_untracked() else {
            return;
        };
        if subject == recipient_peer {
            return;
        }
        let Some(subject_contact) = ui.contact(&subject) else {
            ui.notify("That contact is no longer in your chats.");
            return;
        };
        if subject_contact.request {
            ui.notify("Accept that chat request before sharing it.");
            return;
        }
        let Some(recipient_contact) = ui.contact(&recipient_peer) else {
            ui.notify("That recipient chat is no longer available.");
            return;
        };
        if recipient_contact.request || recipient_contact.is_quarantined() {
            ui.notify("Accept or clear quarantine on that chat before sharing a contact to it.");
            return;
        }
        let name = sanitize_shared_name(&shared_name.get_untracked());
        let pq_pinned = shared_contact_pq_pinned(&subject_contact, server_pq_disabled(ui));
        send(
            recipient_peer,
            content::Kind::Contact(content::Contact {
                key: subject.to_vec(),
                name,
                pq_pinned,
            }),
        );
        close_dialog();
        ui.notify(format!(
            "Shared {} with {}.",
            subject_contact.label(),
            recipient_contact.label(),
        ));
    };

    let intro = move || {
        let who = ui
            .contact(&subject)
            .map(|c| c.label())
            .unwrap_or_else(|| short(&subject));
        format!("Send {who}'s contact card to another chat so they can start an encrypted chat.")
    };

    view! {
        <form on:submit=submit>
            <h2>"Share this contact"</h2>
            <p>{intro}</p>
            {move || {
                ui.contact(&subject).map(|contact| {
                    let letters = avatar_letters(&contact.name, &contact.peer);
                    let pq = shared_contact_pq_pinned(&contact, server_pq_disabled(ui));
                    view! {
                        <div class="share-preview">
                            <span class="avatar">{letters}</span>
                            <div class="share-option-text">
                                <strong>{contact.label()}</strong>
                                <span>{short(&contact.peer)}</span>
                            </div>
                            {pq.then(|| view! { <span class="sec-badge pq">"PQ pinned"</span> })}
                        </div>
                    }
                })
            }}
            <label>"Send to"</label>
            <Show when=move || candidates.with(|list| list.len() > 5)>
                <input
                    type="search"
                    placeholder="Filter chats…"
                    autocomplete="off"
                    bind:value=query
                    on:keydown=move |ev: ev::KeyboardEvent| {
                        if ev.key() == "Enter" {
                            ev.prevent_default();
                        }
                    }
                />
            </Show>
            <div class="share-list" role="listbox" aria-label="Choose a chat">
                <For
                    each=move || filtered_peers.get()
                    key=|peer| *peer
                    children=move |peer| {
                        let live = Memo::new(move |_| ui.contact(&peer));
                        view! {
                            <button
                                type="button"
                                class="share-option"
                                class:selected=move || selected_recipient.get() == Some(peer)
                                role="option"
                                aria-selected=move || if selected_recipient.get() == Some(peer) { "true" } else { "false" }
                                on:click=move |_| picked.set(Some(peer))
                            >
                                <span class="avatar">
                                    {move || {
                                        live.with(|c| {
                                            c.as_ref()
                                                .map(|c| avatar_letters(&c.name, &c.peer))
                                                .unwrap_or_else(|| hex(&peer[..1]))
                                        })
                                    }}
                                </span>
                                <span class="share-option-text">
                                    <strong>
                                        {move || {
                                            live.with(|c| {
                                                c.as_ref()
                                                    .map(ContactView::label)
                                                    .unwrap_or_else(|| short(&peer))
                                            })
                                        }}
                                    </strong>
                                    <span>{short(&peer)}</span>
                                </span>
                                {move || live.get().map(|c| security_badge(&c, false))}
                            </button>
                        }
                    }
                />
                <Show when=move || filtered_peers.with(Vec::is_empty)>
                    <p class="share-empty">
                        {move || {
                            if !candidates.with(Vec::is_empty) {
                                "No matching chats."
                            } else {
                                "No eligible chats to share with yet."
                            }
                        }}
                    </p>
                </Show>
            </div>
            <label for="share-name">"Name to share (optional)"</label>
            <input
                id="share-name"
                autocomplete="off"
                maxlength=NAME_MAX
                placeholder="Leave blank to share key only"
                bind:value=shared_name
            />
            <Show when=move || will_pin_pq.get()>
                <p class="pq-pin-hint">
                    <span class="sec-badge pq">"PQ pinned"</span>
                    " Includes post-quantum pinning so their new chat refuses classical downgrades."
                </p>
            </Show>
            <div class="actions">
                <button
                    type="button"
                    class="btn aside"
                    on:click=move |_| ui.dialog.set(Some(Dialog::Contact(subject)))
                >
                    "Back"
                </button>
                <button type="button" class="btn" on:click=move |_| close_dialog()>
                    "Cancel"
                </button>
                <button type="submit" class="btn primary" disabled=move || !can_submit()>
                    "Share"
                </button>
            </div>
        </form>
    }
}

#[component]
fn InviteQr(from_identity: bool) -> impl IntoView {
    let ui = ui();
    let link = Memo::new(move |_| {
        ui.me
            .with(|me| me.as_ref().map(invitation_link).unwrap_or_default())
    });
    let qr = Memo::new(move |_| {
        let current = link.get();
        (!current.is_empty()).then(|| QrCode::encode_text(&current))
    });
    let has_qr = Signal::derive(move || qr.with(|code| matches!(code, Some(Ok(_)))));
    let link_empty = Signal::derive(move || link.with(String::is_empty));
    let copied_image_gen = RwSignal::new(0u32);
    let download_anchor = NodeRef::<html::A>::new();

    let on_copy_image = move |_| {
        let Some(png) = qr.with_untracked(|code| match code {
            Some(Ok(code)) => Some(code.to_export_png()),
            _ => None,
        }) else {
            return;
        };
        let promise = start_copy_png(&png);
        spawn_local(async move {
            let ok = match promise {
                Some(promise) => JsFuture::from(promise).await.is_ok(),
                None => false,
            };
            if !ok {
                ui.notify(
                    "The browser would not copy the QR code image; download the PNG instead.",
                );
                return;
            }
            flash_copied(copied_image_gen).await;
        });
    };

    let on_download = move |_| {
        let Some(png) = qr.with_untracked(|code| match code {
            Some(Ok(code)) => Some(code.to_export_png()),
            _ => None,
        }) else {
            return;
        };
        if !download_blob(&png, "image/png", "ratchetx2-invite.png", download_anchor) {
            ui.notify("Could not prepare the QR code image for download.");
        }
    };

    view! {
        <div class="qr-dialog">
            <h2>"Invitation QR code"</h2>
            <p>"Scan this code to open your invitation link and start an encrypted chat."</p>
            <div class="qr-stage">
                {move || match qr.get() {
                    Some(Ok(code)) => {
                        let total = code.total_size(QUIET_ZONE);
                        let view_box = format!("0 0 {total} {total}");
                        let path = code.svg_path(QUIET_ZONE);
                        view! {
                            <div class="qr-card">
                                <svg
                                    class="qr-svg"
                                    viewBox=view_box
                                    shape-rendering="crispEdges"
                                    role="img"
                                    aria-label="QR code for your invitation link"
                                >
                                    <rect class="qr-bg" width=total height=total />
                                    <path class="qr-fg" d=path />
                                </svg>
                            </div>
                        }
                        .into_any()
                    }
                    Some(Err(_)) => view! {
                        <p class="error" role="alert">
                            "Your invitation link is too long to encode as a QR code."
                        </p>
                    }
                    .into_any(),
                    None => ().into_any(),
                }}
                {move || {
                    ui.me.get().map(|me| {
                        let has_pq = invitation_pins_pq(&me);
                        let who = if me.name.is_empty() {
                            short(&me.key)
                        } else {
                            format!("{} · {}", me.name, short(&me.key))
                        };
                        view! {
                            <div class="qr-caption">
                                <span class="qr-who">{who}</span>
                                {has_pq.then(|| view! { <span class="sec-badge pq">"PQ pinned"</span> })}
                            </div>
                        }
                    })
                }}
            </div>
            <div class="qr-actions">
                <CopyButton
                    text=link.into()
                    what="your invitation link"
                    failure_notice="The browser would not copy your invitation link; copy it from Your identity instead."
                    label=("Copy link", "Copied link")
                    disabled=Some(link_empty)
                />
                <CopyFeedbackButton
                    copied_gen=copied_image_gen
                    label=Some(("Copy image", "Copied image"))
                    disabled=Some(Signal::derive(move || !has_qr.get()))
                    on_click=on_copy_image
                />
                <button
                    type="button"
                    class="btn small"
                    disabled=move || !has_qr.get()
                    on:click=on_download
                >
                    {icon(Icon::Download)}
                    "Download PNG"
                </button>
            </div>
            <a hidden node_ref=download_anchor></a>
            <div class="actions">
                {from_identity.then(|| {
                    view! {
                        <button
                            type="button"
                            class="btn aside"
                            on:click=move |_| ui.dialog.set(Some(Dialog::Identity))
                        >
                            "Back"
                        </button>
                    }
                })}
                <button type="button" class="btn primary" on:click=move |_| close_dialog()>
                    "Close"
                </button>
            </div>
        </div>
    }
}

#[component]
fn ActivityDialog() -> impl IntoView {
    view! {
        <div>
            <h2>"Activity"</h2>
            <p>"Recent vault, sync, and encryption events in this browser session."</p>
            <ActivityList />
            <div class="actions">
                <button type="button" class="btn primary" on:click=move |_| close_dialog()>
                    "Close"
                </button>
            </div>
        </div>
    }
}
