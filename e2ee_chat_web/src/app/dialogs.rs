use leptos::{ev, html, prelude::*, task::spawn_local};
use session::{PublicKey, safety_number};

use crate::{
    engine::{NAME_MAX, StartChatError, same_server},
    state::{ClassicalPrompt, Dialog, PendingNewChat, Phase},
    util::{key_from_text, key_to_text, short},
};

use super::{
    ActivityList, Toast,
    auth::{CreateVault, Elsewhere, SignInDialog, Unavailable, UnlockVault},
    chat::{contact_can_upgrade_to_pq, security_badge},
    common::{
        AllowClassical, Copyable, Progress, act_while, can_allow_classical,
        cancel_active_chat_history_reservation, cancel_chat_history,
        cancel_retained_chat_history_reservation, close_dialog, commit_chat_history,
        invitation_link, is_chat_history_owned, pq_available, reserve_chat_history,
        retain_active_chat_history_reservation, retain_chat_history, server_pq_disabled,
        strict_pq_enabled, upgrade_disabled_tip,
    },
    engine,
    files::FileBrowser,
    settings::Settings,
    ui,
};

/// The modal dialog: the vault's while it is locked, then the one the page asks for.
#[component]
pub(super) fn VaultDialog() -> impl IntoView {
    let ui = ui();
    let dialog = NodeRef::<html::Dialog>::new();
    let shown = move || match ui.phase.get() {
        Phase::Create | Phase::Locked | Phase::Elsewhere | Phase::Unavailable(_, _) => true,
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
        // The vault's dialog stays until the vault opens.
        if ui.phase.get_untracked() != Phase::Unlocked {
            event.prevent_default();
        } else if ui
            .dialog
            .with_untracked(|dialog| matches!(dialog, Some(Dialog::SignIn)))
        {
            // Dismissed, e.g. with Escape, the sign-in is put off, as "Not now" puts it off:
            // cancel any in-flight auto-start submission; retain a pushed history slot if a
            // waiting NewChat draft is restored, otherwise unwind it back to the chat list.
            if engine().dismiss_sign_in() {
                retain_active_chat_history_reservation();
                if !event.cancelable() {
                    restored_new_chat_non_cancelable.set_value(true);
                }
                event.prevent_default();
            } else {
                cancel_active_chat_history_reservation();
            }
        } else if ui
            .dialog
            .with_untracked(|dialog| matches!(dialog, Some(Dialog::NewChat { .. })))
        {
            // Revoke any in-flight submission, draft, dialog state, and reservation synchronously
            // on `cancel` (before the queued `close` event runs) so a late 403 in that interval
            // cannot capture the dismissed draft or reopen SignIn.
            engine().cancel_active_startup_submission();
            cancel_active_chat_history_reservation();
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
                Phase::Create | Phase::Locked | Phase::Elsewhere | Phase::Unavailable(_, _)
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
                cancel_active_chat_history_reservation();
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
                (Phase::Unlocked, Some(Dialog::Settings)) => view! { <Settings /> }.into_any(),
                (Phase::Unlocked, Some(Dialog::Contact(peer))) => {
                    view! { <ContactInfo peer /> }.into_any()
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
    classical_needed: RwSignal<Option<bool>>,
    progress: Progress,
) {
    match err {
        StartChatError::SignInRequired | StartChatError::Cancelled => progress.clear(),
        StartChatError::ClassicalApprovalRequired { peer_signed_off } => {
            let _ = classical_needed.try_set(Some(peer_signed_off));
            progress.try_fail(if peer_signed_off {
                "This peer signed a manifest disabling post-quantum encryption."
            } else {
                "This peer has no post-quantum prekeys on the server."
            });
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

#[component]
fn NewChat(key: String, name: String, server: Option<String>, pq_pinned: bool) -> impl IntoView {
    let ui = ui();
    // An invitation for another server than the vault's: the inviter's keys are not on it.
    let elsewhere = ui.me.get_untracked().and_then(|me| {
        server
            .as_ref()
            .filter(|server| !same_server(server, &me.server))
            .map(|server| (server.clone(), me.server))
    });
    engine().new_chat_mounted(key.clone(), name.clone(), server.clone(), pq_pinned);
    let last_key = StoredValue::new(key.clone());
    let key = RwSignal::new(key);
    let name = RwSignal::new(name);
    let server_saved = StoredValue::new(server);
    let progress = Progress::new();
    let classical_needed = RwSignal::new(None::<bool>);
    if let Some(feedback) = engine().take_new_chat_feedback() {
        apply_start_chat_error(feedback, classical_needed, progress);
    }
    Effect::new(move || {
        let current_key = key.get();
        let current_name = name.get();
        let key_changed = last_key.with_value(|prev| *prev != current_key);
        if key_changed {
            last_key.set_value(current_key.clone());
            classical_needed.set(None);
            if !progress.working.get_untracked() {
                progress.clear();
            }
        }
        engine().new_chat_edited(current_key, current_name);
    });
    let active_submit = StoredValue::new(None::<(u64, super::history::Reservation)>);
    on_cleanup(move || {
        engine().new_chat_unmounted();
        if let Some((submit_id, reservation)) =
            active_submit.try_update_value(Option::take).flatten()
        {
            let handed_to_sign_in = ui
                .dialog
                .with_untracked(|dialog| matches!(dialog, Some(Dialog::SignIn)));
            if !handed_to_sign_in {
                let _ = cancel_chat_history(Some(reservation));
                engine().cancel_startup_submission(submit_id);
            }
        }
    });
    let start = move |allow_classical: bool| {
        if progress.working.get_untracked() {
            return;
        }
        classical_needed.set(None);
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
        progress.start("Fetching their prekeys…");
        let engine = engine();
        let draft = PendingNewChat {
            key: raw_key,
            name: name.get_untracked(),
            server: server_saved.get_value(),
            pq_pinned,
            allow_classical,
            auto_start: true,
        };
        let submit_id = engine.begin_new_chat_submit(draft.clone());
        let reservation = reserve_chat_history();
        active_submit.set_value(Some((submit_id, reservation)));
        spawn_local(async move {
            let outcome = engine
                .start_chat(
                    submit_id,
                    &draft.key,
                    draft.name.clone(),
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
                    if !cancelled && is_chat_history_owned(Some(reservation)) {
                        engine.clear_pending_new_chat(submit_id);
                        engine.close_dialog_if_new_chat();
                        commit_chat_history(Some(reservation), peer).await;
                    }
                }
                Err(StartChatError::Cancelled) => {
                    let _ = cancel_chat_history(Some(reservation));
                    progress.clear();
                }
                Err(StartChatError::SignInRequired) => {
                    // Retain the gesture-pushed reserved slot across the `NewChat -> SignIn`
                    // handoff so submitting SignIn reuses it without a `history.back()` race.
                    let still_owned = !cancelled && retain_chat_history(Some(reservation));
                    progress.clear();
                    if still_owned {
                        engine.require_sign_in_for_new_chat(submit_id, draft);
                    }
                }
                Err(err) => {
                    // Retain the gesture-pushed reserved slot while `NewChat` stays open for a
                    // retry (e.g. "Allow classical"); closing `NewChat` unwinds it cleanly.
                    let still_owned = !cancelled && retain_chat_history(Some(reservation));
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
                "Paste their identity key. Their prekeys come from the server, and a greeting "
                "with your name starts the session."
            </p>
            {pq_pinned.then(|| {
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
            })}
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
                disabled=move || progress.working.get()
                bind:value=name
            />
            {elsewhere
                .map(|(theirs, yours)| {
                    view! {
                        <p class="warning">
                            "They are on " {theirs} ", and your vault on " {yours}
                            ": a chat needs both of you on one server, so it cannot start here."
                        </p>
                    }
                })}
            {move || {
                classical_needed.get().map(|peer_signed_off| {
                    let strict_pq = strict_pq_enabled(ui);
                    view! {
                        <div class="classical-box" role="alert">
                            <p>
                                {if strict_pq {
                                    "Require post-quantum (strict mode) blocks classical exceptions. To allow a classical chat, disable strict mode in Settings first."
                                } else if peer_signed_off {
                                    "The peer explicitly turned post-quantum encryption off. Only allow classical encryption if you expect that."
                                } else {
                                    "No post-quantum prekeys were returned for this peer. Allow a classical (non-PQ) chat?"
                                }}
                            </p>
                            {(!strict_pq).then(|| view! {
                                <button
                                    type="button"
                                    class="btn small"
                                    disabled=move || progress.working.get()
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
                        cancel_retained_chat_history_reservation();
                        close_dialog();
                    }
                >
                    "Cancel"
                </button>
                <button class="btn primary" type="submit" disabled=move || progress.working.get()>
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
                "Others start a chat with your identity key, or by opening your invitation "
                "link. Both are public: only this browser can answer."
            </p>
            <label>"Identity key"</label>
            <Copyable text=key_to_text(&me.key) what="your key" />
            <label>"Invitation link"</label>
            {move || {
                let link = ui.me.get().as_ref().map(invitation_link).unwrap_or_default();
                view! { <Copyable text=link what="your invitation link" /> }
            }}
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
        contact.hello_name.clone()
    } else {
        contact.name.clone()
    });
    let name_edited = RwSignal::new(false);
    // When approving classical encryption on a newly quarantined chat request unpacks the peer's
    // `Hello` inside this dialog, prefill the untouched name field with their `hello_name`.
    Effect::new(move |_| {
        if let Some(c) = live_contact()
            && c.request
            && !c.hello_name.is_empty()
            && !name_edited.get_untracked()
            && name.get_untracked().is_empty()
        {
            name.set(c.hello_name);
        }
    });
    let confirm_delete = RwSignal::new(false);
    // Saving, accepting or deleting, which its buttons wait for.
    let busy = RwSignal::new(false);
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
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
        if !confirm_delete.get_untracked() {
            confirm_delete.set(true);
            return;
        }
        let engine = engine();
        act_while(busy, async move {
            engine.delete(peer).await?;
            super::history::forget_peer(peer);
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
        Some(c) if c.request => match c.hello_name.as_str() {
            "" => format!("{} wants to chat.", short(&peer)),
            hello => format!("{} wants to chat, and goes by “{hello}”.", short(&peer)),
        },
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
            <Copyable text=key_to_text(&peer) what="their key" />
            <label for="contact-name">"Their name, for you"</label>
            <input
                id="contact-name"
                autocomplete="off"
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
                    {move || match (confirm_delete.get(), is_request()) {
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
