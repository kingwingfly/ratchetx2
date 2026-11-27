use std::{cell::Cell, rc::Rc};

use leptos::{ev, prelude::*, task::spawn_local};
use session::PqConfig;

use crate::{
    engine::{StartChatError, VaultOpenError, origin, same_server},
    kdf_worker::KdfCancelToken,
    state::{Dialog, SignInSuccessAction, UnavailableReason},
    util::{NAME_MAX, day, validate_relay_url},
};

use super::{
    common::{ConfirmGuard, Progress, SecretInput, ToggleSwitch, invited_server, lock},
    engine, history,
};

/// Sign in to the server with its password, which storing files there takes, as they cost it
/// storage: what waited for it goes then, and any pending invitation / new-chat draft resumes.
#[component]
pub(super) fn SignInDialog() -> impl IntoView {
    let password_input = SecretInput::new();
    let active_submit = StoredValue::new(None::<(u64, history::Reservation)>);
    // Bind async sign-in completions strictly to this mounted form instance so dismissing a
    // password-only SignInDialog never allows its late completion to adopt a newer auto-start draft.
    let alive = StoredValue::new_local(Rc::new(Cell::new(true)));
    on_cleanup(move || {
        let _ = alive.try_with_value(|flag| flag.set(false));
        password_input.clear();
        if let Some((auto_start_id, reservation)) =
            active_submit.try_update_value(Option::take).flatten()
        {
            let _ = history::cancel_reservation(Some(reservation));
            engine().cancel_startup_submission(auto_start_id);
        }
    });
    let progress = Progress::new();
    let pending_hint = engine()
        .pending_new_chat_hint()
        .map(|(auto_start, has_key)| match (auto_start, has_key) {
            (true, _) => {
                "Sign in to continue starting your chat — your invitation details are saved."
            }
            (false, true) => "After you sign in, your invitation will open automatically.",
            (false, false) => "After you sign in, you will return to starting your chat.",
        });
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        if progress.working.get_untracked() {
            return;
        }
        let secret = password_input.take();
        let engine = engine();
        // Reserve a chat-level history entry during the submit gesture when sign-in will
        // auto-start a pending chat so WebKit preserves swipe-back after slow relay requests.
        let auto_start_id = engine.pending_auto_start_id();
        if let Some(id) = auto_start_id {
            engine.begin_sign_in_auto_start(id);
        }
        let reservation = auto_start_id.map(|_| history::reserve());
        if let (Some(id), Some(res)) = (auto_start_id, reservation) {
            active_submit.set_value(Some((id, res)));
        }
        let alive = alive.get_value();
        progress.start("Signing in…");
        spawn_local(async move {
            let result = engine.sign_in(&secret).await;
            drop(secret);
            let clear_active = |target_id: Option<u64>| {
                if let Some(target_id) = target_id {
                    let _ = active_submit.try_update_value(|slot| {
                        if slot.is_some_and(|(id, _)| id == target_id) {
                            *slot = None;
                        }
                    });
                }
            };
            match result {
                Ok(signed_in) => {
                    let until = day(signed_in.expires);
                    // If this SignInDialog instance was dismissed/unmounted or its auto-start
                    // draft was cancelled/superseded while signing in, do not start a cancelled
                    // chat or adopt a newer dialog's draft.
                    if !alive.get()
                        || auto_start_id.is_some_and(|id| {
                            engine.is_submission_cancelled(id)
                                || !history::is_reservation_owned(reservation)
                        })
                    {
                        clear_active(auto_start_id);
                        let _ = history::cancel_reservation(reservation);
                        if let Some(id) = auto_start_id {
                            engine.finish_auto_start_chat(id, None);
                            engine.finish_submission(id);
                        }
                        progress.clear();
                        engine.ui().notify(format!(
                            "Signed in until {until}: waiting messages and files go now."
                        ));
                        return;
                    }
                    match engine.complete_sign_in_flow() {
                        SignInSuccessAction::Close => {
                            clear_active(auto_start_id);
                            let _ = history::cancel_reservation(reservation);
                            if let Some(id) = auto_start_id {
                                engine.finish_submission(id);
                            }
                            engine.close_dialog_if_sign_in();
                            engine.ui().notify(format!(
                                "Signed in until {until}: waiting messages and files go now."
                            ));
                        }
                        SignInSuccessAction::ReopenNewChat(dialog) => {
                            clear_active(auto_start_id);
                            let _ = history::retain_reservation(reservation);
                            if let Some(id) = auto_start_id {
                                engine.finish_submission(id);
                            }
                            engine.ui().dialog.set(Some(dialog));
                            engine.ui().notify(format!("Signed in until {until}."));
                        }
                        SignInSuccessAction::AutoStartChat { id, pending } => {
                            if auto_start_id != Some(id) {
                                clear_active(auto_start_id);
                                let _ = history::cancel_reservation(reservation);
                                if let Some(prev_id) = auto_start_id {
                                    engine.finish_submission(prev_id);
                                }
                                progress.clear();
                                engine.close_dialog_if_sign_in();
                                engine.ui().notify(format!(
                                    "Signed in until {until}: waiting messages and files go now."
                                ));
                                return;
                            }
                            if let Some(res) = reservation {
                                active_submit.set_value(Some((id, res)));
                            }
                            progress.try_start("Starting chat…");
                            let outcome = engine
                                .start_chat(
                                    id,
                                    &pending.key,
                                    pending.name.clone(),
                                    pending.server.as_deref(),
                                    pending.pq_pinned,
                                    pending.allow_classical,
                                )
                                .await;
                            clear_active(Some(id));
                            let cancelled = engine.is_submission_cancelled(id);
                            engine.finish_submission(id);
                            match outcome {
                                Ok(peer) => {
                                    if cancelled || !history::is_reservation_owned(reservation) {
                                        engine.finish_auto_start_chat(id, None);
                                        progress.clear();
                                        return;
                                    }
                                    engine.finish_auto_start_chat(id, None);
                                    engine.close_dialog_if_new_chat();
                                    history::commit_reservation(reservation, peer).await;
                                    // If sending the initial greeting hit a secondary
                                    // `SignInRequired` after persisting the chat, `SignInDialog`
                                    // intentionally stayed open — reset `progress` so buttons are
                                    // usable again.
                                    if engine
                                        .ui()
                                        .dialog
                                        .with_untracked(|d| matches!(d, Some(Dialog::SignIn)))
                                    {
                                        progress.try_fail(
                                            "Sign-in is still required by the server to send the \
                                             greeting.",
                                        );
                                    } else {
                                        progress.clear();
                                        engine.ui().notify(format!("Signed in until {until}."));
                                    }
                                }
                                Err(StartChatError::Cancelled) => {
                                    let _ = history::cancel_reservation(reservation);
                                    progress.clear();
                                }
                                Err(StartChatError::SignInRequired) => {
                                    // Retain the gesture-pushed reserved slot while `SignInDialog`
                                    // stays open for a retry.
                                    let still_owned =
                                        !cancelled && history::retain_reservation(reservation);
                                    if still_owned {
                                        engine.finish_auto_start_chat(
                                            id,
                                            Some(StartChatError::SignInRequired),
                                        );
                                        progress
                                            .try_fail("Sign-in is still required by the server.");
                                    } else {
                                        progress.clear();
                                    }
                                }
                                Err(err) => {
                                    // Retain the gesture-pushed reserved slot as `SignInDialog`
                                    // reopens `NewChat` for retry (e.g. "Allow classical").
                                    let still_owned =
                                        !cancelled && history::retain_reservation(reservation);
                                    progress.clear();
                                    if still_owned {
                                        engine.finish_auto_start_chat(id, Some(err));
                                    }
                                    engine.ui().notify(format!("Signed in until {until}."));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    clear_active(auto_start_id);
                    if alive.get() {
                        let _ = history::retain_reservation(reservation);
                        if let Some(id) = auto_start_id {
                            engine.finish_submission(id);
                        }
                        progress.try_fail(e);
                        password_input.focus();
                    } else {
                        let _ = history::cancel_reservation(reservation);
                        if let Some(id) = auto_start_id {
                            engine.finish_submission(id);
                        }
                        progress.clear();
                    }
                }
            }
        });
    };
    view! {
        <form on:submit=submit>
            <h2>"Sign in to this server"</h2>
            <p>
                "This server is only for those signed in to it, as all that goes through it "
                "costs it storage. Enter the password its owner gave you; this browser stays "
                "signed in for a while. What you sent waits until then, unless you cancel it in "
                "its chat."
            </p>
            {pending_hint.map(|hint| view! { <p class="hint">{hint}</p> })}
            <label for="server-password">"The server's password"</label>
            <input
                id="server-password"
                node_ref=password_input.node
                type="password"
                autocomplete="current-password"
                required
                autofocus
            />
            {progress.view()}
            <div class="actions">
                <button
                    type="button"
                    class="btn"
                    disabled=move || progress.working.get()
                    on:click=move |_| {
                        password_input.clear();
                        if engine().dismiss_sign_in() {
                            history::retain_active_reservation();
                        } else {
                            history::cancel_active_reservation();
                        }
                    }
                >
                    "Not now"
                </button>
                <button type="submit" class="btn primary" disabled=move || progress.working.get()>
                    "Sign in"
                </button>
            </div>
        </form>
    }
}

#[component]
pub(super) fn CreateVault() -> impl IntoView {
    let name = RwSignal::new(String::new());
    let passphrase_input = SecretInput::new();
    let repeat_input = SecretInput::new();
    let cancel_token = StoredValue::new_local(None::<KdfCancelToken>);
    on_cleanup(move || {
        if let Some(token) = cancel_token.try_update_value(Option::take).flatten() {
            token.cancel();
        }
        passphrase_input.clear();
        repeat_input.clear();
    });
    let pq_compiled = !PqConfig::compiled_suites().is_empty();
    let pq_enabled = RwSignal::new(pq_compiled);
    let page_origin = origin();
    let invited = invited_server();
    let cross_origin_invited = invited
        .as_ref()
        .is_some_and(|inv| !same_server(inv, &page_origin));
    let server = RwSignal::new(invited.unwrap_or_else(|| page_origin.clone()));
    let progress = Progress::new();
    let cancel_kdf = move |_| {
        if let Some(token) = cancel_token.try_update_value(Option::take).flatten() {
            token.cancel();
        }
    };
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        if progress.working.get_untracked() {
            return;
        }
        let target_server = match validate_relay_url(&server.get_untracked()) {
            Ok(valid) => valid,
            Err(err) => {
                progress.fail(err);
                return;
            }
        };
        let secret = passphrase_input.take();
        let repeated = repeat_input.take();
        if secret.chars().count() < 8 {
            progress.fail("Use a passphrase of 8 characters or more.");
            passphrase_input.focus();
            return;
        }
        if *secret != *repeated {
            progress.fail("The passphrases differ.");
            passphrase_input.focus();
            return;
        }
        drop(repeated);
        let enable_pq = pq_enabled.get_untracked();
        let display_name = name.get_untracked();
        let cancel = KdfCancelToken::new();
        cancel_token.set_value(Some(cancel.clone()));
        progress.start("Deriving encryption key…");
        let engine = engine();
        spawn_local(async move {
            let result = engine
                .create(
                    display_name,
                    secret,
                    target_server,
                    enable_pq,
                    cancel.clone(),
                )
                .await;
            let _ = cancel_token.try_update_value(|slot| {
                if slot.as_ref().is_some_and(|active| active.ptr_eq(&cancel)) {
                    *slot = None;
                }
            });
            match result {
                Ok(()) => {}
                Err(VaultOpenError::Cancelled) => {
                    progress.clear();
                    passphrase_input.focus();
                }
                Err(VaultOpenError::Failed(e)) => {
                    progress.try_fail(e);
                    passphrase_input.focus();
                }
            }
        });
    };
    let page_origin_for_check = page_origin.clone();
    let is_third_party = move || {
        let current = server.get();
        !current.trim().is_empty() && !same_server(&current, &page_origin_for_check)
    };
    view! {
        <form on:submit=submit>
            <h2>"Create your vault"</h2>
            <p>
                "A new identity key is made here and kept in this browser with your chats, "
                "sealed by a passphrase. There is no recovery: forget the passphrase, and the "
                "vault is lost."
            </p>
            <label for="name">"Your name, which new chats see"</label>
            <input
                id="name"
                autocomplete="nickname"
                maxlength=NAME_MAX
                disabled=move || progress.working.get()
                bind:value=name
            />
            <label for="password">"Passphrase"</label>
            <input
                id="password"
                type="password"
                autocomplete="new-password"
                required
                disabled=move || progress.working.get()
                node_ref=passphrase_input.node
            />
            <label for="repeat">"Passphrase, again"</label>
            <input
                id="repeat"
                type="password"
                autocomplete="new-password"
                required
                disabled=move || progress.working.get()
                node_ref=repeat_input.node
            />
            <label for="server">"Server"</label>
            <input
                id="server"
                type="url"
                required
                disabled=move || progress.working.get()
                bind:value=server
            />
            <Show when=is_third_party>
                <p class="warning" role="alert">
                    {if cross_origin_invited {
                        "Warning: this invitation link pre-filled a third-party relay server ("
                    } else {
                        "Warning: this is a third-party relay server ("
                    }}
                    {move || server.get()}
                    "). Creating your vault permanently binds your identity to that relay and cannot be changed later. "
                    <button
                        type="button"
                        class="link"
                        disabled=move || progress.working.get()
                        on:click={
                            let page_origin = page_origin.clone();
                            move |_| server.set(page_origin.clone())
                        }
                    >
                        "Use this page's server instead"
                    </button>
                </p>
            </Show>
            {pq_compiled.then(|| {
                view! {
                    <div class="settings-card create-pq">
                        <ToggleSwitch
                            id="create-pq"
                            title="Post-quantum encryption"
                            description="Protects new chats against future quantum computers."
                            checked=Signal::derive(move || pq_enabled.get())
                            disabled=Signal::derive(move || progress.working.get())
                            on_toggle=move |on| pq_enabled.set(on)
                        />
                    </div>
                }
            })}
            {progress.view()}
            <div class="actions">
                <Show when=move || progress.working.get()>
                    <button type="button" class="btn" on:click=cancel_kdf>
                        "Cancel"
                    </button>
                </Show>
                <button class="btn primary" type="submit" disabled=move || progress.working.get()>
                    "Create"
                </button>
            </div>
        </form>
    }
}

#[component]
pub(super) fn UnlockVault() -> impl IntoView {
    let passphrase_input = SecretInput::new();
    let cancel_token = StoredValue::new_local(None::<KdfCancelToken>);
    let deriving = RwSignal::new(false);
    on_cleanup(move || {
        if let Some(token) = cancel_token.try_update_value(Option::take).flatten() {
            token.cancel();
        }
        passphrase_input.clear();
    });
    let progress = Progress::new();
    let confirm_reset = ConfirmGuard::new();
    let cancel_kdf = move |_| {
        if let Some(token) = cancel_token.try_update_value(Option::take).flatten() {
            token.cancel();
        }
    };
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        if progress.working.get_untracked() {
            return;
        }
        confirm_reset.disarm();
        let secret = passphrase_input.take();
        let cancel = KdfCancelToken::new();
        cancel_token.set_value(Some(cancel.clone()));
        deriving.set(true);
        progress.start("Deriving encryption key…");
        let engine = engine();
        spawn_local(async move {
            let result = engine.unlock(secret, cancel.clone()).await;
            let _ = cancel_token.try_update_value(|slot| {
                if slot.as_ref().is_some_and(|active| active.ptr_eq(&cancel)) {
                    *slot = None;
                }
            });
            let _ = deriving.try_set(false);
            match result {
                Ok(()) => {}
                Err(VaultOpenError::Cancelled) => {
                    progress.clear();
                    passphrase_input.focus();
                }
                Err(VaultOpenError::Failed(e)) => {
                    progress.try_fail(e);
                    passphrase_input.focus();
                }
            }
        });
    };
    let reset = move |_| {
        if progress.working.get_untracked() {
            return;
        }
        if !confirm_reset.confirm_or_arm() {
            return;
        }
        passphrase_input.clear();
        progress.start("Deleting the vault…");
        spawn_local(async move {
            match crate::vault::Vault::destroy().await {
                Ok(()) => lock(),
                Err(e) => progress.try_fail(e.to_string()),
            }
        });
    };
    view! {
        <form on:submit=submit>
            <h2>"Unlock your vault"</h2>
            <p>"Your identity key and chats are sealed in this browser by your passphrase."</p>
            <label for="password">"Passphrase"</label>
            <input
                id="password"
                type="password"
                autocomplete="current-password"
                required
                autofocus
                disabled=move || progress.working.get()
                node_ref=passphrase_input.node
            />
            {progress.view()}
            <div class="actions">
                <Show
                    when=move || deriving.get()
                    fallback=move || {
                        view! {
                            <button
                                type="button"
                                class="btn danger"
                                disabled=move || progress.working.get()
                                on:click=reset
                            >
                                {move || {
                                    if confirm_reset.is_armed() {
                                        "Delete it all, for good?"
                                    } else {
                                        "Forgot it: start over"
                                    }
                                }}
                            </button>
                        }
                    }
                >
                    <button type="button" class="btn" on:click=cancel_kdf>
                        "Cancel"
                    </button>
                </Show>
                <button class="btn primary" type="submit" disabled=move || progress.working.get()>
                    "Unlock"
                </button>
            </div>
        </form>
    }
}

#[component]
pub(super) fn IncompatibleVault(version: u32) -> impl IntoView {
    let progress = Progress::new();
    let confirm_reset = ConfirmGuard::new();
    let reset = move |_| {
        if progress.working.get_untracked() {
            return;
        }
        if !confirm_reset.confirm_or_arm() {
            return;
        }
        progress.start("Deleting incompatible vault…");
        spawn_local(async move {
            match crate::vault::Vault::destroy().await {
                Ok(()) => lock(),
                Err(e) => progress.try_fail(e.to_string()),
            }
        });
    };
    view! {
        <div>
            <h2>"Incompatible vault format"</h2>
            <p>
                {format!(
                    "This browser holds a vault from format version {version}, which is \
                     incompatible with the current vault format (v{}). Automatic migration is \
                     not supported; reset the vault to create a new identity and start fresh.",
                    crate::vault::VAULT_VERSION_V3
                )}
            </p>
            <p class="warning" role="alert">
                "Resetting permanently deletes the incompatible local vault, keys, and chat \
                 history from this browser."
            </p>
            {progress.view()}
            <div class="actions">
                <button
                    type="button"
                    class="btn danger"
                    disabled=move || progress.working.get()
                    on:click=reset
                >
                    {move || {
                        if confirm_reset.is_armed() {
                            "Delete old vault, for good?"
                        } else {
                            "Reset vault and start over"
                        }
                    }}
                </button>
            </div>
        </div>
    }
}

#[component]
pub(super) fn Elsewhere() -> impl IntoView {
    view! {
        <div>
            <h2>"Open in another tab"</h2>
            <p>
                "The vault is open in another tab or window of this browser. Two pages on one "
                "vault would tangle its sessions, so close the other one — this page will "
                "continue automatically, or you can reload it."
            </p>
            <div class="actions">
                <button class="btn primary" on:click=move |_| lock()>
                    "Reload"
                </button>
            </div>
        </div>
    }
}

#[component]
pub(super) fn Unavailable(reason: UnavailableReason, error: String) -> impl IntoView {
    let progress = Progress::new();
    let confirm_reset = ConfirmGuard::new();
    let allow_reset = reason == UnavailableReason::CorruptVault;
    let reset = move |_| {
        if progress.working.get_untracked() {
            return;
        }
        if !confirm_reset.confirm_or_arm() {
            return;
        }
        progress.start("Deleting incomplete vault…");
        spawn_local(async move {
            match crate::vault::Vault::destroy().await {
                Ok(()) => lock(),
                Err(e) => progress.try_fail(e.to_string()),
            }
        });
    };
    let (heading, copy) = match reason {
        UnavailableReason::InsecureContext => (
            "Secure context required",
            "Open this page over HTTPS (or localhost) so the browser provides the Web Locks API \
             needed to keep concurrent tabs from corrupting your vault.",
        ),
        UnavailableReason::LocksUnavailable => (
            "Web Locks unavailable",
            "This browser does not provide the Web Locks API needed to prevent concurrent tabs \
             from corrupting your vault. Try a modern browser or check site restrictions.",
        ),
        UnavailableReason::StorageUnavailable => (
            "Storage unavailable",
            "The browser would not open its storage, so whether a vault is here is unknown, and \
             nothing was changed. Private windows and blocked site data can cause this.",
        ),
        UnavailableReason::CorruptVault => (
            "Vault data incomplete or corrupt",
            "The vault header is missing, but encrypted records or rollback metadata still exist \
             in this browser. Nothing was overwritten automatically. Reset the vault explicitly \
             if you want to discard the remaining data and start fresh.",
        ),
    };
    view! {
        <div>
            <h2>{heading}</h2>
            <p>{copy}</p>
            <p class="error">{error}</p>
            {progress.view()}
            <div class="actions">
                <Show when=move || allow_reset>
                    <button
                        type="button"
                        class="btn danger"
                        disabled=move || progress.working.get()
                        on:click=reset
                    >
                        {move || {
                            if confirm_reset.is_armed() {
                                "Delete incomplete vault, for good?"
                            } else {
                                "Reset vault and start over"
                            }
                        }}
                    </button>
                </Show>
                <button
                    class="btn primary"
                    disabled=move || progress.working.get()
                    on:click=move |_| lock()
                >
                    "Reload"
                </button>
            </div>
        </div>
    }
}
