use leptos::{ev, prelude::*, task::spawn_local};
use session::PqConfig;

use crate::{
    engine::{NAME_MAX, StartChatError, origin},
    state::{Dialog, SignInSuccessAction, UnavailableReason},
    util::{day, sleep},
};

use super::{
    common::{ASKED_SHOWN, Progress, SecretInput, ToggleSwitch, invited_server, lock},
    engine,
};

/// Sign in to the server with its password, which storing files there takes, as they cost it
/// storage: what waited for it goes then, and any pending invitation / new-chat draft resumes.
#[component]
pub(super) fn SignInDialog() -> impl IntoView {
    let password_input = SecretInput::new();
    on_cleanup(move || password_input.clear());
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
        progress.start("Signing in…");
        spawn_local(async move {
            let result = engine.sign_in(&secret).await;
            drop(secret);
            match result {
                Ok(signed_in) => {
                    let until = day(signed_in.expires);
                    match engine.complete_sign_in_flow() {
                        SignInSuccessAction::Close => {
                            engine.close_dialog_if_sign_in();
                            engine.ui().notify(format!(
                                "Signed in until {until}: waiting messages and files go now."
                            ));
                        }
                        SignInSuccessAction::ReopenNewChat(dialog) => {
                            engine.ui().dialog.set(Some(dialog));
                            engine.ui().notify(format!("Signed in until {until}."));
                        }
                        SignInSuccessAction::AutoStartChat(pending) => {
                            progress.try_start("Starting chat…");
                            match engine
                                .start_chat(
                                    &pending.key,
                                    pending.name.clone(),
                                    pending.pq_pinned,
                                    pending.allow_classical,
                                )
                                .await
                            {
                                Ok(peer) => {
                                    engine.finish_auto_start_chat(None);
                                    engine.close_dialog_if_new_chat();
                                    engine.open(Some(peer)).await;
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
                                Err(StartChatError::SignInRequired) => {
                                    engine.finish_auto_start_chat(Some(
                                        StartChatError::SignInRequired,
                                    ));
                                    progress.try_fail("Sign-in is still required by the server.");
                                }
                                Err(err) => {
                                    progress.clear();
                                    engine.finish_auto_start_chat(Some(err));
                                    engine.ui().notify(format!("Signed in until {until}."));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    progress.try_fail(e);
                    password_input.focus();
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
                        engine().dismiss_sign_in();
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
    on_cleanup(move || {
        passphrase_input.clear();
        repeat_input.clear();
    });
    let pq_compiled = !PqConfig::compiled_suites().is_empty();
    let pq_enabled = RwSignal::new(pq_compiled);
    let invited = invited_server();
    let server = RwSignal::new(invited.clone().unwrap_or_else(origin));
    let progress = Progress::new();
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        if progress.working.get_untracked() {
            return;
        }
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
        let target_server = server.get_untracked();
        progress.start("Deriving the key…");
        let engine = engine();
        spawn_local(async move {
            // Argon2 blocks the page for a moment; let it show why first.
            sleep(50).await;
            let result = engine
                .create(display_name, secret, target_server, enable_pq)
                .await;
            if let Err(e) = result {
                progress.try_fail(e);
            }
        });
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
            <input id="name" autocomplete="nickname" maxlength=NAME_MAX bind:value=name />
            <label for="password">"Passphrase"</label>
            <input
                id="password"
                type="password"
                autocomplete="new-password"
                required
                node_ref=passphrase_input.node
            />
            <label for="repeat">"Passphrase, again"</label>
            <input
                id="repeat"
                type="password"
                autocomplete="new-password"
                required
                node_ref=repeat_input.node
            />
            <label for="server">"Server"</label>
            <input id="server" type="url" required bind:value=server />
            {invited
                .map(|_| {
                    view! {
                        <p class="hint">
                            "The server of your invitation: a chat needs both of you on one."
                        </p>
                    }
                })}
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
    on_cleanup(move || passphrase_input.clear());
    let progress = Progress::new();
    let confirm_reset = RwSignal::new(false);
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        if progress.working.get_untracked() {
            return;
        }
        let secret = passphrase_input.take();
        progress.start("Deriving the key…");
        let engine = engine();
        spawn_local(async move {
            sleep(50).await;
            if let Err(e) = engine.unlock(secret).await {
                progress.try_fail(e);
                passphrase_input.focus();
            }
        });
    };
    let reset = move |_| {
        if progress.working.get_untracked() {
            return;
        }
        if !confirm_reset.get_untracked() {
            confirm_reset.set(true);
            set_timeout(
                move || {
                    if confirm_reset.try_get_untracked() == Some(true)
                        && progress.working.try_get_untracked() == Some(false)
                    {
                        confirm_reset.set(false);
                    }
                },
                ASKED_SHOWN,
            );
            return;
        }
        passphrase_input.clear();
        progress.start("Deleting the vault…");
        spawn_local(async move {
            match crate::vault::Vault::destroy().await {
                Ok(()) => lock(),
                Err(e) => progress.fail(e.to_string()),
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
                node_ref=passphrase_input.node
            />
            {progress.view()}
            <div class="actions">
                <button
                    type="button"
                    class="btn danger"
                    disabled=move || progress.working.get()
                    on:click=reset
                >
                    {move || {
                        if confirm_reset.get() {
                            "Delete it all, for good?"
                        } else {
                            "Forgot it: start over"
                        }
                    }}
                </button>
                <button class="btn primary" type="submit" disabled=move || progress.working.get()>
                    "Unlock"
                </button>
            </div>
        </form>
    }
}

#[component]
pub(super) fn Elsewhere() -> impl IntoView {
    view! {
        <div>
            <h2>"Open in another tab"</h2>
            <p>
                "The vault is open in another tab or window of this browser. Two pages on one "
                "vault would tangle its sessions, so close the other one, then reload this page."
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
    };
    view! {
        <div>
            <h2>{heading}</h2>
            <p>{copy}</p>
            <p class="error">{error}</p>
            <div class="actions">
                <button class="btn primary" on:click=move |_| lock()>
                    "Reload"
                </button>
            </div>
        </div>
    }
}
