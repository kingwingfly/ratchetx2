use leptos::{ev, html, prelude::*, task::spawn_local};
use session::{PublicKey, safety_number};

use crate::{
    engine::{NAME_MAX, StartChatError, same_server},
    state::{ClassicalPrompt, Dialog, PendingNewChat, Phase},
    util::{key_to_text, short},
};

use super::{
    ActivityList, Toast,
    auth::{CreateVault, Elsewhere, SignInDialog, Unavailable, UnlockVault},
    chat::{contact_can_upgrade_to_pq, security_badge},
    common::{
        AllowClassical, Copyable, Progress, act_while, can_allow_classical, close_dialog,
        invitation_link, pq_available, server_pq_disabled, strict_pq_enabled, upgrade_disabled_tip,
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
    Effect::new(move || {
        let shown = shown();
        if let Some(dialog) = dialog.get() {
            if shown && !dialog.open() {
                let _ = dialog.show_modal();
            } else if !shown && dialog.open() {
                dialog.close();
            }
        }
    });
    let on_cancel = move |event: ev::Event| {
        // The vault's dialog stays until the vault opens.
        if ui.phase.get_untracked() != Phase::Unlocked {
            event.prevent_default();
        } else if ui
            .dialog
            .with_untracked(|dialog| matches!(dialog, Some(Dialog::SignIn)))
        {
            // Dismissed, e.g. with Escape, the sign-in is put off, as "Not now" puts it off.
            // If an invitation / NewChat draft was waiting behind sign-in, restore it and keep
            // the native modal dialog open instead of letting it close and clear `ui.dialog`.
            if engine().dismiss_sign_in() {
                event.prevent_default();
            }
        }
    };
    let on_close = move |_| {
        // Ignore stale queued close events if a new modal dialog has already opened.
        if dialog.get_untracked().is_some_and(|d| !d.open()) {
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
        StartChatError::SignInRequired => progress.clear(),
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
    let key = RwSignal::new(key);
    let name = RwSignal::new(name);
    let server_saved = StoredValue::new(server);
    Effect::new(move || {
        engine().new_chat_edited(key.get(), name.get());
    });
    on_cleanup(move || {
        engine().new_chat_unmounted();
    });
    let progress = Progress::new();
    let classical_needed = RwSignal::new(None::<bool>);
    if let Some(feedback) = engine().take_new_chat_feedback() {
        apply_start_chat_error(feedback, classical_needed, progress);
    }
    let start = move |allow_classical: bool| {
        classical_needed.set(None);
        progress.start("Fetching their prekeys…");
        let engine = engine();
        let draft = PendingNewChat {
            key: key.get_untracked(),
            name: name.get_untracked(),
            server: server_saved.get_value(),
            pq_pinned,
            allow_classical,
            auto_start: true,
        };
        engine.begin_new_chat_submit(draft.clone());
        spawn_local(async move {
            let outcome = engine
                .start_chat(
                    &draft.key,
                    draft.name.clone(),
                    draft.pq_pinned,
                    draft.allow_classical,
                )
                .await;
            engine.end_new_chat_submit();
            match outcome {
                Ok(peer) => {
                    engine.close_dialog_if_new_chat();
                    engine.open(Some(peer)).await;
                }
                Err(StartChatError::SignInRequired) => {
                    progress.clear();
                    engine.require_sign_in_for_new_chat(draft);
                }
                Err(err) => apply_start_chat_error(err, classical_needed, progress),
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
            <input id="peer-key" required autocomplete="off" spellcheck="false" bind:value=key />
            <label for="peer-name">"Their name, for you"</label>
            <input id="peer-name" autocomplete="off" bind:value=name />
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
                    on:click=move |_| close_dialog()
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
            engine.ui().dialog.set(None);
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
        act_while(busy, async move {
            if req {
                engine.accept(peer, name.get_untracked()).await?;
            } else {
                engine.rename(peer, name.get_untracked()).await?;
            }
            engine.ui().dialog.set(None);
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
            engine.ui().dialog.set(None);
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
                    let show_dismiss = c.has_downgrade();
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
            <input id="contact-name" autocomplete="off" bind:value=name />
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
