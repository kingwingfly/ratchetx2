use leptos::{ev, prelude::*, task::spawn_local};
use session::{PqConfig, PqSuite};

use crate::{
    engine::{PqSaveOutcome, origin, same_server},
    state::{Dialog, ServerPqStatus, SignIn},
    util::day,
};

use super::{
    common::{ToggleSwitch, act_while, close_dialog, server_pq_disabled},
    engine, ui,
};

/// Display label and concise hint for an ML-KEM suite in the segmented control.
fn pq_suite_option(suite: PqSuite) -> (&'static str, &'static str) {
    match suite {
        PqSuite::MlKem1024 => ("ML-KEM-1024", "Stronger"),
        PqSuite::MlKem768 => ("ML-KEM-768", "Smaller"),
    }
}

/// Compact pill `(css_class, label, tooltip)` for the server's advertised PQ support.
fn server_pq_pill(status: &ServerPqStatus) -> (&'static str, &'static str, String) {
    match status {
        ServerPqStatus::Enabled { suites, pq_ratchet } => {
            let names: Vec<_> = suites
                .iter()
                .map(|s| match s {
                    PqSuite::MlKem1024 => "ML-KEM-1024",
                    PqSuite::MlKem768 => "ML-KEM-768",
                })
                .collect();
            let list = if names.is_empty() {
                "enabled".to_string()
            } else {
                names.join(", ")
            };
            let title = if *pq_ratchet {
                format!("Server supports post-quantum encryption ({list}, continuous re-keying).")
            } else {
                format!("Server supports post-quantum encryption ({list}).")
            };
            ("sec-badge pq", "Server: PQ ready", title)
        }
        ServerPqStatus::Disabled => (
            "sec-badge classical",
            "Server: Classical only",
            "This server does not have post-quantum encryption enabled.".to_string(),
        ),
        ServerPqStatus::AudienceMismatch => (
            "sec-badge danger",
            "Server: ID mismatch",
            "Server ID did not match this server's expected audience.".to_string(),
        ),
        ServerPqStatus::Unknown => (
            "sec-badge neutral",
            "Server: Checking…",
            "Checking server post-quantum support…".to_string(),
        ),
    }
}

#[component]
pub(super) fn Settings() -> impl IntoView {
    let ui = ui();
    let Some(me) = ui.me.get_untracked() else {
        return ().into_any();
    };
    let server_url = me.server.clone();
    let can_sign_in_here = same_server(&server_url, &origin());
    let compiled_suites = PqConfig::compiled_suites();
    let pq_compiled = !compiled_suites.is_empty();
    let initial_pq = me.pq_config.clone();
    let pq_enabled = RwSignal::new(pq_compiled && initial_pq.pq_enabled);
    let preferred_suite = RwSignal::new(if compiled_suites.contains(&initial_pq.preferred_suite) {
        initial_pq.preferred_suite
    } else {
        PqConfig::default_suite()
    });
    let pq_ratchet_enabled = RwSignal::new(pq_compiled && initial_pq.pq_ratchet_enabled);
    let strict_pq = RwSignal::new(pq_compiled && initial_pq.pq_enabled && initial_pq.strict_pq);
    let advanced_open = pq_compiled && (initial_pq.strict_pq || !initial_pq.pq_ratchet_enabled);
    let server_pq_disabled = Signal::derive(move || server_pq_disabled(ui));
    // Saving settings, signing out, or deleting an isolated contact, which buttons wait for.
    let busy = RwSignal::new(false);
    let confirm_isolated = RwSignal::new(None::<Vec<u8>>);
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        if !pq_compiled {
            close_dialog();
            return;
        }
        let engine = engine();
        let next_pq = PqConfig {
            pq_enabled: pq_enabled.get_untracked(),
            preferred_suite: preferred_suite.get_untracked(),
            pq_ratchet_enabled: pq_ratchet_enabled.get_untracked(),
            strict_pq: pq_enabled.get_untracked() && strict_pq.get_untracked(),
        };
        act_while(busy, async move {
            // Always invoke `set_pq_config`: it compares against live vault state, rolls back
            // definitively refused configs, and reports durable local saves clearly.
            let outcome = engine.set_pq_config(next_pq).await?;
            engine.ui().dialog.set(None);
            match outcome {
                PqSaveOutcome::Published => engine
                    .ui()
                    .notify("Saved settings and published updated prekeys."),
                PqSaveOutcome::Unchanged => engine.ui().notify("Settings saved."),
                PqSaveOutcome::SavedLocallyNeedsSignIn => engine
                    .ui()
                    .notify("Saved locally; sign in to publish updated prekeys."),
                PqSaveOutcome::SavedLocallyPendingPublish => engine
                    .ui()
                    .notify("Saved locally; prekeys will publish once connected."),
            }
            Ok(())
        });
    };
    // Whether this browser is signed in to the server (only possible on the server's own origin).
    let signed_in = RwSignal::new(None::<Result<Option<SignIn>, String>>);
    if can_sign_in_here {
        spawn_local(async move {
            signed_in.try_set(Some(engine().signed_in().await));
        });
    }
    let sign_out = move |_| {
        let engine = engine();
        act_while(busy, async move {
            engine.sign_out().await?;
            signed_in.try_set(Some(Ok(None)));
            engine
                .ui()
                .notify("Signed out: messages and files wait for the next sign-in.");
            Ok(())
        });
    };
    let pq_controls_disabled = Signal::derive(move || busy.get() || !pq_enabled.get());
    let strict_pq_disabled = Signal::derive(move || {
        pq_controls_disabled.get() || (server_pq_disabled.get() && !strict_pq.get())
    });
    let server_row = move || {
        if !can_sign_in_here {
            return view! {
                <div class="settings-server-row">
                    <div class="settings-copy">
                        <strong>"Different server origin"</strong>
                        <small>
                            {format!(
                                "Your vault uses {server_url}. Open that server's own page to sign in or out."
                            )}
                        </small>
                    </div>
                </div>
            }
            .into_any();
        }
        match signed_in.get() {
            None => view! {
                <div class="settings-server-row">
                    <div class="settings-copy">
                        <span class="settings-muted">"Checking sign-in status…"</span>
                    </div>
                </div>
            }
            .into_any(),
            Some(Ok(Some(signed_in))) => view! {
                <div class="settings-server-row">
                    <div class="settings-copy">
                        <strong>{format!("Signed in until {}", day(signed_in.expires))}</strong>
                        <small>{server_url.clone()}</small>
                    </div>
                    <button
                        type="button"
                        class="btn small"
                        disabled=move || busy.get()
                        on:click=sign_out
                    >
                        "Sign out"
                    </button>
                </div>
            }
            .into_any(),
            Some(Ok(None)) => view! {
                <div class="settings-server-row">
                    <div class="settings-copy">
                        <strong>"Not signed in"</strong>
                        <small>"Sign in to send messages and files through this server."</small>
                    </div>
                    <button
                        type="button"
                        class="btn primary small"
                        disabled=move || busy.get()
                        on:click=move |_| ui.dialog.set(Some(Dialog::SignIn))
                    >
                        "Sign in"
                    </button>
                </div>
            }
            .into_any(),
            Some(Err(e)) => view! {
                <div class="settings-server-row">
                    <div class="settings-copy">
                        <span class="settings-error">{format!("Cannot reach server: {e}")}</span>
                    </div>
                </div>
            }
            .into_any(),
        }
    };
    let encryption_card = if pq_compiled {
        let suites_for_segments = compiled_suites.clone();
        view! {
            <div class="settings-card">
                <ToggleSwitch
                    id="pq-enabled"
                    title="Post-quantum encryption"
                    description="Protects new chats against future quantum computers."
                    checked=Signal::derive(move || pq_enabled.get())
                    disabled=Signal::derive(move || busy.get())
                    on_toggle=move |on| {
                        pq_enabled.set(on);
                        if !on {
                            strict_pq.set(false);
                        }
                    }
                />
                <div class="settings-block" class:disabled=move || pq_controls_disabled.get()>
                    <div id="pq-strength-label" class="settings-sublabel">
                        "Preferred key strength"
                    </div>
                    <div
                        class="segmented"
                        role="radiogroup"
                        aria-labelledby="pq-strength-label"
                    >
                        {suites_for_segments
                            .into_iter()
                            .map(|suite| {
                                let (label, hint) = pq_suite_option(suite);
                                view! {
                                    <button
                                        type="button"
                                        class="segment"
                                        class:active=move || preferred_suite.get() == suite
                                        role="radio"
                                        aria-checked=move || {
                                            if preferred_suite.get() == suite {
                                                "true"
                                            } else {
                                                "false"
                                            }
                                        }
                                        disabled=move || pq_controls_disabled.get()
                                        on:click=move |_| preferred_suite.set(suite)
                                    >
                                        <span class="segment-title">{label}</span>
                                        <span class="segment-hint">{hint}</span>
                                    </button>
                                }
                            })
                            .collect_view()}
                    </div>
                </div>
                <p class="settings-note">
                    "Changes apply to new or re-keyed chats; existing chats keep their current encryption."
                </p>
                <Show when=move || server_pq_disabled.get()>
                    <p class="settings-warn">
                        "This server does not have post-quantum encryption enabled. New chats will \
                         use classical encryption, and Require post-quantum cannot be turned on."
                    </p>
                </Show>
                <details class="settings-advanced" open=advanced_open>
                    <summary>"Advanced"</summary>
                    <div class="settings-advanced-body">
                        <ToggleSwitch
                            id="pq-ratchet"
                            title="Continuous PQ re-keying"
                            description="Refresh quantum-resistant keys during long chats so sessions recover if a device is ever compromised."
                            checked=Signal::derive(move || pq_ratchet_enabled.get())
                            disabled=pq_controls_disabled
                            on_toggle=move |on| pq_ratchet_enabled.set(on)
                        />
                        <ToggleSwitch
                            id="pq-strict"
                            title="Require post-quantum"
                            description="Block classical-only chats and refuse fallback."
                            checked=Signal::derive(move || strict_pq.get())
                            disabled=strict_pq_disabled
                            on_toggle=move |on| strict_pq.set(on)
                        />
                    </div>
                </details>
            </div>
        }
        .into_any()
    } else {
        view! {
            <div class="settings-card">
                <div class="settings-status-row">
                    <div class="settings-copy">
                        <strong>"Classical encryption only"</strong>
                        <small>"This client was built without post-quantum cryptography."</small>
                    </div>
                    <span class="sec-badge classical">"Classical"</span>
                </div>
            </div>
        }
        .into_any()
    };
    view! {
        <form class="settings-form" on:submit=submit>
            <h2>"Settings"</h2>
            <section class="settings-section">
                <div class="settings-section-head">
                    <h3>"Encryption"</h3>
                    {pq_compiled.then_some(move || {
                        ui.me.with(|me| {
                            me.as_ref().map(|m| {
                                let (class, label, title) = server_pq_pill(&m.server_pq);
                                view! {
                                    <span class=class title=title>
                                        {label}
                                    </span>
                                }
                            })
                        })
                    })}
                </div>
                {encryption_card}
            </section>
            <section class="settings-section">
                <div class="settings-section-head">
                    <h3>"Server"</h3>
                </div>
                <div class="settings-card">{server_row}</div>
            </section>
            <Show when=move || !ui.isolated_contacts.with(Vec::is_empty)>
                <section class="settings-section">
                    <div class="settings-section-head">
                        <h3>"Isolated contacts"</h3>
                        <span class="sec-badge danger">"Corrupt record"</span>
                    </div>
                    <div class="settings-card">
                        <p class="settings-warn isolated-intro">
                            "Corrupt contact records stay isolated so post-quantum pinning and \
                             local history are never silently discarded. Delete an isolated record \
                             to permanently clear it and allow starting a new chat with that peer."
                        </p>
                        <For
                            each=move || ui.isolated_contacts.get()
                            key=|item| (item.raw_peer.clone(), item.records, item.pq_pinned)
                            children=move |item| {
                                let raw_peer = StoredValue::new(item.raw_peer);
                                let label = StoredValue::new(item.label);
                                let pq_pinned = item.pq_pinned;
                                let detail = if item.records > 1 {
                                    format!("{} ({} corrupt records)", item.reason, item.records)
                                } else {
                                    item.reason
                                };
                                let asking = Signal::derive(move || {
                                    confirm_isolated.with(|pending| {
                                        pending.as_ref().is_some_and(|p| raw_peer.with_value(|r| p == r))
                                    })
                                });
                                view! {
                                    <div class="isolated-row">
                                        <div class="isolated-row-head">
                                            <div class="settings-copy">
                                                <strong>{label.get_value()}</strong>
                                                <small>{detail}</small>
                                            </div>
                                            <Show when=move || !asking.get()>
                                                <button
                                                    type="button"
                                                    class="btn danger small"
                                                    disabled=move || busy.get()
                                                    on:click=move |_| {
                                                        confirm_isolated.set(Some(raw_peer.get_value()));
                                                    }
                                                >
                                                    "Delete…"
                                                </button>
                                            </Show>
                                        </div>
                                        {pq_pinned.then(|| {
                                            view! {
                                                <span class="sec-meta">
                                                    "Post-quantum encryption was pinned for this peer."
                                                </span>
                                            }
                                        })}
                                        <Show when=move || asking.get()>
                                            <div class="isolated-confirm" role="alert">
                                                <p>
                                                    {if pq_pinned {
                                                        "Permanently delete this isolated contact, its local history, and its post-quantum pin?"
                                                    } else {
                                                        "Permanently delete this isolated contact and its local history?"
                                                    }}
                                                </p>
                                                <div class="isolated-actions">
                                                    <button
                                                        type="button"
                                                        class="btn small"
                                                        disabled=move || busy.get()
                                                        on:click=move |_| confirm_isolated.set(None)
                                                    >
                                                        "Keep"
                                                    </button>
                                                    <button
                                                        type="button"
                                                        class="btn danger small"
                                                        disabled=move || busy.get()
                                                        on:click=move |_| {
                                                            let engine = engine();
                                                            let peer_bytes = raw_peer.get_value();
                                                            let name = label.get_value();
                                                            act_while(busy, async move {
                                                                engine.delete_isolated(peer_bytes).await?;
                                                                confirm_isolated.try_set(None);
                                                                engine.ui().notify(format!(
                                                                    "Deleted isolated contact {name}."
                                                                ));
                                                                Ok(())
                                                            });
                                                        }
                                                    >
                                                        "Confirm delete"
                                                    </button>
                                                </div>
                                            </div>
                                        </Show>
                                    </div>
                                }
                            }
                        />
                    </div>
                </section>
            </Show>
            <div class="actions">
                {if pq_compiled {
                    view! {
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
                    }
                    .into_any()
                } else {
                    view! {
                        <button
                            type="button"
                            class="btn primary"
                            disabled=move || busy.get()
                            on:click=move |_| close_dialog()
                        >
                            "Close"
                        </button>
                    }
                    .into_any()
                }}
            </div>
        </form>
    }
    .into_any()
}
