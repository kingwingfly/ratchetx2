use leptos::{ev, html, prelude::*};
use session::PublicKey;

use crate::{
    content,
    icon::{Icon, icon},
};

use super::common::{send, send_files_to};

/// Whether entering a chat should auto-focus the composer textarea.
///
/// Desktop devices with a fine hovering pointer (mouse/trackpad) keep auto-focus so typing starts
/// right away; touch-first portable devices (phones, tablets, 2-in-1s in tablet mode) skip
/// auto-focus so the virtual keyboard does not pop up automatically.
fn should_autofocus_composer(hover_none: bool, pointer_coarse: bool) -> bool {
    !(hover_none || pointer_coarse)
}

fn matches_media(query: &str) -> bool {
    window()
        .match_media(query)
        .ok()
        .flatten()
        .is_some_and(|list| list.matches())
}

fn autofocus_allowed() -> bool {
    should_autofocus_composer(
        matches_media("(hover: none)"),
        matches_media("(pointer: coarse)"),
    )
}

#[component]
pub(super) fn Composer(
    peer: PublicKey,
    disabled: Signal<bool>,
    placeholder: Signal<&'static str>,
) -> impl IntoView {
    let text = RwSignal::new(String::new());
    let textarea = NodeRef::<html::Textarea>::new();
    let file_input = NodeRef::<html::Input>::new();
    // Typing goes to the composer when a chat opens on devices with a physical keyboard;
    // skip on portable/touch devices so the virtual keyboard does not pop up automatically.
    Effect::new(move || {
        if autofocus_allowed()
            && !disabled.get_untracked()
            && let Some(textarea) = textarea.get()
        {
            let _ = textarea.focus();
        }
    });
    let submit = move || {
        if disabled.get_untracked() {
            return;
        }
        let message = text.get_untracked();
        let trimmed = message.trim();
        if trimmed.is_empty() {
            return;
        }
        if trimmed.len() > crate::engine::MAX_TEXT_BYTES {
            super::ui().notify(format!(
                "Message is too long (maximum {} KiB).",
                crate::engine::MAX_TEXT_BYTES / 1024
            ));
            return;
        }
        text.set(String::new());
        send(peer, content::Kind::Text(trimmed.to_string()));
    };
    let on_keydown = move |event: ev::KeyboardEvent| {
        if event.key() == "Enter" && !event.shift_key() && !event.is_composing() {
            event.prevent_default();
            submit();
        }
    };
    let on_files_change = move |event: ev::Event| {
        let input: web_sys::HtmlInputElement = event_target(&event);
        if super::ui().open.get_untracked() == Some(peer)
            && disabled.try_get_untracked() == Some(false)
            && let Some(files) = input.files()
        {
            send_files_to(peer, files);
        }
        // So that picking the same file again sends it again.
        input.set_value("");
    };
    let rows = move || text.with(|text| text.split('\n').count().clamp(1, 6));
    view! {
        <div class="composer">
            <button
                type="button"
                class="btn icon"
                title="Attach files, or drop them on the page"
                aria-label="Attach files"
                disabled=disabled
                on:click=move |_| {
                    if let Some(input) = file_input.get_untracked() {
                        input.click();
                    }
                }
            >
                {icon(Icon::Attach)}
            </button>
            <textarea
                node_ref=textarea
                rows=rows
                placeholder=move || placeholder.get()
                disabled=disabled
                prop:value=move || text.get()
                on:input=move |event| text.set(event_target_value(&event))
                on:keydown=on_keydown
            ></textarea>
            <button
                class="btn icon primary"
                title="Send (Enter)"
                aria-label="Send"
                disabled=disabled
                on:click=move |_| submit()
            >
                {icon(Icon::Send)}
            </button>
            <input type="file" multiple hidden node_ref=file_input on:change=on_files_change />
        </div>
    }
}
