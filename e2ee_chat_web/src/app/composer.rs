use leptos::{ev, html, prelude::*};
use session::PublicKey;

use crate::{
    content,
    icon::{Icon, icon},
};

use super::common::{send, send_files};

#[component]
pub(super) fn Composer(
    peer: PublicKey,
    disabled: Signal<bool>,
    placeholder: Signal<&'static str>,
) -> impl IntoView {
    let text = RwSignal::new(String::new());
    let textarea = NodeRef::<html::Textarea>::new();
    let file_input = NodeRef::<html::Input>::new();
    // Typing goes to the composer when a chat opens.
    Effect::new(move || {
        if let Some(textarea) = textarea.get() {
            let _ = textarea.focus();
        }
    });
    let submit = move || {
        let message = text.get_untracked();
        if message.trim().is_empty() {
            return;
        }
        text.set(String::new());
        send(peer, content::Kind::Text(message.trim().to_string()));
    };
    let on_keydown = move |event: ev::KeyboardEvent| {
        if event.key() == "Enter" && !event.shift_key() && !event.is_composing() {
            event.prevent_default();
            submit();
        }
    };
    let on_files_change = move |event: ev::Event| {
        let input: web_sys::HtmlInputElement = event_target(&event);
        if let Some(files) = input.files() {
            send_files(files);
        }
        // So that picking the same file again sends it again.
        input.set_value("");
    };
    let rows = move || text.with(|text| text.split('\n').count().clamp(1, 6));
    view! {
        <div class="composer">
            <button
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
