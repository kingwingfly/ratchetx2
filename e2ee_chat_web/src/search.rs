//! Searching what the viewer shows as text: code and text, Markdown, diffs, tables, lists of
//! files and cards. The text of its nodes goes to a worker, which searches it with a regular
//! expression, in linear time whatever the pattern, and the matches are marked with the CSS
//! Custom Highlight API: the page stays as it is, so a match may run across the spans of
//! highlighted code. The highlight registry is among web-sys's unstable APIs, so it is called as
//! JavaScript sees it.

use js_sys::{Array, Function, Reflect};
use leptos::{ev, html, prelude::*, task::spawn_local};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::{MutationObserver, MutationObserverInit, Node, Range};

use crate::{
    icon::{Icon, icon},
    util::sleep,
    workers,
};

/// Milliseconds a search waits for the typing, or the content, to settle.
const SETTLE: i32 = 150;
/// The highlights' names, as the stylesheet's `::highlight()`s style them.
const MATCHES: &str = "search";
const CURRENT: &str = "search-current";
/// What a tree walker shows: text nodes.
const SHOW_TEXT: u32 = 0x4;

/// How the last search went.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// None asked.
    Idle,
    /// Its count of matches, and whether there are more than counted.
    Found(usize, bool),
    /// The pattern is no regular expression, for this reason.
    Invalid(String),
}

/// A search box for the text in `content`, which goes through its matches: Enter for the next,
/// Shift+Enter for the one before, and Esc clears it; Ctrl+F, or ⌘F, finds it.
#[component]
pub fn Search(content: NodeRef<html::Div>) -> impl IntoView {
    let query = RwSignal::new(String::new());
    let case = RwSignal::new(false);
    let regex = RwSignal::new(true);
    let outcome = RwSignal::new(Outcome::Idle);
    let current = RwSignal::new(0usize);
    // The matches, as ranges of the content's text nodes.
    let ranges = StoredValue::new_local(Vec::<Range>::new());
    // Bumped as the content changes, as highlighted code comes in, or slides turn.
    let changes = RwSignal::new(0u64);
    // The searches started, so that one overtaken by another is dropped.
    let searches = StoredValue::new(0u64);
    let input = NodeRef::<html::Input>::new();

    let watching = StoredValue::new_local(None::<(MutationObserver, Closure<dyn FnMut()>)>);
    Effect::new(move || {
        let Some(root) = content.get() else {
            return;
        };
        let changed = Closure::<dyn FnMut()>::new(move || changes.update(|n| *n += 1));
        let Ok(observer) = MutationObserver::new(changed.as_ref().unchecked_ref()) else {
            return;
        };
        let options = MutationObserverInit::new();
        options.set_child_list(true);
        options.set_subtree(true);
        options.set_character_data(true);
        let _ = observer.observe_with_options(&root, &options);
        if let Some(Some((old, _))) = watching.try_update_value(|w| w.replace((observer, changed)))
        {
            old.disconnect();
        }
    });

    let show = move |index: usize| {
        ranges.with_value(|ranges| {
            let Some(range) = ranges.get(index) else {
                unhighlight(CURRENT);
                return;
            };
            highlight(CURRENT, std::slice::from_ref(range));
            if let Some(root) = content.get_untracked() {
                scroll_to(&root, range);
            }
        });
    };

    Effect::new(move || {
        let (pattern, case, regex) = (query.get(), case.get(), regex.get());
        changes.track();
        let Some(root) = content.get_untracked() else {
            return;
        };
        let search = searches.with_value(|n| n + 1);
        searches.set_value(search);
        spawn_local(async move {
            // Gone, or overtaken, before it began.
            if searches.try_get_value() != Some(search) {
                return;
            }
            if pattern.is_empty() {
                clear(ranges);
                outcome.set(Outcome::Idle);
                return;
            }
            sleep(SETTLE).await;
            if searches.try_get_value() != Some(search) {
                return;
            }
            let (text, nodes) = text_of(&root);
            let found = workers::find(&text, &pattern, case, regex).await;
            if searches.try_get_value() != Some(search) {
                return;
            }
            match found {
                Ok((matches, more)) => {
                    let found: Vec<Range> = matches
                        .iter()
                        .filter_map(|&(start, end)| range(&nodes, start, end))
                        .collect();
                    highlight(MATCHES, &found);
                    let count = found.len();
                    ranges.set_value(found);
                    outcome.set(Outcome::Found(count, more));
                    let index = current.get_untracked().min(count.saturating_sub(1));
                    current.set(index);
                    show(index);
                }
                Err(e) => {
                    clear(ranges);
                    outcome.set(Outcome::Invalid(e));
                }
            }
        });
    });

    let step = move |by: isize| {
        let count = ranges.with_value(Vec::len);
        if count == 0 {
            return;
        }
        let index = (current.get_untracked() as isize + by).rem_euclid(count as isize) as usize;
        current.set(index);
        show(index);
    };
    let on_keydown = move |event: ev::KeyboardEvent| match event.key().as_str() {
        "Enter" => {
            event.prevent_default();
            step(if event.shift_key() { -1 } else { 1 });
        }
        // Clearing it, rather than closing the viewer, unless it is clear already.
        "Escape" if !query.get_untracked().is_empty() => {
            event.prevent_default();
            event.stop_propagation();
            query.set(String::new());
        }
        _ => {}
    };
    let finds = window_event_listener(ev::keydown, move |event| {
        if (event.ctrl_key() || event.meta_key()) && event.key().eq_ignore_ascii_case("f") {
            event.prevent_default();
            if let Some(input) = input.get_untracked() {
                let _ = input.focus();
                input.select();
            }
        }
    });
    on_cleanup(move || {
        finds.remove();
        if let Some(Some((observer, _))) = watching.try_update_value(Option::take) {
            observer.disconnect();
        }
        unhighlight(MATCHES);
        unhighlight(CURRENT);
    });

    let count = move || match outcome.get() {
        Outcome::Idle => String::new(),
        Outcome::Found(0, _) => "none".to_string(),
        Outcome::Found(count, more) => {
            format!(
                "{} / {count}{}",
                current.get() + 1,
                if more { "+" } else { "" }
            )
        }
        Outcome::Invalid(_) => "invalid".to_string(),
    };
    let problem = move || match outcome.get() {
        Outcome::Invalid(e) => e,
        _ => String::new(),
    };
    let toggle = move |on: RwSignal<bool>, title: &'static str, label: &'static str| {
        view! {
            <button
                type="button"
                class="btn icon small toggle"
                class:on=move || on.get()
                title=title
                aria-label=title
                aria-pressed=move || on.get().to_string()
                on:click=move |_| on.update(|on| *on = !*on)
            >
                {label}
            </button>
        }
    };
    view! {
        <div class="search" class:invalid=move || matches!(outcome.get(), Outcome::Invalid(_))>
            <input
                node_ref=input
                type="search"
                placeholder="Search"
                aria-label="Search"
                title=problem
                spellcheck="false"
                autocomplete="off"
                prop:value=move || query.get()
                on:input=move |event| query.set(event_target_value(&event))
                on:keydown=on_keydown
            />
            <span class="search-count" title=problem>{count}</span>
            {toggle(case, "Match case", "Aa")}
            {toggle(regex, "Regular expression", ".*")}
            <button
                type="button"
                class="btn icon small"
                title="Previous match (Shift+Enter)"
                aria-label="Previous match"
                on:click=move |_| step(-1)
            >
                {icon(Icon::Up)}
            </button>
            <button
                type="button"
                class="btn icon small"
                title="Next match (Enter)"
                aria-label="Next match"
                on:click=move |_| step(1)
            >
                {icon(Icon::Down)}
            </button>
        </div>
    }
}

/// The text of `root`'s text nodes, joined, and each node with where its text starts in it, in
/// UTF-16 code units, as the matches count.
fn text_of(root: &Node) -> (String, Vec<(Node, u32)>) {
    let (mut text, mut nodes, mut units) = (String::new(), Vec::new(), 0u32);
    let Ok(walker) = document().create_tree_walker_with_what_to_show(root, SHOW_TEXT) else {
        return (text, nodes);
    };
    while let Ok(Some(node)) = walker.next_node() {
        let data = node.node_value().unwrap_or_default();
        nodes.push((node, units));
        units += data.encode_utf16().count() as u32;
        text.push_str(&data);
    }
    (text, nodes)
}

/// The range of the text from `start` to `end`, in UTF-16 code units of the text of `nodes`.
fn range(nodes: &[(Node, u32)], start: u32, end: u32) -> Option<Range> {
    // The node a match starts in, and the one it ends in, where it may end at the node's end.
    let first = nodes
        .partition_point(|(_, from)| *from <= start)
        .checked_sub(1)?;
    let last = nodes
        .partition_point(|(_, from)| *from < end)
        .checked_sub(1)?;
    let (start_node, start_from) = &nodes[first];
    let (end_node, end_from) = &nodes[last];
    let range = document().create_range().ok()?;
    range.set_start(start_node, start - start_from).ok()?;
    range.set_end(end_node, end - end_from).ok()?;
    Some(range)
}

/// Scroll `root` so that `range` shows in its middle.
fn scroll_to(root: &web_sys::Element, range: &Range) {
    let (rect, frame) = (
        range.get_bounding_client_rect(),
        root.get_bounding_client_rect(),
    );
    let offset = rect.top() - frame.top() - f64::from(root.client_height()) / 2.0;
    root.set_scroll_top(root.scroll_top() + offset as i32);
}

/// The page's highlight registry, if it has one.
fn registry() -> Option<JsValue> {
    let css = Reflect::get(&js_sys::global(), &"CSS".into()).ok()?;
    Reflect::get(&css, &"highlights".into())
        .ok()
        .filter(|registry| !registry.is_undefined())
}

/// Call `method` of `registry` with `arguments`.
fn call(registry: &JsValue, method: &str, arguments: &Array) {
    if let Some(method) = Reflect::get(registry, &method.into())
        .ok()
        .and_then(|method| method.dyn_into::<Function>().ok())
    {
        let _ = method.apply(registry, arguments);
    }
}

/// Mark `ranges` as the highlight `name`.
fn highlight(name: &str, ranges: &[Range]) {
    let Some(registry) = registry() else {
        return;
    };
    let Some(constructor) = Reflect::get(&js_sys::global(), &"Highlight".into())
        .ok()
        .and_then(|constructor| constructor.dyn_into::<Function>().ok())
    else {
        return;
    };
    let ranges: Array = ranges.iter().collect();
    if let Ok(highlight) = Reflect::construct(&constructor, &ranges) {
        call(&registry, "set", &Array::of2(&name.into(), &highlight));
    }
}

fn unhighlight(name: &str) {
    if let Some(registry) = registry() {
        call(&registry, "delete", &Array::of1(&name.into()));
    }
}

/// Forget the matches, and their marks.
fn clear(ranges: StoredValue<Vec<Range>, LocalStorage>) {
    ranges.set_value(Vec::new());
    unhighlight(MATCHES);
    unhighlight(CURRENT);
}
