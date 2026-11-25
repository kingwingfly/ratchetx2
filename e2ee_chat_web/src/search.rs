//! Searching what the viewer shows as text: code and text, Markdown, diffs, tables, lists of
//! files and cards. The text of its nodes goes to a worker, which searches it with a regular
//! expression, in linear time whatever the pattern, and the matches are marked with the CSS
//! Custom Highlight API: the page stays as it is, so a match may run across the spans of
//! highlighted code. The highlight registry is among web-sys's unstable APIs, so it is called as
//! JavaScript sees it.

use js_sys::Array;
use leptos::{ev, html, prelude::*, task::spawn_local};
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
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

/// A DOM text node together with its starting UTF-16 offset and UTF-16 length in the combined
/// searchable text.
struct TextSegment {
    node: Node,
    from: u32,
    len: u32,
}

/// Find the logical boundary ancestor (table cell, diff line, list item, block element) of `node`
/// within `root`, together with the separator to insert when adjacent text nodes cross it.
fn boundary_ancestor(node: &Node, root: &Node) -> Option<(Node, char)> {
    let mut cur = node.parent_node();
    while let Some(parent) = cur {
        if parent == *root {
            break;
        }
        if let Some(el) = parent.dyn_ref::<web_sys::Element>() {
            let tag = el.tag_name();
            if matches!(tag.as_str(), "TD" | "TH" | "DT" | "DD") {
                return Some((parent, '\t'));
            }
            if tag == "SPAN"
                && el.class_name().split_whitespace().any(|c| {
                    matches!(
                        c,
                        "diff-file" | "diff-hunk" | "diff-added" | "diff-removed" | "diff-context"
                    )
                })
            {
                return Some((parent, '\n'));
            }
            if matches!(
                tag.as_str(),
                "TR" | "LI"
                    | "P"
                    | "DIV"
                    | "H1"
                    | "H2"
                    | "H3"
                    | "H4"
                    | "H5"
                    | "H6"
                    | "PRE"
                    | "BLOCKQUOTE"
                    | "SECTION"
            ) {
                return Some((parent, '\n'));
            }
        }
        cur = parent.parent_node();
    }
    None
}

/// The text of `root`'s text nodes, joined with logical separators across table cells, diff lines,
/// and blocks so cross-cell/cross-line false matches do not occur, and each node with its starting
/// UTF-16 offset and UTF-16 length.
fn text_of(root: &Node) -> (String, Vec<TextSegment>) {
    let (mut text, mut nodes, mut units) = (String::new(), Vec::new(), 0u32);
    let Ok(walker) = document().create_tree_walker_with_what_to_show(root, SHOW_TEXT) else {
        return (text, nodes);
    };
    let mut prev_boundary: Option<Node> = None;
    while let Ok(Some(node)) = walker.next_node() {
        let data = node.node_value().unwrap_or_default();
        let cur_boundary = boundary_ancestor(&node, root);
        if !nodes.is_empty() {
            let crossed = match (&prev_boundary, &cur_boundary) {
                (Some(prev), Some((cur, sep))) if prev != cur => Some(*sep),
                (None, Some((_, sep))) => Some(*sep),
                (Some(_), None) => Some('\n'),
                _ => None,
            };
            if let Some(sep) = crossed
                && !text.ends_with(['\n', '\t'])
                && !data.starts_with(['\n', '\t'])
            {
                text.push(sep);
                units = units.saturating_add(1);
            }
        }
        prev_boundary = cur_boundary.map(|(n, _)| n);
        let len = data.encode_utf16().count() as u32;
        nodes.push(TextSegment {
            node,
            from: units,
            len,
        });
        units = units.saturating_add(len);
        text.push_str(&data);
    }
    (text, nodes)
}

/// Map a UTF-16 match `[start, end)` onto `(first_idx, start_offset, last_idx, end_offset)` over
/// sorted non-overlapping `(from, len)` segments, handling zero-width matches (`start == end`)
/// cleanly at offset `0`, interior offsets, and segment boundaries without inverting `set_start` /
/// `set_end` or underflowing.
fn locate_range(segments: &[(u32, u32)], start: u32, end: u32) -> Option<(usize, u32, usize, u32)> {
    if segments.is_empty() || end < start {
        return None;
    }
    if start == end {
        let first = segments
            .partition_point(|&(from, _)| from <= start)
            .checked_sub(1)?;
        let (from, len) = segments[first];
        let offset = start.checked_sub(from)?.min(len);
        return Some((first, offset, first, offset));
    }
    let first = segments
        .partition_point(|&(from, _)| from <= start)
        .checked_sub(1)?;
    let last = segments
        .partition_point(|&(from, _)| from < end)
        .checked_sub(1)?;
    if last < first {
        return None;
    }
    let (start_from, start_len) = segments[first];
    let (end_from, end_len) = segments[last];
    let start_offset = start.checked_sub(start_from)?.min(start_len);
    let end_offset = end.checked_sub(end_from)?.min(end_len);
    if first == last && end_offset < start_offset {
        return None;
    }
    Some((first, start_offset, last, end_offset))
}

/// The range of the text from `start` to `end`, in UTF-16 code units of the text of `nodes`.
fn range(nodes: &[TextSegment], start: u32, end: u32) -> Option<Range> {
    let spans: Vec<(u32, u32)> = nodes.iter().map(|seg| (seg.from, seg.len)).collect();
    let (first, start_off, last, end_off) = locate_range(&spans, start, end)?;
    let range = document().create_range().ok()?;
    range.set_start(&nodes[first].node, start_off).ok()?;
    range.set_end(&nodes[last].node, end_off).ok()?;
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

#[wasm_bindgen]
extern "C" {
    type GlobalWithHighlight;
    #[wasm_bindgen(method, getter = CSS, catch)]
    fn css(this: &GlobalWithHighlight) -> Result<Option<CssNamespace>, JsValue>;
    type CssNamespace;
    #[wasm_bindgen(method, getter, catch)]
    fn highlights(this: &CssNamespace) -> Result<Option<HighlightRegistry>, JsValue>;
    type HighlightRegistry;
    #[wasm_bindgen(method, catch)]
    fn set(
        this: &HighlightRegistry,
        name: &str,
        highlight: &CustomHighlight,
    ) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    fn delete(this: &HighlightRegistry, name: &str) -> Result<(), JsValue>;
    #[wasm_bindgen(js_name = Highlight)]
    type CustomHighlight;
    #[wasm_bindgen(constructor, variadic, catch, js_class = "Highlight")]
    fn new(ranges: &Array) -> Result<CustomHighlight, JsValue>;
}

fn registry() -> Option<HighlightRegistry> {
    js_sys::global()
        .unchecked_ref::<GlobalWithHighlight>()
        .css()
        .ok()??
        .highlights()
        .ok()?
}

fn highlight(name: &str, ranges: &[Range]) {
    if let Some(registry) = registry()
        && let Ok(mark) = CustomHighlight::new(&ranges.iter().collect())
    {
        let _ = registry.set(name, &mark);
    }
}

fn unhighlight(name: &str) {
    if let Some(registry) = registry() {
        let _ = registry.delete(name);
    }
}

/// Forget the matches, and their marks.
fn clear(ranges: StoredValue<Vec<Range>, LocalStorage>) {
    ranges.set_value(Vec::new());
    unhighlight(MATCHES);
    unhighlight(CURRENT);
}

#[cfg(test)]
mod tests {
    use super::locate_range;

    #[test]
    fn zero_width_matches_do_not_drop_at_zero_or_invert_at_boundaries() {
        // Two contiguous text nodes: [0..3) and [3..6).
        let segs = [(0, 3), (3, 3)];
        assert_eq!(locate_range(&segs, 0, 0), Some((0, 0, 0, 0)));
        assert_eq!(locate_range(&segs, 2, 2), Some((0, 2, 0, 2)));
        assert_eq!(locate_range(&segs, 3, 3), Some((1, 0, 1, 0)));
        assert_eq!(locate_range(&segs, 6, 6), Some((1, 3, 1, 3)));
        assert_eq!(locate_range(&segs, 4, 2), None);
        assert_eq!(locate_range(&[], 0, 0), None);
    }

    #[test]
    fn separated_segments_clamp_synthetic_separator_offsets() {
        // Two diff lines or table cells separated by a 1-unit synthetic separator:
        // seg 0 = [0..3), separator at 3, seg 1 = [4..7).
        let segs = [(0, 3), (4, 3)];
        assert_eq!(locate_range(&segs, 0, 3), Some((0, 0, 0, 3)));
        assert_eq!(locate_range(&segs, 4, 7), Some((1, 0, 1, 3)));
        // Match spanning across the synthetic separator maps cleanly to valid node offsets.
        assert_eq!(locate_range(&segs, 2, 5), Some((0, 2, 1, 1)));
        // Match ending on the synthetic separator clamps to the end of segment 0.
        assert_eq!(locate_range(&segs, 1, 4), Some((0, 1, 0, 3)));
    }
}
