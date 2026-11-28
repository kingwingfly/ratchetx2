//! Searching what the viewer shows as text: code and text, Markdown, diffs, tables, lists of
//! files and cards. The text of its nodes goes to a worker, which searches it with a regular
//! expression, in linear time whatever the pattern, and the matches are marked with the CSS
//! Custom Highlight API: the page stays as it is, so a match may run across the spans of
//! highlighted code. The highlight registry is among web-sys's unstable APIs, so it is called as
//! JavaScript sees it.
//!
//! Virtualized views (such as large unified diffs) do not mount off-screen rows in the DOM, so
//! they provide a [`VirtualLines`] handle instead: lines are joined with `'\n'` and searched via
//! [`workers::find`], matches are mapped via binary search over per-line UTF-16 start offsets,
//! and navigating to a hit scrolls the virtual viewport before highlighting mounted rows.

use std::{
    cell::{Cell, OnceCell},
    collections::HashMap,
    ops::Range as StdRange,
    rc::Rc,
};

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

thread_local! {
    static NEXT_VIRTUAL_ID: Cell<u64> = const { Cell::new(1) };
}

fn next_virtual_id() -> u64 {
    NEXT_VIRTUAL_ID.with(|cell| {
        let id = cell.get();
        cell.set(id.wrapping_add(1).max(1));
        id
    })
}

/// A match located within a [`VirtualTextIndex`], using 0-based line indices and UTF-16
/// code-unit column offsets within each line (matching `workers::find` and DOM `Range` offsets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VirtualMatch {
    /// First line touched by the match.
    pub start_line: usize,
    /// UTF-16 code-unit offset within `start_line`.
    pub start_col: u32,
    /// Last line touched by the match (`end_line >= start_line`).
    pub end_line: usize,
    /// Exclusive UTF-16 code-unit offset within `end_line`.
    pub end_col: u32,
}

/// Searchable line-oriented text joined with `'\n'` together with each line's `(utf16_start,
/// utf16_len)` span in the joined string, enabling `O(log N)` offset-to-`(line, col)` lookup.
#[derive(Debug, Clone)]
pub(crate) struct VirtualTextIndex {
    text: String,
    lines: Vec<(u32, u32)>,
}

impl VirtualTextIndex {
    /// Join `lines` with `'\n'` and index each line's starting UTF-16 code-unit offset and
    /// UTF-16 code-unit length in a single pass.
    pub(crate) fn from_lines<'a>(iter: impl IntoIterator<Item = &'a str>) -> Self {
        let iter = iter.into_iter();
        let (lower, _) = iter.size_hint();
        let mut text = String::new();
        let mut lines = Vec::with_capacity(lower);
        let mut units = 0u32;
        for line in iter {
            if !lines.is_empty() {
                text.push('\n');
                units = units.saturating_add(1);
            }
            let len = u32::try_from(line.encode_utf16().count()).unwrap_or(u32::MAX);
            lines.push((units, len));
            units = units.saturating_add(len);
            text.push_str(line);
        }
        Self { text, lines }
    }

    /// The `\n`-joined text passed to [`workers::find`].
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// Number of indexed lines.
    #[cfg(test)]
    pub(crate) fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// Map a single UTF-16 code-unit offset in [`Self::text`] to `(line_idx, utf16_col)`.
    /// Offsets on a synthetic `'\n'` separator clamp to the end of the preceding line; offsets
    /// beyond the end clamp to the end of the last line.
    #[cfg(test)]
    pub(crate) fn locate_offset(&self, offset: u32) -> Option<(usize, u32)> {
        if self.lines.is_empty() {
            return None;
        }
        let line_idx = self
            .lines
            .partition_point(|&(from, _)| from <= offset)
            .checked_sub(1)?;
        let (from, len) = self.lines[line_idx];
        let col = offset.saturating_sub(from).min(len);
        Some((line_idx, col))
    }

    /// Map a UTF-16 match `[start, end)` from [`workers::find`] onto a [`VirtualMatch`].
    pub(crate) fn locate_match(&self, start: u32, end: u32) -> Option<VirtualMatch> {
        let (start_line, start_col, end_line, end_col) = locate_range(&self.lines, start, end)?;
        Some(VirtualMatch {
            start_line,
            start_col,
            end_line,
            end_col,
        })
    }

    /// Project `matched` onto the non-empty UTF-16 column range `(col_start, col_end)` within
    /// `line_idx`, returning `None` if `line_idx` is outside the match or has zero highlightable
    /// code units on that line (e.g., an empty line or a leading `'\n'` boundary).
    pub(crate) fn line_span(&self, matched: VirtualMatch, line_idx: usize) -> Option<(u32, u32)> {
        if line_idx < matched.start_line || line_idx > matched.end_line {
            return None;
        }
        let (_, line_len) = *self.lines.get(line_idx)?;
        let col_start = if line_idx == matched.start_line {
            matched.start_col.min(line_len)
        } else {
            0
        };
        let col_end = if line_idx == matched.end_line {
            matched.end_col.min(line_len)
        } else {
            line_len
        };
        (col_start < col_end).then_some((col_start, col_end))
    }

    /// First line of `matched` that actually carries visible highlightable characters, falling
    /// back to `matched.start_line` for newline-only matches.
    pub(crate) fn scroll_target_line(&self, matched: VirtualMatch) -> usize {
        for line_idx in matched.start_line..=matched.end_line {
            if self.line_span(matched, line_idx).is_some() {
                return line_idx;
            }
        }
        matched.start_line
    }

    /// Map all raw `(start, end)` UTF-16 matches returned by [`workers::find`], returning the
    /// mapped [`VirtualMatch`] list and the maximum line span (`end_line - start_line`) seen.
    pub(crate) fn map_matches(&self, raw: &[(u32, u32)]) -> (Vec<VirtualMatch>, usize) {
        let mut mapped = Vec::with_capacity(raw.len());
        let mut max_span_lines = 0usize;
        for &(start, end) in raw {
            if let Some(m) = self.locate_match(start, end) {
                max_span_lines = max_span_lines.max(m.end_line - m.start_line);
                mapped.push(m);
            }
        }
        (mapped, max_span_lines)
    }
}

/// Return the indices in `matches` (ordered by ascending `start_line`) that overlap the half-open
/// mounted line window `visible`, given `max_span_lines = max(end_line - start_line)`.
pub(crate) fn visible_match_indices(
    matches: &[VirtualMatch],
    max_span_lines: usize,
    visible: StdRange<usize>,
) -> Vec<usize> {
    if matches.is_empty() || visible.is_empty() {
        return Vec::new();
    }
    let min_start = visible.start.saturating_sub(max_span_lines);
    let from = matches.partition_point(|m| m.start_line < min_start);
    let mut out = Vec::new();
    for (idx, m) in matches.iter().enumerate().skip(from) {
        if m.start_line >= visible.end {
            break;
        }
        if m.end_line >= visible.start {
            out.push(idx);
        }
    }
    out
}

/// Search provider bridging a virtualized line view (such as a large `DiffView`) with [`Search`].
///
/// The joined text and per-line UTF-16 offset table are built lazily on the first non-empty
/// search, so opening a large diff without searching incurs zero extra allocation.
#[derive(Clone)]
pub struct VirtualLines {
    id: u64,
    build_index: Rc<dyn Fn() -> VirtualTextIndex>,
    index: Rc<OnceCell<VirtualTextIndex>>,
    viewport: NodeRef<html::Div>,
    window_el: NodeRef<html::Div>,
    window: RwSignal<StdRange<usize>>,
    scroll_to_line: Rc<dyn Fn(usize)>,
}

impl VirtualLines {
    /// Register a new virtualized line provider with its lazy index builder, scroll viewport,
    /// mounted-rows container (`<span data-line="…">` children), reactive mounted window range,
    /// and vertical scroll callback.
    pub(crate) fn new(
        build_index: impl Fn() -> VirtualTextIndex + 'static,
        viewport: NodeRef<html::Div>,
        window_el: NodeRef<html::Div>,
        window: RwSignal<StdRange<usize>>,
        scroll_to_line: impl Fn(usize) + 'static,
    ) -> Self {
        Self {
            id: next_virtual_id(),
            build_index: Rc::new(build_index),
            index: Rc::new(OnceCell::new()),
            viewport,
            window_el,
            window,
            scroll_to_line: Rc::new(scroll_to_line),
        }
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    fn index(&self) -> &VirtualTextIndex {
        self.index.get_or_init(|| (self.build_index)())
    }

    fn viewport_el(&self) -> Option<web_sys::Element> {
        self.viewport
            .try_get_untracked()
            .flatten()
            .map(JsCast::unchecked_into)
    }

    fn window_el(&self) -> Option<web_sys::Element> {
        self.window_el
            .try_get_untracked()
            .flatten()
            .map(JsCast::unchecked_into)
    }

    fn window(&self) -> RwSignal<StdRange<usize>> {
        self.window
    }

    fn scroll_to_line(&self, line_idx: usize) {
        (self.scroll_to_line)(line_idx);
    }
}

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

/// Stored matches for either a normal DOM view or a virtualized line provider.
enum SearchHits {
    Dom(Vec<Range>),
    Virtual {
        provider_id: u64,
        matches: Vec<VirtualMatch>,
        max_span_lines: usize,
    },
}

impl SearchHits {
    fn len(&self) -> usize {
        match self {
            Self::Dom(ranges) => ranges.len(),
            Self::Virtual { matches, .. } => matches.len(),
        }
    }
}

/// A search box for the text in `content`, which goes through its matches: Enter for the next,
/// Shift+Enter for the one before, and Esc clears it; Ctrl+F, or ⌘F, finds it.
///
/// When `virtual_lines` carries an active [`VirtualLines`] provider, searches run against its
/// full `\n`-joined text via [`workers::find`] and scroll/highlight mounted virtual rows on
/// demand; otherwise the existing DOM `TreeWalker` behavior is preserved unchanged.
#[component]
pub fn Search(
    content: NodeRef<html::Div>,
    #[prop(optional)] virtual_lines: Option<RwSignal<Option<VirtualLines>, LocalStorage>>,
) -> impl IntoView {
    let query = RwSignal::new(String::new());
    let case = RwSignal::new(false);
    let regex = RwSignal::new(true);
    let outcome = RwSignal::new(Outcome::Idle);
    let current = RwSignal::new(0usize);
    // The matches, either as DOM ranges or mapped virtual line hits.
    let hits = StoredValue::new_local(SearchHits::Dom(Vec::new()));
    // Bumped as non-virtual DOM content changes, as highlighted code comes in, or slides turn.
    let changes = RwSignal::new(0u64);
    // Bumped when virtual match highlights need re-application (e.g., navigation to a hit).
    let highlight_rev = RwSignal::new(0u64);
    // Active navigation target `(provider_id, match_index)` awaiting horizontal reveal once mounted.
    let pending_reveal = StoredValue::new(None::<(u64, usize)>);
    // The searches started, so that one overtaken by another is dropped.
    let searches = StoredValue::new(0u64);
    let here = StoredValue::new(());
    let input = NodeRef::<html::Input>::new();

    let active_virtual = move || {
        virtual_lines
            .and_then(|sig| sig.try_get_untracked())
            .flatten()
    };

    let watching = StoredValue::new_local(None::<(MutationObserver, Closure<dyn FnMut()>)>);
    Effect::new(move || {
        let is_virtual = virtual_lines.is_some_and(|sig| sig.with(Option::is_some));
        if is_virtual {
            if let Some(Some((old, _))) = watching.try_update_value(Option::take) {
                old.disconnect();
            }
            return;
        }
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
        enum Action {
            None,
            Dom(Range),
            Virtual(u64, VirtualMatch),
        }
        let action = hits.with_value(|hits| match hits {
            SearchHits::Dom(ranges) => ranges.get(index).cloned().map_or(Action::None, Action::Dom),
            SearchHits::Virtual {
                provider_id,
                matches,
                ..
            } => matches
                .get(index)
                .copied()
                .map_or(Action::None, |m| Action::Virtual(*provider_id, m)),
        });
        match action {
            Action::None => {
                unhighlight(CURRENT);
            }
            Action::Dom(range) => {
                highlight(CURRENT, std::slice::from_ref(&range));
                if let Some(root) = content.get_untracked() {
                    scroll_to(&root, &range);
                }
            }
            Action::Virtual(provider_id, matched) => {
                if let Some(provider) = active_virtual()
                    && provider.id() == provider_id
                {
                    let target_line = provider.index().scroll_target_line(matched);
                    provider.scroll_to_line(target_line);
                    pending_reveal.set_value(Some((provider_id, index)));
                    highlight_rev.update(|n| *n = n.wrapping_add(1));
                }
            }
        }
    };

    // Re-apply CSS Custom Highlights onto currently mounted virtual rows whenever the virtual
    // viewport scrolls, the active match changes, or a new virtual search settles.
    let apply_virtual_highlights = move |provider: &VirtualLines| -> bool {
        let window = provider.window().get_untracked();
        let Some(window_el) = provider.window_el() else {
            return false;
        };
        let active_index = current.get_untracked();
        let mut needs_retry = false;
        let mut target_mounted = false;
        let mut active_first_range: Option<Range> = None;

        hits.with_value(|hits| {
            let SearchHits::Virtual {
                provider_id,
                matches,
                max_span_lines,
            } = hits
            else {
                return;
            };
            if *provider_id != provider.id() {
                unhighlight(MATCHES);
                unhighlight(CURRENT);
                return;
            }
            if matches.is_empty() || window.is_empty() {
                unhighlight(MATCHES);
                unhighlight(CURRENT);
                return;
            }
            let index = provider.index();
            let mounted = mounted_line_nodes(&window_el);
            if !mounted.contains_key(&window.start) {
                needs_retry = true;
            }
            let visible_indices = visible_match_indices(matches, *max_span_lines, window.clone());
            let mut all_ranges = Vec::new();
            let mut current_ranges = Vec::new();
            for match_idx in visible_indices {
                let matched = matches[match_idx];
                let is_current = match_idx == active_index;
                if is_current {
                    let target_line = index.scroll_target_line(matched);
                    target_mounted = mounted.contains_key(&target_line);
                    if !target_mounted {
                        needs_retry = true;
                    }
                }
                let from_line = matched.start_line.max(window.start);
                let to_line = matched.end_line.min(window.end - 1);
                for line_idx in from_line..=to_line {
                    let Some((col_start, col_end)) = index.line_span(matched, line_idx) else {
                        continue;
                    };
                    let Some(Some(text_node)) = mounted.get(&line_idx) else {
                        continue;
                    };
                    if let Some(r) = create_text_range(text_node, col_start, col_end) {
                        if is_current {
                            if active_first_range.is_none() {
                                active_first_range = Some(r.clone());
                            }
                            current_ranges.push(r.clone());
                        }
                        all_ranges.push(r);
                    }
                }
            }
            if all_ranges.is_empty() {
                unhighlight(MATCHES);
            } else {
                highlight(MATCHES, &all_ranges);
            }
            if current_ranges.is_empty() {
                unhighlight(CURRENT);
            } else {
                highlight(CURRENT, &current_ranges);
            }
        });

        if target_mounted && pending_reveal.get_value() == Some((provider.id(), active_index)) {
            pending_reveal.set_value(None);
            if let Some(range) = active_first_range
                && let Some(viewport) = provider.viewport_el()
            {
                scroll_horizontal_to(&viewport, &range);
            }
        }
        needs_retry
    };

    Effect::new(move || {
        let Some(provider) = virtual_lines.and_then(|sig| sig.get()) else {
            return;
        };
        let window = provider.window().get();
        let _active_idx = current.get();
        highlight_rev.track();
        let needs_retry = apply_virtual_highlights(&provider);
        // If `window` updated before `<For>` committed the new row spans, re-apply on the next
        // animation frame once the mounted rows are present in the DOM.
        if needs_retry && !window.is_empty() {
            let provider = provider.clone();
            request_animation_frame(move || {
                if here.try_get_value().is_some()
                    && active_virtual().map(|p| p.id()) == Some(provider.id())
                {
                    let _ = apply_virtual_highlights(&provider);
                }
            });
        }
    });

    Effect::new(move || {
        let (pattern, case, regex) = (query.get(), case.get(), regex.get());
        let provider = virtual_lines.and_then(|sig| sig.get());
        if provider.is_none() {
            changes.track();
        }
        let root = content.get_untracked();
        if provider.is_none() && root.is_none() {
            return;
        }
        let search = searches.with_value(|n| n + 1);
        searches.set_value(search);
        spawn_local(async move {
            // Gone, or overtaken, before it began.
            if searches.try_get_value() != Some(search) {
                return;
            }
            if pattern.is_empty() {
                clear(hits);
                pending_reveal.set_value(None);
                outcome.set(Outcome::Idle);
                return;
            }
            sleep(SETTLE).await;
            if searches.try_get_value() != Some(search) {
                return;
            }
            if let Some(provider) = provider {
                let found = workers::find(provider.index().text(), &pattern, case, regex).await;
                if searches.try_get_value() != Some(search) {
                    return;
                }
                if active_virtual().map(|p| p.id()) != Some(provider.id()) {
                    return;
                }
                match found {
                    Ok((matches, more)) => {
                        let (mapped, max_span_lines) = provider.index().map_matches(&matches);
                        let count = mapped.len();
                        hits.set_value(SearchHits::Virtual {
                            provider_id: provider.id(),
                            matches: mapped,
                            max_span_lines,
                        });
                        outcome.set(Outcome::Found(count, more));
                        let index = current.get_untracked().min(count.saturating_sub(1));
                        current.set(index);
                        if count == 0 {
                            unhighlight(MATCHES);
                            unhighlight(CURRENT);
                            pending_reveal.set_value(None);
                        } else {
                            show(index);
                        }
                    }
                    Err(e) => {
                        clear(hits);
                        pending_reveal.set_value(None);
                        outcome.set(Outcome::Invalid(e));
                    }
                }
            } else if let Some(root) = root {
                let (text, nodes) = text_of(&root);
                let found = workers::find(&text, &pattern, case, regex).await;
                if searches.try_get_value() != Some(search) {
                    return;
                }
                if active_virtual().is_some() {
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
                        hits.set_value(SearchHits::Dom(found));
                        outcome.set(Outcome::Found(count, more));
                        let index = current.get_untracked().min(count.saturating_sub(1));
                        current.set(index);
                        show(index);
                    }
                    Err(e) => {
                        clear(hits);
                        outcome.set(Outcome::Invalid(e));
                    }
                }
            }
        });
    });

    let step = move |by: isize| {
        let count = hits.with_value(SearchHits::len);
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

/// Collect each mounted `<span data-line="…">` row inside `window_el` together with its first
/// text node child (if non-empty).
fn mounted_line_nodes(window_el: &web_sys::Element) -> HashMap<usize, Option<Node>> {
    let mut map = HashMap::new();
    let Ok(nodes) = window_el.query_selector_all("span[data-line]") else {
        return map;
    };
    for i in 0..nodes.length() {
        let Some(node) = nodes.item(i) else {
            continue;
        };
        let Ok(el) = node.dyn_into::<web_sys::Element>() else {
            continue;
        };
        let Some(line_idx) = el
            .get_attribute("data-line")
            .and_then(|s| s.parse::<usize>().ok())
        else {
            continue;
        };
        let mut text_node = None;
        let mut child = el.first_child();
        while let Some(c) = child {
            if c.node_type() == Node::TEXT_NODE {
                text_node = Some(c);
                break;
            }
            child = c.next_sibling();
        }
        map.insert(line_idx, text_node);
    }
    map
}

/// Create a DOM `Range` covering UTF-16 code units `[start, end)` within a single text node.
fn create_text_range(node: &Node, start: u32, end: u32) -> Option<Range> {
    if end < start {
        return None;
    }
    let range = document().create_range().ok()?;
    range.set_start(node, start).ok()?;
    range.set_end(node, end).ok()?;
    Some(range)
}

/// Horizontally scroll `viewport` if `range` is outside the visible horizontal band (e.g., a hit
/// deep inside a long single line).
fn scroll_horizontal_to(viewport: &web_sys::Element, range: &Range) {
    let vw = f64::from(viewport.client_width());
    if vw <= 0.0 {
        return;
    }
    let rect = range.get_bounding_client_rect();
    let frame = viewport.get_bounding_client_rect();
    let rel_left = rect.left() - frame.left();
    let rel_right = rect.right() - frame.left();
    let margin = (vw * 0.1).min(48.0);
    if rel_left >= margin && rel_right <= vw - margin {
        return;
    }
    let anchor_width = rect.width().min(vw * 0.5);
    let target = f64::from(viewport.scroll_left()) + rel_left - (vw - anchor_width) / 2.0;
    viewport.set_scroll_left(target.max(0.0).round() as i32);
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
fn clear(hits: StoredValue<SearchHits, LocalStorage>) {
    hits.set_value(SearchHits::Dom(Vec::new()));
    unhighlight(MATCHES);
    unhighlight(CURRENT);
}

#[cfg(test)]
mod tests {
    use super::{VirtualMatch, VirtualTextIndex, locate_range, visible_match_indices};

    /// Convert a byte range `[byte_start, byte_end)` in `text` to UTF-16 code units, matching
    /// `e2ee_chat_preview::search::find` (`workers::find`).
    fn utf16_range(text: &str, byte_start: usize, byte_end: usize) -> (u32, u32) {
        let start = text[..byte_start].encode_utf16().count() as u32;
        let end = start + text[byte_start..byte_end].encode_utf16().count() as u32;
        (start, end)
    }

    /// Slice `line` using UTF-16 code-unit offsets `[start, end)`, matching DOM `Range` slicing.
    fn slice_utf16(line: &str, start: u32, end: u32) -> String {
        let units: Vec<u16> = line.encode_utf16().collect();
        String::from_utf16(&units[start as usize..end as usize]).expect("valid UTF-16 boundary")
    }

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

    #[test]
    fn virtual_index_maps_ascii_and_unicode_utf16_surrogate_pairs() {
        // Line 0: '+'(1) + 'é'(1) + '世'(1) + '😀'(2) + "foo"(3) = 8 UTF-16 units
        // Separator '\n' at 8 -> Line 1 starts at 9
        // Line 1: '-'(1) + '🚀'(2) + "日本語"(3) + "bar"(3) = 9 UTF-16 units
        // Separator '\n' at 18 -> Line 2 starts at 19
        // Line 2: " 👨‍👩‍👧‍👦end" (' '(1) + 4 emoji*2 + 3 ZWJ*1 = 12 + "end"(3) = 15 UTF-16 units)
        let lines = ["+é世😀foo", "-🚀日本語bar", " 👨‍👩‍👧‍👦end"];
        let index = VirtualTextIndex::from_lines(lines);
        assert_eq!(index.line_count(), 3);
        assert_eq!(index.text(), "+é世😀foo\n-🚀日本語bar\n 👨‍👩‍👧‍👦end");

        // Locate "foo" on line 0 after 2B, 3B, and 4B (surrogate-pair) characters.
        let pos = index.text().find("foo").unwrap();
        let (s, e) = utf16_range(index.text(), pos, pos + "foo".len());
        let m = index.locate_match(s, e).unwrap();
        assert_eq!(
            m,
            VirtualMatch {
                start_line: 0,
                start_col: 5,
                end_line: 0,
                end_col: 8,
            }
        );
        assert_eq!(
            slice_utf16(lines[0], m.start_col, m.end_col),
            "foo".to_string()
        );

        // Locate surrogate-pair emoji '🚀' and CJK "日本語" on line 1.
        let rocket_pos = index.text().find('🚀').unwrap();
        let (rs, re) = utf16_range(index.text(), rocket_pos, rocket_pos + '🚀'.len_utf8());
        let rm = index.locate_match(rs, re).unwrap();
        assert_eq!(
            rm,
            VirtualMatch {
                start_line: 1,
                start_col: 1,
                end_line: 1,
                end_col: 3,
            }
        );
        assert_eq!(slice_utf16(lines[1], rm.start_col, rm.end_col), "🚀");

        let cjk_pos = index.text().find("日本語").unwrap();
        let (cs, ce) = utf16_range(index.text(), cjk_pos, cjk_pos + "日本語".len());
        let cm = index.locate_match(cs, ce).unwrap();
        assert_eq!(
            cm,
            VirtualMatch {
                start_line: 1,
                start_col: 3,
                end_line: 1,
                end_col: 6,
            }
        );
        assert_eq!(slice_utf16(lines[1], cm.start_col, cm.end_col), "日本語");

        // Locate "end" after multi-codepoint ZWJ family emoji on line 2.
        let end_pos = index.text().find("end").unwrap();
        let (es, ee) = utf16_range(index.text(), end_pos, end_pos + 3);
        let em = index.locate_match(es, ee).unwrap();
        assert_eq!(em.start_line, 2);
        assert_eq!(em.end_line, 2);
        assert_eq!(slice_utf16(lines[2], em.start_col, em.end_col), "end");
        assert_eq!(index.locate_offset(es), Some((2, em.start_col)));
    }

    #[test]
    fn virtual_index_handles_empty_inputs_and_empty_lines() {
        let empty = VirtualTextIndex::from_lines(std::iter::empty::<&str>());
        assert_eq!(empty.line_count(), 0);
        assert_eq!(empty.text(), "");
        assert_eq!(empty.locate_offset(0), None);
        assert_eq!(empty.locate_match(0, 1), None);

        // Leading, consecutive interior, and trailing empty lines.
        let lines = ["", "", "+alpha", "", "", "-beta", ""];
        let index = VirtualTextIndex::from_lines(lines);
        assert_eq!(index.text(), "\n\n+alpha\n\n\n-beta\n");

        let alpha_byte = index.text().find("alpha").unwrap();
        let (as_, ae) = utf16_range(index.text(), alpha_byte, alpha_byte + 5);
        assert_eq!(
            index.locate_match(as_, ae),
            Some(VirtualMatch {
                start_line: 2,
                start_col: 1,
                end_line: 2,
                end_col: 6,
            })
        );

        let beta_byte = index.text().find("beta").unwrap();
        let (bs, be) = utf16_range(index.text(), beta_byte, beta_byte + 4);
        assert_eq!(
            index.locate_match(bs, be),
            Some(VirtualMatch {
                start_line: 5,
                start_col: 1,
                end_line: 5,
                end_col: 5,
            })
        );

        // Single newline match between empty lines clamps safely without panicking.
        let nl = index.locate_match(0, 1).unwrap();
        assert_eq!(nl.start_line, 0);
        assert_eq!(index.line_span(nl, 0), None);
        assert_eq!(index.scroll_target_line(nl), 0);
    }

    #[test]
    fn virtual_index_handles_cross_line_matches_and_scroll_target_line() {
        let lines = ["+first 😀", "", "-second 世", "+third"];
        let index = VirtualTextIndex::from_lines(lines);

        // Match spanning line 0 -> empty line 1 -> line 2.
        let needle = "😀\n\n-second";
        let pos = index.text().find(needle).unwrap();
        let (s, e) = utf16_range(index.text(), pos, pos + needle.len());
        let m = index.locate_match(s, e).unwrap();
        assert_eq!(m.start_line, 0);
        assert_eq!(m.end_line, 2);
        assert_eq!(index.line_span(m, 0), Some((7, 9)));
        assert_eq!(slice_utf16(lines[0], 7, 9), "😀");
        assert_eq!(index.line_span(m, 1), None);
        assert_eq!(index.line_span(m, 2), Some((0, 7)));
        assert_eq!(slice_utf16(lines[2], 0, 7), "-second");
        assert_eq!(index.line_span(m, 3), None);
        assert_eq!(index.scroll_target_line(m), 0);

        // Match starting on '\n' across empty line 1 into line 2: scroll target advances to line 2
        // where visible highlightable text starts.
        let leading_nl = "\n\n-second";
        let pos2 = index.text().find(leading_nl).unwrap();
        let (s2, e2) = utf16_range(index.text(), pos2, pos2 + leading_nl.len());
        let m2 = index.locate_match(s2, e2).unwrap();
        assert_eq!(index.line_span(m2, 0), None);
        assert_eq!(index.line_span(m2, 1), None);
        assert_eq!(index.line_span(m2, 2), Some((0, 7)));
        assert_eq!(index.scroll_target_line(m2), 2);
    }

    #[test]
    fn virtual_index_handles_long_single_line() {
        let prefix = format!("+{}{}", "a".repeat(50_000), "😀".repeat(250));
        let line = format!("{prefix}NEEDLE{}", "b".repeat(50_000));
        let lines = [line.as_str(), "-next"];
        let index = VirtualTextIndex::from_lines(lines);

        let pos = index.text().find("NEEDLE").unwrap();
        let (s, e) = utf16_range(index.text(), pos, pos + 6);
        let m = index.locate_match(s, e).unwrap();
        // '+'(1) + 50_000 'a' + 250*2 UTF-16 units for '😀' = 50_501
        assert_eq!(
            m,
            VirtualMatch {
                start_line: 0,
                start_col: 50_501,
                end_line: 0,
                end_col: 50_507,
            }
        );
        assert_eq!(slice_utf16(&line, m.start_col, m.end_col), "NEEDLE");

        let next_pos = index.text().find("-next").unwrap();
        let (ns, ne) = utf16_range(index.text(), next_pos, next_pos + 5);
        let nm = index.locate_match(ns, ne).unwrap();
        assert_eq!(
            nm,
            VirtualMatch {
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: 5,
            }
        );
    }

    #[test]
    fn virtual_index_locates_hits_at_line_15000_of_20000_line_diff() {
        let lines: Vec<String> = (0..20_000)
            .map(|i| match i {
                0 => "diff --git a/big.rs b/big.rs".to_string(),
                15_000 => "+    let target = \"🚀 match_15000\";".to_string(),
                19_999 => "-    // end_marker".to_string(),
                _ => format!(" context line {i:05} with padding"),
            })
            .collect();
        let index = VirtualTextIndex::from_lines(lines.iter().map(String::as_str));
        assert_eq!(index.line_count(), 20_000);

        let pos_15k = index.text().find("match_15000").unwrap();
        let (s_15k, e_15k) = utf16_range(index.text(), pos_15k, pos_15k + "match_15000".len());
        let pos_end = index.text().find("end_marker").unwrap();
        let (s_end, e_end) = utf16_range(index.text(), pos_end, pos_end + "end_marker".len());

        let (mapped, max_span) = index.map_matches(&[(s_15k, e_15k), (s_end, e_end)]);
        assert_eq!(max_span, 0);
        assert_eq!(mapped.len(), 2);

        let m_15k = mapped[0];
        assert_eq!(m_15k.start_line, 15_000);
        assert_eq!(m_15k.end_line, 15_000);
        assert_eq!(
            slice_utf16(&lines[15_000], m_15k.start_col, m_15k.end_col),
            "match_15000"
        );
        assert_eq!(index.scroll_target_line(m_15k), 15_000);

        let m_end = mapped[1];
        assert_eq!(m_end.start_line, 19_999);
        assert_eq!(m_end.end_line, 19_999);
        assert_eq!(
            slice_utf16(&lines[19_999], m_end.start_col, m_end.end_col),
            "end_marker"
        );

        // Visible window centered around line 15,000 selects only hit 0.
        assert_eq!(
            visible_match_indices(&mapped, max_span, 14_960..15_070),
            [0]
        );
        // Visible window at top selects neither hit.
        assert!(visible_match_indices(&mapped, max_span, 0..100).is_empty());
        // Visible window at bottom selects only hit 1.
        assert_eq!(
            visible_match_indices(&mapped, max_span, 19_920..20_000),
            [1]
        );
    }

    #[test]
    fn visible_match_indices_includes_multiline_matches_overlapping_window() {
        let matches = [
            VirtualMatch {
                start_line: 2,
                start_col: 0,
                end_line: 5,
                end_col: 3,
            },
            VirtualMatch {
                start_line: 10,
                start_col: 0,
                end_line: 25,
                end_col: 4,
            },
            VirtualMatch {
                start_line: 20,
                start_col: 1,
                end_line: 20,
                end_col: 5,
            },
            VirtualMatch {
                start_line: 30,
                start_col: 0,
                end_line: 30,
                end_col: 2,
            },
        ];
        // Match 1 spans 15 lines (10..=25) and fully crosses the window 15..22.
        assert_eq!(visible_match_indices(&matches, 15, 15..22), [1, 2]);
        // Window 25..30 touches the tail of match 1 (end_line == 25), excludes match 3 (30).
        assert_eq!(visible_match_indices(&matches, 15, 25..30), [1]);
        // Empty window returns empty.
        assert!(visible_match_indices(&matches, 15, 15..15).is_empty());
    }
}
