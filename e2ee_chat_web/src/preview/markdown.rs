use std::{collections::VecDeque, fmt};

use e2ee_chat_preview::rpc::DIAGRAM_SOURCE_MAX;
use pulldown_cmark::{CodeBlockKind, CowStr, Event, LinkType, Options, Parser, Tag, TagEnd};
use pulldown_latex::config::DisplayMode;

use super::{
    HIGHLIGHT_MAX, PreviewBudget,
    mathml::mathml,
    sanitize::{escape, is_safe_image_src, normalize_safe_href, sanitize_html},
};

/// Maximum rendered HTML bytes emitted by [`markdown`] before truncating cleanly.
pub(super) const MARKDOWN_HTML_MAX: usize = 2 * 1024 * 1024;
/// Maximum Markdown parser events processed per document.
pub(super) const MARKDOWN_EVENTS_MAX: usize = 100_000;
/// Maximum byte length allowed for a single Markdown link destination URL.
pub(super) const LINK_URL_MAX: usize = 4 * 1024;
/// Maximum byte length allowed for a link/image title attribute.
const LINK_TITLE_MAX: usize = 1024;
/// Maximum math expressions rendered per Markdown document before falling back to escaped TeX.
pub(super) const MARKDOWN_MATH_MAX: usize = 500;
/// Maximum cumulative rendered MathML bytes per Markdown document.
pub(super) const MARKDOWN_MATH_BYTES_MAX: usize = 512 * 1024;
/// Maximum inline data-URL images admitted per Markdown document.
pub(super) const MARKDOWN_IMAGES_MAX: usize = 64;
/// Maximum cumulative bytes across inline data-URL images per Markdown document.
pub(super) const MARKDOWN_IMAGE_BYTES_MAX: usize = 2 * 1024 * 1024;
/// Maximum total slides across all columns in [`slides`].
pub(super) const SLIDES_MAX: usize = 200;
/// Maximum cumulative HTML bytes across an entire slide deck in [`slides`].
const SLIDES_HTML_MAX: usize = 4 * 1024 * 1024;
/// Chunk size used when splitting unusually large single `Event::Text` items so bounded writes
/// retain the prefix up to `MARKDOWN_HTML_MAX` instead of dropping the whole paragraph.
const TEXT_CHUNK_MAX: usize = 64 * 1024;

const MARKDOWN_TRUNCATION_NOTE: &str =
    "<p class=\"preview-note\">Preview truncated because this document is too large.</p>";

struct BoundedHtmlWriter {
    out: String,
    max: usize,
    truncated: bool,
}

impl BoundedHtmlWriter {
    fn new(max: usize) -> Self {
        Self {
            out: String::new(),
            max,
            truncated: false,
        }
    }
}

impl fmt::Write for BoundedHtmlWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.out.len().saturating_add(s.len()) > self.max {
            self.truncated = true;
            return Err(fmt::Error);
        }
        self.out.push_str(s);
        Ok(())
    }
}

/// Find the byte offset right after the closing delimiter of an HTML5 comment (`<!-->`, `<!--->`,
/// `-->`, or `--!>`), where `after_open` starts immediately after `"<!--"`.
fn find_html_comment_end(after_open: &str) -> Option<usize> {
    if after_open.starts_with('>') {
        return Some(1);
    }
    if after_open.starts_with("->") {
        return Some(2);
    }
    find_continued_comment_end(after_open)
}

/// Find the byte offset right after `-->` or `--!>` in an already-open HTML5 comment.
fn find_continued_comment_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'-' && bytes[i + 1] == b'-' {
            if bytes[i + 2] == b'>' {
                return Some(i + 3);
            }
            if bytes[i + 2] == b'!' && bytes.get(i + 3) == Some(&b'>') {
                return Some(i + 4);
            }
        }
        i += 1;
    }
    None
}

/// Strip HTML5 comments from `html` while tracking multi-line `in_comment` state across lines of
/// a single HTML block, preserving any non-comment text before or after `-->` / `--!>`.
///
/// When `allow_unclosed` is `false` (for `Event::InlineHtml`), an unclosed `<!--` without a
/// matching closer in `html` is kept as literal text rather than swallowing subsequent content.
fn strip_html_comments(html: &str, in_comment: &mut bool, allow_unclosed: bool) -> (String, bool) {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    let mut stripped_any = false;

    while !rest.is_empty() {
        if *in_comment {
            stripped_any = true;
            if let Some(end) = find_continued_comment_end(rest) {
                *in_comment = false;
                rest = &rest[end..];
            } else {
                rest = "";
            }
            continue;
        }
        let Some(open) = rest.find("<!--") else {
            out.push_str(rest);
            break;
        };
        let after = &rest[open + 4..];
        if let Some(end) = find_html_comment_end(after) {
            out.push_str(&rest[..open]);
            stripped_any = true;
            rest = &after[end..];
        } else if allow_unclosed {
            out.push_str(&rest[..open]);
            stripped_any = true;
            *in_comment = true;
            rest = "";
        } else {
            // Unclosed `<!--` in inline HTML: keep verbatim so it renders as escaped text.
            out.push_str(rest);
            break;
        }
    }

    (out, stripped_any)
}

/// Split `text` into valid UTF-8 chunks of at most [`TEXT_CHUNK_MAX`] bytes.
fn push_chunked_text<'a>(pending: &mut VecDeque<Event<'a>>, text: CowStr<'a>) {
    if text.len() <= TEXT_CHUNK_MAX {
        pending.push_back(Event::Text(text));
        return;
    }
    let mut start = 0;
    let s = text.as_ref();
    while start < s.len() {
        let mut end = (start + TEXT_CHUNK_MAX).min(s.len());
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        pending.push_back(Event::Text(s[start..end].to_string().into()));
        start = end;
    }
}

struct MarkdownEvents<'a, 'b> {
    inner: Parser<'a>,
    pending: VecDeque<Event<'a>>,
    in_block_comment: bool,
    events_budget: PreviewBudget,
    math_count: PreviewBudget,
    math_bytes: PreviewBudget,
    image_count: PreviewBudget,
    image_bytes: PreviewBudget,
    truncated: &'b mut bool,
}

impl<'a, 'b> MarkdownEvents<'a, 'b> {
    fn new(inner: Parser<'a>, truncated: &'b mut bool) -> Self {
        Self {
            inner,
            pending: VecDeque::new(),
            in_block_comment: false,
            events_budget: PreviewBudget::new(MARKDOWN_EVENTS_MAX),
            math_count: PreviewBudget::new(MARKDOWN_MATH_MAX),
            math_bytes: PreviewBudget::new(MARKDOWN_MATH_BYTES_MAX),
            image_count: PreviewBudget::new(MARKDOWN_IMAGES_MAX),
            image_bytes: PreviewBudget::new(MARKDOWN_IMAGE_BYTES_MAX),
            truncated,
        }
    }

    fn pull_raw(&mut self) -> Option<Event<'a>> {
        let event = self.inner.next()?;
        if !self.events_budget.try_push() {
            *self.truncated = true;
            return None;
        }
        Some(event)
    }

    fn buffer_code_block(&mut self, kind: CodeBlockKind<'a>) -> Event<'a> {
        let lang = match &kind {
            CodeBlockKind::Fenced(info) => info.split_whitespace().next().unwrap_or(""),
            CodeBlockKind::Indented => "",
        };
        if lang.is_empty() {
            return Event::Html("<pre><code>".into());
        }
        let max_bytes = if lang.eq_ignore_ascii_case("mermaid") {
            DIAGRAM_SOURCE_MAX
        } else {
            HIGHLIGHT_MAX
        };
        let mut buffered: Vec<Event<'a>> = Vec::new();
        let mut total_bytes = 0usize;
        let mut oversized = false;
        while let Some(next) = self.pull_raw() {
            match next {
                Event::Text(text) => {
                    total_bytes = total_bytes.saturating_add(text.len());
                    buffered.push(Event::Text(text));
                    if total_bytes > max_bytes {
                        oversized = true;
                        break;
                    }
                }
                Event::End(TagEnd::CodeBlock) => {
                    buffered.push(Event::Html("</code></pre>\n".into()));
                    break;
                }
                other => {
                    buffered.push(other);
                }
            }
        }
        for ev in buffered {
            if let Event::Text(text) = ev {
                push_chunked_text(&mut self.pending, text);
            } else {
                self.pending.push_back(ev);
            }
        }
        if oversized {
            Event::Html("<pre><code>".into())
        } else {
            Event::Html(format!("<pre><code data-lang=\"{}\">", escape(lang)).into())
        }
    }

    fn render_math(&mut self, tex: &str, mode: DisplayMode) -> String {
        if !self.math_count.try_push() {
            return escape(tex);
        }
        let rendered = mathml(tex, mode);
        if !self.math_bytes.take(rendered.len()) {
            return escape(tex);
        }
        rendered
    }

    fn safe_image_url(&mut self, url: CowStr<'_>) -> CowStr<'a> {
        let trimmed = url.trim_matches(|c: char| c.is_ascii_whitespace());
        if !is_safe_image_src(trimmed) {
            return "".into();
        }
        if !self.image_count.try_push() || !self.image_bytes.take(trimmed.len()) {
            return "".into();
        }
        trimmed.to_string().into()
    }
}

impl<'a> Iterator for MarkdownEvents<'a, '_> {
    type Item = Event<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ev) = self.pending.pop_front() {
                return Some(ev);
            }
            let event = self.pull_raw()?;
            match event {
                Event::Start(Tag::HtmlBlock) => {
                    self.in_block_comment = false;
                    return Some(Event::Start(Tag::HtmlBlock));
                }
                Event::End(TagEnd::HtmlBlock) => {
                    self.in_block_comment = false;
                    return Some(Event::End(TagEnd::HtmlBlock));
                }
                Event::Html(html) => {
                    let (kept, stripped) =
                        strip_html_comments(&html, &mut self.in_block_comment, true);
                    if stripped && kept.trim().is_empty() {
                        continue;
                    }
                    push_chunked_text(&mut self.pending, kept.into());
                }
                Event::InlineHtml(html) => {
                    let mut local_comment = false;
                    let (kept, stripped) = strip_html_comments(&html, &mut local_comment, false);
                    if stripped && kept.is_empty() {
                        continue;
                    }
                    push_chunked_text(&mut self.pending, kept.into());
                }
                Event::Start(Tag::Link {
                    link_type,
                    dest_url,
                    title,
                    id,
                }) => {
                    let (link_type, dest_url) = safe_link(link_type, dest_url);
                    let title = clamp_title(title);
                    return Some(Event::Start(Tag::Link {
                        link_type,
                        dest_url,
                        title,
                        id,
                    }));
                }
                Event::Start(Tag::Image {
                    link_type,
                    dest_url,
                    title,
                    id,
                }) => {
                    let dest_url = self.safe_image_url(dest_url);
                    let title = clamp_title(title);
                    return Some(Event::Start(Tag::Image {
                        link_type,
                        dest_url,
                        title,
                        id,
                    }));
                }
                Event::Start(Tag::CodeBlock(kind)) => {
                    return Some(self.buffer_code_block(kind));
                }
                Event::End(TagEnd::CodeBlock) => {
                    return Some(Event::Html("</code></pre>\n".into()));
                }
                Event::InlineMath(tex) => {
                    let rendered = self.render_math(&tex, DisplayMode::Inline);
                    return Some(Event::InlineHtml(rendered.into()));
                }
                Event::DisplayMath(tex) => {
                    let rendered = self.render_math(&tex, DisplayMode::Block);
                    return Some(Event::Html(rendered.into()));
                }
                Event::Text(text) if text.len() > TEXT_CHUNK_MAX => {
                    push_chunked_text(&mut self.pending, text);
                }
                other => return Some(other),
            }
        }
    }
}

fn clamp_title(title: CowStr<'_>) -> CowStr<'_> {
    if title.len() <= LINK_TITLE_MAX {
        return title;
    }
    let mut end = LINK_TITLE_MAX;
    while !title.is_char_boundary(end) {
        end -= 1;
    }
    title[..end].to_string().into()
}

/// Markdown `source` as HTML: GitHub's flavour, with maths, as MathML. Raw HTML shows as
/// written, and HTML comments not at all, such as reveal.js's slide attributes. Code blocks are
/// `<pre><code data-lang="…">`, for the page to highlight, or to draw if Mermaid, unless too
/// large. Output is strictly bounded to prevent reference-link/image amplification.
pub fn markdown(source: &str) -> String {
    markdown_with_budget(source, MARKDOWN_HTML_MAX)
}

fn markdown_with_budget(source: &str, max_html: usize) -> String {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_MATH
        | Options::ENABLE_GFM;
    let mut events_truncated = false;
    let mut writer = BoundedHtmlWriter::new(max_html);
    {
        let events = MarkdownEvents::new(Parser::new_ext(source, options), &mut events_truncated);
        let _ = pulldown_cmark::html::write_html_fmt(&mut writer, events);
    }
    let mut sanitized = sanitize_html(&writer.out);
    if events_truncated || writer.truncated {
        sanitized.push_str(MARKDOWN_TRUNCATION_NOTE);
    }
    sanitized
}

/// A link to the web, to mail, or within the document; any other or oversized link goes nowhere.
fn safe_link(link_type: LinkType, url: CowStr<'_>) -> (LinkType, CowStr<'_>) {
    if url.len() > LINK_URL_MAX {
        return (LinkType::Inline, "#".into());
    }
    if link_type == LinkType::Email {
        if let Some(normalized) = normalize_safe_href(&format!("mailto:{url}"))
            && normalized.len() <= LINK_URL_MAX
            && let Some(address) = normalized.strip_prefix("mailto:")
            && !address.is_empty()
        {
            return (LinkType::Email, address.to_string().into());
        }
        return (LinkType::Inline, "#".into());
    }
    (
        link_type,
        normalize_safe_href(&url)
            .filter(|normalized| normalized.len() <= LINK_URL_MAX)
            .map(CowStr::from)
            .unwrap_or_else(|| "#".into()),
    )
}

/// Tracks CommonMark fenced code blocks (`` ``` `` / `~~~`) across lines so slide separators and
/// speaker-note markers inside code blocks are never misinterpreted.
#[derive(Default)]
struct FenceTracker {
    active: Option<(u8, usize)>,
}

impl FenceTracker {
    fn is_fenced(&self) -> bool {
        self.active.is_some()
    }

    fn observe(&mut self, line: &str) {
        let bytes = line.as_bytes();
        let indent = bytes.iter().take(4).take_while(|&&b| b == b' ').count();
        if indent > 3 {
            return;
        }
        let rest = &bytes[indent..];
        let Some(&first) = rest.first() else {
            return;
        };
        if first != b'`' && first != b'~' {
            return;
        }
        let count = rest.iter().take_while(|&&b| b == first).count();
        if count < 3 {
            return;
        }
        let after = &rest[count..];
        match self.active {
            None => {
                // CommonMark §4.5: backtick fence info strings cannot contain backticks.
                if first == b'`' && after.contains(&b'`') {
                    return;
                }
                self.active = Some((first, count));
            }
            Some((ch, open_len)) => {
                if ch == first
                    && count >= open_len
                    && after
                        .iter()
                        .all(|&b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                {
                    self.active = None;
                }
            }
        }
    }
}

/// The slides of the reveal.js Markdown `source`, as HTML, in columns: a `---` line starts the
/// next column, and a `--` line the next slide in it. Separators and `Note:`/`Notes:` speaker
/// notes inside fenced code blocks are preserved verbatim. Bounded to at most [`SLIDES_MAX`]
/// slides and [`SLIDES_HTML_MAX`] cumulative HTML bytes.
pub fn slides(source: &str) -> Vec<Vec<String>> {
    let mut columns: Vec<Vec<String>> = vec![Vec::new()];
    let mut current = String::new();
    let mut fence = FenceTracker::default();
    let mut slide_budget = PreviewBudget::new(SLIDES_MAX);
    let _ = slide_budget.try_push(); // Count the first slide.
    let mut html_remaining = SLIDES_HTML_MAX;
    let mut truncated = false;

    let render_slide = |raw: &str, remaining: &mut usize| -> String {
        let cap = (*remaining).min(MARKDOWN_HTML_MAX);
        let html = markdown_with_budget(without_notes(raw), cap);
        *remaining = remaining.saturating_sub(html.len());
        html
    };

    for line in source.lines() {
        let trimmed_end = line.trim_end();
        if !fence.is_fenced() && (trimmed_end == "---" || trimmed_end == "--") {
            let rendered = render_slide(&current, &mut html_remaining);
            columns.last_mut().expect("never empty").push(rendered);
            current.clear();
            fence = FenceTracker::default();

            if !slide_budget.try_push() {
                truncated = true;
                break;
            }
            if trimmed_end == "---" {
                columns.push(Vec::new());
            }
            continue;
        }
        fence.observe(line);
        current.push_str(line);
        current.push('\n');
    }

    if !truncated {
        let rendered = render_slide(&current, &mut html_remaining);
        columns.last_mut().expect("never empty").push(rendered);
    } else if let Some(last_slide) = columns.last_mut().and_then(|col| col.last_mut()) {
        last_slide.push_str(&format!(
            "<p class=\"preview-note\">Only the first {SLIDES_MAX} slides show.</p>"
        ));
    }

    columns
}

/// `slide` without its speaker notes (ignoring `Note:`/`Notes:` lines inside fenced code blocks).
fn without_notes(slide: &str) -> &str {
    let mut fence = FenceTracker::default();
    let mut start = 0;
    for line in slide.split_inclusive('\n') {
        if !fence.is_fenced() {
            let trimmed = line.trim_start();
            if trimmed.len() >= 5 && trimmed[..5].eq_ignore_ascii_case("note:")
                || trimmed.len() >= 6 && trimmed[..6].eq_ignore_ascii_case("notes:")
            {
                return &slide[..start];
            }
        }
        fence.observe(line);
        start += line.len();
    }
    slide
}
