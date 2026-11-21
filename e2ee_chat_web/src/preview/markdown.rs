use pulldown_cmark::{CodeBlockKind, CowStr, Event, Options, Parser, Tag, TagEnd};
use pulldown_latex::config::DisplayMode;

use super::{
    mathml::mathml,
    sanitize::{escape, is_safe_image_src, normalize_safe_href, sanitize_html},
};

/// Markdown `source` as HTML: GitHub's flavour, with maths, as MathML. Raw HTML shows as
/// written, and HTML comments not at all, such as reveal.js's slide attributes. Code blocks are
/// `<pre><code data-lang="…">`, for the page to highlight, or to draw if Mermaid.
pub fn markdown(source: &str) -> String {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_MATH
        | Options::ENABLE_GFM;
    let mut in_comment = false;
    let events = Parser::new_ext(source, options).filter_map(|event| {
        Some(match event {
            Event::Html(html) | Event::InlineHtml(html) => {
                let comment = in_comment || html.trim_start().starts_with("<!--");
                in_comment = comment && !html.contains("-->");
                if comment {
                    return None;
                }
                Event::Text(html)
            }
            Event::Start(Tag::Link {
                link_type,
                dest_url,
                title,
                id,
            }) => Event::Start(Tag::Link {
                link_type,
                dest_url: safe_link(dest_url),
                title,
                id,
            }),
            Event::Start(Tag::Image {
                link_type,
                dest_url,
                title,
                id,
            }) => Event::Start(Tag::Image {
                link_type,
                dest_url: safe_image(dest_url),
                title,
                id,
            }),
            Event::Start(Tag::CodeBlock(kind)) => {
                let lang = match &kind {
                    CodeBlockKind::Fenced(info) => info.split_whitespace().next().unwrap_or(""),
                    CodeBlockKind::Indented => "",
                };
                Event::Html(format!("<pre><code data-lang=\"{}\">", escape(lang)).into())
            }
            Event::End(TagEnd::CodeBlock) => Event::Html("</code></pre>\n".into()),
            Event::InlineMath(tex) => Event::InlineHtml(mathml(&tex, DisplayMode::Inline).into()),
            Event::DisplayMath(tex) => Event::Html(mathml(&tex, DisplayMode::Block).into()),
            event => event,
        })
    });
    let mut html = String::new();
    pulldown_cmark::html::push_html(&mut html, events);
    sanitize_html(&html)
}

/// A link to the web, to mail, or within the document; any other goes nowhere.
fn safe_link(url: CowStr<'_>) -> CowStr<'_> {
    normalize_safe_href(&url)
        .map(CowStr::from)
        .unwrap_or_else(|| "#".into())
}

/// An image from a `data:image/` URL; any other shows none, rather than reach out.
fn safe_image(url: CowStr<'_>) -> CowStr<'_> {
    if is_safe_image_src(&url) {
        url.trim().to_string().into()
    } else {
        "".into()
    }
}

/// The slides of the reveal.js Markdown `source`, as HTML, in columns: a `---` line starts the
/// next column, and a `--` line the next slide in it. Speaker notes, from a `Note:` line on, do
/// not show.
pub fn slides(source: &str) -> Vec<Vec<String>> {
    split(source, "---")
        .iter()
        .map(|column| {
            split(column, "--")
                .iter()
                .map(|slide| markdown(without_notes(slide)))
                .collect()
        })
        .collect()
}

/// `source` cut at each line that is `separator`.
fn split(source: &str, separator: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    for line in source.lines() {
        if line.trim_end() == separator {
            parts.push(String::new());
        } else {
            let part = parts.last_mut().expect("never empty");
            part.push_str(line);
            part.push('\n');
        }
    }
    parts
}

/// `slide` without its speaker notes.
fn without_notes(slide: &str) -> &str {
    let mut start = 0;
    for line in slide.split_inclusive('\n') {
        let lower = line.trim_start().to_lowercase();
        if lower.starts_with("note:") || lower.starts_with("notes:") {
            return &slide[..start];
        }
        start += line.len();
    }
    slide
}
