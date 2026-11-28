use pulldown_latex::{
    config::DisplayMode,
    event::{
        ColorChange, ColorTarget, Content, DelimiterSize, DelimiterType, Dimension, DimensionUnit,
        EnvironmentFlow, Event as LatexEvent, Font, Grouping, StateChange, Visual,
    },
};

use crate::rpc::{DIAGRAM_SOURCE_MAX, HIGHLIGHT_MAX, Method, Request, Response, WorkerService};
use crate::validate_highlight_html;

use super::{
    MARKDOWN_HTML_MAX, MARKDOWN_SOURCE_MAX, SLIDES_HTML_MAX, SLIDES_MAX, Service, markdown,
    mathml::MathmlRenderer,
    render_markdown, render_slides,
    sanitize::{postprocess_ammonia_html, sanitize_html, tag_tables_are_sorted},
    slides,
};

// Share the attribute name between sanitizer inputs and checks on rendered output.
const STYLE_ATTRIBUTE: &str = "style";

fn assert_no_inline_style(html: &str) {
    assert!(!html.contains(&format!("{STYLE_ATTRIBUTE}=")), "{html}");
}

#[test]
fn markdown_keeps_to_itself() {
    let html = markdown(
        "# Title\n\n<script>alert(1)</script>\n\n<!-- .slide: data-x -->\n\n\
         [web](https://example.com) [script](javascript:alert(1)) [file](notes.md)\n\n\
         ![tracker](https://example.com/pixel.png) ![inline](data:image/png;base64,AAAA)\n\n\
         ```rust\nfn main() {}\n```\n\n$a^2$\n",
    );
    assert!(html.contains("<h1>Title</h1>"), "{html}");
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "{html}"
    );
    assert!(!html.contains("<script"), "{html}");
    assert!(!html.contains("slide:"), "{html}");
    assert!(
        html.contains(
            r#"<a href="https://example.com" target="_blank" rel="noopener noreferrer">web</a>"#
        ),
        "{html}"
    );
    assert!(html.contains(r##"<a href="#">script</a>"##), "{html}");
    assert!(html.contains(r##"<a href="#">file</a>"##), "{html}");
    assert!(html.contains(r#"<img alt="tracker" />"#), "{html}");
    assert!(!html.contains(r#"src="""#), "{html}");
    assert!(
        html.contains(r#"src="data:image/png;base64,AAAA""#),
        "{html}"
    );
    assert!(
        html.contains("<pre><code data-lang=\"rust\">fn main() {}\n</code></pre>"),
        "{html}"
    );
    assert!(html.contains("<math"), "{html}");
    // Maths keeps to itself too.
    assert!(!markdown(r"$\text{<script>}$").contains("<script"));
}

#[test]
fn markdown_ref_link_and_image_amplification_stay_bounded() {
    // 1. HTML output amplification (e.g. 600 KiB of `&` expanding 5x to 3 MiB `&amp;` and
    //    large NBSP / reference / inline link documents) stays strictly linear and stops at
    //    MARKDOWN_HTML_MAX with a truncation note.
    let amp_md = format!("{}\n", "&".repeat(600_000));
    let html = markdown(&amp_md);
    assert!(
        html.len() <= MARKDOWN_HTML_MAX,
        "html len {} exceeded budget",
        html.len()
    );
    assert!(html.contains("preview-note"), "expected truncation notice");
    assert_eq!(sanitize_html(&html), html);

    // 1b. Large NBSP text run and huge `&`-filled `alt` attribute stay linear and bounded.
    let nbsp_md = format!("{}\n", "\u{00A0}".repeat(200_000));
    let nbsp_html = markdown(&nbsp_md);
    assert!(nbsp_html.len() <= MARKDOWN_HTML_MAX);
    assert_eq!(sanitize_html(&nbsp_html), nbsp_html);
    let huge_alt = sanitize_html(&format!(
        r#"<img alt="{}" src="data:image/png;base64,AAAA">"#,
        "&amp;".repeat(20_000)
    ));
    assert!(
        huge_alt.len() <= 8 * 1024,
        "alt must be clamped: {}",
        huge_alt.len()
    );

    // 2. Reference-link amplification stays strictly bounded.
    let long_url = format!("https://example.com/{}", "a".repeat(3000));
    let refs = "[x] ".repeat(2_000);
    let ref_md = format!("[x]: {long_url}\n\n{refs}\n");
    let ref_html = markdown(&ref_md);
    assert!(ref_html.len() <= MARKDOWN_HTML_MAX);
    assert_eq!(sanitize_html(&ref_html), ref_html);

    // 2b. Adversarial tiny external link flood (post-sanitization attribute expansion) stays <= MARKDOWN_HTML_MAX.
    let tiny_links = "[a](http://x) ".repeat(90_000);
    let tiny_html = markdown(&tiny_links);
    assert!(
        tiny_html.len() <= MARKDOWN_HTML_MAX,
        "tiny link flood exceeded MARKDOWN_HTML_MAX: {}",
        tiny_html.len()
    );
    assert!(tiny_html.contains("preview-note"));
    assert_eq!(sanitize_html(&tiny_html), tiny_html);

    // 3. Event flood (> MARKDOWN_EVENTS_MAX) stops early with a truncation note.
    let event_flood = "- a\n".repeat(40_000);
    let event_html = markdown(&event_flood);
    assert!(
        event_html.contains("preview-note"),
        "expected event-budget truncation notice"
    );
    assert!(event_html.len() <= MARKDOWN_HTML_MAX);
    assert_eq!(sanitize_html(&event_html), event_html);

    // 4. Oversized link destination (> LINK_URL_MAX) is neutralized to `#`.
    let huge_url = format!("https://example.com/{}", "a".repeat(8 * 1024));
    let huge_link = markdown(&format!("[click]({huge_url})"));
    assert!(
        huge_link.contains(r##"<a href="#">click</a>"##),
        "{huge_link}"
    );

    // 5. Reference-image amplification: one valid base64 PNG referenced 200 times is capped.
    let img_payload = "A".repeat(40_000);
    let img_refs = "![p][i] ".repeat(200);
    let img_md = format!("[i]: data:image/png;base64,{img_payload}\n\n{img_refs}\n");
    let img_html = markdown(&img_md);
    assert!(img_html.len() <= MARKDOWN_HTML_MAX);
    assert!(img_html.matches("data:image/png;base64,").count() <= 64);

    // 6. Per-document math budget caps rendered `<math` expressions and falls back to escaped TeX.
    let math_spam = "$x$ ".repeat(600);
    let math_html = markdown(&math_spam);
    assert_eq!(math_html.matches("<math").count(), 500);
}

#[test]
fn markdown_omits_data_lang_for_oversized_code_and_mermaid_blocks() {
    let huge_rust = format!("```rust\n{}\n```\n", "a".repeat(HIGHLIGHT_MAX + 16));
    let rust_html = markdown(&huge_rust);
    assert!(rust_html.contains("<pre><code>"), "{rust_html}");
    assert!(!rust_html.contains(r#"data-lang="rust""#));

    let huge_mermaid = format!(
        "```mermaid\nflowchart LR\n{}\n```\n",
        "A-->B\n".repeat(DIAGRAM_SOURCE_MAX / 5)
    );
    let mermaid_html = markdown(&huge_mermaid);
    assert!(mermaid_html.contains("<pre><code>"));
    assert!(!mermaid_html.contains(r#"data-lang="mermaid""#));

    // Normal sized blocks keep their `data-lang`.
    let small = markdown("```mermaid\nflowchart LR\nA-->B\n```\n");
    assert!(
        small.contains(r#"<pre><code data-lang="mermaid">"#),
        "{small}"
    );
}

#[test]
fn markdown_comments_handle_html5_closers_unclosed_and_trailing_text() {
    // Trailing text after a comment on the same line is preserved.
    let trailing = markdown("<!-- comment --> visible trailing text\n");
    assert!(!trailing.contains("comment"), "{trailing}");
    assert!(trailing.contains("visible trailing text"), "{trailing}");

    // HTML5 abrupt comment closers (`<!-->`, `<!--->`, `--!>`) do not lock comment mode.
    for input in [
        "<!-->\n\n<b>after</b>\n",
        "<!--->\n\n<b>after</b>\n",
        "<!-- hidden --!>\n\n<b>after</b>\n",
    ] {
        let html = markdown(input);
        assert!(
            html.contains("&lt;b&gt;after&lt;/b&gt;"),
            "input={input:?} html={html}"
        );
    }

    // An unclosed inline `<!--` does not swallow later inline HTML in the document.
    let unclosed = markdown("Hello <!-- not closed\n\nSecond paragraph <em>kept</em>.\n");
    assert!(unclosed.contains("Second paragraph"), "{unclosed}");
    assert!(unclosed.contains("&lt;em&gt;kept&lt;/em&gt;"), "{unclosed}");
}

#[test]
fn mathml_escapes_operator_names_errors_and_relations() {
    // 1. \operatorname{...} unescaped HTML injection vector.
    let op_img = markdown(r"$\operatorname{<img src=x onerror=alert(1)>}$");
    assert!(!op_img.contains("<img"), "{op_img}");
    assert!(
        op_img.contains("<mi>&lt;img src=x onerror=alert(1)&gt;</mi>"),
        "{op_img}"
    );

    // 2. \mathop{...} unescaped HTML injection vector.
    let op_iframe = markdown(r#"$\mathop{<iframe src="/">}$"#);
    assert!(!op_iframe.contains("<iframe"), "{op_iframe}");
    assert!(op_iframe.contains("&lt;iframe"), "{op_iframe}");

    // 3. Broken LaTeX syntax errors containing <script>alert(1)</script> must bail out to
    // escaped raw TeX rather than emitting raw <merror><mtext>...</mtext></merror>.
    for broken in [
        r"$\frac{1}{<script>alert(1)</script>$",
        r"$\unknowncommand{<script>alert(1)</script>}$",
        r"$\begin{matrix} <script>alert(1)</script>$",
        r"$a^^<script>alert(1)</script>$",
        r"$\left<script>alert(1)</script>$",
    ] {
        let html = markdown(broken);
        assert!(!html.contains("<script"), "input={broken} html={html}");
        assert!(!html.contains("<merror"), "input={broken} html={html}");
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "input={broken} html={html}"
        );
    }

    // 4. <, >, and & in math relations, delimiters, and environments must be HTML-escaped.
    let rel = markdown(r"$a < b > c$");
    assert!(rel.contains("<mo>&lt;</mo>"), "{rel}");
    assert!(rel.contains("<mo>&gt;</mo>"), "{rel}");
    assert!(!rel.contains("<mo><</mo>"), "{rel}");
    assert!(!rel.contains("<mo>></mo>"), "{rel}");

    let invalid_delim = markdown(r"$\left< x \right>$");
    assert!(!invalid_delim.contains("<merror"), "{invalid_delim}");
    assert!(
        invalid_delim.contains(r"\left&lt; x \right&gt;"),
        "{invalid_delim}"
    );

    let angle_delim = markdown(r"$\left\langle x \right\rangle$");
    assert!(angle_delim.contains("<math"), "{angle_delim}");
    assert!(angle_delim.contains("stretchy=\"true\""), "{angle_delim}");

    // Direct MathmlRenderer escaping test for raw `<`, `>`, `&` in delimiters, ops, and ordinaries.
    let synthetic_events = [
        LatexEvent::Begin(Grouping::LeftRight(Some('<'), Some('>'))),
        LatexEvent::Content(Content::Ordinary {
            content: '<',
            stretchy: false,
        }),
        LatexEvent::Content(Content::BinaryOp {
            content: '&',
            small: false,
        }),
        LatexEvent::Content(Content::Delimiter {
            content: '>',
            size: Some(DelimiterSize::Big),
            ty: DelimiterType::Close,
        }),
        LatexEvent::End,
    ];
    let synthetic_html = MathmlRenderer::new(&synthetic_events, DisplayMode::Inline)
        .render()
        .expect("valid synthetic events");
    assert!(
        synthetic_html.contains("<mo stretchy=\"true\">&lt;</mo>"),
        "{synthetic_html}"
    );
    assert!(
        synthetic_html.contains("<mo stretchy=\"true\">&gt;</mo>"),
        "{synthetic_html}"
    );
    assert!(synthetic_html.contains("<mi>&lt;</mi>"), "{synthetic_html}");
    assert!(synthetic_html.contains("&amp;"), "{synthetic_html}");
    assert!(
        synthetic_html.contains("minsize=\"1.2em\" maxsize=\"1.2em\">&gt;</mo>"),
        "{synthetic_html}"
    );

    let mat = markdown(r"$$\begin{pmatrix} a & b \\ c & d \end{pmatrix}$$");
    assert!(mat.contains("<math display=\"block\">"), "{mat}");
    assert!(mat.contains("<mtable"), "{mat}");
    assert!(mat.contains("<mi>a</mi>"), "{mat}");
    assert!(mat.contains("<mi>d</mi>"), "{mat}");

    // 5. Inline styles are excluded by the page's content security policy.
    let styled_math = markdown(
        r"$\color{red}{x} + \colorbox{yellow}{y} + \fcolorbox{red}{yellow}{z} \kern -1em w$",
    );
    assert_no_inline_style(&styled_math);
    assert!(styled_math.contains("class=\"ml-box\""), "{styled_math}");

    let spaced_align = markdown("$$\\begin{align} a &= b \\\\[1em] c &= d \\end{align}$$");
    assert_no_inline_style(&spaced_align);
    assert!(spaced_align.contains("<mtable"), "{spaced_align}");
}

#[test]
fn cases_and_split_allow_one_alignment_per_row() {
    let align = || LatexEvent::EnvironmentFlow(EnvironmentFlow::Alignment);
    let newline = || {
        LatexEvent::EnvironmentFlow(EnvironmentFlow::NewLine {
            spacing: None,
            horizontal_lines: Box::default(),
        })
    };
    let render =
        |events: &[LatexEvent<'_>]| MathmlRenderer::new(events, DisplayMode::Block).render();

    for group in [
        Grouping::Cases { left: true },
        Grouping::Cases { left: false },
        Grouping::Split,
    ] {
        let begin = || LatexEvent::Begin(group.clone());
        let rows = render(&[begin(), align(), newline(), align(), LatexEvent::End])
            .expect("each row may align once");
        assert_eq!(rows.matches("</mtd><mtd>").count(), 2);
        assert_eq!(
            render(&[begin(), align(), align(), LatexEvent::End]),
            Err(())
        );
        assert_eq!(
            render(&[
                begin(),
                align(),
                newline(),
                align(),
                align(),
                LatexEvent::End
            ]),
            Err(())
        );
    }
}

#[test]
fn mathml_alignat_limits_columns_stretchy_ordinary_and_dimensions() {
    let align = || LatexEvent::EnvironmentFlow(EnvironmentFlow::Alignment);
    let render =
        |events: &[LatexEvent<'_>]| MathmlRenderer::new(events, DisplayMode::Block).render();

    // Alignat with pairs=1 allows 2 columns (1 `&`), rejecting 3 columns (2 `&`s).
    let begin1 = || {
        LatexEvent::Begin(Grouping::Alignat {
            pairs: 1,
            eq_numbers: false,
        })
    };
    let two_cols = render(&[begin1(), align(), LatexEvent::End]).expect("1 pair = 2 cols");
    assert_eq!(two_cols.matches("</mtd><mtd>").count(), 1);
    assert_eq!(
        render(&[begin1(), align(), align(), LatexEvent::End]),
        Err(())
    );

    // Alignat with pairs=2 allows 4 columns (3 `&`s), rejecting 5 columns (4 `&`s).
    let begin2 = || LatexEvent::Begin(Grouping::Alignedat { pairs: 2 });
    let four_cols =
        render(&[begin2(), align(), align(), align(), LatexEvent::End]).expect("2 pairs = 4 cols");
    assert_eq!(four_cols.matches("</mtd><mtd>").count(), 3);
    assert_eq!(
        render(&[
            begin2(),
            align(),
            align(),
            align(),
            align(),
            LatexEvent::End
        ]),
        Err(())
    );

    // Stretchy `Ordinary` uses `open_tag` so `ml-box` border state is preserved.
    let stretchy_boxed = render(&[
        LatexEvent::StateChange(StateChange::Color(ColorChange {
            color: (255, 0, 0),
            target: ColorTarget::Border,
        })),
        LatexEvent::Content(Content::Ordinary {
            content: '\u{2192}',
            stretchy: true,
        }),
    ])
    .expect("stretchy ordinary renders");
    assert!(
        stretchy_boxed.contains(r#"<mo class="ml-box" stretchy="true">"#),
        "{stretchy_boxed}"
    );

    // Unit-normalized dimension clamping (`<= 20em` equivalent) & negative non-offset rejection.
    let dims = render(&[
        LatexEvent::Space {
            width: Some(Dimension {
                value: 50.0,
                unit: DimensionUnit::In,
            }),
            height: Some(Dimension {
                value: -2.0,
                unit: DimensionUnit::Em,
            }),
            depth: Some(Dimension {
                value: 100.0,
                unit: DimensionUnit::Cm,
            }),
        },
        LatexEvent::Visual(Visual::Fraction(Some(Dimension {
            value: -1.0,
            unit: DimensionUnit::Pt,
        }))),
        LatexEvent::Content(Content::Number("1")),
        LatexEvent::Content(Content::Number("2")),
    ])
    .expect("dimensions render");
    assert!(dims.contains(r#"width="3.3333in""#), "{dims}");
    assert!(!dims.contains("height="), "{dims}");
    assert!(dims.contains(r#"depth="8.4666cm""#), "{dims}");
    assert!(!dims.contains("linethickness="), "{dims}");
    // Sanitizer accepts all clamped dimensions verbatim.
    assert_eq!(sanitize_html(&dims), dims);
}

#[test]
fn markdown_and_sanitizer_block_html_injection_and_unsafe_attributes() {
    // Raw HTML blocks and inline HTML in Markdown render as escaped text, never active tags.
    let raw = markdown(
        r#"<a ping="https://evil.example" href="https://ok.example">click</a>

<iframe src="/"></iframe>

<div class="slides full">phishing overlay</div>

<svg onload="alert(1)"><script>alert(1)</script></svg>

<form action="https://evil.example"><input type="password"></form>
"#,
    );
    assert!(!raw.contains("<a "), "{raw}");
    assert!(!raw.contains("<iframe"), "{raw}");
    assert!(!raw.contains("<div"), "{raw}");
    assert!(!raw.contains("<svg"), "{raw}");
    assert!(!raw.contains("<script"), "{raw}");
    assert!(!raw.contains("<form"), "{raw}");
    assert!(!raw.contains("<input"), "{raw}");
    assert!(raw.contains("&lt;a ping="), "{raw}");

    // Direct sanitizer checks (defense-in-depth if any upstream component ever emits raw HTML).
    let a_ping = sanitize_html(&format!(
        r#"<a href="https://example.com" ping="https://evil.example" onclick="alert(1)" {STYLE_ATTRIBUTE}="position:fixed" target="_top">go</a>"#
    ));
    assert_eq!(
        a_ping,
        r#"<a href="https://example.com" target="_blank" rel="noopener noreferrer">go</a>"#
    );

    let entity_js = sanitize_html(
        r#"<a href="&#x6a;avascript:alert(1)">a</a><a href="javascript&colon;alert(1)">b</a><a href="java&#x09;script:alert(1)">c</a>"#,
    );
    assert_eq!(
        entity_js,
        r##"<a href="#">a</a><a href="#">b</a><a href="#">c</a>"##
    );

    let dangerous_tags = sanitize_html(
        r#"<p>ok</p><script>if (a < b) alert(1)</script><style>body{display:none}</style><iframe src="/">bad</iframe><object data="x">bad</object><embed src="x"><form><button>x</button></form><base href="https://evil.example"><meta http-equiv="refresh" content="0"><link rel="stylesheet" href="x"><svg onload=alert(1)><g>bad</g></svg>"#,
    );
    assert_eq!(dangerous_tags, "<p>ok</p>");

    // Non-allowlisted classes (such as app overlay `.slides.full`) are stripped.
    let overlay = sanitize_html(r#"<div class="slides full">overlay</div>"#);
    assert_eq!(overlay, "<div>overlay</div>");

    // Slash-separated attributes and duplicate attributes cannot bypass allowlists; rejected img omits src.
    let slash_img =
        sanitize_html(r#"<img/onerror=alert(1) src="https://tracker.example/x.png" alt="pic">"#);
    assert_eq!(slash_img, r#"<img alt="pic" />"#);

    // HTML tags injected inside <math> namespace are dropped; MathML tags outside <math> are
    // dropped entirely as namespace-invalid subtrees by `ammonia`.
    let mxss = sanitize_html(&format!(
        r#"<math display="inline"><mtext><img src=x onerror=alert(1)><a href="https://evil.example">x</a></mtext><mi href="javascript:alert(1)" {STYLE_ATTRIBUTE}="color:red">y</mi></math><mi>stray</mi>"#
    ));
    assert_eq!(
        mxss,
        r#"<math display="inline"><mtext>x</mtext><mi>y</mi></math>"#
    );
    assert_eq!(sanitize_html(&mxss), mxss);

    // The aligned table must also satisfy the content security policy.
    let gfm_table = markdown("| a | b |\n| :--- | ---: |\n| 1 | 2 |\n");
    assert!(gfm_table.contains("<table>"), "{gfm_table}");
    assert!(gfm_table.contains("<th>a</th>"), "{gfm_table}");
    assert_no_inline_style(&gfm_table);

    // Tasklists keep disabled checkbox inputs while arbitrary <input> is dropped.
    let tasklist = markdown("- [x] done\n- [ ] todo\n");
    assert!(
        tasklist.contains(r#"<input disabled="" type="checkbox" checked="" />"#),
        "{tasklist}"
    );
    assert!(
        tasklist.contains(r#"<input disabled="" type="checkbox" />"#),
        "{tasklist}"
    );
    assert_eq!(
        sanitize_html(
            r#"<input type="text" value="phish"><input type="checkbox" onclick="alert(1)">"#
        ),
        r#"<input disabled="" type="checkbox" />"#
    );
}

#[test]
fn sanitize_html_is_linear_on_unclosed_tags_and_caps_attrs_and_drop_stack() {
    // Unclosed tags/quotes that previously triggered O(n^2) rescans must stay fast and safe.
    for payload in [
        "<a ".repeat(20_000),
        "<a x=\"".repeat(20_000),
        format!("{}y=\">", "<a x='\"' ".repeat(5_000)),
        format!("{}y=\">", "<a".repeat(20_000)),
    ] {
        let out = sanitize_html(&payload);
        assert!(!out.contains("<a "), "unclosed tags must be escaped");
    }

    // Incomplete start tag at EOF is discarded per HTML5 spec (matching browser DOM parsing),
    // while quoted `>` inside a complete attribute value does not blind later real tags.
    assert_eq!(sanitize_html(r#"<a x="<p>ok</p>" y"#), "");
    assert_eq!(
        sanitize_html(r#"<a x=">" y>ok</a><p>after</p>"#),
        r##"<a href="#">ok</a><p>after</p>"##
    );

    // Excessive attributes on one tag are capped and deduplicated without quadratic blowup.
    let many_attrs: String = (0..500).map(|i| format!(" data-a{i}=\"1\"")).collect();
    let capped = sanitize_html(&format!("<p{many_attrs}>hi</p>"));
    assert_eq!(capped, "<p>hi</p>");

    // Deeply nested dropped containers do not grow unboundedly or overflow the stack.
    let deep_svg = format!(
        "{}bad{}<p>ok</p>",
        "<svg>".repeat(1000),
        "</svg>".repeat(1000)
    );
    assert_eq!(sanitize_html(&deep_svg), "<p>ok</p>");
}

#[test]
fn sanitize_html_handles_rawtext_in_drop_stack_html5_edge_cases_and_footnotes() {
    // Foreign-content (`<svg>`) and HTML RCDATA/rawtext tags match HTML5 browser parsing without
    // ever leaking active scripts, event handlers, or mXSS payloads.
    // Note: per WHATWG HTML5 foreign content rules, `<script>` inside `<svg>` is NOT in HTML
    // Script Data state, so `</svg>` closes both `<script>` and `<svg>` in browsers; any element
    // after `</svg>` is parsed and sanitized in the HTML namespace.
    assert_eq!(
        sanitize_html(r#"<svg><script></svg><p>leaked</p></script></svg><p>ok</p>"#),
        "<p>leaked</p><p>ok</p>"
    );
    assert_eq!(
        sanitize_html(r#"<svg><script></svg><img src=x onerror=alert(1)></script></svg><p>ok</p>"#),
        "<img /><p>ok</p>"
    );
    assert_eq!(
        sanitize_html(
            r#"<svg><style><a title="</style><img src=x onerror=alert(1)>"></style></svg><p>ok</p>"#
        ),
        "<p>ok</p>"
    );
    assert_eq!(
        sanitize_html(r#"<math><mtext><style><img src=x onerror=alert(1)></style></mtext></math>"#),
        "<math><mtext></mtext></math>"
    );
    assert_eq!(
        sanitize_html(r#"<svg><script><svg></script></svg><p>ok</p>"#),
        "<p>ok</p>"
    );
    assert_eq!(
        sanitize_html(r#"<form><textarea></form><p>leaked</p></textarea></form><p>ok</p>"#),
        "<p>ok</p>"
    );

    // HTML5 comment edge cases: `<!-->`, `<!--->`, and `--!>`.
    assert_eq!(sanitize_html("<!--><p>ok</p>"), "<p>ok</p>");
    assert_eq!(sanitize_html("<!---><p>ok</p>"), "<p>ok</p>");
    assert_eq!(sanitize_html("<!-- c --!><p>ok</p>"), "<p>ok</p>");

    // Self-closing `<math/>` closes the foreign element so trailing `<mi>` is outside `<math>`
    // and dropped by `ammonia` as namespace-invalid.
    assert_eq!(
        sanitize_html(r#"<math display="inline"/><mi>stray</mi><p>ok</p>"#),
        r#"<math display="inline"></math><p>ok</p>"#
    );

    // MathML text integration points (`<mtext>`, `<mi>`, `<mn>`, `<mo>`): `<mspace />` inside
    // `<mtext>` is parsed in the HTML namespace and dropped to prevent parser differentials, while
    // allowlisted HTML children inside `<mtext>` / `<mi>` are stripped keeping their text only.
    assert_eq!(
        sanitize_html(r#"<math display="inline"><mtext>a<mspace width="1em" />b</mtext></math>"#),
        r#"<math display="inline"><mtext>a</mtext></math>"#
    );
    assert_eq!(
        sanitize_html(
            r#"<math display="inline"><mtext>a<strong>b</strong>c</mtext><mi><p>x</p></mi></math>"#
        ),
        r#"<math display="inline"><mtext>abc</mtext><mi>x</mi></math>"#
    );

    // Nested `<math>` inside `<mtext>` or `<mrow>` cannot close the outer `<math>` early or leak
    // links/elements out of MathML isolation, and output stays idempotent.
    let nested_math_in_mtext = sanitize_html(
        r#"<math><mtext><math>a</math><a href="https://evil.example">b</a></mtext></math>"#,
    );
    assert_eq!(nested_math_in_mtext, "<math><mtext>ab</mtext></math>");
    assert_eq!(sanitize_html(&nested_math_in_mtext), nested_math_in_mtext);

    let nested_math_in_mrow =
        sanitize_html(r#"<math><mrow><math><mi>x</mi></math><mi>y</mi></mrow></math>"#);
    assert_eq!(
        nested_math_in_mrow,
        "<math><mrow><mi>x</mi><mi>y</mi></mrow></math>"
    );
    assert_eq!(sanitize_html(&nested_math_in_mrow), nested_math_in_mrow);

    // Nested same-tag inside MathML text integration points (`mtext`/`mi`/`mn`/`mo`) cannot close
    // the outer integration point early — both when `ammonia` drops HTML-namespace inner tags and
    // when nested `<math>` keeps MathML-namespace inner tags (plus direct post-pass coverage).
    for tip in ["mtext", "mi", "mn", "mo"] {
        let html_ns_nested = sanitize_html(&format!(
            "<math><{tip}>a<{tip}>b</{tip}><mi>c</mi>d</{tip}></math>"
        ));
        assert_eq!(
            html_ns_nested,
            format!("<math><{tip}>ad</{tip}></math>"),
            "tip={tip}"
        );
        assert_eq!(sanitize_html(&html_ns_nested), html_ns_nested);

        let math_ns_nested = sanitize_html(&format!(
            r#"<math><{tip}>a<math><{tip}>b</{tip}></math><a href="https://evil.example">c</a></{tip}></math>"#
        ));
        assert_eq!(
            math_ns_nested,
            format!("<math><{tip}>abc</{tip}></math>"),
            "tip={tip}"
        );
        assert_eq!(sanitize_html(&math_ns_nested), math_ns_nested);

        let direct_post = postprocess_ammonia_html(&format!(
            "<math><{tip}>a<{tip}>b</{tip}><mi>c</mi>d</{tip}></math>"
        ));
        assert_eq!(
            direct_post,
            format!("<math><{tip}>abcd</{tip}></math>"),
            "tip={tip}"
        );
    }

    // Combined nested `<math>` + nested `<mtext>` inside `<mtext>` stays balanced and idempotent.
    let deep_nested_math = sanitize_html(
        r#"<math><mtext>a<math><mtext>b<math><mtext>c</mtext></math></mtext></math><a href="https://evil.example">d</a></mtext></math>"#,
    );
    assert_eq!(deep_nested_math, "<math><mtext>abcd</mtext></math>");
    assert_eq!(sanitize_html(&deep_nested_math), deep_nested_math);

    // Quote-aware `>` scanning in `postprocess_ammonia_html` handles unescaped `>` inside quoted
    // attributes (defense-in-depth per WHATWG §13.3 in case a future html5ever stops escaping `>`).
    let quoted_gt_attr = postprocess_ammonia_html(
        r#"<a href="https://example.com" title="a> <img onerror=alert(1)>">ok</a>"#,
    );
    assert_eq!(
        quoted_gt_attr,
        r#"<a href="https://example.com" title="a> <img onerror=alert(1)>" target="_blank" rel="noopener noreferrer">ok</a>"#
    );
    assert_eq!(
        sanitize_html(&quoted_gt_attr),
        r#"<a href="https://example.com" title="a&gt; &lt;img onerror=alert(1)&gt;" target="_blank" rel="noopener noreferrer">ok</a>"#
    );

    // Unquoted attribute values preserve trailing `/` and do not self-close the element.
    assert_eq!(
        sanitize_html("<a href=https://example.com/>ok</a>"),
        r#"<a href="https://example.com/" target="_blank" rel="noopener noreferrer">ok</a>"#
    );

    // Dotted and non-ASCII footnote IDs stay aligned between `<a href>` and `<div id>`.
    let dotted = sanitize_html(
        r##"<a href="#sec.1">1</a><div class="footnote-definition" id="sec.1">body</div>"##,
    );
    assert!(dotted.contains(r##"href="#fn-sec.1""##), "{dotted}");
    assert!(dotted.contains(r#"id="fn-sec.1""#), "{dotted}");
    assert_eq!(sanitize_html(&dotted), dotted);

    let unicode = sanitize_html(
        r##"<a href="#注1">1</a><div class="footnote-definition" id="注1">body</div>"##,
    );
    assert!(unicode.contains(r##"href="#fn-注1""##), "{unicode}");
    assert!(unicode.contains(r#"id="fn-注1""#), "{unicode}");
    assert_eq!(sanitize_html(&unicode), unicode);
}

#[test]
fn sanitize_html_restricts_image_data_urls_and_mathml_dimensions() {
    // Raster base64 data URLs are allowed.
    for mime in ["png", "jpeg", "gif", "webp", "avif"] {
        let src = format!("data:image/{mime};base64,AAAA");
        let out = sanitize_html(&format!(r#"<img src="{src}" alt="ok">"#));
        assert_eq!(out, format!(r#"<img src="{src}" alt="ok" />"#));
    }

    // SVG data URLs, non-base64 data URLs, invalid base64, empty bodies, and remote URLs omit `src`.
    for bad in [
        "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",
        "data:image/svg+xml,<svg onload=alert(1)>",
        "data:image/bmp;base64,AAAA",
        "data:image/png,rawdata",
        "data:image/png;base64,!!!not-base64!!!",
        "data:image/png;base64,",
        "data:text/html;base64,PHNjcmlwdD4=",
        "https://tracker.example/pixel.png",
    ] {
        let out = sanitize_html(&format!(r#"<img src="{bad}" alt="x">"#));
        assert_eq!(out, r#"<img alt="x" />"#, "bad={bad}");
    }

    // Oversized data URL (> 2 MiB) omits `src`.
    let huge_src = format!("data:image/png;base64,{}", "A".repeat(2 * 1024 * 1024 + 4));
    assert_eq!(
        sanitize_html(&format!(r#"<img src="{huge_src}" alt="big">"#)),
        r#"<img alt="big" />"#
    );

    // MathML dimension magnitudes and negative non-offset dimensions are enforced.
    let bad_dims = sanitize_html(
        r#"<math display="inline"><mspace width="999999999999999999in" height="-1em" depth="50in" /><mfrac linethickness="-1pt"><mi>a</mi><mi>b</mi></mfrac><mo minsize="-2em" maxsize="400px">(</mo></math>"#,
    );
    assert_eq!(
        bad_dims,
        r#"<math display="inline"><mspace /><mfrac><mi>a</mi><mi>b</mi></mfrac><mo>(</mo></math>"#
    );
    // Valid negative `mspace width` within `-20em..=20em` is preserved.
    let ok_neg = sanitize_html(r#"<math display="inline"><mspace width="-1.5em" /></math>"#);
    assert_eq!(
        ok_neg,
        r#"<math display="inline"><mspace width="-1.5em" /></math>"#
    );
}

#[test]
fn sanitize_tag_tables_are_sorted_and_highlight_validator_enforces_shape() {
    assert!(tag_tables_are_sorted());

    assert!(validate_highlight_html("").is_ok());
    assert!(
        validate_highlight_html(
            r#"<span class="hl-keyword">fn</span> <span class="hl-function_name">f</span>(&amp;&lt;&gt;&quot;&apos;&#39;&#x27;)"#
        )
        .is_ok()
    );
    for bad in [
        "<script>alert(1)</script>",
        r#"<span class="hl-keyword" onclick="alert(1)">fn</span>"#,
        r#"<span class="other">fn</span>"#,
        r#"<span class="hl-">fn</span>"#,
        r#"<span class="hl-Bad">fn</span>"#,
        r#"<span class="hl-keyword">unclosed"#,
        "</span>",
        "a < b",
        "a > b",
        "a & b",
        "a &unknown; b",
        "a &#1234567890123; b",
    ] {
        assert!(
            validate_highlight_html(bad).is_err(),
            "expected rejection for {bad}"
        );
    }
}

#[test]
fn valid_latex_mathml_and_markdown_render_cleanly() {
    let md = markdown(
        "## Euler\n\n\
         Inline $\\frac{\\sqrt{x^2 + 1}}{\\sin(x)}$ and $\\mathbf{v} \\neq 0$ and $\\bigl(a + b\\bigr)$.\n\n\
         $$\\sum_{i=1}^{n} i^2 = \\frac{n(n+1)(2n+1)}{6}$$\n\n\
         $$\\begin{cases} x & x \\ge 0 \\\\ -x & x < 0 \\end{cases}$$\n",
    );
    assert!(md.contains("<h2>Euler</h2>"), "{md}");
    assert!(md.contains("<mfrac>"), "{md}");
    assert!(md.contains("<msqrt>"), "{md}");
    assert!(md.contains("<msup>"), "{md}");
    assert!(md.contains("<munderover>"), "{md}");
    assert!(md.contains("<math display=\"inline\">"), "{md}");
    assert!(md.contains("<math display=\"block\">"), "{md}");
    assert!(md.contains("minsize=\"1.2em\" maxsize=\"1.2em\""), "{md}");
    assert!(md.contains("<mo>&lt;</mo>"), "{md}");
    assert_no_inline_style(&md);
}

#[test]
fn slides_follow_reveal() {
    let deck = "# One\n\n---\n\n# Two\n\n--\n\n# Two, below\n\nNote: not shown\n\n---\n\n# Three\n";
    let deck = slides(deck);
    assert_eq!(deck.iter().map(Vec::len).collect::<Vec<_>>(), [1, 2, 1]);
    assert!(deck[1][1].contains("Two, below"));
    assert!(!deck[1][1].contains("not shown"));
}

#[test]
fn slides_preserve_fenced_code_blocks_and_cap_slide_count() {
    let deck = slides(
        "# Code\n\n```yaml\n---\na: 1\n--\nNote: kept in backticks\n```\n\n~~~txt\n---\nNotes: kept in tildes\n~~~\n\nNote: real speaker note\n",
    );
    assert_eq!(deck.len(), 1);
    assert_eq!(deck[0].len(), 1);
    let slide = &deck[0][0];
    assert!(slide.contains("Note: kept in backticks"), "{slide}");
    assert!(slide.contains("Notes: kept in tildes"), "{slide}");
    assert!(!slide.contains("real speaker note"), "{slide}");

    // Excessive separators are capped at SLIDES_MAX instead of spawning millions of slides.
    let spam = "--\n".repeat(SLIDES_MAX + 500);
    let capped = slides(&spam);
    let total_slides: usize = capped.iter().map(Vec::len).sum();
    assert_eq!(total_slides, SLIDES_MAX);
    let total_bytes: usize = capped.iter().flatten().map(String::len).sum();
    assert!(total_bytes <= SLIDES_HTML_MAX);
    let last = capped.last().unwrap().last().unwrap();
    assert!(last.contains(&SLIDES_MAX.to_string()), "{last}");
}

#[test]
fn markdown_footnotes_prefix_ids_and_hrefs_preventing_dom_clobbering() {
    let md = "Attach something[^file-picker].\n\n[^file-picker]: footnote body\n";
    let html = markdown(md);
    assert!(
        !html.contains(r#"id="file-picker""#),
        "footnote clobbered #file-picker: {html}"
    );
    assert!(
        !html.contains(r##"href="#file-picker""##),
        "footnote href missing fn- prefix: {html}"
    );
    assert!(
        html.contains(r#"id="fn-file-picker""#),
        "expected fn- prefixed id: {html}"
    );
    assert!(
        html.contains(r##"href="#fn-file-picker""##),
        "expected fn- prefixed href: {html}"
    );
    // Sanitizer must remain idempotent (re-sanitizing does not double-prefix).
    assert_eq!(sanitize_html(&html), html);

    // Max-length (64-char) footnote id remains idempotent after fn- prefixing.
    let long_id = "a".repeat(64);
    let long_html = sanitize_html(&format!(
        r##"<div class="footnote-definition" id="{long_id}"><a href="#{long_id}">1</a></div>"##
    ));
    assert!(long_html.contains(&format!(r#"id="fn-{long_id}""#)));
    assert!(long_html.contains(&format!(r##"href="#fn-{long_id}""##)));
    assert_eq!(sanitize_html(&long_html), long_html);
}

#[test]
fn markdown_and_sanitizer_links_normalize_schemes_and_external_attrs() {
    let html = markdown(
        "[secure](HTTPS://Example.COM/CasePath?Token=AbC) \
         [plain](HTTP://example.com/Path) \
         [mail](MAILTO:User@Example.COM) \
         [bad](JAVASCRIPT:alert(1)) \
         <alice@example.com>",
    );
    assert!(
        html.contains(
            r#"<a href="https://Example.COM/CasePath?Token=AbC" target="_blank" rel="noopener noreferrer">secure</a>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(
            r#"<a href="http://example.com/Path" target="_blank" rel="noopener noreferrer">plain</a>"#
        ),
        "{html}"
    );
    assert!(
        html.contains(r#"<a href="mailto:User@Example.COM">mail</a>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<a href="mailto:alice@example.com">alice@example.com</a>"#),
        "{html}"
    );
    assert!(!html.to_ascii_lowercase().contains("javascript:"), "{html}");
    assert_eq!(sanitize_html(&html), html);

    // Overridden target/rel on external links are replaced idempotently; mailto/fragments get none.
    let http = sanitize_html(r#"<a href="HTTP://example.com/a" target="_self" rel="opener">a</a>"#);
    assert_eq!(
        http,
        r#"<a href="http://example.com/a" target="_blank" rel="noopener noreferrer">a</a>"#
    );
    assert_eq!(sanitize_html(&http), http);
    assert_eq!(
        sanitize_html(r#"<a href="mailto:user@example.com">mail</a>"#),
        r#"<a href="mailto:user@example.com">mail</a>"#
    );
    assert_eq!(
        sanitize_html(r##"<a href="#note">jump</a>"##),
        r##"<a href="#fn-note">jump</a>"##
    );
}

#[test]
fn mathml_bounds_directives_arrays_and_hlines() {
    // Excessive zero-event directives fall back cleanly without stack overflow.
    let relax_spam = format!("$${}$$", "\\relax ".repeat(200));
    let rendered = markdown(&relax_spam);
    assert!(!rendered.contains("<math"), "{rendered}");

    // Oversized array column specs and consecutive hlines fall back cleanly.
    let wide_array = format!(
        "$$\\begin{{array}}{{{}c}}x\\end{{array}}$$",
        "|".repeat(200)
    );
    assert!(!markdown(&wide_array).contains("<math"));
    let hline_spam = format!(
        "$$\\begin{{array}}{{c}}{}x\\end{{array}}$$",
        "\\hline ".repeat(64)
    );
    assert!(!markdown(&hline_spam).contains("<math"));
}

#[test]
fn mathml_maps_unicode_fonts_and_spaces() {
    // Bold digamma (`\u{03DC}` / `\u{03DD}` -> U+1D7CA / U+1D7CB) via renderer.
    let bold_digamma = MathmlRenderer::new(
        &[
            LatexEvent::Begin(Grouping::Normal),
            LatexEvent::StateChange(StateChange::Font(Some(Font::Bold))),
            LatexEvent::Content(Content::Ordinary {
                content: '\u{03DC}',
                stretchy: false,
            }),
            LatexEvent::Content(Content::Ordinary {
                content: '\u{03DD}',
                stretchy: false,
            }),
            LatexEvent::End,
        ],
        DisplayMode::Inline,
    )
    .render()
    .expect("bold digamma renders");
    assert!(bold_digamma.contains('\u{1D7CA}'), "{bold_digamma}");
    assert!(bold_digamma.contains('\u{1D7CB}'), "{bold_digamma}");

    // Fraktur exceptions H (U+210C) and I (U+2111).
    let fraktur = markdown(r"$$\mathfrak{H}\ \mathfrak{I}$$");
    assert!(fraktur.contains('\u{210C}'), "{fraktur}");
    assert!(fraktur.contains('\u{2111}'), "{fraktur}");
    assert!(!fraktur.contains('\u{210D}'), "{fraktur}");

    // SansSerifItalic (`\mathsfit{AZ}` -> U+1D608, U+1D621).
    let sans_italic = markdown(r"$$\mathsfit{AZ}$$");
    assert!(sans_italic.contains('\u{1D608}'), "{sans_italic}");
    assert!(sans_italic.contains('\u{1D621}'), "{sans_italic}");

    // TeX math spaces (`\ `, `~`) render real U+00A0 rather than literal `&amp;nbsp;`.
    let spaced = markdown(r"$a\ b~c$");
    assert!(spaced.contains("<math"), "{spaced}");
    assert!(spaced.contains('\u{00A0}'), "{spaced}");
    assert!(!spaced.contains("&amp;nbsp;"), "{spaced}");
}

#[test]
fn mathml_preflight_blocks_known_parser_bypasses() {
    // Known `pulldown-latex 0.8.0` panic, OOM, and stack-overflow inputs fall back cleanly.
    let nested_empty_groups = format!(
        "$${}$$",
        format!("{}{}", "{".repeat(16), "}".repeat(16)).repeat(20)
    );
    let nasty_inputs = [
        r"$$\char é$$".to_string(),
        r"$$\begin{alignat}{é}a & b\end{alignat}$$".to_string(),
        "$$\\kern 1em\u{00A0}x$$".to_string(),
        r"$$\color{#€€}x$$".to_string(),
        format!("$${}x$$", r"\not ".repeat(500)),
        format!("$${}x$$", "%\n".repeat(4000)),
        r"$$\def\a#1{#1#1#1#1#1#1#1#1#1#1}\def\b#1{\a{\a{\a{\a{\a{#1}}}}}}\b{x}$$".to_string(),
        r"$$\newcommand{\a}[0][x]{y}\a$$".to_string(),
        format!("$${}1$$", r"\frac1".repeat(600)),
        format!("$${}1$$", r"\frac{1}".repeat(600)),
        format!("$${}x$$", r"\sqrt[]".repeat(600)),
        format!("$${}1$$", r"\overset1".repeat(600)),
        format!("$${}x$$", r"\sideset12".repeat(500)),
        format!("$${}x$$", r"\xleftarrow[]".repeat(500)),
        format!("$${}x$$", r"\textcolor{red}".repeat(400)),
        format!("$${}x$$", r"\buildrel1\over".repeat(400)),
        // Optional-bracket smuggling & unbraced-primitive desync bypasses.
        r"$$\sqrt[\char é]{x}$$".to_string(),
        r"$$\sqrt[\color{#€€}x]{y}$$".to_string(),
        r"$$\sqrt[\newcommand{\a}[0][x]{y}\a]{z}$$".to_string(),
        r"$$\sqrt[\def\a#1{#1#1#1#1#1#1#1#1#1#1}\def\b#1{\a{\a{\a{\a{\a{#1}}}}}}\b{x}]{y}$$"
            .to_string(),
        format!("$$\\xleftarrow[{}x]{{y}}$$", r"\not ".repeat(300)),
        format!("$${}x$$", r"\frac é".repeat(600)),
        format!("$${}x$$", r"\frac\big(".repeat(600)),
        format!("$${}x$$", r"\frac1\mathup".repeat(450)),
        format!("$${}x$$", r"\buildrel a b\over".repeat(400)),
        // `%`-comment desyncs and unbraced color arguments.
        r"$$\color{%}\n#€€}x$$".replace(r"\n", "\n"),
        r"$$\fcolorbox{red%}\n}{#€€}{x}$$".replace(r"\n", "\n"),
        r"$$\begin{alignat}{%}\né}a & b\end{alignat}$$".replace(r"\n", "\n"),
        r"$$\color #€€ x$$".to_string(),
        // Wave 2 preflight bypasses: `%`/`[` inside `\color[...]`, `%` inside `\begin{alignat%\n}`,
        // and nested `{{...}}` exceeding `MATH_GROUPS_MAX`.
        "$$\\color[rgb%]{x}\n]{#€€}y$$".to_string(),
        r"$$\color[[rgb]]{#€€}y$$".to_string(),
        "$$\\begin{alignat%\n}{é}a & b\\end{alignat}$$".to_string(),
        nested_empty_groups,
        // Nested `[...]` optional-bracket desync and deeply nested `\sqrt[...]{a}`.
        format!("$${}x$$", r"\sqrt[[1]{a}]".repeat(500)),
        format!("$${}1{}$$", r"\sqrt[".repeat(500), "]{a}".repeat(500)),
    ];
    for input in &nasty_inputs {
        let out = markdown(input);
        assert!(
            !out.contains("<math"),
            "expected preflight fallback for {input:?}, got: {out}"
        );
    }

    // Legitimate `\textcolor`, `\sqrt[3]{x}`, `\begin{alignat}{2}`, long runs of Greek symbols,
    // and many side-by-side braced or single-leaf primitives still render cleanly.
    assert!(markdown(r"$$\textcolor{red}{\alpha}$$").contains("<math"));
    assert!(markdown(r"$$\sqrt[3]{x} + \xrightarrow[n]{f}$$").contains("<math"));
    assert!(markdown(r"$$\begin{alignat}{2}a & = b\end{alignat}$$").contains("<math"));
    assert!(
        markdown(
            r"$$\alpha \beta \gamma \delta \epsilon \zeta \eta \theta \iota \kappa \lambda \mu \nu \xi \omicron \pi \rho \sigma$$"
        )
        .contains("<math")
    );
    let many_fracs = format!("$${}$$", vec![r"\frac{1}{2}"; 40].join(" + "));
    assert!(markdown(&many_fracs).contains("<math"));
    let many_unbraced_leaves =
        format!("$${}$$", vec![r"\frac12 + \vec x + \sqrt2"; 20].join(" + "));
    assert!(markdown(&many_unbraced_leaves).contains("<math"));
}

#[test]
fn mathml_fuzz_never_panics_emits_no_inline_style_and_is_idempotent() {
    let tokens = [
        r"\frac",
        r"\genfrac",
        r"\sideset",
        r"\sqrt",
        r"\xleftarrow",
        r"\xrightarrow",
        r"\buildrel",
        r"\over",
        r"\mathup",
        r"\mathbf",
        r"\not",
        r"\big(",
        r"\text",
        r"\color",
        r"\textcolor",
        r"\fcolorbox",
        r"\begin{alignat}",
        r"\end{alignat}",
        r"\begin{array}{c}",
        r"\end{array}",
        r"\relax",
        r"\def",
        r"\char",
        r"\\",
        r"\hline",
        "{",
        "}",
        "[",
        "]",
        "%",
        "\n",
        "^",
        "_",
        "&",
        " ",
        "1",
        "é",
        "#€€",
        "\u{00A0}",
    ];
    let mut seed = 0xD1B5_4A32_D192_ED03u64;
    let mut next_u64 = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut expr = String::with_capacity(512);
    for _ in 0..2_000 {
        expr.clear();
        expr.push_str("$$");
        let count = 1 + (next_u64() as usize % 48);
        for _ in 0..count {
            expr.push_str(tokens[next_u64() as usize % tokens.len()]);
        }
        expr.push_str("$$");
        let rendered = markdown(&expr);
        assert!(rendered.len() <= 300 * 1024);
        assert_no_inline_style(&rendered);
        assert_eq!(sanitize_html(&rendered), rendered);
    }
}

#[test]
fn slides_handles_multibyte_utf8_lines_without_panicking() {
    // Multi-byte UTF-8 lines where byte offsets 5 and 6 fall inside a character.
    let deck =
        "日本語\n\néééé\n\n🎉🚀✨\n\nNotes: secret speaker notes\n---\n# Second\n\nNOTE: hidden";
    let rendered = slides(deck);
    assert_eq!(rendered.len(), 2);
    assert!(rendered[0][0].contains("日本語"));
    assert!(rendered[0][0].contains("éééé"));
    assert!(rendered[0][0].contains("🎉🚀✨"));
    assert!(!rendered[0][0].contains("secret speaker notes"));
    assert!(rendered[1][0].contains("Second"));
    assert!(!rendered[1][0].contains("hidden"));
}

#[test]
fn markdown_service_dispatches_and_enforces_source_caps() {
    let mut service = Service;
    assert!(service.accepts(Method::Markdown));
    assert!(service.accepts(Method::Slides));
    assert!(!service.accepts(Method::Svg));
    assert!(!service.accepts(Method::Find));

    let Response::Markdown(html) = service
        .handle(Request::Markdown {
            source: "# Hello\n".into(),
        })
        .unwrap()
    else {
        panic!("expected Markdown response");
    };
    assert!(html.contains("<h1>Hello</h1>"), "{html}");

    let Response::Slides(deck) = service
        .handle(Request::Slides {
            source: "# A\n---\n# B\n".into(),
        })
        .unwrap()
    else {
        panic!("expected Slides response");
    };
    assert_eq!(deck.len(), 2);
    assert!(deck[0][0].contains("<h1>A</h1>"));
    assert!(deck[1][0].contains("<h1>B</h1>"));

    assert!(service.handle(Request::Close { doc_id: 1 }).is_err());

    let oversized = "a".repeat(MARKDOWN_SOURCE_MAX + 1);
    assert!(render_markdown(&oversized).is_err());
    assert!(render_slides(&oversized).is_err());
}
