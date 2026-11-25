use std::io::{Cursor, Read, Write};

use ::zip::write::{FullFileOptions, SimpleFileOptions};
use e2ee_chat_preview::rpc::DIAGRAM_SOURCE_MAX;
use pulldown_latex::{
    config::DisplayMode,
    event::{
        ColorChange, ColorTarget, Content, DelimiterSize, DelimiterType, Dimension, DimensionUnit,
        EnvironmentFlow, Event as LatexEvent, Font, Grouping, StateChange, Visual,
    },
};

use super::*;
use super::{
    archive::{tar, tar_slice, validate_zip_central_directory, zip},
    markdown::{MARKDOWN_HTML_MAX, SLIDES_MAX},
    mathml::MathmlRenderer,
    sanitize::{sanitize_html, tag_tables_are_sorted},
    structured::{contacts, diff, events},
};

// Share the attribute name between sanitizer inputs and checks on rendered output.
const STYLE_ATTRIBUTE: &str = "style";

fn assert_no_inline_style(html: &str) {
    assert!(!html.contains(&format!("{STYLE_ATTRIBUTE}=")), "{html}");
}

/// Build a minimal valid 54-byte Windows BMP (BITMAPINFOHEADER, 1x1 24bpp).
fn minimal_bmp() -> Vec<u8> {
    let mut bmp = vec![0u8; 58];
    bmp[0..2].copy_from_slice(b"BM");
    bmp[2..6].copy_from_slice(&58u32.to_le_bytes()); // file size
    bmp[10..14].copy_from_slice(&54u32.to_le_bytes()); // pixel offset
    bmp[14..18].copy_from_slice(&40u32.to_le_bytes()); // BITMAPINFOHEADER
    bmp[18..22].copy_from_slice(&1i32.to_le_bytes()); // width
    bmp[22..26].copy_from_slice(&1i32.to_le_bytes()); // height
    bmp[26..28].copy_from_slice(&1u16.to_le_bytes()); // planes
    bmp[28..30].copy_from_slice(&24u16.to_le_bytes()); // bpp
    bmp
}

/// Build a minimal valid Ogg BOS page with `payload` (e.g. `b"OpusHead"` or `b"\x80theora"`).
fn minimal_ogg(payload: &[u8]) -> Vec<u8> {
    let mut ogg = Vec::with_capacity(28 + payload.len());
    ogg.extend_from_slice(b"OggS");
    ogg.push(0); // version
    ogg.push(0x02); // BOS
    ogg.extend_from_slice(&[0u8; 8]); // granule
    ogg.extend_from_slice(&1u32.to_le_bytes()); // serial
    ogg.extend_from_slice(&0u32.to_le_bytes()); // sequence
    ogg.extend_from_slice(&0u32.to_le_bytes()); // crc
    ogg.push(1); // 1 segment
    ogg.push(payload.len() as u8);
    ogg.extend_from_slice(payload);
    ogg
}

/// Build a minimal valid 42-byte FLAC header + STREAMINFO metadata block.
fn minimal_flac() -> Vec<u8> {
    let mut flac = vec![0u8; 42];
    flac[0..4].copy_from_slice(b"fLaC");
    flac[4] = 0x80; // last metadata block, type 0 = STREAMINFO
    flac[5..8].copy_from_slice(&[0, 0, 34]); // 34-byte STREAMINFO
    flac
}

#[test]
fn files_sort_by_content_then_name_then_type() {
    // By content, whatever the name.
    assert_eq!(sort("notes.txt", "", b"\x89PNG\r\n\x1a\n...."), Sort::Image);
    assert_eq!(sort("photo", "", b"\x89PNG\r\n\x1a\n...."), Sort::Image);
    assert_eq!(sort("clip", "", b"\x1aE\xdf\xa3....webm"), Sort::Video);
    assert_eq!(sort("x.bin", "", b"%PDF-1.7\n..."), Sort::Document);
    assert_eq!(sort("backup", "", b"7z\xbc\xaf\x27\x1c...."), Sort::Archive);
    // An office document is a ZIP archive.
    assert_eq!(sort("report.docx", "", b"PK\x03\x04...."), Sort::Document);
    // By name, as an attachment's content is not here.
    assert_eq!(sort("main.rs", "", b""), Sort::Code);
    assert_eq!(sort("README.md", "", b""), Sort::Document);
    assert_eq!(sort("song.FLAC", "", b""), Sort::Audio);
    assert_eq!(sort("site.tar.gz", "", b""), Sort::Archive);
    // Then by the type its sender gave, then as text or not.
    assert_eq!(sort("clip", "video/mp4", b""), Sort::Video);
    assert_eq!(sort("letter", "", b"Dear Bob"), Sort::Document);
    assert_eq!(
        sort("blob", "application/octet-stream", b"\0\x01"),
        Sort::Other
    );
    assert_eq!(sort("blob", "", b""), Sort::Other);
}

#[test]
fn kinds_come_from_contents_first() {
    let kind_of = |name, data: &[u8]| kind(name, "", data);
    assert_eq!(kind_of("x.bin", b"%PDF-1.7\n..."), Kind::Pdf);
    assert_eq!(
        kind_of("photo.txt", b"\x89PNG\r\n\x1a\n...."),
        Kind::Image("image/png")
    );
    assert_eq!(
        kind_of("a", b"\0\0\0\x1cftypavif\0\0\0\0"),
        Kind::Image("image/avif")
    );
    assert_eq!(
        kind_of("clip", b"\0\0\0\x14ftypqt  \0\0\0\0"),
        Kind::Video("video/quicktime")
    );
    assert_eq!(
        kind_of("voice", b"\0\0\0\x1cftypM4A \0\0\0\0"),
        Kind::Audio("audio/mp4")
    );
    assert_eq!(
        kind_of("photo.heic", b"\0\0\0\x18ftypheic\0\0\0\0"),
        Kind::None
    );
    assert_eq!(
        kind_of("a.opus", &minimal_ogg(b"OpusHead")),
        Kind::Audio("audio/ogg")
    );
    assert_eq!(
        kind_of("v.ogv", &minimal_ogg(b"\x80theora")),
        Kind::Video("video/ogg")
    );
    assert_eq!(
        kind_of("song", b"ID3\x04\0\0\0\0\0\x10"),
        Kind::Audio("audio/mpeg")
    );
    assert_eq!(kind_of("pic", &minimal_bmp()), Kind::Image("image/bmp"));
    assert_eq!(kind_of("track", &minimal_flac()), Kind::Audio("audio/flac"));
    assert_eq!(
        kind_of("logo.svg", b"<?xml version=\"1.0\"?><svg xmlns=\"\"></svg>"),
        Kind::Image("image/svg+xml")
    );
    // Office documents are archives, but show nothing.
    assert_eq!(kind_of("report.docx", b"PK\x03\x04...."), Kind::None);
    assert_eq!(kind_of("blob", &[0xC3, 0x28, 0x00]), Kind::None);
    // Text, highlighted as its name says, unless too long.
    assert_eq!(
        kind_of("main.rs", b"fn main() {}"),
        Kind::Code {
            text: "fn main() {}".into(),
            language: Some("rust")
        }
    );
    let long = vec![b'a'; HIGHLIGHT_MAX + 1];
    assert!(matches!(
        kind_of("a.rs", &long),
        Kind::Code { language: None, .. }
    ));
    assert_eq!(
        kind_of("a.json", br#"{"a":[1,2]}"#),
        Kind::Code {
            text: "{\n  \"a\": [\n    1,\n    2\n  ]\n}".into(),
            language: Some("json")
        }
    );
}

#[test]
fn sniffing_avoids_text_false_positives_handles_mime_params_utf8_prefix_and_svg_cap() {
    // Plain text starting with "BM", "ID3", "OggS", or "fLaC" must stay text/Document, not media.
    for (name, text) in [
        (
            "notes.txt",
            "BM is an abbreviation in a long plain text document exceeding 26 bytes.",
        ),
        (
            "readme.txt",
            "ID3 tags store audio metadata such as artist and album.",
        ),
        (
            "spec.txt",
            "OggS is the page capture pattern of the Ogg container format.",
        ),
        (
            "codec.txt",
            "fLaC is a lossless audio codec with 34-byte STREAMINFO headers.",
        ),
    ] {
        assert_eq!(sort(name, "", text.as_bytes()), Sort::Document, "{name}");
        assert!(
            matches!(kind(name, "", text.as_bytes()), Kind::Code { .. }),
            "expected text preview for {name}, got {:?}",
            kind(name, "", text.as_bytes())
        );
    }

    // Invalid ID3 flags or non-synchsafe size bytes are rejected.
    assert!(media_mime("a", "", b"ID3\x04\0\x01\0\0\0\x10").is_none());
    assert!(media_mime("a", "", b"ID3\x04\0\0\x80\0\0\x10").is_none());

    // MIME parameters (`; codecs=...`, `; charset=...`) are stripped cleanly before matching.
    assert_eq!(
        media_mime("clip", r#"video/mp4; codecs="avc1.42E01E""#, b""),
        Some("video/mp4")
    );
    assert_eq!(
        sort("clip", r#"video/mp4; codecs="avc1.42E01E""#, b""),
        Sort::Video
    );
    assert_eq!(
        kind("clip", r#"audio/aac; profile="lc""#, b""),
        Kind::Audio("audio/aac")
    );
    assert_eq!(
        sort("doc", "application/pdf; name=report.pdf", b""),
        Sort::Document
    );
    assert_eq!(
        sort("note", "text/plain; charset=utf-8", b""),
        Sort::Document
    );

    // Prefix UTF-8 scan in `sort()` tolerates a multi-byte UTF-8 character straddling 8 KiB.
    let mut boundary_utf8 = vec![b'a'; 8 * 1024 - 1];
    boundary_utf8.extend_from_slice("é".as_bytes()); // 2 bytes straddling offset 8192
    boundary_utf8.extend_from_slice(b" trailing text");
    assert_eq!(sort("utf8file", "", &boundary_utf8), Sort::Document);
    // Invalid UTF-8 inside the prefix (not an MP3/AAC sync header) is still Sort::Other.
    assert_eq!(sort("binfile", "", &[0xC3, 0x28, 0x80]), Sort::Other);

    // SVG preview size is capped at SVG_MAX and `<svg` is only sniffed in the prefix.
    let mut oversized_svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\">".to_vec();
    oversized_svg.resize(SVG_MAX + 1, b' ');
    assert_eq!(image_mime("huge.svg", &oversized_svg), None);

    let mut late_svg = vec![b' '; 9 * 1024];
    late_svg.extend_from_slice(b"<svg></svg>");
    assert_eq!(image_mime("late.svg", &late_svg), None);
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
    //    large reference/inline link documents) stops at MARKDOWN_HTML_MAX with a truncation note.
    let amp_md = format!("{}\n", "&".repeat(600_000));
    let html = markdown(&amp_md);
    assert!(
        html.len() <= MARKDOWN_HTML_MAX + 1024,
        "html len {} exceeded budget",
        html.len()
    );
    assert!(html.contains("preview-note"), "expected truncation notice");
    assert_eq!(sanitize_html(&html), html);

    // 2. Reference-link amplification stays strictly bounded.
    let long_url = format!("https://example.com/{}", "a".repeat(3000));
    let refs = "[x] ".repeat(2_000);
    let ref_md = format!("[x]: {long_url}\n\n{refs}\n");
    let ref_html = markdown(&ref_md);
    assert!(ref_html.len() <= MARKDOWN_HTML_MAX + 1024);
    assert_eq!(sanitize_html(&ref_html), ref_html);

    // 3. Event flood (> MARKDOWN_EVENTS_MAX) stops early with a truncation note.
    let event_flood = "- a\n".repeat(40_000);
    let event_html = markdown(&event_flood);
    assert!(
        event_html.contains("preview-note"),
        "expected event-budget truncation notice"
    );
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
    assert!(img_html.len() <= MARKDOWN_HTML_MAX + 1024);
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

    // HTML tags injected inside <math> namespace are dropped; MathML tags outside <math> are dropped.
    let mxss = sanitize_html(&format!(
        r#"<math display="inline"><mtext><img src=x onerror=alert(1)><a href="https://evil.example">x</a></mtext><mi href="javascript:alert(1)" {STYLE_ATTRIBUTE}="color:red">y</mi></math><mi>stray</mi>"#
    ));
    assert_eq!(
        mxss,
        r#"<math display="inline"><mtext>x</mtext><mi>y</mi></math>stray"#
    );

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

    // Quoted `>` inside an earlier unclosed tag must not blind later real tags.
    let after_quoted_gt = sanitize_html(r#"<a x="<p>ok</p>" y"#);
    assert!(after_quoted_gt.contains("<p>ok</p>"), "{after_quoted_gt}");

    // Excessive attributes on one tag are capped and deduplicated without quadratic blowup.
    let many_attrs: String = (0..500).map(|i| format!(" data-a{i}=\"1\"")).collect();
    let capped = sanitize_html(&format!("<p{many_attrs}>hi</p>"));
    assert_eq!(capped, "<p>hi</p>");

    // Deeply nested dropped containers do not grow `drop_stack` unboundedly.
    let deep_svg = format!(
        "{}bad{}<p>ok</p>",
        "<svg>".repeat(1000),
        "</svg>".repeat(1000)
    );
    assert_eq!(sanitize_html(&deep_svg), "<p>ok</p>");
}

#[test]
fn sanitize_html_handles_rawtext_in_drop_stack_html5_edge_cases_and_footnotes() {
    // Rawtext tags inside `drop_stack` must not let inner `</svg>` prematurely pop `drop_stack`
    // or let inner `<svg>` swallow the rest of the document.
    assert_eq!(
        sanitize_html(r#"<svg><script></svg><p>leaked</p></script></svg><p>ok</p>"#),
        "<p>ok</p>"
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

    // Self-closing `<math/>` must not leave `math_depth` incremented for trailing MathML tags.
    assert_eq!(
        sanitize_html(r#"<math display="inline"/><mi>stray</mi><p>ok</p>"#),
        r#"<math display="inline"></math>stray<p>ok</p>"#
    );

    // `<mspace />` inside `<mtext>` integration point is dropped to prevent HTML5 parser differentials.
    assert_eq!(
        sanitize_html(r#"<math display="inline"><mtext>a<mspace width="1em" />b</mtext></math>"#),
        r#"<math display="inline"><mtext>ab</mtext></math>"#
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
fn csv_table_bounds_columns_and_total_cells() {
    // Adversarial single row with many columns is capped to COLS_MAX + truncation cell.
    let wide_row = (0..COLS_MAX + 50)
        .map(|i| format!("c{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let Kind::Table(wide) = kind("wide.csv", "", wide_row.as_bytes()) else {
        panic!("expected table");
    };
    assert_eq!(wide.rows.len(), 1);
    assert_eq!(wide.rows[0].len(), COLS_MAX + 1);
    assert_eq!(wide.rows[0][0], "c0");
    assert_eq!(wide.rows[0][COLS_MAX - 1], format!("c{}", COLS_MAX - 1));
    assert_eq!(wide.rows[0][COLS_MAX], "… (+50 more columns)");
    assert!(wide.more);
    assert!(!wide.truncated_rows);
    assert!(wide.truncated_columns);
    assert!(!wide.truncated_cells);
    assert!(wide.notice().unwrap().contains(&COLS_MAX.to_string()));

    // Adversarial grid with many rows x COLS_MAX columns stops at CELLS_MAX total cells.
    let row_line = (0..COLS_MAX).map(|_| "x").collect::<Vec<_>>().join(",");
    let many_rows = vec![row_line; 300].join("\n");
    let Kind::Table(grid) = kind("grid.csv", "", many_rows.as_bytes()) else {
        panic!("expected table");
    };
    let rendered_cells: usize = grid.rows.iter().map(Vec::len).sum();
    assert!(
        rendered_cells <= CELLS_MAX,
        "rendered_cells={rendered_cells}"
    );
    assert_eq!(grid.rows.len(), CELLS_MAX / COLS_MAX);
    assert!(grid.more);
    assert!(!grid.truncated_rows);
    assert!(!grid.truncated_columns);
    assert!(grid.truncated_cells);
    assert!(grid.notice().unwrap().contains(&CELLS_MAX.to_string()));

    // Tall narrow table stops at ROWS_MAX.
    let tall = vec!["a,b"; ROWS_MAX + 10].join("\n");
    let Kind::Table(tall_table) = kind("tall.csv", "", tall.as_bytes()) else {
        panic!("expected table");
    };
    assert_eq!(tall_table.rows.len(), ROWS_MAX);
    assert!(tall_table.more);
    assert!(tall_table.truncated_rows);
    assert!(!tall_table.truncated_columns);
    assert!(!tall_table.truncated_cells);
    assert!(tall_table.notice().unwrap().contains(&ROWS_MAX.to_string()));
}

#[test]
fn table_notice_handles_exact_row_limit_and_parse_errors() {
    // Exactly ROWS_MAX rows where only row 0 exceeds COLS_MAX must NOT claim row truncation.
    let wide_first = (0..COLS_MAX + 2)
        .map(|i| format!("c{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut rows = Vec::with_capacity(ROWS_MAX);
    rows.push(wide_first);
    for _ in 1..ROWS_MAX {
        rows.push("a,b".to_string());
    }
    let csv = rows.join("\n");
    let Kind::Table(exact) = kind("exact.csv", "", csv.as_bytes()) else {
        panic!("expected table");
    };
    assert_eq!(exact.rows.len(), ROWS_MAX);
    assert!(exact.more);
    assert!(!exact.truncated_rows);
    assert!(exact.truncated_columns);
    let notice = exact.notice().expect("column truncation notice");
    assert!(notice.contains(&COLS_MAX.to_string()), "{notice}");
    assert!(!notice.contains(&ROWS_MAX.to_string()), "{notice}");

    // A table with `more: true` and no limit flags (e.g. CSV parse error) reports parse failure.
    let errored = Table {
        rows: vec![vec!["a".into()]],
        more: true,
        truncated_rows: false,
        truncated_columns: false,
        truncated_cells: false,
    };
    let err_notice = errored.notice().expect("parse error notice");
    assert!(err_notice.contains("could not be parsed"), "{err_notice}");
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
    let last = capped.last().unwrap().last().unwrap();
    assert!(last.contains(&SLIDES_MAX.to_string()), "{last}");
}

#[test]
fn tables_cards_and_diffs() {
    let Kind::Table(table) = kind("a.csv", "", b"name,age\n\"Doe, J\",30\n") else {
        panic!("a table");
    };
    assert_eq!(table.rows, [["name", "age"], ["Doe, J", "30"]]);
    assert!(!table.more);

    let vcard = "BEGIN:VCARD\r\nVERSION:4.0\r\nN:Doe;Jane;;;\r\nTEL;TYPE=cell:+1 555\r\n\
                 ADR:;;1 Main St;Springfield;;12345;\r\n  USA\r\nEND:VCARD\r\n";
    assert_eq!(
        contacts(vcard).items,
        [Card {
            title: "Jane Doe".into(),
            fields: vec![
                ("Phone", "+1 555".into()),
                ("Address", "1 Main St, Springfield, 12345, USA".into())
            ]
        }]
    );
    let ics = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:Lab meeting\nDTSTART:20261028T140000Z\n\
               LOCATION:Room 2\\, east\nBEGIN:VALARM\nDESCRIPTION:reminder\nEND:VALARM\n\
               END:VEVENT\nEND:VCALENDAR\n";
    assert_eq!(
        events(ics).items,
        [Card {
            title: "Lab meeting".into(),
            fields: vec![
                ("Starts", "2026-10-28 14:00 UTC".into()),
                ("Where", "Room 2, east".into())
            ]
        }]
    );

    let parsed_diff =
        diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n same\n");
    let kinds: Vec<_> = parsed_diff.lines.iter().map(|(kind, _)| *kind).collect();
    use DiffLine::*;
    assert_eq!(kinds, [File, File, File, Hunk, Removed, Added, Context]);
}

#[test]
fn diff_caps_lines_and_classifies_multi_file_unified_headers() {
    // Plain `diff -u` with multiple files and no `diff --git` separator line.
    let multi = "\
--- file1.txt\t2026-01-01
+++ file1.txt\t2026-01-02
@@ -1 +1 @@
-old1
+new1
--- file2.txt\t2026-01-01
+++ file2.txt\t2026-01-02
@@ -1 +1 @@
-old2
+new2
";
    let parsed = diff(multi);
    let kinds: Vec<_> = parsed.lines.iter().map(|(k, _)| *k).collect();
    use DiffLine::*;
    assert_eq!(
        kinds,
        [
            File, File, Hunk, Removed, Added, File, File, Hunk, Removed, Added
        ]
    );
    assert!(!parsed.truncated);

    // Diff lines are capped at DIFF_LINES_MAX with an accurate notice.
    let huge = "+line\n".repeat(DIFF_LINES_MAX + 50);
    let capped = diff(&huge);
    assert_eq!(capped.lines.len(), DIFF_LINES_MAX);
    assert!(capped.truncated);
    assert!(
        capped
            .notice()
            .unwrap()
            .contains(&DIFF_LINES_MAX.to_string())
    );
}

#[test]
fn vcard_and_ical_handle_quoted_colons_tzid_groups_escaping_mailto_recovery_and_caps() {
    // Quoted colon in parameter, Apple group prefix, escaped `\;` inside structured N/ORG/ADR,
    // and escaped backslashes.
    let vcard = concat!(
        "BEGIN:VCARD\r\n",
        "VERSION:4.0\r\n",
        "N:Smith\\;Jr.;Jane;;;\r\n",
        "item1.EMAIL;ALTREP=\"http://example.com/u\":alice@example.com\r\n",
        "ORG:Acme\\; Inc.;Engineering\r\n",
        "ADR:;;1\\;2 Main St;City;;;\r\n",
        "NOTE:C:\\\\notes\\nLine2\\,a\\;b\r\n",
        "END:VCARD\r\n",
    );
    let Kind::Cards(cards) = kind("a.vcf", "text/vcard", vcard.as_bytes()) else {
        panic!("expected Cards preview");
    };
    assert_eq!(cards.items.len(), 1);
    assert_eq!(cards.items[0].title, "Jane Smith;Jr.");
    assert_eq!(
        cards.items[0].fields,
        vec![
            ("Email", "alice@example.com".into()),
            ("Organization", "Acme; Inc., Engineering".into()),
            ("Address", "1;2 Main St, City".into()),
            ("Note", "C:\\notes\nLine2,a;b".into()),
        ]
    );

    // iCalendar: TZID displayed on DTSTART/DTEND, mixed-case Mailto: stripped, and unclosed
    // BEGIN:VALARM recovers on END:VEVENT (and unclosed VEVENT recovers on next BEGIN:VEVENT).
    let ics = concat!(
        "BEGIN:VCALENDAR\n",
        "BEGIN:VEVENT\n",
        "SUMMARY;ALTREP=\"https://cal.example/1\":Standup\n",
        "DTSTART;TZID=America/New_York:20261028T093000\n",
        "DTEND;TZID=\"Europe/Berlin\":20261028T100000\n",
        "ORGANIZER;CN=Alice:Mailto:alice@example.com\n",
        "ATTENDEE:mAiLtO:bob@example.com\n",
        "BEGIN:VALARM\n",
        "DESCRIPTION:ignored alarm\n",
        "END:VEVENT\n",
        "BEGIN:VEVENT\n",
        "SUMMARY:Second event\n",
        "END:VEVENT\n",
        "END:VCALENDAR\n",
    );
    let parsed_events = events(ics);
    assert_eq!(parsed_events.items.len(), 2);
    assert_eq!(parsed_events.items[0].title, "Standup");
    assert_eq!(
        parsed_events.items[0].fields,
        vec![
            ("Starts", "2026-10-28 09:30 America/New_York".into()),
            ("Ends", "2026-10-28 10:00 Europe/Berlin".into()),
            ("Organizer", "alice@example.com".into()),
            ("Attendee", "bob@example.com".into()),
        ]
    );
    assert_eq!(parsed_events.items[1].title, "Second event");

    // Cards and fields per card are bounded by CARDS_MAX and CARD_FIELDS_MAX.
    let many_fields: String = (0..CARD_FIELDS_MAX + 20)
        .map(|i| format!("EMAIL:u{i}@example.com\n"))
        .collect();
    let big_card = contacts(&format!("BEGIN:VCARD\nFN:Busy\n{many_fields}END:VCARD\n"));
    assert_eq!(big_card.items.len(), 1);
    assert_eq!(big_card.items[0].fields.len(), CARD_FIELDS_MAX);
    assert!(!big_card.truncated_cards);
    assert!(big_card.truncated_fields);
    assert!(big_card.notice().is_some());

    let many_cards = "BEGIN:VCARD\nFN:Person\nEND:VCARD\n".repeat(CARDS_MAX + 25);
    let capped_cards = contacts(&many_cards);
    assert_eq!(capped_cards.items.len(), CARDS_MAX);
    assert!(capped_cards.truncated_cards);
    assert!(
        capped_cards
            .notice()
            .unwrap()
            .contains(&CARDS_MAX.to_string())
    );
}

#[test]
fn archives_list_their_entries() {
    let mut zip = ::zip::ZipWriter::new(Cursor::new(vec![]));
    zip.add_directory("docs/", ::zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.start_file("docs/a.txt", ::zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"hello").unwrap();
    let data = zip.finish().unwrap().into_inner();
    assert_eq!(
        kind("a.zip", "", &data),
        Kind::Archive(Listing {
            entries: vec![
                Entry {
                    path: "docs/".into(),
                    size: 0,
                    directory: true,
                    note: None,
                },
                Entry {
                    path: "docs/a.txt".into(),
                    size: 5,
                    directory: false,
                    note: None,
                },
            ],
            complete: true,
        })
    );

    let mut tar_builder = ::tar::Builder::new(vec![]);
    let mut header = ::tar::Header::new_gnu();
    header.set_size(5);
    header.set_cksum();
    tar_builder
        .append_data(&mut header, "a.txt", &b"hello"[..])
        .unwrap();
    let tar_bytes = tar_builder.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
    gz.write_all(&tar_bytes).unwrap();
    let expected = Kind::Archive(Listing {
        entries: vec![Entry {
            path: "a.txt".into(),
            size: 5,
            directory: false,
            note: None,
        }],
        complete: true,
    });
    assert_eq!(kind("a.tar.gz", "", &gz.finish().unwrap()), expected);
    assert_eq!(kind("a.tar", "", &tar_bytes), expected);
    assert_eq!(
        tar_slice(&tar_bytes),
        Some(Listing {
            entries: vec![Entry {
                path: "a.txt".into(),
                size: 5,
                directory: false,
                note: None,
            }],
            complete: true,
        })
    );
}

#[test]
fn tar_rejects_longname_and_pax_bombs_all_zero_gz_and_supports_multigz() {
    // 1. All-zero `.gz` must return None (not an empty tar listing).
    let mut zero_gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
    zero_gz.write_all(&[0u8; 4096]).unwrap();
    let zero_gz = zero_gz.finish().unwrap();
    assert_eq!(tar(MultiGzDecoder::new(&zero_gz[..]), UNPACKED_MAX), None);
    assert_eq!(kind("zeros.gz", "", &zero_gz), Kind::None);

    // 2. GNU LongName (`L`) > 4 KiB bomb inside `.tar.gz` stops before allocating the bomb.
    let mut bomb_tar = Vec::new();
    let mut long_hdr = ::tar::Header::new_gnu();
    long_hdr.set_entry_type(::tar::EntryType::GNULongName);
    long_hdr.set_path("././@LongLink").unwrap();
    long_hdr.set_size(16 << 20); // 16 MiB LongName header
    long_hdr.set_cksum();
    bomb_tar.extend_from_slice(long_hdr.as_bytes());
    let mut bomb_gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
    bomb_gz.write_all(&bomb_tar).unwrap();
    // Append compressed zeros for the 16 MiB payload.
    std::io::copy(&mut std::io::repeat(b'a').take(16 << 20), &mut bomb_gz).unwrap();
    let bomb_gz = bomb_gz.finish().unwrap();
    assert_eq!(tar(MultiGzDecoder::new(&bomb_gz[..]), UNPACKED_MAX), None);

    // 3. PAX (`x`) > 4 KiB bomb is also rejected before allocation.
    let mut pax_bomb = Vec::new();
    let mut pax_hdr = ::tar::Header::new_ustar();
    pax_hdr.set_entry_type(::tar::EntryType::XHeader);
    pax_hdr.set_path("pax").unwrap();
    pax_hdr.set_size(8 * 1024);
    pax_hdr.set_cksum();
    pax_bomb.extend_from_slice(pax_hdr.as_bytes());
    pax_bomb.resize(pax_bomb.len() + 8 * 1024, b' ');
    assert_eq!(tar_slice(&pax_bomb), None);

    // 4. Valid GNU LongName (<= 4 KiB) still lists properly.
    let long_name = format!("dir/{}.txt", "x".repeat(200));
    let mut long_builder = ::tar::Builder::new(vec![]);
    let mut hdr = ::tar::Header::new_gnu();
    hdr.set_size(3);
    hdr.set_cksum();
    long_builder
        .append_data(&mut hdr, &long_name, &b"abc"[..])
        .unwrap();
    let long_tar = long_builder.into_inner().unwrap();
    let listing = tar_slice(&long_tar).expect("valid longname tar");
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].path, long_name);
    assert!(listing.complete);

    // 5. Multi-member gzip (`.tar.gz` concatenated from two gzip streams) lists all entries.
    let mut tar_builder = ::tar::Builder::new(vec![]);
    for (name, body) in [("first.txt", b"111"), ("second.txt", b"222")] {
        let mut h = ::tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_cksum();
        tar_builder.append_data(&mut h, name, &body[..]).unwrap();
    }
    let full_tar = tar_builder.into_inner().unwrap();
    let mid = full_tar.len() / 2;
    let mut multi_gz = Vec::new();
    for part in [&full_tar[..mid], &full_tar[mid..]] {
        let mut enc = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
        enc.write_all(part).unwrap();
        multi_gz.extend_from_slice(&enc.finish().unwrap());
    }
    let Kind::Archive(multi_listing) = kind("multi.tar.gz", "", &multi_gz) else {
        panic!("expected multi-member tar.gz archive");
    };
    let paths: Vec<_> = multi_listing
        .entries
        .iter()
        .map(|e| e.path.as_str())
        .collect();
    assert_eq!(paths, ["first.txt", "second.txt"]);
    assert!(multi_listing.complete);
}

#[test]
fn archives_sanitize_bidi_paths_and_flag_links_and_traversal() {
    // ZIP with BiDi RLO spoofing, control chars, traversal, and Unix symlink mode.
    let mut zip_writer = ::zip::ZipWriter::new(Cursor::new(vec![]));
    zip_writer
        .start_file("doc\u{202E}fdp.exe\x07", SimpleFileOptions::default())
        .unwrap();
    zip_writer.write_all(b"x").unwrap();
    zip_writer
        .start_file("../etc/passwd", SimpleFileOptions::default())
        .unwrap();
    zip_writer.write_all(b"y").unwrap();
    zip_writer
        .add_symlink("link", "target", SimpleFileOptions::default())
        .unwrap();
    let zip_bytes = zip_writer.finish().unwrap().into_inner();
    let listing = zip(&zip_bytes).expect("zip listing");
    assert_eq!(listing.entries[0].path, "docfdp.exe");
    assert_eq!(listing.entries[0].note, None);
    assert_eq!(listing.entries[1].path, "../etc/passwd");
    assert_eq!(listing.entries[1].note.as_deref(), Some("path traversal"));
    assert_eq!(listing.entries[2].note.as_deref(), Some("symlink"));

    // TAR with BiDi path, traversal, symlink, and hardlink.
    let mut tar_bytes = Vec::new();
    let mut add_raw = |name: &str, entry_type: ::tar::EntryType, link: Option<&str>| {
        let mut h = ::tar::Header::new_gnu();
        h.set_entry_type(entry_type);
        h.set_size(0);
        // Write raw bytes directly into header name/linkname fields to allow traversal/BiDi.
        let name_bytes = name.as_bytes();
        h.as_gnu_mut().unwrap().name[..name_bytes.len()].copy_from_slice(name_bytes);
        if let Some(target) = link {
            let t = target.as_bytes();
            h.as_gnu_mut().unwrap().linkname[..t.len()].copy_from_slice(t);
        }
        h.set_cksum();
        tar_bytes.extend_from_slice(h.as_bytes());
    };
    add_raw("a/\u{202E}b.txt", ::tar::EntryType::Regular, None);
    add_raw(
        "slink",
        ::tar::EntryType::Symlink,
        Some("../secret\u{202E}"),
    );
    add_raw("hlink", ::tar::EntryType::Link, Some("orig.txt"));
    add_raw("/abs/path", ::tar::EntryType::Regular, None);
    tar_bytes.extend_from_slice(&[0u8; 1024]);

    let tar_listing = tar_slice(&tar_bytes).expect("tar listing");
    assert_eq!(tar_listing.entries[0].path, "a/b.txt");
    assert_eq!(tar_listing.entries[0].note, None);
    assert_eq!(
        tar_listing.entries[1].note.as_deref(),
        Some("symlink -> ../secret")
    );
    assert_eq!(
        tar_listing.entries[2].note.as_deref(),
        Some("hardlink -> orig.txt")
    );
    assert_eq!(tar_listing.entries[3].path, "/abs/path");
    assert_eq!(
        tar_listing.entries[3].note.as_deref(),
        Some("path traversal")
    );
}

/// One real entry, with an uncommented EOCD so its fields can be varied independently.
fn sample_zip(zip64: bool) -> Vec<u8> {
    let mut writer = ::zip::ZipWriter::new(Cursor::new(Vec::new()));
    if zip64 {
        // large_file sets the entry's ZIP64 fields. An extensible data sector also
        // makes ZipWriter emit a ZIP64 end record for this small directory.
        writer.set_raw_zip64_extensible_data_sector(Box::default());
        writer.start_file("a.txt", SimpleFileOptions::default().large_file(true))
    } else {
        writer.start_file(
            "a.txt",
            FullFileOptions::default().with_file_comment("file comment"),
        )
    }
    .unwrap();
    writer.write_all(b"hello").unwrap();
    writer.finish().unwrap().into_inner()
}

#[track_caller]
fn assert_sample_listing(data: &[u8]) {
    assert_eq!(
        kind("a.zip", "", data),
        Kind::Archive(Listing {
            entries: vec![Entry {
                path: "a.txt".into(),
                size: 5,
                directory: false,
                note: None,
            }],
            complete: true,
        })
    );
}

#[track_caller]
fn assert_zip_rejected(data: &[u8]) {
    assert!(validate_zip_central_directory(data).is_none());
    assert_eq!(zip(data), None);
    assert_eq!(kind("a.zip", "", data), Kind::None);
}

#[track_caller]
fn assert_zip_field_rejected<const N: usize>(data: &[u8], offset: usize, value: [u8; N]) {
    let mut data = data.to_vec();
    data[offset..offset + N].copy_from_slice(&value);
    assert_zip_rejected(&data);
}

#[test]
fn empty_and_commented_zips_list_cleanly() {
    let mut empty = [0; 22];
    empty[..4].copy_from_slice(b"PK\x05\x06");
    assert_eq!(
        kind("a.zip", "", &empty),
        Kind::Archive(Listing {
            entries: vec![],
            complete: true
        })
    );

    let mut data = sample_zip(false);
    assert_sample_listing(&data);
    let end = data.len() - 22;
    data[end + 20..].copy_from_slice(&u16::MAX.to_le_bytes());
    let mut comment = vec![b'x'; usize::from(u16::MAX)];
    // This signature inside the archive comment has no matching comment length.
    let pos = comment.len() - 32;
    comment[pos..pos + 4].copy_from_slice(b"PK\x05\x06");
    data.extend_from_slice(&comment);
    assert_sample_listing(&data);
    data.pop();
    assert_zip_rejected(&data);
}

#[test]
fn archive_comments_cannot_change_the_listed_directory() {
    let mut comment = [0; 23];
    comment[..4].copy_from_slice(b"PK\x05\x06");
    for zip64 in [false, true] {
        let mut data = sample_zip(zip64);
        let end = data.len() - 22;
        data[end + 20..].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        data.extend_from_slice(&comment);
        assert_sample_listing(&data);
    }
}

fn padded_zip(directory_size: u32) -> Vec<u8> {
    let mut data = sample_zip(false);
    let end = data.len() - 22;
    let mut footer: [u8; 22] = data[end..].try_into().unwrap();
    let start = u32::from_le_bytes(footer[16..20].try_into().unwrap()) as usize;
    data.truncate(end);
    data.resize(start + directory_size as usize, 0);
    footer[12..16].copy_from_slice(&directory_size.to_le_bytes());
    data.extend_from_slice(&footer);
    data
}

#[test]
fn zip_preflight_limits_entries_before_indexing() {
    let max = ENTRIES_MAX as u16;
    // Leave enough room for the declared fixed headers, so only the count crosses its limit.
    let mut data = padded_zip(46 * u32::from(max + 1));
    let end = data.len() - 22;
    for count in [max, max + 1] {
        data[end + 8..end + 10].copy_from_slice(&count.to_le_bytes());
        data[end + 10..end + 12].copy_from_slice(&count.to_le_bytes());
        if count == max {
            assert!(validate_zip_central_directory(&data).is_some());
        } else {
            assert_zip_rejected(&data);
        }
    }
}

#[test]
fn zip_preflight_limits_declared_and_physical_directory_size() {
    let data = sample_zip(false);
    let end = data.len() - 22;
    let too_large = ZIP_CENTRAL_DIR_MAX as u32 + 1;
    assert_zip_field_rejected(&data, end + 12, too_large.to_le_bytes());

    let mut padded = padded_zip(too_large);
    assert_zip_rejected(&padded);
    let padded_end = padded.len() - 22;
    // The small original size now under-declares the span to the end record.
    padded[padded_end + 12..padded_end + 16].copy_from_slice(&data[end + 12..end + 16]);
    assert_zip_rejected(&padded);
}

#[test]
fn zip_preflight_rejects_inconsistent_or_incomplete_end_records() {
    let data = sample_zip(false);
    let end = data.len() - 22;
    assert_zip_field_rejected(&data, end + 4, 1u16.to_le_bytes());
    assert_zip_field_rejected(&data, end + 6, 1u16.to_le_bytes());
    assert_zip_field_rejected(&data, end + 8, 0u16.to_le_bytes());
    assert_zip_field_rejected(&data, end + 12, 45u32.to_le_bytes());
    assert_zip_field_rejected(&data, end + 16, 0u32.to_le_bytes()); // local file header
    assert_zip_field_rejected(&data, end + 16, (end as u32).to_le_bytes());
    assert_zip_field_rejected(&data, end + 16, (u32::MAX - 1).to_le_bytes());
    assert_zip_field_rejected(&data, end + 8, [0; 4]); // empty with nonzero directory size

    for field in [4, 6, 8, 10] {
        assert_zip_field_rejected(&data, end + field, u16::MAX.to_le_bytes());
    }
    for field in [12, 16] {
        assert_zip_field_rejected(&data, end + field, u32::MAX.to_le_bytes());
    }

    assert_zip_rejected(&data[..21]);
    assert_zip_rejected(&data[..end]);
    assert_zip_rejected(&data[..data.len() - 1]);
    let mut trailing = data;
    trailing.push(0);
    assert_zip_rejected(&trailing);
}

/// Offsets of the ZIP64 end record, its locator and the standard end record in the fixture.
fn zip64_positions(data: &[u8]) -> (usize, usize, usize) {
    let end = data.len() - 22;
    let locator = end - 20;
    assert_eq!(&data[locator..locator + 4], b"PK\x06\x07");
    let record = u64::from_le_bytes(data[locator + 8..locator + 16].try_into().unwrap()) as usize;
    assert_eq!(&data[record..record + 4], b"PK\x06\x06");
    (record, locator, end)
}

#[test]
fn zip64_lists_entries_with_concrete_or_sentinel_standard_fields() {
    let mut data = sample_zip(true);
    assert_sample_listing(&data);
    let (record, _, end) = zip64_positions(&data);
    let size = u64::from_le_bytes(data[record + 40..record + 48].try_into().unwrap());
    data[end + 12..end + 16].copy_from_slice(&(size as u32).to_le_bytes());
    assert_sample_listing(&data);
    data[end + 4..end + 20].fill(0xff);
    assert_sample_listing(&data);
}

#[test]
fn zip64_preflight_checks_locator_record_and_disk_fields() {
    let data = sample_zip(true);
    let (record, locator, _) = zip64_positions(&data);
    assert_zip_field_rejected(&data, locator, *b"oops");
    assert_zip_field_rejected(&data, locator + 4, 1u32.to_le_bytes());
    assert_zip_field_rejected(&data, locator + 16, 2u32.to_le_bytes());
    assert_zip_field_rejected(&data, locator + 8, (locator as u64 - 55).to_le_bytes());
    assert_zip_field_rejected(&data, locator + 8, u64::MAX.to_le_bytes());
    assert_zip_field_rejected(&data, record, *b"oops");
    for size in [43, (locator - record - 12 + 1) as u64, u64::MAX] {
        assert_zip_field_rejected(&data, record + 4, size.to_le_bytes());
    }
    for disk in [16, 20] {
        assert_zip_field_rejected(&data, record + disk, 1u32.to_le_bytes());
    }
    assert_zip_field_rejected(&data, record + 24, 0u64.to_le_bytes());
}

#[test]
fn zip64_preflight_bounds_the_full_width_directory_fields() {
    let mut data = sample_zip(true);
    let (record, _, end) = zip64_positions(&data);
    data[end + 4..end + 20].fill(0xff);
    assert_zip_field_rejected(&data, record + 40, (ZIP_CENTRAL_DIR_MAX + 1).to_le_bytes());
    assert_zip_field_rejected(&data, record + 48, (record as u64).to_le_bytes());
    assert_zip_field_rejected(&data, record + 48, (u64::MAX - 1).to_le_bytes());
    let count = ENTRIES_MAX as u64 + 1;
    data[record + 24..record + 32].copy_from_slice(&count.to_le_bytes());
    data[record + 32..record + 40].copy_from_slice(&count.to_le_bytes());
    assert_zip_rejected(&data);
}

#[test]
fn zip64_preflight_cross_checks_each_concrete_standard_field() {
    let mut data = sample_zip(true);
    let (record, _, end) = zip64_positions(&data);
    for disk in [4, 6] {
        assert_zip_field_rejected(&data, end + disk, 1u16.to_le_bytes());
    }
    for count in [8, 10] {
        assert_zip_field_rejected(&data, end + count, 2u16.to_le_bytes());
    }
    for field in [12, 16] {
        assert_zip_field_rejected(&data, end + field, 0u32.to_le_bytes());
    }
    // The locator is authoritative even when every standard field is concrete.
    let size = u64::from_le_bytes(data[record + 40..record + 48].try_into().unwrap());
    data[end + 12..end + 16].copy_from_slice(&(size as u32).to_le_bytes());
    for field in [24, 32] {
        data[record + field..record + field + 8].copy_from_slice(&50_000u64.to_le_bytes());
    }
    assert_zip_rejected(&data);
}

#[test]
fn listing_a_tar_stops_at_its_limit() {
    // A small file, one that unpacks to 4 MiB of zeros, and another after it.
    let mut builder = ::tar::Builder::new(vec![]);
    for (name, size) in [("a.txt", 5), ("zeros", 4 << 20), ("b.txt", 5)] {
        let mut header = ::tar::Header::new_gnu();
        header.set_size(size);
        header.set_cksum();
        builder
            .append_data(&mut header, name, std::io::repeat(0).take(size))
            .unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
    gz.write_all(&builder.into_inner().unwrap()).unwrap();
    let gz = gz.finish().unwrap();
    assert!(gz.len() < 64 << 10, "{} bytes", gz.len());
    let names = |listing: &Listing| -> Vec<String> {
        listing
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect()
    };

    // Within the limit, all of it.
    let whole = tar(MultiGzDecoder::new(&gz[..]), 8 << 20).unwrap();
    assert_eq!(names(&whole), ["a.txt", "zeros", "b.txt"]);
    assert!(whole.complete);

    // Past it, what came before, and that there is more.
    let cut = tar(MultiGzDecoder::new(&gz[..]), 1 << 20).unwrap();
    assert_eq!(names(&cut), ["a.txt", "zeros"]);
    assert!(!cut.complete);
}

#[test]
fn gzip_that_is_not_a_tar_lists_nothing() {
    let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
    gz.write_all(&[0xFF; 4096]).unwrap();
    assert_eq!(
        tar(MultiGzDecoder::new(&gz.finish().unwrap()[..]), UNPACKED_MAX),
        None
    );
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
fn deeply_nested_json_pretty_print_stays_bounded() {
    // 100 levels of nesting with ~100 KB input would expand >10 MB if unbounded.
    let nested = format!(
        "{}{}{}{}",
        "[".repeat(100),
        "0,".repeat(50_000),
        "0",
        "]".repeat(100)
    );
    let Kind::Code { text, .. } = kind("nest.json", "application/json", nested.as_bytes()) else {
        panic!("expected Code preview");
    };
    assert!(text.len() <= TEXT_MAX);
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
fn events_handles_multibyte_utf8_organizer_and_attendee_without_panicking() {
    // Byte offset 7 falls inside a multi-byte UTF-8 scalar in both ORGANIZER and ATTENDEE.
    let ics = "\
BEGIN:VCALENDAR\r\n\
BEGIN:VEVENT\r\n\
SUMMARY:会議\r\n\
ORGANIZER:日本語テスト\r\n\
ATTENDEE:🎉🚀✨テスト\r\n\
ATTENDEE:MaIlTo:alice@example.com\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";
    let cards = events(ics);
    assert_eq!(cards.items.len(), 1);
    assert_eq!(cards.items[0].title, "会議");
    assert!(
        cards.items[0]
            .fields
            .contains(&("Organizer", "日本語テスト".to_string()))
    );
    assert!(
        cards.items[0]
            .fields
            .contains(&("Attendee", "🎉🚀✨テスト".to_string()))
    );
    assert!(
        cards.items[0]
            .fields
            .contains(&("Attendee", "alice@example.com".to_string()))
    );
}
