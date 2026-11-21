use std::io::{Cursor, Read, Write};

use ::zip::write::{FullFileOptions, SimpleFileOptions};
use pulldown_latex::{
    config::DisplayMode,
    event::{
        Content, DelimiterSize, DelimiterType, EnvironmentFlow, Event as LatexEvent, Grouping,
    },
};

use super::*;
use super::{
    archive::{tar, validate_zip_central_directory, zip},
    mathml::MathmlRenderer,
    sanitize::sanitize_html,
    structured::{contacts, diff, events},
};

// Share the attribute name between sanitizer inputs and checks on rendered output.
const STYLE_ATTRIBUTE: &str = "style";

fn assert_no_inline_style(html: &str) {
    assert!(!html.contains(&format!("{STYLE_ATTRIBUTE}=")), "{html}");
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
        kind_of("a.opus", b"OggS\0\x02....OpusHead"),
        Kind::Audio("audio/ogg")
    );
    assert_eq!(kind_of("song", b"ID3\x04\0\0"), Kind::Audio("audio/mpeg"));
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
    assert!(html.contains(r#"<img src="" alt="tracker" />"#), "{html}");
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
        r"$\color{red}{x} + \colorbox{yellow}{y} + \fcolorbox{red}{yellow}{z} \kern -1em w$"
            .to_string()
            .as_str(),
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

    // Slash-separated attributes and duplicate attributes cannot bypass allowlists.
    let slash_img =
        sanitize_html(r#"<img/onerror=alert(1) src="https://tracker.example/x.png" alt="pic">"#);
    assert_eq!(slash_img, r#"<img src="" alt="pic" />"#);

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
    assert!(!tall_table.truncated_columns);
    assert!(!tall_table.truncated_cells);
    assert!(tall_table.notice().unwrap().contains(&ROWS_MAX.to_string()));
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
fn tables_cards_and_diffs() {
    let Kind::Table(table) = kind("a.csv", "", b"name,age\n\"Doe, J\",30\n") else {
        panic!("a table");
    };
    assert_eq!(table.rows, [["name", "age"], ["Doe, J", "30"]]);
    assert!(!table.more);

    let vcard = "BEGIN:VCARD\r\nVERSION:4.0\r\nN:Doe;Jane;;;\r\nTEL;TYPE=cell:+1 555\r\n\
                 ADR:;;1 Main St;Springfield;;12345;\r\n  USA\r\nEND:VCARD\r\n";
    assert_eq!(
        contacts(vcard),
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
        events(ics),
        [Card {
            title: "Lab meeting".into(),
            fields: vec![
                ("Starts", "2026-10-28 14:00 UTC".into()),
                ("Where", "Room 2, east".into())
            ]
        }]
    );

    let lines = diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n same\n");
    let kinds: Vec<_> = lines.iter().map(|(kind, _)| *kind).collect();
    use DiffLine::*;
    assert_eq!(kinds, [File, File, File, Hunk, Removed, Added, Context]);
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
                    directory: true
                },
                Entry {
                    path: "docs/a.txt".into(),
                    size: 5,
                    directory: false
                },
            ],
            complete: true,
        })
    );

    let mut tar = ::tar::Builder::new(vec![]);
    let mut header = ::tar::Header::new_gnu();
    header.set_size(5);
    header.set_cksum();
    tar.append_data(&mut header, "a.txt", &b"hello"[..])
        .unwrap();
    let tar = tar.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
    gz.write_all(&tar).unwrap();
    let expected = Kind::Archive(Listing {
        entries: vec![Entry {
            path: "a.txt".into(),
            size: 5,
            directory: false,
        }],
        complete: true,
    });
    assert_eq!(kind("a.tar.gz", "", &gz.finish().unwrap()), expected);
    assert_eq!(kind("a.tar", "", &tar), expected);
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
                directory: false
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
    let whole = tar(GzDecoder::new(&gz[..]), 8 << 20).unwrap();
    assert_eq!(names(&whole), ["a.txt", "zeros", "b.txt"]);
    assert!(whole.complete);

    // Past it, what came before, and that there is more.
    let cut = tar(GzDecoder::new(&gz[..]), 1 << 20).unwrap();
    assert_eq!(names(&cut), ["a.txt", "zeros"]);
    assert!(!cut.complete);
}

#[test]
fn gzip_that_is_not_a_tar_lists_nothing() {
    let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
    gz.write_all(&[0xFF; 4096]).unwrap();
    assert_eq!(
        tar(GzDecoder::new(&gz.finish().unwrap()[..]), UNPACKED_MAX),
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
fn markdown_links_normalize_uppercase_schemes_preserving_path_case() {
    let html = markdown(
        "[secure](HTTPS://Example.COM/CasePath?Token=AbC) \
         [plain](HTTP://example.com/Path) \
         [mail](MAILTO:User@Example.COM) \
         [bad](JAVASCRIPT:alert(1))",
    );
    assert!(
        html.contains(r#"href="https://Example.COM/CasePath?Token=AbC""#),
        "{html}"
    );
    assert!(html.contains(r#"href="http://example.com/Path""#), "{html}");
    assert!(html.contains(r#"href="mailto:User@Example.COM""#), "{html}");
    assert!(!html.to_ascii_lowercase().contains("javascript:"), "{html}");

    // Direct HTML sanitization also lowercases uppercase schemes and emits safe external attrs.
    let sanitized = sanitize_html(r#"<a href="HTTPS://example.com/KeepCase">x</a>"#);
    assert_eq!(
        sanitized,
        r#"<a href="https://example.com/KeepCase" target="_blank" rel="noopener noreferrer">x</a>"#
    );
}

#[test]
fn sanitize_html_external_links_emit_target_blank_and_noopener_idempotently() {
    let http = sanitize_html(r#"<a href="http://example.com/a" target="_self" rel="opener">a</a>"#);
    assert_eq!(
        http,
        r#"<a href="http://example.com/a" target="_blank" rel="noopener noreferrer">a</a>"#
    );
    assert_eq!(sanitize_html(&http), http);

    let https = sanitize_html(r#"<a href="https://example.com/b">b</a>"#);
    assert_eq!(
        https,
        r#"<a href="https://example.com/b" target="_blank" rel="noopener noreferrer">b</a>"#
    );
    assert_eq!(sanitize_html(&https), https);

    // Mailto and in-page fragments do not get external target/rel attributes.
    let mailto = sanitize_html(r#"<a href="mailto:user@example.com">mail</a>"#);
    assert_eq!(mailto, r#"<a href="mailto:user@example.com">mail</a>"#);
    let frag = sanitize_html(r##"<a href="#note">jump</a>"##);
    assert_eq!(frag, r##"<a href="#fn-note">jump</a>"##);
}
