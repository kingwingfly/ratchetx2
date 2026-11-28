use std::io::{Cursor, Read, Write};

use ::zip::write::{FullFileOptions, SimpleFileOptions};

use super::*;
use super::{
    archive::{tar, tar_slice, validate_zip_central_directory, zip},
    structured::{contacts, diff, events},
};

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
fn markdown_files_defer_rendering_to_worker() {
    assert_eq!(
        kind("notes.md", "text/markdown", b"# Hello\n\n$x^2$\n"),
        Kind::Markdown {
            source: "# Hello\n\n$x^2$\n".into(),
        }
    );
    assert_eq!(
        kind("README.MARKDOWN", "", b"body"),
        Kind::Markdown {
            source: "body".into(),
        }
    );
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
