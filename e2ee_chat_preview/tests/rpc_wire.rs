#![cfg(all(target_arch = "wasm32", feature = "rpc"))]

use e2ee_chat_preview::{
    READY,
    audio::{COVER_MAX, MAX_AUDIO_BYTES, Tags},
    language::Group,
    rpc::{
        AudioTagsCall, CodeHighlightCall, DIAGRAM_SVG_MAX, DiagramSvgCall, MARKDOWN_HTML_MAX,
        MARKDOWN_SOURCE_MAX, MATCHES_MAX, MAX_PAGES, MAX_PDF_BYTES, MAX_PDF_PIXELS, MAX_PDF_SIDE,
        MarkdownCall, Method, PagePixels, PdfCloseCall, PdfOpenCall, PdfOpened, PdfRenderCall,
        RenderedPage, Request, RequestFrame, Response, RpcCall, SLIDES_HTML_MAX, SLIDES_MAX,
        SearchFindCall, SearchFound, SlidesCall, WorkerEvent, decode_audio_tags,
        decode_code_highlight, decode_diagram_svg, decode_markdown, decode_pdf_close,
        decode_pdf_open, decode_pdf_render, decode_search_find, decode_slides, encode_reply_frame,
        encode_request_frame,
    },
};
use js_sys::{
    Array, ArrayBuffer, Float64Array, Object, Uint8Array, Uint8ClampedArray, Uint32Array,
};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

fn assert_single_transfer(transfer: Option<Array>, expected_byte_len: u32) {
    let list = transfer.expect("expected a single transferable ArrayBuffer");
    assert_eq!(list.length(), 1);
    let buf = list
        .get(0)
        .dyn_into::<ArrayBuffer>()
        .expect("transfer entry must be an ArrayBuffer");
    assert_eq!(buf.byte_length(), expected_byte_len);
}

#[wasm_bindgen_test]
fn request_frame_roundtrips_all_methods_and_transfer_lists() {
    // 1. Open (transferable Uint8Array)
    let pdf_bytes = b"%PDF-1.4\n%%EOF\n";
    let payload = encode_request_frame(1, Request::Open(pdf_bytes));
    assert_single_transfer(payload.transfer, pdf_bytes.len() as u32);
    let frame = RequestFrame::decode(payload.value).unwrap();
    assert_eq!(frame.id, 1);
    assert_eq!(frame.method().unwrap(), Method::Open);
    assert_eq!(frame.request().unwrap(), Request::Open(pdf_bytes.to_vec()));

    // 2. Render (no transfer list; covers boundary u32 values)
    let payload = encode_request_frame(
        2,
        Request::Render {
            doc_id: 0,
            page: 42,
            width: u32::MAX,
        },
    );
    assert!(payload.transfer.is_none());
    let frame = RequestFrame::decode(payload.value).unwrap();
    assert_eq!(frame.id, 2);
    assert_eq!(frame.method().unwrap(), Method::Render);
    assert_eq!(
        frame.request().unwrap(),
        Request::Render {
            doc_id: 0,
            page: 42,
            width: u32::MAX,
        }
    );

    // 3. Close
    let payload = encode_request_frame(u32::MAX, Request::Close { doc_id: 99 });
    assert!(payload.transfer.is_none());
    let frame = RequestFrame::decode(payload.value).unwrap();
    assert_eq!(frame.id, u32::MAX);
    assert_eq!(frame.method().unwrap(), Method::Close);
    assert_eq!(frame.request().unwrap(), Request::Close { doc_id: 99 });

    // 4. Tags (transferable Uint8Array)
    let audio_bytes = b"RIFF\x24\x00\x00\x00WAVE";
    let payload = encode_request_frame(4, Request::Tags(audio_bytes));
    assert_single_transfer(payload.transfer, audio_bytes.len() as u32);
    let frame = RequestFrame::decode(payload.value).unwrap();
    assert_eq!(frame.id, 4);
    assert_eq!(frame.method().unwrap(), Method::Tags);
    assert_eq!(
        frame.request().unwrap(),
        Request::Tags(audio_bytes.to_vec())
    );

    // 5. Find
    let payload = encode_request_frame(
        5,
        Request::Find {
            text: "héllo 🚀 world",
            pattern: "🚀",
            case: true,
            regex: false,
        },
    );
    assert!(payload.transfer.is_none());
    let frame = RequestFrame::decode(payload.value).unwrap();
    assert_eq!(frame.id, 5);
    assert_eq!(frame.method().unwrap(), Method::Find);
    assert_eq!(
        frame.request().unwrap(),
        Request::Find {
            text: "héllo 🚀 world".into(),
            pattern: "🚀".into(),
            case: true,
            regex: false,
        }
    );

    // 6. Svg
    let payload = encode_request_frame(6, Request::Svg("flowchart LR\nA-->B"));
    assert!(payload.transfer.is_none());
    let frame = RequestFrame::decode(payload.value).unwrap();
    assert_eq!(frame.id, 6);
    assert_eq!(frame.method().unwrap(), Method::Svg);
    assert_eq!(
        frame.request().unwrap(),
        Request::Svg("flowchart LR\nA-->B".into())
    );

    // 7. Markdown
    let payload = encode_request_frame(
        7,
        Request::Markdown {
            source: "# Title\n\n$a^2$",
        },
    );
    assert!(payload.transfer.is_none());
    let frame = RequestFrame::decode(payload.value).unwrap();
    assert_eq!(frame.id, 7);
    assert_eq!(frame.method().unwrap(), Method::Markdown);
    assert_eq!(
        frame.request().unwrap(),
        Request::Markdown {
            source: "# Title\n\n$a^2$".into(),
        }
    );

    // 8. Slides
    let payload = encode_request_frame(
        8,
        Request::Slides {
            source: "# One\n---\n# Two",
        },
    );
    assert!(payload.transfer.is_none());
    let frame = RequestFrame::decode(payload.value).unwrap();
    assert_eq!(frame.id, 8);
    assert_eq!(frame.method().unwrap(), Method::Slides);
    assert_eq!(
        frame.request().unwrap(),
        Request::Slides {
            source: "# One\n---\n# Two".into(),
        }
    );

    // 9. Highlight
    let payload = encode_request_frame(
        9,
        Request::Highlight {
            language: "rust",
            text: "fn main() {}",
        },
    );
    assert!(payload.transfer.is_none());
    let frame = RequestFrame::decode(payload.value).unwrap();
    assert_eq!(frame.id, 9);
    assert_eq!(frame.method().unwrap(), Method::Highlight);
    assert_eq!(
        frame.request().unwrap(),
        Request::Highlight {
            language: "rust".into(),
            text: "fn main() {}".into(),
        }
    );
}

#[wasm_bindgen_test]
fn request_frame_rejects_malformed_unknown_and_oversized_inputs() {
    // Non-arrays and short frames fail decode().
    for bad in [
        JsValue::NULL,
        JsValue::UNDEFINED,
        JsValue::from_str("open"),
        JsValue::from_f64(1.0),
        Object::new().into(),
        Array::new().into(),
        Array::of1(&1u32.into()).into(),
    ] {
        assert!(RequestFrame::decode(bad).is_err());
    }

    // Invalid request IDs fail decode().
    for bad_id in [
        JsValue::from_f64(-1.0),
        JsValue::from_f64(1.5),
        JsValue::from_f64(f64::NAN),
        JsValue::from_f64(f64::INFINITY),
        JsValue::from_f64(f64::from(u32::MAX) + 1.0),
        JsValue::from_str("1"),
    ] {
        let frame = Array::of2(&bad_id, &"close".into());
        assert!(RequestFrame::decode(frame.into()).is_err());
    }

    // Unknown method preserves frame.id and reports `"no method <name>"`.
    let unknown = RequestFrame::decode(Array::of2(&42u32.into(), &"unknown_op".into()).into())
        .expect("unknown method still decodes frame ID");
    assert_eq!(unknown.id, 42);
    assert_eq!(unknown.method().unwrap_err(), "no method unknown_op");
    assert_eq!(unknown.request().unwrap_err(), "no method unknown_op");

    // Non-string method preserves frame.id and fails method().
    let bad_method = RequestFrame::decode(Array::of2(&43u32.into(), &123u32.into()).into())
        .expect("non-string method still decodes frame ID");
    assert_eq!(bad_method.id, 43);
    assert!(bad_method.method().is_err());

    // Arity and argument-type errors.
    let bad_frames = [
        Array::of2(&1u32.into(), &"close".into()),
        Array::of4(&1u32.into(), &"close".into(), &1u32.into(), &2u32.into()),
        Array::of3(&1u32.into(), &"close".into(), &"1".into()),
        Array::of4(&1u32.into(), &"render".into(), &1u32.into(), &0u32.into()),
        Array::of3(&1u32.into(), &"open".into(), &"not-bytes".into()),
        Array::of3(&1u32.into(), &"tags".into(), &42u32.into()),
        Array::of3(&1u32.into(), &"svg".into(), &42u32.into()),
        Array::of3(&1u32.into(), &"markdown".into(), &42u32.into()),
        Array::of3(&1u32.into(), &"slides".into(), &42u32.into()),
        Array::of2(&1u32.into(), &"markdown".into()),
        Array::of2(&1u32.into(), &"slides".into()),
        Array::of3(&1u32.into(), &"highlight".into(), &"rust".into()),
    ];
    for frame_arr in bad_frames {
        let frame = RequestFrame::decode(frame_arr.into()).unwrap();
        assert!(frame.request().is_err());
    }

    // Wrong boolean type in Find.
    let bad_find = Array::new();
    bad_find.push_many(&[
        10u32.into(),
        "find".into(),
        "abc".into(),
        "a".into(),
        1u32.into(),
        JsValue::FALSE,
    ]);
    let frame = RequestFrame::decode(bad_find.into()).unwrap();
    assert!(frame.request().is_err());

    // Oversized Open payload (> MAX_PDF_BYTES) rejected before copying into Rust memory.
    let huge_pdf = Uint8Array::new_with_length((MAX_PDF_BYTES + 1) as u32);
    let oversized_open = Array::of3(&11u32.into(), &"open".into(), &huge_pdf);
    let frame = RequestFrame::decode(oversized_open.into()).unwrap();
    let err = frame.request().unwrap_err();
    assert!(err.contains("exceeds limit"), "unexpected error: {err}");

    // Oversized Tags payload (> MAX_AUDIO_BYTES) rejected before copying into Rust memory.
    let huge_audio = Uint8Array::new_with_length((MAX_AUDIO_BYTES + 1) as u32);
    let oversized_tags = Array::of3(&12u32.into(), &"tags".into(), &huge_audio);
    let frame = RequestFrame::decode(oversized_tags.into()).unwrap();
    let err = frame.request().unwrap_err();
    assert!(err.contains("exceeds limit"), "unexpected error: {err}");

    // Oversized Markdown & Slides payloads (> MARKDOWN_SOURCE_MAX) rejected.
    let huge_md = "x".repeat(MARKDOWN_SOURCE_MAX + 1);
    for method in ["markdown", "slides"] {
        let oversized_md = Array::of3(&13u32.into(), &method.into(), &huge_md.as_str().into());
        let frame = RequestFrame::decode(oversized_md.into()).unwrap();
        assert!(frame.request().is_err(), "expected rejection for {method}");
    }
}

#[wasm_bindgen_test]
fn response_and_worker_event_roundtrip_all_variants_and_transfers() {
    // Ready notification.
    assert!(matches!(
        WorkerEvent::decode(JsValue::from_str(READY)).unwrap(),
        WorkerEvent::Ready
    ));

    // Opened (Float64Array transfer).
    let opened = PdfOpened {
        doc_id: 7,
        sizes: vec![(612.0, 792.0), (595.28, 841.89)],
    };
    let reply = encode_reply_frame(&10u32.into(), Ok(Response::Opened(opened.clone()).encode()));
    assert_single_transfer(reply.transfer, (opened.sizes.len() * 2 * 8) as u32);
    match WorkerEvent::decode(reply.value).unwrap() {
        WorkerEvent::Reply {
            id: 10,
            result: Ok(val),
        } => {
            assert_eq!(PdfOpenCall::decode_reply(val).unwrap(), opened);
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // Rendered (Uint8ClampedArray transfer).
    let pixels = vec![10, 20, 30, 255, 40, 50, 60, 255];
    let reply = encode_reply_frame(
        &11u32.into(),
        Ok(Response::Rendered(RenderedPage {
            width: 2,
            height: 1,
            pixels: PagePixels::from(pixels.clone()),
        })
        .encode()),
    );
    assert_single_transfer(reply.transfer, pixels.len() as u32);
    match WorkerEvent::decode(reply.value).unwrap() {
        WorkerEvent::Reply {
            id: 11,
            result: Ok(val),
        } => {
            let rendered = PdfRenderCall::decode_reply(val).unwrap();
            assert_eq!(rendered.width, 2);
            assert_eq!(rendered.height, 1);
            assert_eq!(rendered.pixels.to_vec(), pixels);
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // Closed (no transfer).
    let reply = encode_reply_frame(&12u32.into(), Ok(Response::Closed.encode()));
    assert!(reply.transfer.is_none());
    match WorkerEvent::decode(reply.value).unwrap() {
        WorkerEvent::Reply {
            id: 12,
            result: Ok(val),
        } => {
            PdfCloseCall::decode_reply(val).unwrap();
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // Tags(None) (no transfer).
    let reply = encode_reply_frame(&13u32.into(), Ok(Response::Tags(None).encode()));
    assert!(reply.transfer.is_none());
    match WorkerEvent::decode(reply.value).unwrap() {
        WorkerEvent::Reply {
            id: 13,
            result: Ok(val),
        } => {
            assert_eq!(AudioTagsCall::decode_reply(val).unwrap(), None);
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // Tags(Some) without cover (no transfer).
    let tags_no_cover = Tags {
        title: Some("Track".into()),
        artist: None,
        album: Some("Album".into()),
        year: Some(2026),
        cover: None,
    };
    let reply = encode_reply_frame(
        &14u32.into(),
        Ok(Response::Tags(Some(tags_no_cover.clone())).encode()),
    );
    assert!(reply.transfer.is_none());
    match WorkerEvent::decode(reply.value).unwrap() {
        WorkerEvent::Reply {
            id: 14,
            result: Ok(val),
        } => {
            assert_eq!(
                AudioTagsCall::decode_reply(val).unwrap(),
                Some(tags_no_cover)
            );
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // Tags(Some) with cover (Uint8Array transfer).
    let cover_bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let tags_with_cover = Tags {
        title: Some("Cover Track".into()),
        artist: Some("Artist".into()),
        album: None,
        year: None,
        cover: Some(("image/png".into(), cover_bytes.clone())),
    };
    let reply = encode_reply_frame(
        &15u32.into(),
        Ok(Response::Tags(Some(tags_with_cover.clone())).encode()),
    );
    assert_single_transfer(reply.transfer, cover_bytes.len() as u32);
    match WorkerEvent::decode(reply.value).unwrap() {
        WorkerEvent::Reply {
            id: 15,
            result: Ok(val),
        } => {
            assert_eq!(
                AudioTagsCall::decode_reply(val).unwrap(),
                Some(tags_with_cover)
            );
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // Found (Uint32Array transfer).
    let found = SearchFound {
        matches: vec![(0, 5), (12, 18)],
        more: true,
    };
    let reply = encode_reply_frame(&16u32.into(), Ok(Response::Found(found.clone()).encode()));
    assert_single_transfer(reply.transfer, (found.matches.len() * 2 * 4) as u32);
    match WorkerEvent::decode(reply.value).unwrap() {
        WorkerEvent::Reply {
            id: 16,
            result: Ok(val),
        } => {
            assert_eq!(SearchFindCall::decode_reply(val).unwrap(), found);
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // Svg (no transfer).
    let svg = "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>".to_string();
    let reply = encode_reply_frame(&17u32.into(), Ok(Response::Svg(svg.clone()).encode()));
    assert!(reply.transfer.is_none());
    match WorkerEvent::decode(reply.value).unwrap() {
        WorkerEvent::Reply {
            id: 17,
            result: Ok(val),
        } => {
            assert_eq!(DiagramSvgCall::decode_reply(val).unwrap(), svg);
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // Markdown (no transfer).
    let md_html = "<h1>Hello</h1><p>World</p>".to_string();
    let reply = encode_reply_frame(
        &20u32.into(),
        Ok(Response::Markdown(md_html.clone()).encode()),
    );
    assert!(reply.transfer.is_none());
    match WorkerEvent::decode(reply.value).unwrap() {
        WorkerEvent::Reply {
            id: 20,
            result: Ok(val),
        } => {
            assert_eq!(MarkdownCall::decode_reply(val).unwrap(), md_html);
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // Slides (no transfer).
    let deck = vec![
        vec!["<h1>One</h1>".to_string()],
        vec!["<h1>Two</h1>".to_string(), "<p>Sub</p>".to_string()],
    ];
    let reply = encode_reply_frame(&21u32.into(), Ok(Response::Slides(deck.clone()).encode()));
    assert!(reply.transfer.is_none());
    match WorkerEvent::decode(reply.value).unwrap() {
        WorkerEvent::Reply {
            id: 21,
            result: Ok(val),
        } => {
            assert_eq!(SlidesCall::decode_reply(val).unwrap(), deck);
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // Highlighted (no transfer).
    let html = "<a-k>fn</a-k> main() {}".to_string();
    let reply = encode_reply_frame(
        &18u32.into(),
        Ok(Response::Highlighted(html.clone()).encode()),
    );
    assert!(reply.transfer.is_none());
    match WorkerEvent::decode(reply.value).unwrap() {
        WorkerEvent::Reply {
            id: 18,
            result: Ok(val),
        } => {
            assert_eq!(
                <CodeHighlightCall<'_> as RpcCall<'_>>::decode_reply(val).unwrap(),
                html
            );
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // Error reply frame.
    let err_reply = encode_reply_frame(&19u32.into(), Err("render failed".into()));
    assert!(err_reply.transfer.is_none());
    match WorkerEvent::decode(err_reply.value).unwrap() {
        WorkerEvent::Reply {
            id: 19,
            result: Err(err),
        } => assert_eq!(err.as_string().as_deref(), Some("render failed")),
        other => panic!("unexpected event: {other:?}"),
    }
    let _ = Group::Web;
}

#[wasm_bindgen_test]
fn reply_decoders_reject_malformed_and_oversized_frames() {
    // Malformed WorkerEvent frames.
    for bad in [
        JsValue::NULL,
        JsValue::from_str("not-ready"),
        Array::of2(&1u32.into(), &JsValue::TRUE).into(),
        Array::of4(&1u32.into(), &JsValue::TRUE, &JsValue::NULL, &JsValue::NULL).into(),
        Array::of3(&JsValue::from_str("1"), &JsValue::TRUE, &JsValue::NULL).into(),
        Array::of3(&1u32.into(), &1u32.into(), &JsValue::NULL).into(),
        Array::of3(&1u32.into(), &JsValue::FALSE, &123u32.into()).into(),
    ] {
        assert!(WorkerEvent::decode(bad).is_err());
    }

    // decode_pdf_open: odd coords & > MAX_PAGES.
    let odd_sizes = Float64Array::from([100.0, 200.0, 300.0].as_slice());
    assert!(decode_pdf_open(Array::of2(&1u32.into(), &odd_sizes).into()).is_err());
    let too_many_pages = Float64Array::new_with_length((MAX_PAGES * 2 + 2) as u32);
    assert!(decode_pdf_open(Array::of2(&1u32.into(), &too_many_pages).into()).is_err());

    // decode_pdf_render: zero dims, side > MAX_PDF_SIDE, area > MAX_PDF_PIXELS, wrong length.
    let px4 = Uint8ClampedArray::new_with_length(4);
    assert!(decode_pdf_render(Array::of3(&0u32.into(), &1u32.into(), &px4).into()).is_err());
    assert!(decode_pdf_render(Array::of3(&1u32.into(), &0u32.into(), &px4).into()).is_err());
    assert!(
        decode_pdf_render(Array::of3(&(MAX_PDF_SIDE + 1).into(), &1u32.into(), &px4).into())
            .is_err()
    );
    let too_wide_area_side = ((MAX_PDF_PIXELS as f64).sqrt() as u32) + 1;
    assert!(
        decode_pdf_render(
            Array::of3(&too_wide_area_side.into(), &too_wide_area_side.into(), &px4).into()
        )
        .is_err()
    );
    assert!(
        decode_pdf_render(
            Array::of3(
                &2u32.into(),
                &2u32.into(),
                &Uint8ClampedArray::new_with_length(8)
            )
            .into()
        )
        .is_err()
    );

    // decode_pdf_close: must be undefined.
    assert!(decode_pdf_close(JsValue::NULL).is_err());
    assert!(decode_pdf_close(0u32.into()).is_err());

    // decode_audio_tags: disallowed cover MIME, partial cover, oversized cover, invalid year.
    let make_tags = |year: JsValue, mime: JsValue, cover: JsValue| -> JsValue {
        let arr = Array::new();
        arr.push_many(&[
            "Title".into(),
            JsValue::NULL,
            JsValue::NULL,
            year,
            mime,
            cover,
        ]);
        arr.into()
    };
    let small_bytes = Uint8Array::from([1u8, 2, 3].as_slice());
    assert!(
        decode_audio_tags(make_tags(
            JsValue::NULL,
            "image/svg+xml".into(),
            small_bytes.clone().into()
        ))
        .is_err()
    );
    assert!(
        decode_audio_tags(make_tags(JsValue::NULL, "image/png".into(), JsValue::NULL)).is_err()
    );
    assert!(
        decode_audio_tags(make_tags(JsValue::NULL, JsValue::NULL, small_bytes.into())).is_err()
    );
    let oversized_cover = Uint8Array::new_with_length((COVER_MAX + 1) as u32);
    assert!(
        decode_audio_tags(make_tags(
            JsValue::NULL,
            "image/png".into(),
            oversized_cover.into()
        ))
        .is_err()
    );
    assert!(
        decode_audio_tags(make_tags(
            JsValue::from_f64(70_000.0),
            JsValue::NULL,
            JsValue::NULL
        ))
        .is_err()
    );

    // decode_search_find: odd offsets, > MATCHES_MAX, non-bool `more`.
    let odd_matches = Uint32Array::from([0u32, 1, 2].as_slice());
    assert!(decode_search_find(Array::of2(&odd_matches, &JsValue::FALSE).into()).is_err());
    let too_many_matches = Uint32Array::new_with_length((MATCHES_MAX * 2 + 2) as u32);
    assert!(decode_search_find(Array::of2(&too_many_matches, &JsValue::TRUE).into()).is_err());
    let ok_matches = Uint32Array::from([0u32, 2].as_slice());
    assert!(decode_search_find(Array::of2(&ok_matches, &1u32.into()).into()).is_err());

    // decode_diagram_svg, decode_markdown, decode_slides & decode_code_highlight.
    let huge_svg = "x".repeat(DIAGRAM_SVG_MAX + 1);
    assert!(decode_diagram_svg(huge_svg.into()).is_err());
    assert!(decode_diagram_svg(JsValue::NULL).is_err());

    let huge_md_html = "x".repeat(MARKDOWN_HTML_MAX + 1);
    assert!(decode_markdown(huge_md_html.into()).is_err());
    assert!(decode_markdown(JsValue::NULL).is_err());

    // decode_slides: empty outer, empty column, non-string slide, > SLIDES_MAX, > MARKDOWN_HTML_MAX,
    // and cumulative > SLIDES_HTML_MAX.
    assert!(decode_slides(JsValue::NULL).is_err());
    assert!(decode_slides(Array::new().into()).is_err());
    assert!(decode_slides(Array::of1(&Array::new()).into()).is_err());
    assert!(decode_slides(Array::of1(&Array::of1(&42u32.into())).into()).is_err());

    let too_many_slides = Array::new();
    for _ in 0..=SLIDES_MAX {
        too_many_slides.push(&Array::of1(&"s".into()));
    }
    assert!(decode_slides(too_many_slides.into()).is_err());

    let oversized_slide = "x".repeat(MARKDOWN_HTML_MAX + 1);
    assert!(decode_slides(Array::of1(&Array::of1(&oversized_slide.into())).into()).is_err());

    let large_slide = "x".repeat(MARKDOWN_HTML_MAX);
    let too_big_deck = Array::new();
    // 3 slides of 2 MiB each = 6 MiB > SLIDES_HTML_MAX (4 MiB).
    for _ in 0..3 {
        too_big_deck.push(&Array::of1(&large_slide.as_str().into()));
    }
    assert!(SLIDES_HTML_MAX < 3 * MARKDOWN_HTML_MAX);
    assert!(decode_slides(too_big_deck.into()).is_err());

    assert!(decode_code_highlight(JsValue::from_f64(1.0)).is_err());
}

#[cfg(feature = "worker")]
mod worker_dispatch {
    use super::*;
    use e2ee_chat_preview::worker::{WorkerService, dispatch};

    struct MockService {
        accepted: Method,
        handled_count: usize,
        fail_with: Option<String>,
    }

    impl WorkerService for MockService {
        fn accepts(&self, method: Method) -> bool {
            method == self.accepted
        }

        fn handle(&mut self, req: Request) -> Result<Response, String> {
            self.handled_count += 1;
            if let Some(err) = &self.fail_with {
                return Err(err.clone());
            }
            match req {
                Request::Find { text, pattern, .. } => {
                    let matches = text
                        .match_indices(&pattern)
                        .map(|(i, m)| (i as u32, (i + m.len()) as u32))
                        .collect();
                    Ok(Response::Found(SearchFound {
                        matches,
                        more: false,
                    }))
                }
                Request::Open(bytes) => Ok(Response::Opened(PdfOpened {
                    doc_id: bytes.len() as u32,
                    sizes: vec![(612.0, 792.0)],
                })),
                other => Err(format!("unexpected request {:?}", other.method())),
            }
        }
    }

    #[wasm_bindgen_test]
    fn dispatch_handles_valid_requests_and_propagates_transfers() {
        let mut service = MockService {
            accepted: Method::Find,
            handled_count: 0,
            fail_with: None,
        };
        let req = encode_request_frame(
            101,
            Request::Find {
                text: "alpha beta alpha",
                pattern: "alpha",
                case: true,
                regex: false,
            },
        );
        let (reply_id, reply) = dispatch(&mut service, req.value);
        assert_eq!(reply_id.as_f64(), Some(101.0));
        assert_eq!(service.handled_count, 1);
        assert_single_transfer(reply.transfer, 2 * 2 * 4);
        match WorkerEvent::decode(reply.value).unwrap() {
            WorkerEvent::Reply {
                id: 101,
                result: Ok(val),
            } => {
                assert_eq!(
                    SearchFindCall::decode_reply(val).unwrap(),
                    SearchFound {
                        matches: vec![(0, 5), (11, 16)],
                        more: false,
                    }
                );
            }
            other => panic!("unexpected reply: {other:?}"),
        }
    }

    #[wasm_bindgen_test]
    fn dispatch_rejects_unaccepted_unknown_and_malformed_frames() {
        let mut service = MockService {
            accepted: Method::Find,
            handled_count: 0,
            fail_with: None,
        };

        // 1. Unaccepted method with oversized payload must short-circuit before decoding bytes or
        //    calling `handle()`.
        let huge_pdf = Uint8Array::new_with_length((MAX_PDF_BYTES + 1) as u32);
        let unaccepted = Array::of3(&201u32.into(), &"open".into(), &huge_pdf);
        let (reply_id, reply) = dispatch(&mut service, unaccepted.into());
        assert_eq!(reply_id.as_f64(), Some(201.0));
        assert_eq!(service.handled_count, 0);
        assert!(reply.transfer.is_none());
        match WorkerEvent::decode(reply.value).unwrap() {
            WorkerEvent::Reply {
                id: 201,
                result: Err(err),
            } => assert_eq!(err.as_string().as_deref(), Some("no method open")),
            other => panic!("unexpected reply: {other:?}"),
        }

        // 2. Unknown method preserves reply ID without calling `handle()`.
        let unknown = Array::of2(&202u32.into(), &"nonexistent".into());
        let (reply_id, reply) = dispatch(&mut service, unknown.into());
        assert_eq!(reply_id.as_f64(), Some(202.0));
        assert_eq!(service.handled_count, 0);
        match WorkerEvent::decode(reply.value).unwrap() {
            WorkerEvent::Reply {
                id: 202,
                result: Err(err),
            } => assert_eq!(err.as_string().as_deref(), Some("no method nonexistent")),
            other => panic!("unexpected reply: {other:?}"),
        }

        // 3. Valid ID + accepted method + malformed args preserves reply ID.
        let bad_args = Array::of3(&203u32.into(), &"find".into(), &"missing-fields".into());
        let (reply_id, reply) = dispatch(&mut service, bad_args.into());
        assert_eq!(reply_id.as_f64(), Some(203.0));
        assert_eq!(service.handled_count, 0);
        match WorkerEvent::decode(reply.value).unwrap() {
            WorkerEvent::Reply {
                id: 203,
                result: Err(err),
            } => assert!(err.is_string()),
            other => panic!("unexpected reply: {other:?}"),
        }

        // 4. Malformed outer frame (no valid ID) replies with `[undefined, false, err]`.
        let (reply_id, reply) = dispatch(&mut service, JsValue::from_str("corrupt"));
        assert!(reply_id.is_undefined());
        assert_eq!(service.handled_count, 0);
        assert!(reply.transfer.is_none());
        let arr = reply.value.dyn_into::<Array>().unwrap();
        assert_eq!(arr.length(), 3);
        assert!(arr.get(0).is_undefined());
        assert_eq!(arr.get(1).as_bool(), Some(false));
        assert!(arr.get(2).is_string());

        // 5. Service error is wrapped in `[id, false, error]` with no transfer list.
        let mut failing = MockService {
            accepted: Method::Open,
            handled_count: 0,
            fail_with: Some("corrupt PDF".into()),
        };
        let req = encode_request_frame(204, Request::Open(b"bad"));
        let (reply_id, reply) = dispatch(&mut failing, req.value);
        assert_eq!(reply_id.as_f64(), Some(204.0));
        assert_eq!(failing.handled_count, 1);
        assert!(reply.transfer.is_none());
        match WorkerEvent::decode(reply.value).unwrap() {
            WorkerEvent::Reply {
                id: 204,
                result: Err(err),
            } => assert_eq!(err.as_string().as_deref(), Some("corrupt PDF")),
            other => panic!("unexpected reply: {other:?}"),
        }
    }
}
