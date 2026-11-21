//! Serving preview requests in a dedicated web worker.

use js_sys::Array;
use wasm_bindgen::prelude::*;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};

use crate::READY;
use crate::rpc::{Request, RequestFrame, Response, encode_reply_frame};

pub use crate::rpc::WirePayload as Reply;

fn listen(mut handle: impl FnMut(&RequestFrame) -> Result<Reply, String> + 'static) {
    console_error_panic_hook::set_once();
    let scope: DedicatedWorkerGlobalScope = js_sys::global()
        .dyn_into()
        .expect("preview workers run in a dedicated worker scope");
    let answer = scope.clone();
    let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        let reply = match RequestFrame::decode(event.data()) {
            Ok(frame) => encode_reply_frame(&frame.id, handle(&frame)),
            Err(error) => encode_reply_frame(&JsValue::UNDEFINED, Err(error)),
        };
        let sent = match reply.transfer {
            Some(transfer) => answer.post_message_with_transfer(&reply.value, &transfer),
            None => answer.post_message(&reply.value),
        };
        if let Err(error) = sent {
            web_sys::console::error_1(&error);
        }
    });
    scope.set_onmessage(on_message.as_ref().dyn_ref());
    on_message.forget();
    let _ = scope.post_message(&READY.into());
}

/// Answer requests with the original method-name and argument-array callback.
pub fn serve(mut handle: impl FnMut(&str, &Array) -> Result<Reply, String> + 'static) {
    listen(move |frame| handle(&frame.method_name()?, &frame.raw_arguments()));
}

/// Decode requests and send each handler's typed response or error.
pub fn serve_requests(mut handle: impl FnMut(Request) -> Result<Response, String> + 'static) {
    listen(move |frame| handle(frame.request()?).map(Response::encode));
}

/// Serve [`Worker::Pdf`](crate::Worker::Pdf)'s requests.
#[cfg(feature = "pdf")]
pub fn serve_pdf() {
    use std::collections::HashMap;

    use crate::pdf::Document;
    use crate::rpc::PdfOpened;

    let mut documents = HashMap::new();
    let mut opened = 0u32;
    serve_requests(move |request| match request {
        Request::Open(bytes) => {
            let document = Document::open(bytes)?;
            let sizes = document
                .sizes()
                .into_iter()
                .map(|(w, h)| (f64::from(w), f64::from(h)))
                .collect();
            opened = opened.checked_add(1).ok_or("no more document IDs")?;
            documents.insert(opened, document);
            Ok(Response::Opened(PdfOpened {
                doc_id: opened,
                sizes,
            }))
        }
        Request::Render {
            doc_id,
            page,
            width,
        } => {
            let document = documents.get(&doc_id).ok_or("no such document")?;
            document
                .render(page as usize, width)
                .map(Response::Rendered)
        }
        Request::Close { doc_id } => {
            documents.remove(&doc_id);
            Ok(Response::Closed)
        }
        other => Err(format!("no method {}", other.method().as_str())),
    });
}

/// Serve [`Worker::Audio`](crate::Worker::Audio)'s requests.
#[cfg(feature = "audio")]
pub fn serve_audio() {
    serve_requests(|request| match request {
        Request::Tags(bytes) => Ok(Response::Tags(crate::audio::tags(&bytes))),
        other => Err(format!("no method {}", other.method().as_str())),
    });
}

/// Serve [`Worker::Search`](crate::Worker::Search)'s requests.
#[cfg(feature = "search")]
pub fn serve_search() {
    serve_requests(|request| match request {
        Request::Find {
            text,
            pattern,
            case,
            regex,
        } => crate::search::find(&text, &pattern, case, regex).map(Response::Found),
        other => Err(format!("no method {}", other.method().as_str())),
    });
}

/// Serve [`Worker::Diagram`](crate::Worker::Diagram)'s requests.
#[cfg(feature = "diagram")]
pub fn serve_diagram() {
    serve_requests(|request| match request {
        Request::Svg(source) => crate::diagram::svg(&source).map(Response::Svg),
        other => Err(format!("no method {}", other.method().as_str())),
    });
}

/// Serve [`Worker::Code`](crate::Worker::Code)'s requests with the given highlighter.
#[cfg(feature = "code")]
pub fn serve_code(mut code: crate::code::Code) {
    serve_requests(move |request| match request {
        Request::Highlight { language, text } => {
            code.highlight(&language, &text).map(Response::Highlighted)
        }
        other => Err(format!("no method {}", other.method().as_str())),
    });
}
