//! Serving a page's requests in a web worker, as the crate's documentation says, and each
//! engine's requests.

use js_sys::Array;
use wasm_bindgen::prelude::*;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};

use crate::READY;

/// A request's answer: its value, and the buffers in it to move to the page rather than copy.
pub struct Reply {
    pub value: JsValue,
    pub transfer: Option<Array>,
}

impl Reply {
    pub fn new(value: impl Into<JsValue>) -> Self {
        Self {
            value: value.into(),
            transfer: None,
        }
    }
}

/// Answer each request with `handle(method, arguments)`, for as long as the worker lives.
pub fn serve(mut handle: impl FnMut(&str, &Array) -> Result<Reply, String> + 'static) {
    console_error_panic_hook::set_once();
    let scope: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    let answer = scope.clone();
    let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        let request = Array::from(&event.data());
        let id = request.get(0);
        let method = request.get(1).as_string().unwrap_or_default();
        let arguments = request.slice(2, request.length());
        let sent = match handle(&method, &arguments) {
            Ok(Reply { value, transfer }) => {
                let reply = Array::of3(&id, &JsValue::TRUE, &value);
                match transfer {
                    Some(transfer) => answer.post_message_with_transfer(&reply, &transfer),
                    None => answer.post_message(&reply),
                }
            }
            Err(error) => answer.post_message(&Array::of3(&id, &JsValue::FALSE, &error.into())),
        };
        // Unsent, as it cannot be cloned, which is no request's doing.
        if let Err(e) = sent {
            web_sys::console::error_1(&e);
        }
    });
    scope.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();
    let _ = scope.post_message(&READY.into());
}

/// The argument at `index`, as a string.
#[cfg(any(feature = "diagram", feature = "code"))]
fn string(arguments: &Array, index: u32) -> Result<String, String> {
    arguments
        .get(index)
        .as_string()
        .ok_or_else(|| format!("argument {index} is not a string"))
}

/// The argument at `index`, as a whole number.
#[cfg(feature = "pdf")]
fn number(arguments: &Array, index: u32) -> Result<u32, String> {
    arguments
        .get(index)
        .as_f64()
        .filter(|n| n.fract() == 0.0 && (0.0..=u32::MAX.into()).contains(n))
        .map(|n| n as u32)
        .ok_or_else(|| format!("argument {index} is not a whole number"))
}

/// Serve [`Worker::Pdf`](crate::Worker::Pdf)'s requests.
#[cfg(feature = "pdf")]
pub fn serve_pdf() {
    use std::collections::HashMap;

    use js_sys::{Float64Array, Uint8Array, Uint8ClampedArray};

    use crate::pdf::Document;

    let mut documents = HashMap::new();
    let mut opened = 0u32;
    serve(move |method, arguments| match method {
        "open" => {
            let bytes = Uint8Array::new(&arguments.get(0)).to_vec();
            let document = Document::open(bytes)?;
            let sizes: Vec<f64> = document
                .sizes()
                .into_iter()
                .flat_map(|(width, height)| [width.into(), height.into()])
                .collect();
            opened += 1;
            documents.insert(opened, document);
            Ok(Reply::new(Array::of2(
                &opened.into(),
                &Float64Array::from(&sizes[..]),
            )))
        }
        "render" => {
            let document = documents
                .get(&number(arguments, 0)?)
                .ok_or("no such document")?;
            let page = document.render(number(arguments, 1)? as usize, number(arguments, 2)?)?;
            let pixels = Uint8ClampedArray::from(&page.pixels[..]);
            Ok(Reply {
                value: Array::of3(&page.width.into(), &page.height.into(), &pixels).into(),
                transfer: Some(Array::of1(&pixels.buffer())),
            })
        }
        "close" => {
            documents.remove(&number(arguments, 0)?);
            Ok(Reply::new(JsValue::UNDEFINED))
        }
        _ => Err(format!("no method {method}")),
    });
}

/// Serve [`Worker::Diagram`](crate::Worker::Diagram)'s requests.
#[cfg(feature = "diagram")]
pub fn serve_diagram() {
    serve(|method, arguments| match method {
        "svg" => crate::diagram::svg(&string(arguments, 0)?).map(Reply::new),
        _ => Err(format!("no method {method}")),
    });
}

/// Serve [`Worker::Code`](crate::Worker::Code)'s requests, with `code`.
#[cfg(feature = "code")]
pub fn serve_code(mut code: crate::code::Code) {
    serve(move |method, arguments| match method {
        "highlight" => code
            .highlight(&string(arguments, 0)?, &string(arguments, 1)?)
            .map(Reply::new),
        _ => Err(format!("no method {method}")),
    });
}
