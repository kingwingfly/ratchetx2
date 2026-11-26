//! Serving preview requests in a dedicated web worker.

use wasm_bindgen::prelude::*;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};

use crate::READY;
use crate::rpc::{RequestFrame, Response, encode_reply_frame};

pub use crate::rpc::{WirePayload as Reply, WorkerService};

/// Run `service` inside the current dedicated web worker scope, announcing [`READY`] once its
/// message handler is installed.
pub fn run<S: WorkerService + 'static>(mut service: S) {
    console_error_panic_hook::set_once();
    let scope: DedicatedWorkerGlobalScope = js_sys::global()
        .dyn_into()
        .expect("preview workers run in a dedicated worker scope");
    let answer = scope.clone();
    let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        let (reply_id, result) = match RequestFrame::decode(event.data()) {
            Ok(frame) => {
                let id = JsValue::from(frame.id);
                let handled = frame.method().and_then(|method| {
                    if !service.accepts(method) {
                        return Err(format!("no method {}", method.as_str()));
                    }
                    service.handle(frame.request()?).map(Response::encode)
                });
                (id, handled)
            }
            Err(error) => (JsValue::UNDEFINED, Err(error)),
        };
        let reply = encode_reply_frame(&reply_id, result);
        let sent = match reply.transfer {
            Some(transfer) => match answer.post_message_with_transfer(&reply.value, &transfer) {
                Ok(()) => Ok(()),
                Err(error) => {
                    web_sys::console::error_1(&error);
                    let fallback =
                        encode_reply_frame(&reply_id, Err("reply transfer failed".to_string()));
                    answer.post_message(&fallback.value)
                }
            },
            None => answer.post_message(&reply.value),
        };
        if let Err(error) = sent {
            web_sys::console::error_1(&error);
        }
    });
    scope.set_onmessage(on_message.as_ref().dyn_ref());
    on_message.forget();
    if let Err(error) = scope.post_message(&READY.into()) {
        web_sys::console::error_1(&error);
    }
}
