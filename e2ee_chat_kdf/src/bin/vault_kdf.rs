//! Ephemeral dedicated Web Worker binary (`vault_kdf`) running Argon2id off the main UI thread.
//!
//! Wire protocol:
//! - On boot, posts `"ready"`.
//! - Request: `[id, passphrase_u8, salt_u8, memory_kib, iterations, parallelism]` with both
//!   `Uint8Array` buffers transferred from the caller.
//! - Immediately copies `passphrase_u8` and `salt_u8` into `Zeroizing<Vec<u8>>` and zeroes the
//!   transferred JS `Uint8Array` views, runs [`e2ee_chat_kdf::derive_kek`], and posts:
//!   - On success: `[id, true, out_u8]` transferring `out_u8.buffer()` (32 bytes).
//!   - On error: `[id, false, error_message]`.

#[cfg(not(target_arch = "wasm32"))]
fn main() {}

#[cfg(target_arch = "wasm32")]
fn main() {
    worker::run();
}

#[cfg(target_arch = "wasm32")]
mod worker {
    use e2ee_chat_kdf::{KEK_LEN, MAX_PASSPHRASE_BYTES, derive_kek};
    use js_sys::{Array, Uint8Array};
    use wasm_bindgen::{JsCast, JsValue, closure::Closure};
    use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};
    use zeroize::Zeroizing;

    const READY: &str = "ready";

    fn parse_u32(value: &JsValue, field: &str) -> Result<u32, String> {
        let number = value
            .as_f64()
            .ok_or_else(|| format!("invalid {field} in KDF request"))?;
        if !number.is_finite()
            || number.fract() != 0.0
            || number < 0.0
            || number > f64::from(u32::MAX)
        {
            return Err(format!("out-of-range {field} in KDF request"));
        }
        Ok(number as u32)
    }

    fn copy_and_zero(
        view: &Uint8Array,
        max_len: usize,
        field: &str,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let len = view.length() as usize;
        if len > max_len {
            view.fill(0, 0, view.length());
            return Err(format!("{field} exceeds maximum allowed length"));
        }
        let mut out = Zeroizing::new(vec![0u8; len]);
        view.copy_to(&mut out);
        // Zero transferred JS buffer immediately after copying into zeroizing Rust memory.
        view.fill(0, 0, view.length());
        Ok(out)
    }

    fn post_error(scope: &DedicatedWorkerGlobalScope, id: &JsValue, message: &str) {
        let reply = Array::of3(id, &JsValue::FALSE, &JsValue::from_str(message));
        let _ = scope.post_message(&reply);
    }

    fn handle_message(scope: &DedicatedWorkerGlobalScope, data: JsValue) {
        let Ok(array) = data.dyn_into::<Array>() else {
            post_error(scope, &JsValue::UNDEFINED, "malformed KDF request frame");
            return;
        };
        let raw_id = if array.length() > 0 {
            array.get(0)
        } else {
            JsValue::UNDEFINED
        };
        if array.length() != 6 {
            post_error(scope, &raw_id, "malformed KDF request frame");
            return;
        }

        // Extract and zero both JS Uint8Array views up front even if other fields are invalid.
        let pass_res = array
            .get(1)
            .dyn_into::<Uint8Array>()
            .map_err(|_| "missing passphrase buffer in KDF request".to_string())
            .and_then(|view| copy_and_zero(&view, MAX_PASSPHRASE_BYTES, "passphrase"));
        let salt_res = array
            .get(2)
            .dyn_into::<Uint8Array>()
            .map_err(|_| "missing salt buffer in KDF request".to_string())
            .and_then(|view| copy_and_zero(&view, 256, "salt"));

        let id = match parse_u32(&raw_id, "request id") {
            Ok(id) => JsValue::from(id),
            Err(err) => {
                post_error(scope, &raw_id, &err);
                return;
            }
        };
        let passphrase = match pass_res {
            Ok(p) => p,
            Err(err) => {
                post_error(scope, &id, &err);
                return;
            }
        };
        let salt = match salt_res {
            Ok(s) => s,
            Err(err) => {
                post_error(scope, &id, &err);
                return;
            }
        };
        let memory_kib = match parse_u32(&array.get(3), "memory_kib") {
            Ok(v) => v,
            Err(err) => {
                post_error(scope, &id, &err);
                return;
            }
        };
        let iterations = match parse_u32(&array.get(4), "iterations") {
            Ok(v) => v,
            Err(err) => {
                post_error(scope, &id, &err);
                return;
            }
        };
        let parallelism = match parse_u32(&array.get(5), "parallelism") {
            Ok(v) => v,
            Err(err) => {
                post_error(scope, &id, &err);
                return;
            }
        };

        let derived = derive_kek(&passphrase, &salt, memory_kib, iterations, parallelism);
        drop(passphrase);
        drop(salt);

        match derived {
            Ok(kek) => {
                let out = Uint8Array::new_with_length(KEK_LEN as u32);
                out.copy_from(kek.as_slice());
                drop(kek);
                let transfer = Array::of1(&out.buffer());
                let reply = Array::of3(&id, &JsValue::TRUE, &out);
                if scope.post_message_with_transfer(&reply, &transfer).is_err() {
                    out.fill(0, 0, out.length());
                    post_error(scope, &id, "failed to transfer derived KEK");
                }
            }
            Err(err) => post_error(scope, &id, &err),
        }
    }

    pub fn run() {
        console_error_panic_hook::set_once();
        let scope: DedicatedWorkerGlobalScope = js_sys::global()
            .dyn_into()
            .expect("vault_kdf runs in a dedicated worker scope");
        let answer = scope.clone();
        let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            handle_message(&answer, event.data());
        });
        scope.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        on_message.forget();
        let _ = scope.post_message(&JsValue::from_str(READY));
    }
}
