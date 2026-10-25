//! Browser APIs that may be missing: the Web Locks API, in older browsers, and the clipboard,
//! outside secure contexts. Calling a missing one would throw into the WebAssembly caller, so
//! each is looked for first. web-sys has the Web Locks API only among its unstable APIs, so it is
//! called as JavaScript sees it.

use std::{cell::RefCell, rc::Rc};

use futures::channel::oneshot;
use js_sys::{Function, Object, Promise, Reflect};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::Navigator;

fn navigator() -> Navigator {
    web_sys::window().expect("a window").navigator()
}

/// Whether `navigator` has the API `name`.
fn has(navigator: &Navigator, name: &str) -> bool {
    Reflect::get(navigator, &name.into()).is_ok_and(|api| !api.is_undefined())
}

/// Take the lock `name` for as long as the page lives; `false` if another page holds it.
pub async fn take_lock(name: &str) -> bool {
    let navigator = navigator();
    // Without locks, there is no telling.
    let Some(locks) = Reflect::get(&navigator, &"locks".into())
        .ok()
        .filter(|locks| !locks.is_undefined())
    else {
        return true;
    };
    let Some(request) = Reflect::get(&locks, &"request".into())
        .ok()
        .and_then(|request| request.dyn_into::<Function>().ok())
    else {
        return true;
    };
    let (taken, told) = oneshot::channel();
    let taken = Rc::new(RefCell::new(Some(taken)));
    let tell = {
        let taken = taken.clone();
        move |held: bool| {
            if let Some(taken) = taken.borrow_mut().take() {
                let _ = taken.send(held);
            }
        }
    };
    let granted = {
        let tell = tell.clone();
        Closure::<dyn FnMut(JsValue) -> Promise>::new(move |lock: JsValue| {
            let held = !lock.is_null();
            tell(held);
            if held {
                // Held until the page goes.
                Promise::new(&mut |_, _| {})
            } else {
                Promise::resolve(&JsValue::UNDEFINED)
            }
        })
    };
    let options = Object::new();
    let _ = Reflect::set(&options, &"ifAvailable".into(), &JsValue::TRUE);
    let requested = request.call3(&locks, &name.into(), &options, granted.as_ref());
    // Called once, but the lock's promise lives with the page.
    granted.forget();
    // A request that fails, like no locks, must not keep the page loading forever.
    match requested.map(Promise::from) {
        Ok(requested) => spawn_local(async move {
            if JsFuture::from(requested).await.is_err() {
                tell(true);
            }
        }),
        Err(_) => tell(true),
    }
    told.await.unwrap_or(true)
}

/// Copy `text` to the clipboard; `false` if the browser refused.
pub async fn copy(text: &str) -> bool {
    let navigator = navigator();
    has(&navigator, "clipboard")
        && JsFuture::from(navigator.clipboard().write_text(text))
            .await
            .is_ok()
}
