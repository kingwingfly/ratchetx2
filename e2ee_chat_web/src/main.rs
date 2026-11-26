//! The E2EE chat's web client: X3DH and the double ratchet run in the page, and the server only
//! relays. See the README.

mod app;
mod content;
mod engine;
mod glue;
mod icon;
mod notify;
mod preview;
mod qr;
mod search;
mod state;
mod transport;
mod util;
mod vault;
mod workers;

#[cfg(all(test, target_arch = "wasm32"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::App);
}
