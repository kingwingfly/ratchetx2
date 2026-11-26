//! The worker that renders Markdown documents and reveal.js slides.

fn main() {
    e2ee_chat_preview::worker::run(e2ee_chat_preview::markdown::Service);
}
