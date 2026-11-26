//! The worker that shows PDF pages.

fn main() {
    e2ee_chat_preview::worker::run(e2ee_chat_preview::pdf::PdfService::new());
}
