//! The worker that searches previews' text with regular expressions.

fn main() {
    e2ee_chat_preview::worker::run(e2ee_chat_preview::search::SearchService);
}
