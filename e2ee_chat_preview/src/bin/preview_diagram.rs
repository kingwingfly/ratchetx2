//! The worker that shows Mermaid diagrams.

fn main() {
    e2ee_chat_preview::worker::run(e2ee_chat_preview::diagram::DiagramService::new());
}
