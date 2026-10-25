//! The worker that highlights [`Group::Systems`](e2ee_chat_preview::language::Group)'s languages.

fn main() {
    e2ee_chat_preview::worker::serve_code(e2ee_chat_preview::code::systems());
}
