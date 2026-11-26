//! The worker that highlights [`Group::Web`](e2ee_chat_preview::language::Group)'s languages.

fn main() {
    e2ee_chat_preview::worker::run(e2ee_chat_preview::code::web());
}
