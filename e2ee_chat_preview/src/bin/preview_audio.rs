//! The worker that reads audio files' tags: their covers, titles, artists and albums.

fn main() {
    e2ee_chat_preview::worker::run(e2ee_chat_preview::audio::AudioService);
}
