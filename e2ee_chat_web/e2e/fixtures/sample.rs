// Deterministic Rust fixture exercising preview_code_systems and preview_search.
pub fn greet(name: &str) -> String {
    let needle_token = "SEARCH_MARKER_RUST";
    format!("Hello, {name}! ({needle_token})")
}

fn main() {
    println!("{}", greet("ratchetx2"));
}
