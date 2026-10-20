E2EE chat parties on top of the [ratchetx2](https://crates.io/crates/ratchetx2) double ratchet.

A [`Party`](party::Party) encrypts messages and their headers ([header encryption](https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption)), handles skipped and out-of-order messages, and sends them through a [`Transport`](transport::Transport).

# Features

- **grpc** (enabled by default): tonic-based message server and [`RpcTransport`](transport::RpcTransport) client (protoc is needed). Without it, the crate is pure Rust and builds for `wasm32-unknown-unknown` (enable getrandom's `wasm_js` feature in the final application there).

# Example

```rust
use ratchetx2::{DhPrivateKey, SharedKeys};
use primitives::{transport::ChannelTransport, Party};

# #[tokio::main]
# async fn main() {
let shared_keys = SharedKeys {
    secret_key: [0; 32],
    header_key_alice: [1; 32],
    header_key_bob: [2; 32],
};
let bob_ratchetx2 = shared_keys.bob(DhPrivateKey::generate());
let alice_ratchetx2 = shared_keys.alice(&bob_ratchetx2.public_key());
let (a, b) = ChannelTransport::new();
let mut alice = Party::new(alice_ratchetx2, a, "AliceBob");
let mut bob = Party::new(bob_ratchetx2, b, "AliceBob");
alice.push("hello world").await.unwrap();
assert_eq!(bob.fetch().await.unwrap().remove(0).unwrap(), b"hello world");
alice.push("hello Bob").await.unwrap();
assert_eq!(bob.fetch().await.unwrap().remove(0).unwrap(), b"hello Bob");
bob.push("hello Alice").await.unwrap();
assert_eq!(alice.fetch().await.unwrap().remove(0).unwrap(), b"hello Alice");
# }
```
