Double-ratchet message encryption on top of [ratchetx2](https://crates.io/crates/ratchetx2), with [header encryption](https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption).

A [`Party`](party::Party) encrypts and decrypts messages: it handles skipped and out-of-order messages, and rejects duplicates. It does no I/O; how [`EncryptedMessage`](proto::EncryptedMessage)s travel is up to the caller.

The message format is defined in `proto/party.proto` (package `party.v1`), so other languages can read it.

# Features

- **protox** (default): compile the `.proto` files with [protox](https://crates.io/crates/protox); without it, `protoc` must be installed.
- **serde**, **rkyv**: derive their traits on the message types.

On `wasm32-unknown-unknown`, enable getrandom's `wasm_js` feature in the final application.

# Example

```rust
use party::Party;
use ratchetx2::{DhPrivateKey, Ratchet, SharedKeys};

let shared_keys = SharedKeys {
    secret_key: [0; 32],
    header_key_alice: [1; 32],
    header_key_bob: [2; 32],
};
let bob_ratchet = Ratchet::bob(&shared_keys, DhPrivateKey::generate());
let alice_ratchet = Ratchet::alice(&shared_keys, &bob_ratchet.public_key()).unwrap();
let mut alice = Party::new(alice_ratchet, "AliceBob");
let mut bob = Party::new(bob_ratchet, "AliceBob");

let message = alice.encrypt(b"hello world").unwrap();
assert_eq!(bob.decrypt(&message).unwrap(), b"hello world");
// Bob can only encrypt after he has decrypted Alice's first message.
let message = bob.encrypt(b"hello Alice").unwrap();
assert_eq!(alice.decrypt(&message).unwrap(), b"hello Alice");
```
