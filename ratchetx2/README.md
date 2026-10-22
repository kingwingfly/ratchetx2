A double-ratchet implementation following [Signal](https://signal.org/docs/specifications/doubleratchet/).

Pure Rust (no C dependencies), so it also builds for `wasm32-unknown-unknown`.

# E2EE chat app (TUI)

An E2EE chat server-client TUI app base on this crate is available [here](https://github.com/kingwingfly/ratchetx2). The repository also has unpublished companion crates: `xeddsa` (XEdDSA), `x3dh` (X3DH key agreement), `party` (header encryption over this crate), and `storage`, `protocol` and `session` for the chat itself.

# Compared to others

1. There's no global party state, instead, it is each ratchet having its own state.
2. It's really double-ratchet (2 kinds of ratchets), DhRootRatchet and MessageRatchet (AKA ChainRatchet).

# WebAssembly

On `wasm32-unknown-unknown`, randomness comes from [getrandom](https://docs.rs/getrandom), which needs its JavaScript backend enabled by the final application:

```toml
[target.'cfg(all(target_arch = "wasm32", target_os = "unknown"))'.dependencies]
getrandom = { version = "0.4", features = ["wasm_js"] }
```

# Example

After a key agreement such as X3DH, derive the shared keys from its secret with `SharedKeys::from_secret`. Ratchet only example:
```rust
use ratchetx2::{DhPrivateKey, SharedKeys};

let shared_keys = SharedKeys {
    secret_key: [0; 32],
    header_key_alice: [1; 32],
    header_key_bob: [2; 32],
};
let mut bob = shared_keys.bob(DhPrivateKey::generate());
let mut alice = shared_keys.alice(&bob.public_key()).unwrap();
// Bob has no sending chain until he has received from Alice.
assert_eq!(bob.step_message_ratchet_sender(), None);

// Alice sends first
bob.step_dh_root(&alice.public_key()).unwrap();
assert_eq!(alice, bob); // Alice and Bob have the "same" state
// The receiver steps to the same message keys as the sender.
for _ in 0..2 {
    let message_key = alice.step_message_ratchet_sender().unwrap();
    assert_eq!(message_key, bob.step_message_ratchet_receiver().unwrap());
}

// Bob sends
bob.step_dh_root(&alice.public_key()).unwrap();
alice.step_dh_root(&bob.public_key()).unwrap();
assert_eq!(alice, bob);
for _ in 0..2 {
    let message_key = bob.step_message_ratchet_sender().unwrap();
    assert_eq!(message_key, alice.step_message_ratchet_receiver().unwrap());
}

// Alice sends
alice.step_dh_root(&bob.public_key()).unwrap();
bob.step_dh_root(&alice.public_key()).unwrap();
assert_eq!(alice, bob);
for _ in 0..2 {
    let message_key = alice.step_message_ratchet_sender().unwrap();
    assert_eq!(message_key, bob.step_message_ratchet_receiver().unwrap());
}
```
