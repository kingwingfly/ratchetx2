A double-ratchet implementation following [Signal](https://signal.org/docs/specifications/doubleratchet/).

Pure Rust (no C dependencies), so it also builds for `wasm32-unknown-unknown`.

# E2EE chat app (TUI)

An E2EE chat server-client TUI app base on this crate is available [here](https://github.com/kingwingfly/ratchetx2). The repository also has unpublished companion crates: `primitives` (chat parties with header encryption, message transports), `x3dh` (X3DH over gRPC) and `xeddsa` (XEdDSA).

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

Ratchet only example:
```rust
use ratchetx2::{DhPrivateKey, SharedKeys};

let shared_keys = SharedKeys {
    secret_key: [0; 32],
    header_key_alice: [1; 32],
    header_key_bob: [2; 32],
};
let mut bob = shared_keys.bob(DhPrivateKey::generate());
let mut alice = shared_keys.alice(&bob.public_key());

// Alice sends first
bob.step_dh_root(&alice.public_key());
assert_eq!(alice, bob); // Alice and Bob have the "same" state
assert_eq!(alice.step_msgs(), bob.step_msgr()); // returning the same message key
assert_eq!(alice.step_msgs(), bob.step_msgr());

// Bob sends
bob.step_dh_root(&alice.public_key());
alice.step_dh_root(&bob.public_key());
assert_eq!(alice, bob);
assert_eq!(bob.step_msgs(), alice.step_msgr());
assert_eq!(bob.step_msgs(), alice.step_msgr());

// Alice sends
alice.step_dh_root(&bob.public_key());
bob.step_dh_root(&alice.public_key());
assert_eq!(alice, bob);
assert_eq!(alice.step_msgs(), bob.step_msgr());
assert_eq!(alice.step_msgs(), bob.step_msgr());
```
