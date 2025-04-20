A double-ratchet implementation following [Signal](https://signal.org/docs/specifications/doubleratchet/).

# Compared to others

My code is much more object-oriented.

1. There's no global party state, instead, it is each ratchet having its own state.
2. It's really double-ratchet (2 kinds of ratchets), DhRootRatchet and MessageRatchet (AKA ChainRatchet).
3. Header encryption support.
4. Provide chat parties implementation.

# Example

Ratchet only example:
```rust
use ratchetx2::SharedKeys;

let shared_keys = SharedKeys {
    secret_key: [0; 32],
    header_key_alice: [1; 32],
    header_key_bob: [2; 32],
};
let mut bob = shared_keys.bob();
let mut alice = shared_keys.alice(bob.public_key());

// Alice sends first
bob.step_dh_root(alice.public_key());
assert_eq!(alice, bob); // Alice and Bob have the "same" state
assert_eq!(alice.step_msgs(), bob.step_msgr()); // returning the same message key
assert_eq!(alice.step_msgs(), bob.step_msgr());

// Bob sends
bob.step_dh_root(alice.public_key());
alice.step_dh_root(bob.public_key());
assert_eq!(alice, bob);
assert_eq!(bob.step_msgs(), alice.step_msgr());
assert_eq!(bob.step_msgs(), alice.step_msgr());

// Alice sends
alice.step_dh_root(bob.public_key());
bob.step_dh_root(alice.public_key());
assert_eq!(alice, bob);
assert_eq!(alice.step_msgs(), bob.step_msgr());
assert_eq!(alice.step_msgs(), bob.step_msgr());
```

E2EE chat app example:
```rust
use ratchetx2::{transport::ChannelTransport, Party, SharedKeys};

# #[tokio::main]
# async fn main() {
let shared_keys = SharedKeys {
    secret_key: [0; 32],
    header_key_alice: [1; 32],
    header_key_bob: [2; 32],
};
let (a, b) = ChannelTransport::new();
let bob = shared_keys.bob();
let alice = shared_keys.alice(bob.public_key());
let mut alice = Party::new(alice, a);
let mut bob = Party::new(bob, b);
alice.send(b"hello world", b"").await.unwrap();
assert_eq!(bob.recv(b"").await.unwrap(), b"hello world");
alice.send(b"hello Bob", b"").await.unwrap();
assert_eq!(bob.recv(b"").await.unwrap(), b"hello Bob");
bob.send(b"hello Alice", b"").await.unwrap();
assert_eq!(alice.recv(b"").await.unwrap(), b"hello Alice");
# }
```
