A double-ratchet implementation following [Signal](https://signal.org/docs/specifications/doubleratchet/).

# Compared to others

My code is much more object-oriented.

1. There's no global party state, instead, it is each ratchet having its own state.
2. It's really double-ratchet (2 kinds of ratchets), DhRootRatchet and MessageRatchet(AKA ChainRatchet).
3. HeaderKey support.
4. Do nothing about message/header encryption/decryption, instead, provide correct message/header keys only.

# Example
```rust
use ratchetx2::SharedKeys;

let shared_keys = SharedKeys {
    secret_key: [0; 32],
    header_key_alice: [1; 32],
    header_key_bob: [2; 32],
};
let mut alice = shared_keys.alice();
let mut bob = shared_keys.bob();

// Alice sends first
alice.step_dh_root(bob.public_key());
bob.step_dh_root(alice.public_key());
assert_eq!(alice, bob); // debug_assertions only, Alice and Bob have the "same" state
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
