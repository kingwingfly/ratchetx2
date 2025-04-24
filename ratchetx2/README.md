A double-ratchet implementation following [Signal](https://signal.org/docs/specifications/doubleratchet/).

Also with X3DH and XEdDSA implementation.

# Compared to others

1. There's no global party state, instead, it is each ratchet having its own state.
2. It's really double-ratchet (2 kinds of ratchets), DhRootRatchet and MessageRatchet (AKA ChainRatchet).
3. Header encryption support.
4. Provide chat parties implementation.
5. Provide gRPC transport implementation.
6. Provide X3DH shared key initialization implementation.
7. Provide XEdDSA implementation.

# Example

Ratchet only example:
```rust
use ratchetx2::SharedKeys;
use ratchetx2::rand::SystemRandom;
use ratchetx2::agreement::{EphemeralPrivateKey, X25519};

let shared_keys = SharedKeys {
    secret_key: [0; 32],
    header_key_alice: [1; 32],
    header_key_bob: [2; 32],
};
let mut bob = shared_keys.bob(EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).unwrap());
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

E2EE chat app example:
```rust
use ratchetx2::{transport::ChannelTransport, Party, SharedKeys};
use ratchetx2::rand::SystemRandom;
use ratchetx2::agreement::{EphemeralPrivateKey, X25519};

# #[tokio::main]
# async fn main() {
let shared_keys = SharedKeys {
    secret_key: [0; 32],
    header_key_alice: [1; 32],
    header_key_bob: [2; 32],
};
let bob_ratchetx2 = shared_keys.bob(EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).unwrap());
let alice_ratchetx2 = shared_keys.alice(&bob_ratchetx2.public_key());
let (a, b) = ChannelTransport::new();
let mut alice = Party::new(alice_ratchetx2, a);
let mut bob = Party::new(bob_ratchetx2, b);
alice.push("hello world", "AliceBob").await.unwrap();
assert_eq!(bob.fetch("AliceBob").await.unwrap().remove(0).unwrap(), b"hello world");
alice.push("hello Bob", "AliceBob").await.unwrap();
assert_eq!(bob.fetch("AliceBob").await.unwrap().remove(0).unwrap(), b"hello Bob");
bob.push("hello Alice", "AliceBob").await.unwrap();
assert_eq!(alice.fetch("AliceBob").await.unwrap().remove(0).unwrap(), b"hello Alice");
# }
```

XEdDSA example:
```rust
use ratchetx2::xeddsa::XEdDSAPrivateKey;
use ratchetx2::rand::SystemRandom;

let xeddsa = XEdDSAPrivateKey::generate(&SystemRandom::new());
let signature = xeddsa.sign("hello world");
let public_key = xeddsa.compute_public_key();
public_key.verify("hello world", &signature).unwrap();
assert!(public_key.verify("goodbye world", &signature).is_err());
let alice = XEdDSAPrivateKey::generate(&SystemRandom::new());
let bob = XEdDSAPrivateKey::generate(&SystemRandom::new());
assert_eq!(
    alice.agree_ephemeral(bob.compute_public_key().as_ref()).unwrap(),
    bob.agree_ephemeral(alice.compute_public_key().as_ref()).unwrap()
);
```

X3DH initialize example:
```rust
use ratchetx2::server::RpcServer;
use ratchetx2::x3dh::X3DHClient;

# #[tokio::main]
# async fn main() {
tokio::spawn(async {
    RpcServer::run("127.0.0.1:3002").await.unwrap();
});
// wait server start
tokio::time::sleep(std::time::Duration::from_millis(100)).await;

const SERVER_ADDR: &str = "http://127.0.0.1:3002";

let mut alice_x3dh = X3DHClient::new(SERVER_ADDR).await;
let mut bob_x3dh = X3DHClient::new(SERVER_ADDR).await;
bob_x3dh.publish_keys().await.unwrap();
let mut alice = alice_x3dh
    .push_initial_message(&bob_x3dh.public_identity_key(), SERVER_ADDR)
    .await
    .unwrap();
let mut bob = bob_x3dh
    .handle_initial_message(&alice_x3dh.public_identity_key(), SERVER_ADDR)
    .await
    .unwrap();
alice.push("hello world", "AliceBob").await.unwrap();
assert_eq!(
    bob.fetch("AliceBob").await.unwrap().remove(0).unwrap(),
    b"hello world"
);
alice.push("hello Bob", "AliceBob").await.unwrap();
assert_eq!(
    bob.fetch("AliceBob").await.unwrap().remove(0).unwrap(),
    b"hello Bob"
);
bob.push("hello Alice", "AliceBob").await.unwrap();
assert_eq!(
    alice.fetch("AliceBob").await.unwrap().remove(0).unwrap(),
    b"hello Alice"
);
# }
```
