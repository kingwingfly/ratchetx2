[X3DH](https://signal.org/docs/specifications/x3dh/) (Extended Triple Diffie-Hellman) key agreement, without I/O.

Alice and Bob derive the same 32-byte shared secret key and associated data. Identity keys are [xeddsa](../xeddsa) keys; prekeys and Alice's ephemeral key are X25519 keys. How bundles and initial messages travel is up to the caller.

Parameters: curve X25519, hash SHA-256, info `"x3dh.v1"`, HKDF salt of 32 zero bytes, public keys encoded as their 32 raw bytes, and associated data `IK_A ‖ IK_B`.

Bob's [`LocalPrekeys`] keeps the private keys of the last [`KEPT_GENERATIONS`] generations of prekeys only, deleting older ones so they cannot reveal anything later.

Nothing in an initial message shows that it is Alice's: anyone can send one claiming to be. Only Alice can encrypt with the agreement, though, as it takes her identity key's private key, so the X3DH spec has her initial message carry a first ciphertext, and Bob checks that it decrypts. [`LocalPrekeys::accept`] therefore changes nothing; once the ciphertext decrypts, [`LocalPrekeys::confirm`] uses up the one-time prekey and keeps the message from being accepted again, also one without a one-time prekey sent again. Nothing is signed, so neither can prove to others that they talked.

# Features

- **serde**, **rkyv**: derive their traits on [`PrekeyBundle`] and [`InitialMessage`], and on [`LocalPrekeys`], which serializes with its private keys, to keep them between runs.
- **prost**: [`LocalPrekeys`] as protobuf messages too, defined in `proto/x3dh.proto` (package `x3dh.v1`) so other languages can read them; [protox](https://crates.io/crates/protox) compiles it, so `protoc` is not needed. The bundle and the initial message are in the protocol's `handshake.proto`.

On `wasm32-unknown-unknown`, enable getrandom's `wasm_js` feature in the final application.

# Example

```rust
use x3dh::{LocalPrekeys, PrekeyBundle};
use xeddsa::XEdDSAPrivateKey;

let (alice, bob) = (XEdDSAPrivateKey::generate(), XEdDSAPrivateKey::generate());
let alice_key = alice.compute_public_key().to_bytes();
let bob_key = bob.compute_public_key().to_bytes();

// Bob generates prekeys and publishes them.
let mut prekeys = LocalPrekeys::new();
let published = prekeys.generate(&bob, 10);
let bundle = PrekeyBundle {
    signed_prekey: published.signed_prekey,
    signed_prekey_signature: published.signed_prekey_signature,
    one_time_prekey: published.one_time_prekeys.first().copied(),
};

// Alice starts the session and sends `message` to Bob.
let (message, alice_agreement) = bundle.initiate(&alice, &bob_key).unwrap();
// Bob accepts it, and once something Alice encrypted with the agreement decrypts, confirms it.
let (bob_agreement, _signed_prekey) = prekeys.accept(&bob, &alice_key, &message).unwrap();
assert_eq!(*alice_agreement.secret_key, *bob_agreement.secret_key);
prekeys.confirm(&message).unwrap();
```
