[XEdDSA](https://signal.org/docs/specifications/xeddsa/) enables use of a single key pair format for both elliptic curve Diffie-Hellman and signatures.

Based on Ed25519 and X25519. Pure Rust, so it also builds for `wasm32-unknown-unknown` (enable getrandom's `wasm_js` feature in the final application there).

# Example

```rust
use xeddsa::XEdDSAPrivateKey;

let xeddsa = XEdDSAPrivateKey::generate();
let signature = xeddsa.sign("hello world");
let public_key = xeddsa.compute_public_key();
public_key.verify("hello world", &signature).unwrap();
assert!(public_key.verify("goodbye world", &signature).is_err());
let alice = XEdDSAPrivateKey::generate();
let bob = XEdDSAPrivateKey::generate();
assert_eq!(
    *alice.diffie_hellman(bob.compute_public_key().as_ref()).unwrap(),
    *bob.diffie_hellman(alice.compute_public_key().as_ref()).unwrap()
);
```
