# Changelog

All notable changes to the `ratchetx2` crate will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org).

<!--
Note: In this file, do not use the hard wrap in the middle of a sentence for compatibility with GitHub comment style markdown rendering.
-->

## [Unreleased]

## [0.4.0]

The crate now only contains the double ratchet. `Party` (header encryption), X3DH and XEdDSA moved to separate crates in the repository, which are not published; the transports were replaced by the repository's `protocol` crate.

### Breaking changes

- renamed `Ratchetx2` to `Ratchet`, and its abbreviated methods: `header_key_s`, `header_key_r`, `next_header_key_r`, `step_msgs` and `step_msgr` are now `header_key_sender`, `header_key_receiver`, `next_header_key_receiver`, `step_message_ratchet_sender` and `step_message_ratchet_receiver`
- removed the `party`, `transport`, `x3dh`, `xeddsa` and `server` modules, the `grpc` feature, and the re-exports of `ring`/`aws-lc-rs` (`agreement`, `rand`), `Scalar` and tonic types
- `SharedKeys::alice` and `SharedKeys::bob` are removed: `Ratchet::alice` and `Ratchet::bob` take the `SharedKeys` instead of its three keys
- `Ratchet::bob` takes the new `DhPrivateKey` instead of ring's `EphemeralPrivateKey`
- `Ratchet::alice` and `Ratchet::step_dh_root` return `Result` and fail on an invalid peer public key, leaving the state unchanged, instead of panicking
- `Ratchet::header_key_sender`, `header_key_receiver`, `step_message_ratchet_sender` and `step_message_ratchet_receiver` return `Option`: `None` until the chain is set up by a DH step
- `Ratchet::public_key` returns a `[u8; DH_KEY_LENGTH]` instead of a `Vec<u8>`, like `DhPrivateKey::public_key`
- `Ratchet` is `Clone`

### Added

- the `serde` and `rkyv` features: `Ratchet` and `DhPrivateKey` implement their traits, so a session can be kept between runs
- the `prost` feature: the `proto` module has the ratchet's state as protobuf messages (`proto/ratchetx2.proto`, package `ratchetx2.v1`), zeroized on drop, converting with `proto::Ratchet::from(&ratchet)` and `Ratchet::try_from(&message)`, which fails with the new `error::MalformedState`
- `SharedKeys::from_secret`, deriving the root key and both header keys from a 32-byte shared secret such as X3DH's SK
- `key::KEY_LENGTH` and `key::DH_KEY_LENGTH`, the key lengths, taken from SHA-256's output size and curve25519-dalek's X25519 encoding

### Fixes

- chains no longer start with all-zero header and chain keys
- `Ratchet`'s `Debug` no longer prints keys
- pure-Rust crypto (curve25519-dalek, RustCrypto) instead of ring; builds for `wasm32-unknown-unknown`
