# Changelog

All notable changes to the `ratchetx2` crate will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org).

<!--
Note: In this file, do not use the hard wrap in the middle of a sentence for compatibility with GitHub comment style markdown rendering.
-->

## [Unreleased]

## [0.4.0]

The crate now only contains the double ratchet. Party, transports, X3DH and XEdDSA moved to separate crates in the repository, which are not published.

### Breaking changes

- removed the `party`, `transport`, `x3dh`, `xeddsa` and `server` modules, the `grpc` feature, and the re-exports of `ring`/`aws-lc-rs` (`agreement`, `rand`), `Scalar` and tonic types
- `SharedKeys::bob`/`Ratchetx2::bob` take the new `DhPrivateKey` instead of ring's `EphemeralPrivateKey`
- `SharedKeys::alice`, `Ratchetx2::alice` and `Ratchetx2::step_dh_root` return `Result` and fail on an invalid peer public key, leaving the state unchanged, instead of panicking
- `Ratchetx2::header_key_s`, `header_key_r`, `step_msgs` and `step_msgr` return `Option`: `None` until the chain is set up by a DH step
- `Ratchetx2` is `Clone`

### Fixes

- chains no longer start with all-zero header and chain keys
- pure-Rust crypto (curve25519-dalek, RustCrypto) instead of ring; builds for `wasm32-unknown-unknown`
