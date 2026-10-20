# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org).

<!--
Note: In this file, do not use the hard wrap in the middle of a sentence for compatibility with GitHub comment style markdown rendering.
-->

## [Unreleased]

## [0.3.0] - 2026-10-19

- split ratchetx2 into `ratchetx2` (double ratchet, the only published crate) and the repo-only crates `primitives` (`Party`, transports), `x3dh` and `xeddsa`
- ring -> pure-Rust crypto (curve25519-dalek, ed25519-dalek, RustCrypto); `ratchetx2`, `xeddsa` and `primitives` (without `grpc`) build for `wasm32-unknown-unknown`
- bump deps (tonic/prost 0.14, curve25519-dalek 5; client: ratatui 0.30, ratatui-image 11)
- replace bincode with protobuf (prost derive, no `protoc` needed); the wire format changed, so 0.3.x clients cannot talk to 0.2.x clients
- ratchetx2: `SharedKeys::bob`/`Ratchetx2::bob` take `DhPrivateKey` instead of ring's `EphemeralPrivateKey`; `XEdDSAPrivateKey::generate()` no longer takes an RNG
- fix: X3DH and the DH ratchet no longer duplicate private keys with `transmute_copy`
- fix: header encryption reused the AES-GCM nonce under each chain's header key; every encryption now uses a fresh random nonce (wire format change)
- fix: xeddsa `agree_ephemeral` is renamed `diffie_hellman` and rejects peer keys outside the prime-order subgroup, which let a peer learn the identity key modulo 8
- fix: X3DH now deletes Alice's ephemeral private key and zeroizes the DH outputs as soon as the shared keys are derived, instead of keeping them across network calls
- remove the deprecated e2ee_chat_ingress

## [0.2.7] - 2025-07-09

- bump deps
- make it compile even if no protoc with feature grpc disabled

## [0.2.6] - 2025-05-19

- bug fix

## [0.2.5] - 2025-05-13

- list attempts

## [0.2.4] - 2025-04-29

- fix bug on Windows

## [0.2.3] - 2025-04-27

- improve

## [0.2.2] - 2025-04-27

- improve doc

## [0.2.1] - 2025-04-27

- improve image display

## [0.2.0] - 2025-04-27

- TLS support

## [0.1.1-alpha.1] - 2025-04-27

- Fix tonic over Pingora

## [0.1.0] - 2025-04-26

- MVP
