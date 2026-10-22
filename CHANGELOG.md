# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org).

<!--
Note: In this file, do not use the hard wrap in the middle of a sentence for compatibility with GitHub comment style markdown rendering.
-->

## [Unreleased]

## [0.3.0] - 2026-10-19

The wire protocol changed, so 0.3 clients and servers cannot talk to 0.2 ones.

- split ratchetx2 into crates: `ratchetx2` (double ratchet, the only published crate) and the repo-only `xeddsa`, `x3dh` (key agreement without I/O), `party` (header encryption), `storage` (typed records behind the `HandshakeStore`/`MailboxStore` traits, with an in-memory backend), `protocol` (wire protocol, client traits, server logic, gRPC) and `session` (the client flow)
- the protocol is defined in `.proto` files (packages `handshake.v1`, `mailbox.v1`, `party.v1`) so other languages can implement it; protox compiles them by default, so `protoc` is not needed
- serde, rkyv and gRPC are optional features; except for gRPC, every library builds for `wasm32-unknown-unknown`, and the client and server traits have `Local` variants whose futures need not be `Send`
- ring -> pure-Rust crypto (curve25519-dalek, ed25519-dalek, RustCrypto)
- bump deps (tonic/prost 0.14, curve25519-dalek 5; client: ratatui 0.30, ratatui-image 11)
- the published `ratchetx2` crate goes to 0.4.0, see [its changelog](ratchetx2/CHANGELOG.md); `XEdDSAPrivateKey::generate()` no longer takes an RNG, `sign` returns a `[u8; SIGNATURE_LENGTH]` and public keys have `to_bytes()`
- key, nonce, tag and signature lengths come from the crypto crates (digest, aead, ed25519, curve25519) instead of literals
- X3DH follows the spec: SK = HKDF(32 zero bytes, 32 × 0xFF ‖ DH1..DH4, `"x3dh.v1"`), AD = IK_A ‖ IK_B, and the ratchet's keys come from SK via `SharedKeys::from_secret`
- server: publishing keys and taking initial messages need a signature by the identity key with an increasing timestamp; initial messages are deleted once taken; one-time prekeys, inboxes, message size and fetch size (in messages and bytes) are limited
- client: "list initial messages" takes them from the server and keeps them until accepted; "refresh keys" is now "renew identity"; errors show their causes
- fix: X3DH and the DH ratchet no longer duplicate private keys with `transmute_copy`
- fix: header encryption reused the AES-GCM nonce under each chain's header key; every encryption now draws a random 256-bit nonce and derives its own AES-GCM key and nonce from it, as the Double Ratchet spec asks for at least 128 random bits
- fix: a message's content was not bound to its encrypted header, so someone with a header key could alter a header and the content still decrypted, e.g. lower the previous chain length so that the receiver dropped the keys of delayed messages; the content now also authenticates the encrypted header, as the spec requires
- fix: xeddsa `agree_ephemeral` is renamed `diffie_hellman` and rejects peer keys outside the prime-order subgroup, which let a peer learn the identity key modulo 8
- fix: X3DH deletes Alice's ephemeral private key and zeroizes the DH outputs as soon as the shared keys are derived, instead of keeping them across network calls
- fix: sessions started with all-zero header and chain keys; chains are now unset until the first DH step, and Bob can only send after receiving Alice's first message
- fix: X3DH checks both identities: Alice uses the identity key she asked for, not one returned by the server, and Bob rejects an initial message from an unexpected identity (`session::Client::accept` takes the expected peer)
- fix: Bob kept every prekey's private key forever; now only the last two generations are kept, so older ones cannot reveal sessions later
- fix: messages Alice sent before Bob accepted were lost; mailboxes are now sequenced queues read from a cursor
- fix: receiving rejects duplicates and out-of-range header counters, keeps one undecryptable message from blocking the rest, and only changes state when a message decrypts
- fix: skipped message keys were kept until used, so the keys of lost messages took up the room for skipped keys for good, and then every message after a gap was rejected; now the keys of the peer's last 5 chains (`MAX_SKIPPED_CHAINS`) are kept, and beyond `SKIP_MAX` keys the oldest are dropped
- fix: invalid keys from the network return errors instead of panicking
- fix: `Debug` no longer prints keys (xeddsa, the ratchet, parties); xeddsa uses the spec's hash1 prefix for signing nonces, and zeroizes signing and DH temporaries
- fix: the client no longer pins the TLS server name to 127.0.0.1
- errors are `Error` + `ErrorKind` like `std::io`: match on `err.kind()` instead of strings; the underlying error is kept as `source()`
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
