# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org).

<!--
Note: In this file, do not use the hard wrap in the middle of a sentence for compatibility with GitHub comment style markdown rendering.
-->

## [Unreleased]

## [0.3.0] - 2026-10-19

The wire protocol changed, so 0.3 clients and servers cannot talk to 0.2 ones.

- split ratchetx2 into crates: `ratchetx2` (double ratchet, the only published crate) and the repo-only `xeddsa`, `x3dh` (key agreement without I/O), `party` (header encryption), `storage` (typed records behind the `HandshakeStore`/`MailboxStore` traits, with an in-memory backend), `protocol` (wire protocol, client traits, server logic, Connect) and `session` (the client flow)
- the protocol is defined in `.proto` files (packages `handshake.v1`, `mailbox.v1`, `party.v1`) so other languages can implement it; protox compiles them by default, so `protoc` is not needed
- serde and rkyv are optional features; every library builds for `wasm32-unknown-unknown`, and the client and server traits have `Local` variants whose futures need not be `Send`
- ring -> pure-Rust crypto (curve25519-dalek, ed25519-dalek, RustCrypto)
- bump deps (prost 0.14, curve25519-dalek 5; client: ratatui 0.30, ratatui-image 11)
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
- fix: `Debug` no longer prints keys (xeddsa, the ratchet, parties); xeddsa uses the spec's hash1 prefix for signing nonces, zeroizes signing and DH temporaries, and no longer branches on the secret sign bit when signing
- errors are `Error` + `ErrorKind` like `std::io`: match on `err.kind()` instead of strings; the underlying error is kept as `source()`
- remove the deprecated e2ee_chat_ingress
- remove gRPC (tonic): the services run over Connect, and other transports implement the client traits; with it go e2ee_chat_server, its container image and the self-signed TLS helpers: the Worker serves instead, and the TUI client talks to it over Connect (`<SERVER_ADDR>` is the Worker's address; `--ca` is gone), greeting the peers it starts sessions with
- add `e2ee_chat_worker`, the server as a Cloudflare Worker: the services over Connect, stored in D1 with large message contents in R2, expiring messages after `RETENTION_DAYS`; and `e2ee_chat_web`, a web client in Leptos, whose identity, sessions and history stay in the browser, in IndexedDB sealed by a passphrase (Argon2id, AES-256-GCM)
- attachments (`protocol::attachment`, `attachment.v1`, `session::attachment`), as Signal's: a file too large for a message is encrypted under a key of its own, in chunks of 2 MiB sealed with AES-256-GCM whose nonces hold the index and a last-chunk flag, and uploaded once a signed request has started the upload; a message carries its ID and key. The Worker keeps the chunks in R2 for `RETENTION_DAYS`, up to 50 per attachment; the web client sends files over 1 MiB this way, up to 100 MiB, keeping the chunks in the browser; the message goes as the upload starts, and recipients download the chunks as they come (`GetChunkResponse.uploaded`), while cancelling deletes it (`CancelUpload`); uploads go on after a failure, or after the page goes once the file is chosen again and still has the hash it had as far as it was read (`session::attachment::Upload::resume`); the TUI client shows received files and saves them to `--downloads` with `s`, downloading attachments only then
- `session::safety_number`: Signal's safety number (numeric fingerprint, version 1, 5200 rounds of SHA-512 per side), 60 digits two peers compare out of band; the web client shows it in a chat's info
- notifications (`protocol::notify`, `notify.v1`): a client subscribes with a request signed by its identity key and learns at once of each message and initial message for it; the Worker sends them over WebSockets held by a Durable Object per identity key, hibernating while idle, and the web client fetches what they name at once, polling only every five minutes while they come. The web client's sync button syncs at once, and a chat closes with its close button
- `protocol`'s `connect` feature: the services over the [Connect protocol](https://connectrpc.com/docs/protocol), plain HTTP with protobuf bodies, with a client over any HTTP client and call handling for any HTTP server
- an initial message carries the session's first message (X3DH's initial ciphertext; `first_message` in `handshake.proto`, stored by the servers up to 4 KiB): `Client::initiate` takes its content, and `Client::accept` returns it, failing unless it decrypts, as only the real sender can have encrypted it; so an initial message, which anyone can send claiming to be anyone, is refused, and nothing is signed, which keeps X3DH deniable. `x3dh::LocalPrekeys::accept` no longer changes anything, and `confirm` uses up the one-time prekey once the first message decrypts, and refuses the initial message if sent again (`ErrorKind::Replayed`). The clients greet in the first message, so a peer can write back at once
- `Session::keep`: a new session keeps the earlier ones with its peer behind it, so messages sent on them still decrypt, and sessions started at once by both peers lose no messages; an earlier one takes over if a message on it decrypts while none has on the new one, e.g. as the new one's initial message was lost (`party::Party::has_received`). The clients keep a known contact's old session when a new one starts
- the web client previews files by their content: images (with AVIF, BMP, ICO and SVG, the last as `data:` images, where scripts do not run), video and audio the browser plays, scaled to fit; Markdown, with code highlighted, Mermaid diagrams and maths as MathML, also as reveal.js slides, full screen too; PDFs; code highlighted by tree-sitter in 39 languages; CSV and TSV as tables, JSON pretty-printed, diffs, vCards and iCalendar files as cards, and ZIP and tar archives as lists of files. Peers' Markdown shows no raw HTML and loads no remote images; office documents do not preview. All in Rust: `e2ee_chat_preview` draws PDF pages (hayro), Mermaid diagrams (merman) and highlighted code (arborium) in web workers the page starts when a preview first needs one, the code in four, each with a group of languages
- a client and its sessions can be saved and restored: `Client::state`, `Session::state`, `Client::restore` and `Session::restore`; the states, and the ratchet, party, local prekeys and private keys in them, serialize with the `serde` and `rkyv` features, and with `prost` convert to protobuf messages (`ratchetx2.v1`, `x3dh.v1`, `party.v1`, `session.v1`), which are zeroized on drop

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
