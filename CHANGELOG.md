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
- attachments (`protocol::attachment`, `attachment.v1`, `session::attachment`), as Signal's: a file too large for a message is encrypted under a key of its own, in chunks of 2 MiB sealed with AES-256-GCM whose nonces hold the index and a last-chunk flag, and uploaded once the upload started; a message carries its ID and key. The Worker keeps the chunks in R2 for `RETENTION_DAYS`, up to 50 per attachment; the web client sends files over 1 MiB this way, up to 100 MiB, keeping the chunks in the browser; the message goes as the upload starts, and recipients download the chunks as they come (`GetChunkResponse.uploaded`), while cancelling deletes it (`DeleteAttachment`); uploads go on after a failure, or after the page goes once the file is chosen again and still has the hash it had as far as it was read (`session::attachment::Upload::resume`); the TUI client shows received files and saves them to `--downloads` with `s`, downloading attachments only then
- `session::safety_number`: Signal's safety number (numeric fingerprint, version 1, 5200 rounds of SHA-512 per side), 60 digits two peers compare out of band; the web client shows it in a chat's info
- notifications (`protocol::notify`, `notify.v1`): a client subscribes with a request signed by its identity key and learns at once of each message and initial message for it; the Worker sends them over WebSockets held by a Durable Object per identity key, hibernating while idle and closing sockets that stopped pinging when it next wakes, and the web client fetches what they name at once, polling only every five minutes while they come; away from the page, it closes its socket and syncs every 30 minutes, so that nothing runs on the server meanwhile. The web client's sync button syncs at once, and a chat closes with its close button
- `protocol`'s `connect` feature: the services over the [Connect protocol](https://connectrpc.com/docs/protocol), plain HTTP with protobuf bodies, with a client over any HTTP client and call handling for any HTTP server
- an initial message carries the session's first message (X3DH's initial ciphertext; `first_message` in `handshake.proto`, stored by the servers up to 4 KiB): `Client::initiate` takes its content, and `Client::accept` returns it, failing unless it decrypts, as only the real sender can have encrypted it; so an initial message, which anyone can send claiming to be anyone, is refused, and nothing is signed, which keeps X3DH deniable. `x3dh::LocalPrekeys::accept` no longer changes anything, and `confirm` uses up the one-time prekey once the first message decrypts, and refuses the initial message if sent again (`ErrorKind::Replayed`). The clients greet in the first message, so a peer can write back at once
- `Session::keep`: a new session keeps the last 3 earlier ones with its peer, only to decrypt the messages sent on them, as Signal's session management (Tahini) does: an earlier session never becomes the one sent on again, so whoever stole its keys cannot draw the chat back to it. Of two sessions started at once, both peers pick the one with the higher ID (the X3DH ephemeral key); if the peers still miss each other, the session is retired after 5 turns between sending on it and receiving on an earlier one, and the next message goes on a new one (`Session::needs_new_session`, `ErrorKind::NoSession`), which the clients start with `Client::start_again`. `Session::retire` retires it, e.g. as the peer deleted the chat, which the web client tells it in a message (`content.v1.Deleted`), unless it was a request it never accepted. `Session::receive` stops at a message that does not decrypt, which may be on a session whose initial message came after the last take, with `ErrorKind::Stalled`, and goes on past it once the initial messages are taken (`Session::skip_stalled`), so that no message of a new session is skipped. As Signal's clients do, a session goes with its initial message (`PushRequest.initial_message`) until the peer answers it, so that the peer can accept it from a message (`Received::initial_messages`) if the one in its inbox was lost; where receiving stops, those of the rest of the page are offered too. `Received::earlier` tells a message of an earlier session: a deletion notice on one retires nothing, as the peer started the chat again since. With messages to send and no session, the web client takes the initial messages first, in case the peer started one. A peer's clock goes at most `content::MAX_AHEAD` past the chat's highest, so that it cannot pin the chat's clock at its end. A message carries its Lamport clock (`Content.clock`), inside its encryption, which only its peers see: one more than the highest of the chat's so far, both ways, given as it goes. Both clients show a chat by clock, then by sender, so alike, and a reply after what it answers; a peer's message never goes before its previous one, nor before one it said it read. Events, any number in one message (`content.v1.Events`), tell a sender which of its messages, named by their clocks, were read, and which attachments downloaded, which the clients show as Telegram does: one tick once the server has a message, two once the peer read it, and three once it downloaded its attachment. The session authenticates them as every message, without signatures, so they stay deniable. When the peer deletes the chat, the clients send again, on a new session, what the peer never read. A publish of prekeys whose reply was lost goes again with the same signed prekey and new one-time prekeys (`x3dh::LocalPrekeys::extend`), rather than a new generation, which would delete the private keys of prekeys the server hands out; one refused for want of a sign-in, which the server keeps none of, forgets the one-time prekeys it added (`x3dh::LocalPrekeys::retract`), and the web client publishes again once signed in, rather than every round. The web client keeps files and waiting messages in records apart from the history and the state, reads a file when it shows, and saves only what changed. It shows small media in the chat, read as it scrolls into view: images and GIFs, and videos and audio with their controls, never playing by themselves, attachments up to 8 MiB included; and has a file browser for each chat, by month, on shelves by what the files' contents say they are: media, documents, code, archives and the rest, with previews of media: images, videos' first frames and length, and audio covers. Video and audio attachments play as they are fetched, and seek, through a service worker that asks the page for each range a player wants, which fetches and decrypts only the chunks it needs. The Worker keeps its state in Durable Objects, each with its own SQLite database: one per identity key, with its prekeys, its inbox, the queues of messages to it and its notification sockets, and one per attachment, each deleting what expires with an alarm, rather than in D1 with a daily cron, so that it grows with its users; an alarm that cannot reach R2 tries again an hour later, an alarm is set before what it expires is kept, and only what keeps something creates an object's tables, so that reads, which anyone may make, leave no storage behind. The Worker is only for clients signed in to it with its password, which every call that writes needs, as anyone can make identity keys (`PASSWORD`), which get a cookie signed under `AUTH_KEY` naming who signed in, so that sign-ins with blockchain accounts can come; others get `ErrorKind::SignInRequired`, only from the server's own refusal, not a bare 403 from something in front of it, and the web client asks for the password and sends what waited, in order, a file that waited for its upload to start in its place in the chat, and what waits so can be cancelled from the chat; the Worker refuses sign-ins and sign-outs that browsers say come from another site, and the TUI client signs in from its settings. Objects that the bucket's lifecycle rules delete early are expired, not errors: a message without its content is gone past (`Envelope.message` none), and an attachment notes each chunk put (`StoredAttachment::uploaded`), so a chunk gone since is not found rather than waited for. A message leaves the server once its recipient has it: its push carries SHA-256 of its delivery token (`PushRequest.delivery_hash`), HMAC-SHA256 of its encrypted header under a key from X3DH's shared secret, which only the two peers can compute, and the recipient's next fetch gives the tokens back (`FetchRequest.delivered`, `MailboxStore::delete_delivered`), so that no signature proves who talks to whom. `Session::encrypt` gives a `Sealed` message with its delivery hash, bound to the session it was encrypted on, so that one pushed after another session became active still goes once delivered; a copy received again gives its token too. Attachments stay until they expire, `FILE_RETENTION_DAYS` (90) on the Worker, as recipients may download them again; the server tells when (`StartUploadResponse.expires`, `AttachmentLimits::retention`, `Upload::expires`), and so does the message (`AttachmentPointer.expires`). An attachment has two tokens, neither naming its uploader, and starting an upload is signed by nobody: its upload token, random, which only the uploader gets and the web client forgets once the upload is done, puts its chunks; its delete token, HKDF-SHA256 of its key (`session::attachment::delete_token`), which both peers derive, and whose SHA-256 the upload's start gives (`StartUploadRequest.delete_hash`, `StoredAttachment::delete_hash`), deletes it at any time, uploaded or not (`DeleteAttachment`, `session::attachment::delete`): the web client's file browser deletes sent and received files from the server, and a recipient who deletes one still uploading stops its upload, whose sender is told. Subscriptions, whose time the server checks, are signed with the server's clock (`ServerClock`, which clients learn from the `Date` of its responses, and `Client::with_clock`), so that a device whose clock is off still subscribes. A chunk is put once: putting it again keeps the first copy, so the upload token never changes what was downloaded. The clients keep a known contact's old session when a new one starts
- what the clients' messages carry is defined once, in `content.proto` (`content.v1`, `protocol::content`): text, images, files, greetings, attachments, and that the sender deleted the chat
- the web client previews files by their content: images (with AVIF, BMP, ICO and SVG, the last as `data:` images, where scripts do not run), video and audio the browser plays, scaled to fit; Markdown, with code highlighted, Mermaid diagrams and maths as MathML, also as reveal.js slides, full screen too; PDFs; code highlighted by tree-sitter in 39 languages; CSV and TSV as tables, JSON pretty-printed, diffs, vCards and iCalendar files as cards, and ZIP and tar archives as lists of files. Text previews can be searched with regular expressions, marked with the CSS Custom Highlight API. Peers' Markdown shows no raw HTML and loads no remote images; office documents do not preview. All in Rust: `e2ee_chat_preview` draws PDF pages (hayro), Mermaid diagrams (merman) and highlighted code (arborium) in web workers the page starts when a preview first needs one, the code in four, each with a group of languages
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
