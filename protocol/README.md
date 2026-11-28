The E2EE chat's wire protocol: the v2 post-quantum **handshake** service (`proto/handshake_v2.proto`, module [`handshake_v2`]), the sealed-sender-lite unified **mailbox** service (`proto/mailbox_v2.proto`, module [`mailbox_v2`]), the **attachment** service (`proto/attachment.proto`, module [`attachment`]), encrypted chat **content** (`proto/content.proto`, module [`content`]), and sender-blind **notifications** (`proto/notify.proto`, module [`notify`]).

The **handshake** service publishes identity-signed capability manifests with classical X25519 and post-quantum ML-KEM prekeys, supports non-rotating prekey refills, atomic bundle claims, and two-phase cursor-paginated initial-message delivery (`SendInitialV2`, `ListInitialMessages`, `AckInitialMessages`). It validates suite IDs, exact key/ciphertext lengths, deterministic prekey IDs, and domain-separated XEdDSA signatures with zero ML-KEM cryptography dependencies.

The **mailbox** service keeps one unified monotonic sequence queue per recipient without exposing the sender on `PushV2` or `Notification`. Senders authenticate pushes with a 32-byte deniable write-capability token (hashed to SHA-256 at the protocol boundary), which the recipient registers or revokes per opaque peer slot (`RegisterWriteToken`, `RevokeWriteToken`). Recipients fetch pages with `FetchSigned` (carrying an optional piggybacked monotonic prefix ACK) and acknowledge prefixes explicitly with `AckMessages`. Inline envelopes are capped at 64 KiB, with 1 MiB fetch pages.

The **attachment** service carries files encrypted by their sender under a random key and uploaded in chunks of at most 2 MiB; a message gives the recipients the attachment's ID and key so the server only sees ciphertext. Each attachment uses a random upload token (for uploading chunks) and a key-derived delete token (for deletion by any peer holding the key).

**Notifications** let a client learn immediately that a message or initial message arrived without polling: it subscribes with an audience- and 16-byte-nonce-bound request signed by its identity key under `"notify.v2/subscribe"`, and receives sender-blind hints (`Notification`).

The services run over plain HTTP with the [Connect protocol](https://connectrpc.com/docs/protocol) (module `connect`, enabled by the `connect` feature). For each service there is a client trait ([`HandshakeV2`](handshake_v2::HandshakeV2), [`MailboxV2`](mailbox_v2::MailboxV2), [`Attachments`](attachment::Attachments), each with a `?Send` `Local*` variant), and with the `server` feature, the server logic over the `storage` traits.

# Features

- **protox** (default): compile the `.proto` files with [protox](https://crates.io/crates/protox); without it, `protoc` must be installed.
- **serde**: derive `serde::Serialize` and `serde::Deserialize` on the message types.
- **server**: the servers' logic (`handshake_v2::HandshakeV2Server`, `mailbox_v2::MailboxV2Server`, `attachment::AttachmentServer`).
- **connect**: Connect clients over any HTTP client, and call handling inside any HTTP server (module `connect`); no I/O of its own, so it builds for `wasm32-unknown-unknown`.
