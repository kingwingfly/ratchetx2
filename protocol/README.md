The E2EE chat's wire protocol: the **handshake** service (publish and fetch prekeys, exchange X3DH initial messages) and the **mailbox** service (queues of encrypted messages).

The **attachment** service (`proto/attachment.proto`, module [`attachment`]) carries files too large for a message: their sender encrypts them under a key of their own and uploads them in chunks of at most 2 MiB, once a request signed by its identity key has started the upload, and a message gives the recipients the attachment's ID and key, so the server only sees ciphertext. The recipients can download it while it is uploaded, as a chunk not uploaded yet is told from an attachment that is gone, and the uploader can cancel it.

**Notifications** (`proto/notify.proto`, module [`notify`]) let a client learn at once that something arrived for it, instead of polling: it subscribes with a request signed by its identity key, and the server tells it the sender of each message and each initial message. They carry nothing secret and are only hints, as what arrived is still fetched with the services; how they travel is up to the server, e.g. the Worker's WebSocket.

The messages are defined in `proto/handshake.proto` and `proto/mailbox.proto` (packages `handshake.v1`, `mailbox.v1`), so other languages can implement either side. So is what the clients' messages carry, encrypted, which the server never sees: `proto/content.proto` (package `content.v1`, module [`content`]). Handshake requests that change or read Bob's data are signed with his identity key, see [signed requests](handshake#signed-requests). The handshake messages convert to and from [x3dh](../x3dh)'s types, checking key and signature lengths. An initial message carries the session's first message, X3DH's initial ciphertext, which only its sender can have encrypted: the recipient drops an initial message whose first message does not decrypt. The server cannot tell, so it keeps the first message as it is, up to a size limit.

The services run over plain HTTP with the [Connect protocol](https://connectrpc.com/docs/protocol), which browsers and Cloudflare Workers can speak, and any Connect client can call. The `.proto` files define the services too, so Connect clients in other languages can be generated from them; the paths here are checked against them. Other transports, such as gRPC with stubs generated from the same files, plug in by implementing the client traits and hosting the servers.

For each service there is a client trait ([`Handshake`](handshake::Handshake), [`Mailbox`](mailbox::Mailbox), each with a `Local` variant whose futures need not be `Send`), and with the `server` feature, the server's logic over the [storage](../storage) traits. A server can also be used directly as a client, in-process.

# Features

- **protox** (default): compile the `.proto` files with [protox](https://crates.io/crates/protox); without it, `protoc` must be installed.
- **serde**, **rkyv**: derive their traits on the message types.
- **server**: the servers' logic (`handshake::HandshakeServer`, `mailbox::MailboxServer`).
- **connect**: Connect clients over any HTTP client, and answering calls inside any HTTP server (module `connect`); no I/O of its own, so it builds for `wasm32-unknown-unknown`.
