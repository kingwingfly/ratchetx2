The E2EE chat's wire protocol: the **handshake** service (publish and fetch prekeys, exchange X3DH initial messages) and the **mailbox** service (queues of encrypted messages).

The messages are defined in `proto/handshake.proto` and `proto/mailbox.proto` (packages `handshake.v1`, `mailbox.v1`), so other languages can implement either side. Handshake requests that change or read Bob's data are signed with his identity key, see [`signing`]. The handshake messages convert to and from [x3dh](../x3dh)'s types, checking key and signature lengths.

For each service there is a client trait ([`Handshake`](handshake::Handshake), [`Mailbox`](mailbox::Mailbox), each with a `Local` variant whose futures need not be `Send`), and with the `server` feature, the server's logic over the [storage](../storage) traits. A server can also be used directly as a client, in-process.

# Features

- **protox** (default): compile the `.proto` files with [protox](https://crates.io/crates/protox); without it, `protoc` must be installed.
- **serde**, **rkyv**: derive their traits on the message types.
- **server**: the servers' logic (`handshake::HandshakeServer`, `mailbox::MailboxServer`).
- **grpc**: gRPC clients, and with **server**, a gRPC server (module `grpc`).
