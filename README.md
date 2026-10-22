# About

![screenshot](image/screenshot.png)

- **[E2EE chat server](e2ee_chat_server/README.md)**: Chat server: the handshake and mailbox services over gRPC
- **[E2EE chat client](e2ee_chat_client/README.md)**: TUI chat client, support image

Libraries; only `ratchetx2` is published on crates.io:

- **[ratchetx2](ratchetx2/README.md)**: Double-Ratchet
- **[xeddsa](xeddsa/README.md)**: XEdDSA, signing and Diffie-Hellman with one key
- **[x3dh](x3dh/README.md)**: X3DH key agreement, without I/O
- **[party](party/README.md)**: a chat party: double ratchet with header encryption, and the encrypted message format
- **[storage](storage/README.md)**: what the servers store, as traits over typed records, with an in-memory backend
- **[protocol](protocol/README.md)**: the handshake and mailbox protocol (protobuf), its client traits, the servers' logic, and gRPC
- **[session](session/README.md)**: the client flow: publish keys, start or accept sessions, send and receive

All are pure Rust. Except for gRPC, they build for `wasm32-unknown-unknown`, so a client can run in the browser and the servers' logic in e.g. a Cloudflare Worker, over a storage backend of its own.
