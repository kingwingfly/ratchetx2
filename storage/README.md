Typed storage for the v2 post-quantum handshake, unified idempotent mailbox, and attachment servers.

The traits [`PqHandshakeStore`], [`IdempotentMailboxStore`], and [`AttachmentStore`] (along with
their `?Send` `Local*` counterparts) describe what the servers need as atomic operations on typed
records ([`StoredCapabilityManifest`], [`StoredPqPrekey`], [`StoredInitialMessageV2`],
[`StoredMessage`], [`MailboxPage`], [`StoredAttachment`] and its chunks), so each backend can keep
them in real tables and columns. This crate does not depend on the wire protocol or any ML-KEM
cryptography crates.

# Features

- **memory** (default): [`MemoryStore`], an in-memory backend for tests and development servers.
- **serde**: derive `serde::Serialize` and `serde::Deserialize` on storage records for RPC and
  Durable Object serialization.
- **testing**: conformance suites in the `testing` module that every backend should pass.
