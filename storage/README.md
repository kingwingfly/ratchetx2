Typed storage for the handshake (key server) and mailbox servers.

The traits [`HandshakeStore`], [`MailboxStore`] and [`AttachmentStore`] describe what the servers need as atomic operations on typed records ([`Bundle`], [`StoredInitialMessage`], [`StoredMessage`], [`StoredAttachment`] and its chunks), so each backend can keep them in real tables and columns. This crate does not depend on the wire protocol.

# Features

- **memory** (default): `MemoryStore`, an in-memory backend for tests and development servers.
- **testing**: conformance suites in the `testing` module that every backend should pass.
