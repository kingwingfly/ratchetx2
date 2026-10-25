//! The client's and the sessions' states as protobuf messages, generated from
//! `proto/session.proto` (package `session.v1`), so other languages can read them.
//!
//! Convert with `proto::ClientState::from(client.state())` and `ClientState::try_from(&message)`,
//! and the same for [`SessionState`](crate::SessionState). The messages hold private keys, so
//! keep them secret: they are zeroized on drop, and their `Debug` shows no keys.
use core::fmt;

include!(concat!(env!("OUT_DIR"), "/session.v1.rs"));

impl fmt::Debug for ClientState {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientState")
            .field("prekeys", &self.prekeys)
            .field("last_timestamp", &self.last_timestamp)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SessionState {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionState")
            .field("party", &self.party)
            .field("me", &self.me)
            .field("peer", &self.peer)
            .field("cursor", &self.cursor)
            .finish()
    }
}
