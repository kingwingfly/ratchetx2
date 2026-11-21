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
            .field("publishing", &self.publishing)
            .field("pq_disabled", &self.pq_disabled)
            .field("preferred_pq_suite", &self.preferred_pq_suite)
            .field("pq_ratchet_disabled", &self.pq_ratchet_disabled)
            .field("strict_pq", &self.strict_pq)
            .field("manifest_seq", &self.manifest_seq)
            .field("prekey_generation", &self.prekey_generation)
            .field(
                "recent_manifest_digests",
                &self.recent_manifest_digests.len(),
            )
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PeerPqState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerPqState")
            .field("pq_pinned", &self.pq_pinned)
            .field("pinned_manifest_seq", &self.pinned_manifest_seq)
            .field("allow_classical_exception", &self.allow_classical_exception)
            .field("downgrade_detected", &self.downgrade_detected)
            .field("peer_pq_capable", &self.peer_pq_capable)
            .field("peer_session_seq", &self.peer_session_seq)
            .finish()
    }
}

impl fmt::Debug for SessionSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSecurity")
            .field("is_pq", &self.is_pq)
            .field("suite", &self.suite)
            .field("pq_ratchet", &self.pq_ratchet)
            .finish()
    }
}

impl fmt::Debug for SessionState {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionState")
            .field("party", &self.party)
            .field("id", &self.id)
            .field("known_by_peer", &self.known_by_peer)
            .field("initial_message", &self.initial_message.len())
            .field("others", &self.others)
            .field("me", &self.me)
            .field("peer", &self.peer)
            .field("cursor", &self.cursor)
            .field("last", &self.last)
            .field("direction_changes", &self.direction_changes)
            .field("stalled_through", &self.stalled_through)
            .field("skip_through", &self.skip_through)
            .field("delivered", &self.delivered.len())
            .field("peer_pq", &self.peer_pq)
            .field("next_session_seq", &self.next_session_seq)
            .field("active_security", &self.active_security)
            .field("active_peer_session_seq", &self.active_peer_session_seq)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for EarlierSession {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EarlierSession")
            .field("party", &self.party)
            .finish_non_exhaustive()
    }
}
