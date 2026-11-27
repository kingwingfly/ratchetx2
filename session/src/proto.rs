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
            .field("mailbox_cursor", &self.mailbox_cursor)
            .field("pending_mailbox_ack", &self.pending_mailbox_ack)
            .field("next_grant_version", &self.next_grant_version)
            .field(
                "confirmed_manifest_digests",
                &self.confirmed_manifest_digests.len(),
            )
            .field("manifest_digest_spks", &self.manifest_digest_spks.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SignedPrekeyManifestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedPrekeyManifestDigest")
            .field("digest_len", &self.digest.len())
            .field("signed_prekey_len", &self.signed_prekey.len())
            .finish()
    }
}

impl fmt::Debug for PeerPqState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerPqState")
            .field("pq_pinned", &self.pq_pinned)
            .field("pinned_manifest_seq", &self.pinned_manifest_seq)
            .field("pinned_manifest_digest", &self.pinned_manifest_digest.len())
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

impl fmt::Debug for PendingGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingGrant")
            .field("token_hash_len", &self.token_hash.len())
            .field("grant_version", &self.grant_version)
            .field("pin_active", &self.pin_active)
            .finish()
    }
}

impl fmt::Debug for SessionState {
    /// Shows no keys or write tokens.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionState")
            .field("party", &self.party)
            .field("id", &self.id)
            .field("known_by_peer", &self.known_by_peer)
            .field("initial_message", &self.initial_message.len())
            .field("others", &self.others)
            .field("me", &self.me)
            .field("peer", &self.peer)
            .field("last", &self.last)
            .field("direction_changes", &self.direction_changes)
            .field("peer_pq", &self.peer_pq)
            .field("next_session_seq", &self.next_session_seq)
            .field("active_security", &self.active_security)
            .field("active_peer_session_seq", &self.active_peer_session_seq)
            .field("inbound_token_hash_len", &self.inbound_token_hash.len())
            .field(
                "pending_register_grants",
                &self.pending_register_grants.len(),
            )
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for EarlierSession {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EarlierSession")
            .field("party", &self.party)
            .field("inbound_token_hash_len", &self.inbound_token_hash.len())
            .finish_non_exhaustive()
    }
}
