//! The v2 post-quantum handshake service: identity-signed [`CapabilityManifest`]s, last-resort
//! PQSPKs, signed one-time PQOPKs, non-rotating prekey refills, atomic bundle claims, and
//! two-phase non-destructive initial-message delivery.
//!
//! This module pulls zero ML-KEM dependencies: it validates suite IDs, exact key/ciphertext
//! lengths, deterministic prekey IDs, and domain-separated XEdDSA signatures using [`x3dh`]'s
//! unconditional PQ helpers.

use std::collections::HashSet;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use x3dh::{
    PQ_PREKEY_ID_LENGTH, PQXDH_VERSION, PqInitialMessage, PqPrekeyBundle, PqSuite, PublicKey,
    PublishedPqPrekey, pq_prekey_id, verify_pq_opk_signature, verify_pq_spk_signature,
};
use xeddsa::{SIGNATURE_LENGTH, XEdDSAPrivateKey, XEdDSAPublicKey};

use crate::{
    SigningBuf, check_canonical_key, check_safe_integer,
    error::{Error, ErrorKind, Result},
    fixed, verify_audience, verify_recent,
};

#[allow(missing_docs)]
pub(crate) mod proto {
    include!(concat!(env!("OUT_DIR"), "/handshake.v2.rs"));
}

pub use crate::{NormalizedAudience, normalize_audience};
pub use proto::*;
#[cfg(feature = "server")]
pub use server::{HandshakeV2Limits, HandshakeV2Server, ServerInfoConfig};

/// Domain separator for canonical [`CapabilityManifest`] signatures and digests.
pub const MANIFEST_DOMAIN: &[u8] = b"ratchetx2.manifest.v2\0";
/// Domain separator for canonical [`PublishV2Request`] signatures.
pub const PUBLISH_V2_DOMAIN: &[u8] = b"ratchetx2.publish.v2\0";
/// Domain separator for canonical [`RefillPrekeysRequest`] signatures.
pub const REFILL_PREKEYS_DOMAIN: &[u8] = b"ratchetx2.refill.v2\0";
/// Domain separator for canonical [`ListInitialMessagesRequest`] signatures.
pub const LIST_INITIAL_DOMAIN: &[u8] = b"ratchetx2.list-initial.v2\0";
/// Domain separator for canonical [`AckInitialMessagesRequest`] signatures.
pub const ACK_INITIAL_DOMAIN: &[u8] = b"ratchetx2.ack-initial.v2\0";

/// Client side of the v2 post-quantum handshake service.
#[trait_variant::make(HandshakeV2: Send)]
pub trait LocalHandshakeV2 {
    /// Discover server PQ capabilities and canonical server audience.
    async fn get_server_info(&self, request: GetServerInfoRequest)
    -> Result<GetServerInfoResponse>;
    /// Publish a signed [`CapabilityManifest`] and classical + PQ prekeys.
    async fn publish_v2(&self, request: PublishV2Request) -> Result<PublishV2Response>;
    /// Append fresh classical OPKs and/or signed PQOPKs to the current generation without
    /// rotating SPK or last-resort PQSPKs.
    async fn refill_prekeys(&self, request: RefillPrekeysRequest) -> Result<RefillPrekeysResponse>;
    /// Non-consuming read of a peer's signed [`CapabilityManifest`].
    async fn get_manifest(&self, request: GetManifestRequest) -> Result<GetManifestResponse>;
    /// Atomically claim a peer's prekey bundle (with classical v1 fallback when peer has no
    /// manifest).
    async fn claim_bundle(&self, request: ClaimBundleRequest) -> Result<ClaimBundleResponse>;
    /// Leave a classical (version 1) or PQXDH (version 2) initial message in a recipient's inbox.
    async fn send_initial_v2(&self, request: SendInitialV2Request)
    -> Result<SendInitialV2Response>;
    /// Non-destructively list pending initial messages (both v1 and v2).
    async fn list_initial_messages(
        &self,
        request: ListInitialMessagesRequest,
    ) -> Result<ListInitialMessagesResponse>;
    /// Explicitly acknowledge and delete pending initial messages by their stable inbox IDs.
    async fn ack_initial_messages(
        &self,
        request: AckInitialMessagesRequest,
    ) -> Result<AckInitialMessagesResponse>;
}

/// Maximum number of offered suites / last-resort commitments accepted in a [`CapabilityManifest`].
const MAX_OFFERED_SUITES: usize = 8;

fn push_pq_prekey_canonical(out: &mut SigningBuf, key: &PqPrekey) -> Result<()> {
    let suite = u8::try_from(key.suite).map_err(|_| ErrorKind::Malformed)?;
    let prekey_id: [u8; PQ_PREKEY_ID_LENGTH] = fixed(&key.prekey_id)?;
    let sig: [u8; SIGNATURE_LENGTH] = fixed(&key.signature)?;
    out.push_u8(suite);
    out.push_bytes(&prekey_id);
    out.push_len_bytes_be(&key.encapsulation_key)?;
    out.push_bytes(&sig);
    Ok(())
}

/// Builds the canonical, protobuf-independent signing input for a [`CapabilityManifest`]:
///
/// `b"ratchetx2.manifest.v2\0" || len_u32be(audience) || audience || identity_key(32) ||`
/// `manifest_seq(u64be) || generation(u64be) || issued_at(u64be) || expires_at(u64be) ||`
/// `pq_enabled(1) || strict_pq(1) || pq_ratchet_supported(1) ||`
/// `count_u32be(offered_suites) || [suite(u32be)]* || signed_prekey(32) ||`
/// `count_u32be(pq_last_resort) || [suite(u32be) || prekey_id(32)]*`.
pub fn manifest_signing_input(manifest: &CapabilityManifest) -> Result<Vec<u8>> {
    if manifest.offered_suites.len() > MAX_OFFERED_SUITES
        || manifest.pq_last_resort.len() > MAX_OFFERED_SUITES
    {
        return Err(ErrorKind::Malformed.into());
    }
    let identity_key: PublicKey = fixed(&manifest.identity_key)?;
    let signed_prekey: PublicKey = fixed(&manifest.signed_prekey)?;
    let extra = 4usize
        .saturating_add(manifest.audience.len())
        .saturating_add(107)
        .saturating_add(manifest.offered_suites.len().saturating_mul(4))
        .saturating_add(
            manifest
                .pq_last_resort
                .len()
                .saturating_mul(4 + PQ_PREKEY_ID_LENGTH),
        );
    let mut out = SigningBuf::with_domain(MANIFEST_DOMAIN, extra);
    out.push_audience_be(&manifest.audience)?;
    out.push_bytes(&identity_key);
    out.push_u64_be(manifest.manifest_seq);
    out.push_u64_be(manifest.generation);
    out.push_u64_be(manifest.issued_at);
    out.push_u64_be(manifest.expires_at);
    out.push_u8(u8::from(manifest.pq_enabled));
    out.push_u8(u8::from(manifest.strict_pq));
    out.push_u8(u8::from(manifest.pq_ratchet_supported));
    out.push_count_be(manifest.offered_suites.len())?;
    for &suite in &manifest.offered_suites {
        out.push_u32_be(suite);
    }
    out.push_bytes(&signed_prekey);
    out.push_count_be(manifest.pq_last_resort.len())?;
    for commitment in &manifest.pq_last_resort {
        let id: [u8; PQ_PREKEY_ID_LENGTH] = fixed(&commitment.prekey_id)?;
        out.push_u32_be(commitment.suite);
        out.push_bytes(&id);
    }
    Ok(out.into_vec())
}

/// Computes the canonical 32-byte SHA-256 digest of `manifest`'s signed fields, suitable for
/// binding into [`x3dh`] PQXDH transcripts (`manifest_digest`).
pub fn manifest_digest(manifest: &CapabilityManifest) -> Result<[u8; 32]> {
    let input = manifest_signing_input(manifest)?;
    Ok(Sha256::digest(&input).into())
}

/// Populates `manifest.identity_key` and `manifest.signature` using `identity`.
pub fn sign_manifest(identity: &XEdDSAPrivateKey, manifest: &mut CapabilityManifest) -> Result<()> {
    let identity_key = identity.compute_public_key().to_bytes();
    manifest.identity_key = Bytes::copy_from_slice(&identity_key);
    let input = manifest_signing_input(manifest)?;
    let signature = identity.sign(input);
    manifest.signature = Bytes::copy_from_slice(&signature);
    Ok(())
}

/// Verifies a [`CapabilityManifest`]'s structure, canonical keys, suite/policy invariants,
/// audience binding (`expected_audience`), and XEdDSA signature.
///
/// Does not check wall-clock expiry; combine with [`check_manifest_window`] (or call
/// [`verify_manifest_at`]) when a trusted clock is available.
pub fn verify_manifest(
    manifest: &CapabilityManifest,
    expected_audience: &str,
) -> Result<PublicKey> {
    verify_audience(&manifest.audience, expected_audience)?;
    check_safe_integer(manifest.manifest_seq)?;
    check_safe_integer(manifest.generation)?;
    check_safe_integer(manifest.issued_at)?;
    check_safe_integer(manifest.expires_at)?;
    if manifest.manifest_seq == 0 || manifest.expires_at <= manifest.issued_at {
        return Err(ErrorKind::Malformed.into());
    }

    let identity_key: PublicKey = fixed(&manifest.identity_key)?;
    let signed_prekey: PublicKey = fixed(&manifest.signed_prekey)?;
    check_canonical_key(&signed_prekey)?;

    if manifest.pq_enabled {
        if manifest.offered_suites.is_empty()
            || manifest.offered_suites.len() > MAX_OFFERED_SUITES
            || manifest.pq_last_resort.len() > MAX_OFFERED_SUITES
        {
            return Err(ErrorKind::Malformed.into());
        }
        let mut offered = HashSet::with_capacity(manifest.offered_suites.len());
        for &suite_u32 in &manifest.offered_suites {
            let suite_u8 = u8::try_from(suite_u32).map_err(|_| ErrorKind::Malformed)?;
            if PqSuite::from_u8(suite_u8).is_none() || !offered.insert(suite_u8) {
                return Err(ErrorKind::Malformed.into());
            }
        }
        if manifest.pq_last_resort.len() != offered.len() {
            return Err(ErrorKind::Malformed.into());
        }
        let mut committed = HashSet::with_capacity(manifest.pq_last_resort.len());
        for c in &manifest.pq_last_resort {
            let suite_u8 = u8::try_from(c.suite).map_err(|_| ErrorKind::Malformed)?;
            if !offered.contains(&suite_u8) || !committed.insert(suite_u8) {
                return Err(ErrorKind::Malformed.into());
            }
            let _: [u8; PQ_PREKEY_ID_LENGTH] = fixed(&c.prekey_id)?;
        }
    } else if manifest.strict_pq
        || manifest.pq_ratchet_supported
        || !manifest.offered_suites.is_empty()
        || !manifest.pq_last_resort.is_empty()
    {
        return Err(ErrorKind::Malformed.into());
    }

    let sig: [u8; SIGNATURE_LENGTH] = fixed(&manifest.signature)?;
    let input = manifest_signing_input(manifest)?;
    XEdDSAPublicKey::new(&identity_key)?.verify(input, &sig)?;
    Ok(identity_key)
}

/// Checks that a [`CapabilityManifest`]'s validity window is consistent with `now` (in
/// milliseconds since the Unix epoch): `issued_at <= now + MAX_CLOCK_SKEW` and `expires_at > now`.
///
/// Use this after [`verify_manifest`] when signature verification has already succeeded to avoid
/// verifying the manifest's XEdDSA signature twice.
pub fn check_manifest_window(manifest: &CapabilityManifest, now: u64) -> Result<()> {
    if manifest.issued_at > now.saturating_add(crate::MAX_CLOCK_SKEW) || manifest.expires_at <= now
    {
        return Err(ErrorKind::StaleTimestamp.into());
    }
    Ok(())
}

/// Verifies a [`CapabilityManifest`] (as in [`verify_manifest`]) and checks that its validity
/// window is consistent with `now` (in milliseconds since the Unix epoch):
/// `issued_at <= now + MAX_CLOCK_SKEW` and `expires_at > now`.
pub fn verify_manifest_at(
    manifest: &CapabilityManifest,
    expected_audience: &str,
    now: u64,
) -> Result<PublicKey> {
    let identity_key = verify_manifest(manifest, expected_audience)?;
    check_manifest_window(manifest, now)?;
    Ok(identity_key)
}

/// Builds the canonical signing input for a [`PublishV2Request`].
pub fn publish_v2_signing_input(request: &PublishV2Request) -> Result<Vec<u8>> {
    let manifest = request.manifest.as_ref().ok_or(ErrorKind::Malformed)?;
    let digest = manifest_digest(manifest)?;
    let mut out = SigningBuf::with_domain(PUBLISH_V2_DOMAIN, 128);
    out.push_bytes(&digest);
    match &request.signed_prekey_signature {
        Some(sig) => {
            let sig: [u8; SIGNATURE_LENGTH] = fixed(sig)?;
            out.push_u8(1);
            out.push_bytes(&sig);
        }
        None => out.push_u8(0),
    }
    out.push_count_be(request.one_time_prekeys.len())?;
    for opk in &request.one_time_prekeys {
        let key: PublicKey = fixed(opk)?;
        out.push_bytes(&key);
    }
    out.push_count_be(request.pq_last_resort.len())?;
    for key in &request.pq_last_resort {
        push_pq_prekey_canonical(&mut out, key)?;
    }
    out.push_count_be(request.pq_one_time_prekeys.len())?;
    for key in &request.pq_one_time_prekeys {
        push_pq_prekey_canonical(&mut out, key)?;
    }
    out.push_u64_be(request.timestamp);
    Ok(out.into_vec())
}

/// Builds the canonical signing input for a [`RefillPrekeysRequest`].
pub fn refill_prekeys_signing_input(request: &RefillPrekeysRequest) -> Result<Vec<u8>> {
    let identity_key: PublicKey = fixed(&request.identity_key)?;
    let mut out = SigningBuf::with_domain(REFILL_PREKEYS_DOMAIN, 128);
    out.push_audience_be(&request.audience)?;
    out.push_bytes(&identity_key);
    out.push_u64_be(request.generation);
    out.push_count_be(request.one_time_prekeys.len())?;
    for opk in &request.one_time_prekeys {
        let key: PublicKey = fixed(opk)?;
        out.push_bytes(&key);
    }
    out.push_count_be(request.pq_one_time_prekeys.len())?;
    for key in &request.pq_one_time_prekeys {
        push_pq_prekey_canonical(&mut out, key)?;
    }
    out.push_u64_be(request.timestamp);
    Ok(out.into_vec())
}

/// Builds the canonical signing input for a [`ListInitialMessagesRequest`].
pub fn list_initial_messages_signing_input(
    request: &ListInitialMessagesRequest,
) -> Result<Vec<u8>> {
    let identity_key: PublicKey = fixed(&request.identity_key)?;
    let mut out = SigningBuf::with_domain(
        LIST_INITIAL_DOMAIN,
        48usize.saturating_add(request.audience.len()),
    );
    out.push_audience_be(&request.audience)?;
    out.push_bytes(&identity_key);
    out.push_u32_be(request.limit);
    out.push_u64_be(request.timestamp);
    Ok(out.into_vec())
}

/// Builds the canonical signing input for an [`AckInitialMessagesRequest`].
pub fn ack_initial_messages_signing_input(request: &AckInitialMessagesRequest) -> Result<Vec<u8>> {
    let identity_key: PublicKey = fixed(&request.identity_key)?;
    let extra = 48usize
        .saturating_add(request.audience.len())
        .saturating_add(request.ids.len().saturating_mul(8));
    let mut out = SigningBuf::with_domain(ACK_INITIAL_DOMAIN, extra);
    out.push_audience_be(&request.audience)?;
    out.push_bytes(&identity_key);
    out.push_count_be(request.ids.len())?;
    for &id in &request.ids {
        out.push_u64_be(id);
    }
    out.push_u64_be(request.timestamp);
    Ok(out.into_vec())
}

impl PublishV2Request {
    /// Constructs and signs a [`PublishV2Request`] with `identity`.
    ///
    /// Expects `manifest` to already be signed by `identity` (e.g. via [`sign_manifest`]).
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        identity: &XEdDSAPrivateKey,
        manifest: CapabilityManifest,
        signed_prekey_signature: Option<[u8; SIGNATURE_LENGTH]>,
        one_time_prekeys: &[PublicKey],
        pq_last_resort: Vec<PqPrekey>,
        pq_one_time_prekeys: Vec<PqPrekey>,
        timestamp: u64,
    ) -> Result<Self> {
        check_safe_integer(timestamp)?;
        let mut request = Self {
            manifest: Some(manifest),
            signed_prekey_signature: signed_prekey_signature
                .map(|sig| Bytes::copy_from_slice(&sig)),
            one_time_prekeys: one_time_prekeys
                .iter()
                .map(|k| Bytes::copy_from_slice(k))
                .collect(),
            pq_last_resort,
            pq_one_time_prekeys,
            timestamp,
            signature: Bytes::new(),
        };
        let input = publish_v2_signing_input(&request)?;
        request.signature = Bytes::copy_from_slice(&identity.sign(input));
        Ok(request)
    }

    /// Verifies the embedded [`CapabilityManifest`] (including `expected_audience`) and the
    /// outer [`PublishV2Request`] signature.
    pub fn verify(&self, expected_audience: &str) -> Result<PublicKey> {
        check_safe_integer(self.timestamp)?;
        let manifest = self.manifest.as_ref().ok_or(ErrorKind::Malformed)?;
        let identity_key = verify_manifest(manifest, expected_audience)?;
        let sig: [u8; SIGNATURE_LENGTH] = fixed(&self.signature)?;
        let input = publish_v2_signing_input(self)?;
        XEdDSAPublicKey::new(&identity_key)?.verify(input, &sig)?;
        Ok(identity_key)
    }
}

impl RefillPrekeysRequest {
    /// Constructs and signs a [`RefillPrekeysRequest`] with `identity`.
    pub fn sign(
        identity: &XEdDSAPrivateKey,
        audience: impl Into<String>,
        generation: u64,
        one_time_prekeys: &[PublicKey],
        pq_one_time_prekeys: Vec<PqPrekey>,
        timestamp: u64,
    ) -> Result<Self> {
        check_safe_integer(generation)?;
        check_safe_integer(timestamp)?;
        let identity_key = identity.compute_public_key().to_bytes();
        let mut request = Self {
            audience: audience.into(),
            identity_key: Bytes::copy_from_slice(&identity_key),
            generation,
            one_time_prekeys: one_time_prekeys
                .iter()
                .map(|k| Bytes::copy_from_slice(k))
                .collect(),
            pq_one_time_prekeys,
            timestamp,
            signature: Bytes::new(),
        };
        let input = refill_prekeys_signing_input(&request)?;
        request.signature = Bytes::copy_from_slice(&identity.sign(input));
        Ok(request)
    }

    /// Verifies the audience binding, signature, and timestamp freshness against `now`.
    pub fn verify(&self, expected_audience: &str, now: u64) -> Result<PublicKey> {
        verify_audience(&self.audience, expected_audience)?;
        check_safe_integer(self.generation)?;
        verify_recent(
            &self.identity_key,
            &self.signature,
            self.timestamp,
            now,
            |_| refill_prekeys_signing_input(self),
        )
    }
}

impl ListInitialMessagesRequest {
    /// Constructs and signs a [`ListInitialMessagesRequest`] with `identity`.
    pub fn sign(
        identity: &XEdDSAPrivateKey,
        audience: impl Into<String>,
        limit: u32,
        timestamp: u64,
    ) -> Result<Self> {
        check_safe_integer(timestamp)?;
        let identity_key = identity.compute_public_key().to_bytes();
        let mut request = Self {
            audience: audience.into(),
            identity_key: Bytes::copy_from_slice(&identity_key),
            limit,
            timestamp,
            signature: Bytes::new(),
        };
        let input = list_initial_messages_signing_input(&request)?;
        request.signature = Bytes::copy_from_slice(&identity.sign(input));
        Ok(request)
    }

    /// Verifies the audience binding, signature, and timestamp freshness against `now`.
    pub fn verify(&self, expected_audience: &str, now: u64) -> Result<PublicKey> {
        verify_audience(&self.audience, expected_audience)?;
        verify_recent(
            &self.identity_key,
            &self.signature,
            self.timestamp,
            now,
            |_| list_initial_messages_signing_input(self),
        )
    }
}

impl AckInitialMessagesRequest {
    /// Constructs and signs an [`AckInitialMessagesRequest`] with `identity`.
    pub fn sign(
        identity: &XEdDSAPrivateKey,
        audience: impl Into<String>,
        ids: Vec<u64>,
        timestamp: u64,
    ) -> Result<Self> {
        check_safe_integer(timestamp)?;
        for &id in &ids {
            check_safe_integer(id)?;
        }
        let identity_key = identity.compute_public_key().to_bytes();
        let mut request = Self {
            audience: audience.into(),
            identity_key: Bytes::copy_from_slice(&identity_key),
            ids,
            timestamp,
            signature: Bytes::new(),
        };
        let input = ack_initial_messages_signing_input(&request)?;
        request.signature = Bytes::copy_from_slice(&identity.sign(input));
        Ok(request)
    }

    /// Verifies the audience binding, signature, and timestamp freshness against `now`.
    pub fn verify(&self, expected_audience: &str, now: u64) -> Result<PublicKey> {
        verify_audience(&self.audience, expected_audience)?;
        for &id in &self.ids {
            check_safe_integer(id)?;
        }
        verify_recent(
            &self.identity_key,
            &self.signature,
            self.timestamp,
            now,
            |_| ack_initial_messages_signing_input(self),
        )
    }
}

/// Validates a wire [`PqPrekey`] against `identity_key` using [`x3dh`]'s domain-separated
/// signature verification (last-resort PQSPK vs one-time PQOPK).
pub fn verify_wire_pq_prekey(
    identity_key: &PublicKey,
    prekey: &PqPrekey,
    last_resort: bool,
) -> Result<(PqSuite, [u8; PQ_PREKEY_ID_LENGTH], [u8; SIGNATURE_LENGTH])> {
    let suite_u8 = u8::try_from(prekey.suite).map_err(|_| ErrorKind::Malformed)?;
    let suite = PqSuite::from_u8(suite_u8).ok_or(ErrorKind::Malformed)?;
    if prekey.encapsulation_key.len() != suite.ek_len() {
        return Err(ErrorKind::Malformed.into());
    }
    let id: [u8; PQ_PREKEY_ID_LENGTH] = fixed(&prekey.prekey_id)?;
    let expected_id = pq_prekey_id(suite_u8, &prekey.encapsulation_key);
    if id != expected_id {
        return Err(ErrorKind::Malformed.into());
    }
    let sig: [u8; SIGNATURE_LENGTH] = fixed(&prekey.signature)?;
    if last_resort {
        verify_pq_spk_signature(identity_key, suite_u8, &prekey.encapsulation_key, &sig)?;
    } else {
        verify_pq_opk_signature(identity_key, suite_u8, &prekey.encapsulation_key, &sig)?;
    }
    Ok((suite, id, sig))
}

impl From<&PublishedPqPrekey> for PqPrekey {
    fn from(key: &PublishedPqPrekey) -> Self {
        Self {
            suite: u32::from(key.suite.as_u8()),
            prekey_id: Bytes::copy_from_slice(&key.id),
            encapsulation_key: Bytes::copy_from_slice(&key.encapsulation_key),
            signature: Bytes::copy_from_slice(&key.signature),
        }
    }
}

impl TryFrom<&PqPrekey> for PublishedPqPrekey {
    type Error = Error;

    fn try_from(key: &PqPrekey) -> Result<Self> {
        let suite_u8 = u8::try_from(key.suite).map_err(|_| ErrorKind::Malformed)?;
        let suite = PqSuite::from_u8(suite_u8).ok_or(ErrorKind::Malformed)?;
        if key.encapsulation_key.len() != suite.ek_len() {
            return Err(ErrorKind::Malformed.into());
        }
        let id = fixed(&key.prekey_id)?;
        if pq_prekey_id(suite_u8, &key.encapsulation_key) != id {
            return Err(ErrorKind::Malformed.into());
        }
        Ok(Self {
            suite,
            id,
            encapsulation_key: key.encapsulation_key.to_vec(),
            signature: fixed(&key.signature)?,
        })
    }
}

impl TryFrom<&ClaimBundleResponse> for PqPrekeyBundle {
    type Error = Error;

    /// Converts a PQ-enabled [`ClaimBundleResponse`] into an [`x3dh::PqPrekeyBundle`], choosing
    /// `pq_one_time_prekey` when present and falling back to `pq_last_resort` otherwise.
    fn try_from(response: &ClaimBundleResponse) -> Result<Self> {
        let (pq_key, pq_last_resort) =
            match (&response.pq_one_time_prekey, &response.pq_last_resort) {
                (Some(opk), _) => (opk, false),
                (None, Some(lr)) => (lr, true),
                (None, None) => return Err(ErrorKind::Malformed.into()),
            };
        let parsed = PublishedPqPrekey::try_from(pq_key)?;
        Ok(Self {
            signed_prekey: fixed(&response.signed_prekey)?,
            signed_prekey_signature: response
                .signed_prekey_signature
                .as_deref()
                .map(fixed)
                .transpose()?,
            one_time_prekey: response.one_time_prekey.as_deref().map(fixed).transpose()?,
            pq_suite: parsed.suite,
            pq_prekey: parsed.encapsulation_key,
            pq_prekey_signature: parsed.signature,
            pq_last_resort,
        })
    }
}

impl From<&PqInitialMessage> for InitialMessageV2 {
    /// Without `first_message` or `manifest_digest`, for the caller to populate.
    fn from(message: &PqInitialMessage) -> Self {
        Self {
            id: 0,
            version: message.version,
            identity_key: Bytes::copy_from_slice(&message.identity_key),
            ephemeral_key: Bytes::copy_from_slice(&message.ephemeral_key),
            signed_prekey: Bytes::copy_from_slice(&message.signed_prekey),
            one_time_prekey: message
                .one_time_prekey
                .map(|key| Bytes::copy_from_slice(&key)),
            first_message: None,
            pq_suite: u32::from(message.pq_suite.as_u8()),
            pq_last_resort: message.pq_last_resort,
            pq_prekey_id: Bytes::copy_from_slice(&message.pq_prekey_id),
            pq_ciphertext: Bytes::copy_from_slice(&message.pq_ciphertext),
            manifest_digest: Bytes::new(),
        }
    }
}

impl TryFrom<&InitialMessageV2> for PqInitialMessage {
    type Error = Error;

    fn try_from(message: &InitialMessageV2) -> Result<Self> {
        if message.version != PQXDH_VERSION {
            return Err(ErrorKind::Malformed.into());
        }
        let suite_u8 = u8::try_from(message.pq_suite).map_err(|_| ErrorKind::Malformed)?;
        let pq_suite = PqSuite::from_u8(suite_u8).ok_or(ErrorKind::Malformed)?;
        if message.pq_ciphertext.len() != pq_suite.ct_len() {
            return Err(ErrorKind::Malformed.into());
        }
        Ok(Self {
            version: message.version,
            identity_key: fixed(&message.identity_key)?,
            ephemeral_key: fixed(&message.ephemeral_key)?,
            signed_prekey: fixed(&message.signed_prekey)?,
            one_time_prekey: message.one_time_prekey.as_deref().map(fixed).transpose()?,
            pq_suite,
            pq_last_resort: message.pq_last_resort,
            pq_prekey_id: fixed(&message.pq_prekey_id)?,
            pq_ciphertext: message.pq_ciphertext.to_vec(),
        })
    }
}

impl From<&x3dh::InitialMessage> for InitialMessageV2 {
    /// Classical v1 initial message without `first_message`, for the caller to populate.
    fn from(message: &x3dh::InitialMessage) -> Self {
        Self {
            id: 0,
            version: 1,
            identity_key: Bytes::copy_from_slice(&message.identity_key),
            ephemeral_key: Bytes::copy_from_slice(&message.ephemeral_key),
            signed_prekey: Bytes::copy_from_slice(&message.signed_prekey),
            one_time_prekey: message
                .one_time_prekey
                .map(|key| Bytes::copy_from_slice(&key)),
            first_message: None,
            pq_suite: 0,
            pq_last_resort: false,
            pq_prekey_id: Bytes::new(),
            pq_ciphertext: Bytes::new(),
            manifest_digest: Bytes::new(),
        }
    }
}

impl TryFrom<&InitialMessageV2> for x3dh::InitialMessage {
    type Error = Error;

    fn try_from(message: &InitialMessageV2) -> Result<Self> {
        if message.version != 1 || !message.manifest_digest.is_empty() {
            return Err(ErrorKind::Malformed.into());
        }
        Ok(Self {
            identity_key: fixed(&message.identity_key)?,
            ephemeral_key: fixed(&message.ephemeral_key)?,
            signed_prekey: fixed(&message.signed_prekey)?,
            one_time_prekey: message.one_time_prekey.as_deref().map(fixed).transpose()?,
        })
    }
}

impl From<&crate::handshake::InitialMessage> for InitialMessageV2 {
    fn from(message: &crate::handshake::InitialMessage) -> Self {
        Self {
            id: 0,
            version: 1,
            identity_key: message.identity_key.clone(),
            ephemeral_key: message.ephemeral_key.clone(),
            signed_prekey: message.signed_prekey.clone(),
            one_time_prekey: message.one_time_prekey.clone(),
            first_message: message.first_message.clone(),
            pq_suite: 0,
            pq_last_resort: false,
            pq_prekey_id: Bytes::new(),
            pq_ciphertext: Bytes::new(),
            manifest_digest: Bytes::new(),
        }
    }
}

impl TryFrom<&InitialMessageV2> for crate::handshake::InitialMessage {
    type Error = Error;

    fn try_from(message: &InitialMessageV2) -> Result<Self> {
        if message.version != 1 || !message.manifest_digest.is_empty() {
            return Err(ErrorKind::Malformed.into());
        }
        Ok(Self {
            identity_key: message.identity_key.clone(),
            ephemeral_key: message.ephemeral_key.clone(),
            signed_prekey: message.signed_prekey.clone(),
            one_time_prekey: message.one_time_prekey.clone(),
            first_message: message.first_message.clone(),
        })
    }
}

/// Validated fields extracted from an [`InitialMessageV2`].
#[cfg(feature = "server")]
pub(crate) struct ValidatedInitialMessageV2 {
    pub sender: PublicKey,
    pub ephemeral_key: PublicKey,
    pub signed_prekey: PublicKey,
    pub one_time_prekey: Option<PublicKey>,
    pub pq_suite: Option<u8>,
    pub pq_prekey_id: Option<[u8; PQ_PREKEY_ID_LENGTH]>,
    pub pq_ciphertext: Option<Bytes>,
    pub manifest_digest: Option<[u8; 32]>,
}

/// Validates structural, key, and PQ ciphertext invariants of an [`InitialMessageV2`].
///
/// When `allow_pq_drain` is `true`, any known [`PqSuite`] (validated via [`PqSuite::from_u8`] and
/// exact ciphertext length) is accepted for `version == 2` even if `supported_suites` is empty,
/// allowing in-flight unacknowledged PQ sessions to drain during a `PQ_ENABLED="false"` rollback.
#[cfg(feature = "server")]
pub(crate) fn validate_initial_message_v2(
    message: &InitialMessageV2,
    supported_suites: &[u32],
    allow_pq_drain: bool,
) -> Result<ValidatedInitialMessageV2> {
    let sender: PublicKey = fixed(&message.identity_key)?;
    let ephemeral_key: PublicKey = fixed(&message.ephemeral_key)?;
    let signed_prekey: PublicKey = fixed(&message.signed_prekey)?;
    let one_time_prekey: Option<PublicKey> =
        message.one_time_prekey.as_deref().map(fixed).transpose()?;
    check_canonical_key(&sender)?;
    check_canonical_key(&ephemeral_key)?;
    check_canonical_key(&signed_prekey)?;
    if let Some(opk) = &one_time_prekey {
        check_canonical_key(opk)?;
    }
    match message.version {
        1 => {
            if !message.manifest_digest.is_empty()
                || message.pq_suite != 0
                || message.pq_last_resort
                || !message.pq_prekey_id.is_empty()
                || !message.pq_ciphertext.is_empty()
            {
                return Err(ErrorKind::Malformed.into());
            }
            Ok(ValidatedInitialMessageV2 {
                sender,
                ephemeral_key,
                signed_prekey,
                one_time_prekey,
                pq_suite: None,
                pq_prekey_id: None,
                pq_ciphertext: None,
                manifest_digest: None,
            })
        }
        PQXDH_VERSION => {
            let suite_u8 = u8::try_from(message.pq_suite).map_err(|_| ErrorKind::Malformed)?;
            let suite = PqSuite::from_u8(suite_u8).ok_or(ErrorKind::Malformed)?;
            if !allow_pq_drain && !supported_suites.contains(&message.pq_suite) {
                return Err(ErrorKind::Malformed.into());
            }
            let prekey_id: [u8; PQ_PREKEY_ID_LENGTH] = fixed(&message.pq_prekey_id)?;
            if message.pq_ciphertext.len() != suite.ct_len() {
                return Err(ErrorKind::Malformed.into());
            }
            Ok(ValidatedInitialMessageV2 {
                sender,
                ephemeral_key,
                signed_prekey,
                one_time_prekey,
                pq_suite: Some(suite_u8),
                pq_prekey_id: Some(prekey_id),
                pq_ciphertext: Some(message.pq_ciphertext.clone()),
                manifest_digest: (!message.manifest_digest.is_empty())
                    .then(|| fixed(&message.manifest_digest))
                    .transpose()?,
            })
        }
        _ => Err(ErrorKind::Malformed.into()),
    }
}

#[cfg(feature = "server")]
mod server {
    use std::collections::{HashMap, HashSet};

    use bon::Builder;
    use party::EncryptedMessage;
    use storage::{
        ClaimOutcome, LocalPqHandshakeStore, PqLastResortCommitment as StorageCommitment,
        PublishV2Record, PublishV2Status, RefillPrekeysRecord, RefillStatus,
        StoredCapabilityManifest, StoredInitialMessageV2, StoredPqPrekey,
    };

    use super::*;
    use crate::{
        check_canonical_key, check_monotonic_timestamp, mailbox::MAX_HEADER_SIZE, now_millis,
    };

    /// Runtime server capability configuration advertised via `GetServerInfo` and enforced by
    /// [`HandshakeV2Server`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ServerInfoConfig {
        /// Whether PQ routes and storage are enabled.
        pub pq_enabled: bool,
        /// Supported ML-KEM suite IDs (`1` = ML-KEM-1024, `2` = ML-KEM-768).
        pub supported_suites: Vec<u32>,
        /// Whether the server accepts PQ ratchet headers (up to 8 KiB).
        pub pq_ratchet_supported: bool,
        /// Canonical server audience identifier bound into signed manifests and requests.
        pub server_id: String,
        /// Deprecated compatibility flag kept at `false` in [`GetServerInfoResponse`] for wire
        /// stability: whether legacy v1 handshake/mailbox routes remain enabled.
        pub legacy_v1_enabled: bool,
        /// Deprecated compatibility flag kept at `false` in [`GetServerInfoResponse`] for wire
        /// stability: whether unsigned legacy v1 mailbox fetches remain allowed.
        pub allow_unsigned_fetch: bool,
    }

    impl ServerInfoConfig {
        /// Default PQ-enabled configuration for `server_id` supporting both ML-KEM-1024 and
        /// ML-KEM-768, with legacy v1 compatibility flags disabled (`false`).
        pub fn new(server_id: impl Into<String>) -> Self {
            Self {
                pq_enabled: true,
                supported_suites: vec![
                    u32::from(PqSuite::MlKem1024.as_u8()),
                    u32::from(PqSuite::MlKem768.as_u8()),
                ],
                pq_ratchet_supported: true,
                server_id: server_id.into(),
                legacy_v1_enabled: false,
                allow_unsigned_fetch: false,
            }
        }
    }

    /// Limits of a [`HandshakeV2Server`].
    #[derive(Debug, Clone, Copy)]
    pub struct HandshakeV2Limits {
        /// Most classical one-time prekeys stored or uploaded in one publish/refill.
        pub max_one_time_prekeys: usize,
        /// Most post-quantum one-time prekeys stored or uploaded in one publish/refill.
        pub max_pq_one_time_prekeys: usize,
        /// Most initial messages waiting in one inbox.
        pub max_initial_messages: usize,
        /// Most bytes in the first message (header + content) of an initial message (default 8 KiB).
        pub max_first_message_size: usize,
        /// Most inbox message IDs in one `AckInitialMessages` call.
        pub max_ack_ids: usize,
        /// Most inbox messages returned in one `ListInitialMessages` call.
        pub max_list_limit: usize,
    }

    impl Default for HandshakeV2Limits {
        fn default() -> Self {
            Self {
                max_one_time_prekeys: 100,
                max_pq_one_time_prekeys: 100,
                max_initial_messages: 100,
                max_first_message_size: 8 << 10,
                max_ack_ids: 100,
                max_list_limit: 100,
            }
        }
    }

    /// The v2 post-quantum handshake server logic over any [`LocalPqHandshakeStore`].
    #[derive(Debug, Builder)]
    pub struct HandshakeV2Server<S> {
        #[builder(start_fn)]
        store: S,
        /// Server capabilities and audience identifier.
        info: ServerInfoConfig,
        /// Per-request and per-identity limits.
        #[builder(default)]
        limits: HandshakeV2Limits,
    }

    impl<S> HandshakeV2Server<S> {
        /// A v2 handshake server over `store` with `info` and default limits.
        pub fn new(store: S, info: ServerInfoConfig) -> Self {
            Self::builder(store).info(info).build()
        }
    }

    fn manifest_to_storage(manifest: &CapabilityManifest) -> Result<StoredCapabilityManifest> {
        let mut offered_suites = Vec::with_capacity(manifest.offered_suites.len());
        for &suite in &manifest.offered_suites {
            offered_suites.push(u8::try_from(suite).map_err(|_| ErrorKind::Malformed)?);
        }
        let mut pq_last_resort = Vec::with_capacity(manifest.pq_last_resort.len());
        for c in &manifest.pq_last_resort {
            pq_last_resort.push(StorageCommitment {
                suite: u8::try_from(c.suite).map_err(|_| ErrorKind::Malformed)?,
                prekey_id: fixed(&c.prekey_id)?,
            });
        }
        Ok(StoredCapabilityManifest {
            audience: manifest.audience.clone(),
            identity_key: fixed(&manifest.identity_key)?,
            manifest_seq: manifest.manifest_seq,
            generation: manifest.generation,
            issued_at: manifest.issued_at,
            expires_at: manifest.expires_at,
            pq_enabled: manifest.pq_enabled,
            strict_pq: manifest.strict_pq,
            pq_ratchet_supported: manifest.pq_ratchet_supported,
            offered_suites,
            signed_prekey: fixed(&manifest.signed_prekey)?,
            pq_last_resort,
            signature: fixed(&manifest.signature)?,
        })
    }

    fn manifest_from_storage(manifest: StoredCapabilityManifest) -> CapabilityManifest {
        CapabilityManifest {
            audience: manifest.audience,
            identity_key: Bytes::copy_from_slice(&manifest.identity_key),
            manifest_seq: manifest.manifest_seq,
            generation: manifest.generation,
            issued_at: manifest.issued_at,
            expires_at: manifest.expires_at,
            pq_enabled: manifest.pq_enabled,
            strict_pq: manifest.strict_pq,
            pq_ratchet_supported: manifest.pq_ratchet_supported,
            offered_suites: manifest.offered_suites.into_iter().map(u32::from).collect(),
            signed_prekey: Bytes::copy_from_slice(&manifest.signed_prekey),
            pq_last_resort: manifest
                .pq_last_resort
                .into_iter()
                .map(|c| PqLastResortCommitment {
                    suite: u32::from(c.suite),
                    prekey_id: Bytes::copy_from_slice(&c.prekey_id),
                })
                .collect(),
            signature: Bytes::copy_from_slice(&manifest.signature),
        }
    }

    fn pq_prekey_from_storage(key: StoredPqPrekey) -> PqPrekey {
        PqPrekey {
            suite: u32::from(key.suite),
            prekey_id: Bytes::copy_from_slice(&key.id),
            encapsulation_key: key.encapsulation_key,
            signature: Bytes::copy_from_slice(&key.signature),
        }
    }

    impl<S: LocalPqHandshakeStore> LocalHandshakeV2 for HandshakeV2Server<S> {
        async fn get_server_info(
            &self,
            _request: GetServerInfoRequest,
        ) -> Result<GetServerInfoResponse> {
            Ok(GetServerInfoResponse {
                pq_enabled: self.info.pq_enabled,
                supported_suites: if self.info.pq_enabled {
                    self.info.supported_suites.clone()
                } else {
                    vec![]
                },
                pq_ratchet_supported: self.info.pq_enabled && self.info.pq_ratchet_supported,
                server_id: self.info.server_id.clone(),
                legacy_v1_enabled: self.info.legacy_v1_enabled,
                allow_unsigned_fetch: self.info.allow_unsigned_fetch,
            })
        }

        async fn publish_v2(&self, request: PublishV2Request) -> Result<PublishV2Response> {
            let manifest = request.manifest.as_ref().ok_or(ErrorKind::Malformed)?;
            if !self.info.pq_enabled && manifest.pq_enabled {
                return Err(ErrorKind::Unimplemented.into());
            }
            if request.one_time_prekeys.len() > self.limits.max_one_time_prekeys
                || request.pq_one_time_prekeys.len() > self.limits.max_pq_one_time_prekeys
            {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let now = now_millis();
            check_monotonic_timestamp(request.timestamp, now)?;
            if request.timestamp.abs_diff(now) > crate::MAX_CLOCK_SKEW {
                return Err(ErrorKind::StaleTimestamp.into());
            }

            let identity_key = request.verify(&self.info.server_id)?;
            check_manifest_window(manifest, now)?;
            let signed_prekey: PublicKey = fixed(&manifest.signed_prekey)?;

            // Legacy raw v1 SPK signature: forbidden in strict_pq mode; REQUIRED when pq_enabled
            // is false (otherwise a classical peer cannot verify the SPK and the user becomes
            // unreachable); verified whenever supplied.
            let signed_prekey_signature = match &request.signed_prekey_signature {
                Some(sig) => {
                    if manifest.strict_pq {
                        return Err(ErrorKind::Malformed.into());
                    }
                    let sig: [u8; SIGNATURE_LENGTH] = fixed(sig)?;
                    XEdDSAPublicKey::new(&identity_key)?.verify(signed_prekey, &sig)?;
                    Some(sig)
                }
                None => {
                    if !manifest.pq_enabled {
                        return Err(ErrorKind::Malformed.into());
                    }
                    None
                }
            };

            // Classical OPKs: canonical and unique.
            let mut one_time_prekeys = Vec::with_capacity(request.one_time_prekeys.len());
            let mut seen_opks = HashSet::with_capacity(request.one_time_prekeys.len());
            for opk in &request.one_time_prekeys {
                let key: PublicKey = fixed(opk)?;
                check_canonical_key(&key)?;
                if !seen_opks.insert(key) {
                    return Err(ErrorKind::Malformed.into());
                }
                one_time_prekeys.push(key);
            }

            let mut pq_last_resort = Vec::with_capacity(request.pq_last_resort.len());
            let mut pq_one_time_prekeys = Vec::with_capacity(request.pq_one_time_prekeys.len());

            if manifest.pq_enabled {
                for &suite in &manifest.offered_suites {
                    if !self.info.supported_suites.contains(&suite) {
                        return Err(ErrorKind::Malformed.into());
                    }
                }
                // Match each last-resort PQSPK against manifest commitments and verify signature.
                let mut commitments: HashMap<u8, [u8; PQ_PREKEY_ID_LENGTH]> =
                    HashMap::with_capacity(manifest.pq_last_resort.len());
                for c in &manifest.pq_last_resort {
                    let suite_u8 = u8::try_from(c.suite).map_err(|_| ErrorKind::Malformed)?;
                    commitments.insert(suite_u8, fixed(&c.prekey_id)?);
                }
                if request.pq_last_resort.len() != commitments.len() {
                    return Err(ErrorKind::Malformed.into());
                }
                let mut seen_lr_suites = HashSet::with_capacity(request.pq_last_resort.len());
                let mut seen_pq_ids = HashSet::with_capacity(
                    request.pq_last_resort.len() + request.pq_one_time_prekeys.len(),
                );
                for lr in &request.pq_last_resort {
                    let (suite, id, sig) = verify_wire_pq_prekey(&identity_key, lr, true)?;
                    let suite_u8 = suite.as_u8();
                    let Some(&expected_id) = commitments.get(&suite_u8) else {
                        return Err(ErrorKind::Malformed.into());
                    };
                    if id != expected_id
                        || !seen_lr_suites.insert(suite_u8)
                        || !seen_pq_ids.insert(id)
                    {
                        return Err(ErrorKind::Malformed.into());
                    }
                    pq_last_resort.push(StoredPqPrekey {
                        suite: suite_u8,
                        id,
                        encapsulation_key: lr.encapsulation_key.clone(),
                        signature: sig,
                    });
                }
                for opk in &request.pq_one_time_prekeys {
                    let (suite, id, sig) = verify_wire_pq_prekey(&identity_key, opk, false)?;
                    let suite_u8 = suite.as_u8();
                    if !commitments.contains_key(&suite_u8) || !seen_pq_ids.insert(id) {
                        return Err(ErrorKind::Malformed.into());
                    }
                    pq_one_time_prekeys.push(StoredPqPrekey {
                        suite: suite_u8,
                        id,
                        encapsulation_key: opk.encapsulation_key.clone(),
                        signature: sig,
                    });
                }
            } else if !request.pq_last_resort.is_empty() || !request.pq_one_time_prekeys.is_empty()
            {
                return Err(ErrorKind::Malformed.into());
            }

            let record = PublishV2Record {
                manifest: manifest_to_storage(manifest)?,
                signed_prekey_signature,
                one_time_prekeys,
                pq_last_resort,
                pq_one_time_prekeys,
                timestamp: request.timestamp,
            };
            match self.store.publish_v2(record).await? {
                PublishV2Status::Stored => Ok(PublishV2Response {}),
                PublishV2Status::StaleSequence => Err(ErrorKind::StaleTimestamp.into()),
                PublishV2Status::DuplicatePrekey => Err(ErrorKind::Malformed.into()),
            }
        }

        async fn refill_prekeys(
            &self,
            request: RefillPrekeysRequest,
        ) -> Result<RefillPrekeysResponse> {
            if !self.info.pq_enabled && !request.pq_one_time_prekeys.is_empty() {
                return Err(ErrorKind::Unimplemented.into());
            }
            if request.one_time_prekeys.len() > self.limits.max_one_time_prekeys
                || request.pq_one_time_prekeys.len() > self.limits.max_pq_one_time_prekeys
            {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let identity_key = request.verify(&self.info.server_id, now_millis())?;

            let mut one_time_prekeys = Vec::with_capacity(request.one_time_prekeys.len());
            let mut seen_opks = HashSet::with_capacity(request.one_time_prekeys.len());
            for opk in &request.one_time_prekeys {
                let key: PublicKey = fixed(opk)?;
                check_canonical_key(&key)?;
                if !seen_opks.insert(key) {
                    return Err(ErrorKind::Malformed.into());
                }
                one_time_prekeys.push(key);
            }

            let mut pq_one_time_prekeys = Vec::with_capacity(request.pq_one_time_prekeys.len());
            let mut seen_pq_ids = HashSet::with_capacity(request.pq_one_time_prekeys.len());
            for opk in &request.pq_one_time_prekeys {
                if !self.info.supported_suites.contains(&opk.suite) {
                    return Err(ErrorKind::Malformed.into());
                }
                let (suite, id, sig) = verify_wire_pq_prekey(&identity_key, opk, false)?;
                if !seen_pq_ids.insert(id) {
                    return Err(ErrorKind::Malformed.into());
                }
                pq_one_time_prekeys.push(StoredPqPrekey {
                    suite: suite.as_u8(),
                    id,
                    encapsulation_key: opk.encapsulation_key.clone(),
                    signature: sig,
                });
            }

            let status = self
                .store
                .refill_prekeys(RefillPrekeysRecord {
                    identity_key,
                    generation: request.generation,
                    one_time_prekeys,
                    pq_one_time_prekeys,
                    max_one_time_prekeys: self.limits.max_one_time_prekeys,
                    max_pq_one_time_prekeys: self.limits.max_pq_one_time_prekeys,
                    timestamp: request.timestamp,
                })
                .await?;
            match status {
                RefillStatus::Stored {
                    classical_count,
                    pq_counts,
                } => Ok(RefillPrekeysResponse {
                    classical_one_time_count: classical_count as u32,
                    pq_one_time_counts: pq_counts
                        .into_iter()
                        .map(|(suite, count)| SuiteCount {
                            suite: u32::from(suite),
                            count: count as u32,
                        })
                        .collect(),
                }),
                RefillStatus::NotFound => Err(ErrorKind::NotFound.into()),
                RefillStatus::StaleGeneration | RefillStatus::StaleTimestamp => {
                    Err(ErrorKind::StaleTimestamp.into())
                }
                RefillStatus::DuplicatePrekey => Err(ErrorKind::Malformed.into()),
                RefillStatus::LimitExceeded => Err(ErrorKind::LimitExceeded.into()),
            }
        }

        async fn get_manifest(&self, request: GetManifestRequest) -> Result<GetManifestResponse> {
            if !self.info.pq_enabled {
                return Err(ErrorKind::Unimplemented.into());
            }
            let identity_key: PublicKey = fixed(&request.identity_key)?;
            check_canonical_key(&identity_key)?;
            let manifest = self
                .store
                .get_manifest(&identity_key)
                .await?
                .map(manifest_from_storage);
            Ok(GetManifestResponse { manifest })
        }

        async fn claim_bundle(&self, request: ClaimBundleRequest) -> Result<ClaimBundleResponse> {
            if request.preferred_suites.len() > 8 {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let identity_key: PublicKey = fixed(&request.identity_key)?;
            check_canonical_key(&identity_key)?;
            let mut suites = Vec::with_capacity(request.preferred_suites.len());
            for &suite_u32 in &request.preferred_suites {
                let suite_u8 = u8::try_from(suite_u32).map_err(|_| ErrorKind::Malformed)?;
                if PqSuite::from_u8(suite_u8).is_none() {
                    return Err(ErrorKind::Malformed.into());
                }
                if self.info.pq_enabled
                    && self.info.supported_suites.contains(&suite_u32)
                    && !suites.contains(&suite_u8)
                {
                    suites.push(suite_u8);
                }
            }

            let reject_pq_on_manifest =
                !self.info.pq_enabled && !request.preferred_suites.is_empty();
            let claimed = match self
                .store
                .claim_bundle_checked(&identity_key, &suites, reject_pq_on_manifest)
                .await?
            {
                ClaimOutcome::NotFound => return Err(ErrorKind::NotFound.into()),
                ClaimOutcome::PqDisabledForPqManifest => {
                    return Err(ErrorKind::Unimplemented.into());
                }
                ClaimOutcome::Claimed(claimed) => *claimed,
            };
            Ok(ClaimBundleResponse {
                manifest: claimed.manifest.map(manifest_from_storage),
                signed_prekey: Bytes::copy_from_slice(&claimed.signed_prekey),
                signed_prekey_signature: claimed
                    .signed_prekey_signature
                    .map(|sig| Bytes::copy_from_slice(&sig)),
                one_time_prekey: claimed
                    .one_time_prekey
                    .map(|key| Bytes::copy_from_slice(&key)),
                pq_last_resort: claimed.pq_last_resort.map(pq_prekey_from_storage),
                pq_one_time_prekey: claimed.pq_one_time_prekey.map(pq_prekey_from_storage),
            })
        }

        async fn send_initial_v2(
            &self,
            request: SendInitialV2Request,
        ) -> Result<SendInitialV2Response> {
            let recipient: PublicKey = fixed(&request.recipient)?;
            check_canonical_key(&recipient)?;
            let message = request.message.as_ref().ok_or(ErrorKind::Malformed)?;
            if !self.info.pq_enabled && message.version == PQXDH_VERSION {
                return Err(ErrorKind::Unimplemented.into());
            }
            let first_message = message.first_message.clone().ok_or(ErrorKind::Malformed)?;
            if first_message.header.len() > MAX_HEADER_SIZE
                || first_message
                    .header
                    .len()
                    .saturating_add(first_message.content.len())
                    > self.limits.max_first_message_size
            {
                return Err(ErrorKind::LimitExceeded.into());
            }

            let supported_suites: &[u32] = if self.info.pq_enabled {
                &self.info.supported_suites
            } else {
                &[]
            };
            let validated = validate_initial_message_v2(message, supported_suites, false)?;

            let stored = StoredInitialMessageV2 {
                id: 0,
                version: message.version,
                sender: validated.sender,
                recipient,
                ephemeral_key: validated.ephemeral_key,
                signed_prekey: validated.signed_prekey,
                one_time_prekey: validated.one_time_prekey,
                header: first_message.header,
                content: first_message.content,
                pq_suite: validated.pq_suite,
                pq_last_resort: message.pq_last_resort,
                pq_prekey_id: validated.pq_prekey_id,
                pq_ciphertext: validated.pq_ciphertext,
                manifest_digest: validated.manifest_digest,
            };
            let id = self
                .store
                .add_initial_message_v2(stored, self.limits.max_initial_messages)
                .await?
                .ok_or(ErrorKind::LimitExceeded)?;
            Ok(SendInitialV2Response { id })
        }

        async fn list_initial_messages(
            &self,
            request: ListInitialMessagesRequest,
        ) -> Result<ListInitialMessagesResponse> {
            let identity_key = request.verify(&self.info.server_id, now_millis())?;
            let limit = match request.limit {
                0 => self.limits.max_list_limit,
                n => (n as usize).min(self.limits.max_list_limit),
            };
            let stored = self
                .store
                .list_initial_messages(&identity_key, limit)
                .await?;
            let messages = stored
                .into_iter()
                .map(|m| InitialMessageV2 {
                    id: m.id,
                    version: m.version,
                    identity_key: Bytes::copy_from_slice(&m.sender),
                    ephemeral_key: Bytes::copy_from_slice(&m.ephemeral_key),
                    signed_prekey: Bytes::copy_from_slice(&m.signed_prekey),
                    one_time_prekey: m.one_time_prekey.map(|k| Bytes::copy_from_slice(&k)),
                    first_message: Some(EncryptedMessage {
                        header: m.header,
                        content: m.content,
                    }),
                    pq_suite: m.pq_suite.map_or(0, u32::from),
                    pq_last_resort: m.pq_last_resort,
                    pq_prekey_id: m
                        .pq_prekey_id
                        .map_or_else(Bytes::new, |id| Bytes::copy_from_slice(&id)),
                    pq_ciphertext: m.pq_ciphertext.unwrap_or_default(),
                    manifest_digest: m
                        .manifest_digest
                        .map_or_else(Bytes::new, |d| Bytes::copy_from_slice(&d)),
                })
                .collect();
            Ok(ListInitialMessagesResponse { messages })
        }

        async fn ack_initial_messages(
            &self,
            request: AckInitialMessagesRequest,
        ) -> Result<AckInitialMessagesResponse> {
            if request.ids.len() > self.limits.max_ack_ids {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let identity_key = request.verify(&self.info.server_id, now_millis())?;
            let deleted = self
                .store
                .ack_initial_messages(&identity_key, &request.ids)
                .await?;
            Ok(AckInitialMessagesResponse {
                deleted: deleted as u32,
            })
        }
    }

    #[cfg(test)]
    #[allow(deprecated)]
    mod test {
        use std::sync::Arc;

        use storage::{MemoryStore, PqHandshakeStore};
        use x3dh::{sign_pq_opk, sign_pq_spk};

        use super::*;
        use crate::handshake::{
            FetchBundleRequest, HandshakeServer, LocalHandshake, PublishRequest,
            SendInitialMessageRequest, TakeInitialMessagesRequest,
        };

        /// Wrapper sharing one `Arc<MemoryStore>` across v1 and v2 handshake servers.
        #[derive(Clone)]
        struct SharedStore(Arc<MemoryStore>);

        impl storage::LocalHandshakeStore for SharedStore {
            async fn publish(
                &self,
                bundle: storage::Bundle,
                one_time_prekeys: Vec<PublicKey>,
            ) -> storage::Result<bool> {
                storage::HandshakeStore::publish(&*self.0, bundle, one_time_prekeys).await
            }
            async fn take_bundle(
                &self,
                identity_key: &PublicKey,
            ) -> storage::Result<Option<(storage::Bundle, Option<PublicKey>)>> {
                storage::HandshakeStore::take_bundle(&*self.0, identity_key).await
            }
            async fn add_initial_message(
                &self,
                initial_message: storage::StoredInitialMessage,
                limit: usize,
            ) -> storage::Result<bool> {
                storage::HandshakeStore::add_initial_message(&*self.0, initial_message, limit).await
            }
            async fn take_initial_messages(
                &self,
                recipient: &PublicKey,
                timestamp: u64,
            ) -> storage::Result<Option<Vec<storage::StoredInitialMessage>>> {
                storage::HandshakeStore::take_initial_messages(&*self.0, recipient, timestamp).await
            }
        }

        impl LocalPqHandshakeStore for SharedStore {
            async fn publish_v2(
                &self,
                record: PublishV2Record,
            ) -> storage::Result<PublishV2Status> {
                PqHandshakeStore::publish_v2(&*self.0, record).await
            }
            async fn refill_prekeys(
                &self,
                record: RefillPrekeysRecord,
            ) -> storage::Result<RefillStatus> {
                PqHandshakeStore::refill_prekeys(&*self.0, record).await
            }
            async fn get_manifest(
                &self,
                identity_key: &PublicKey,
            ) -> storage::Result<Option<StoredCapabilityManifest>> {
                PqHandshakeStore::get_manifest(&*self.0, identity_key).await
            }
            async fn claim_bundle(
                &self,
                identity_key: &PublicKey,
                preferred_suites: &[u8],
            ) -> storage::Result<Option<storage::ClaimedPqBundle>> {
                PqHandshakeStore::claim_bundle(&*self.0, identity_key, preferred_suites).await
            }
            async fn claim_bundle_checked(
                &self,
                identity_key: &PublicKey,
                preferred_suites: &[u8],
                reject_pq_on_manifest: bool,
            ) -> storage::Result<storage::ClaimOutcome> {
                PqHandshakeStore::claim_bundle_checked(
                    &*self.0,
                    identity_key,
                    preferred_suites,
                    reject_pq_on_manifest,
                )
                .await
            }
            async fn add_initial_message_v2(
                &self,
                initial_message: StoredInitialMessageV2,
                limit: usize,
            ) -> storage::Result<Option<u64>> {
                PqHandshakeStore::add_initial_message_v2(&*self.0, initial_message, limit).await
            }
            async fn list_initial_messages(
                &self,
                recipient: &PublicKey,
                limit: usize,
            ) -> storage::Result<Vec<StoredInitialMessageV2>> {
                PqHandshakeStore::list_initial_messages(&*self.0, recipient, limit).await
            }
            async fn ack_initial_messages(
                &self,
                recipient: &PublicKey,
                ids: &[u64],
            ) -> storage::Result<usize> {
                PqHandshakeStore::ack_initial_messages(&*self.0, recipient, ids).await
            }
            async fn pq_snapshot(
                &self,
                identity_key: &PublicKey,
            ) -> storage::Result<storage::PqStorageSnapshot> {
                PqHandshakeStore::pq_snapshot(&*self.0, identity_key).await
            }
        }

        impl storage::LocalIdempotentMailboxStore for SharedStore {
            async fn append_idempotent(
                &self,
                sender: &PublicKey,
                recipient: &PublicKey,
                header: Bytes,
                content: Bytes,
                initial_message: Option<Bytes>,
                delivery_hash: Option<[u8; 32]>,
                client_message_id: Option<[u8; 16]>,
            ) -> storage::Result<u64> {
                storage::IdempotentMailboxStore::append_idempotent(
                    &*self.0,
                    sender,
                    recipient,
                    header,
                    content,
                    initial_message,
                    delivery_hash,
                    client_message_id,
                )
                .await
            }
            async fn delete_delivered(
                &self,
                sender: &PublicKey,
                recipient: &PublicKey,
                hashes: &[[u8; 32]],
            ) -> storage::Result<()> {
                storage::IdempotentMailboxStore::delete_delivered(
                    &*self.0, sender, recipient, hashes,
                )
                .await
            }
            async fn read(
                &self,
                sender: &PublicKey,
                recipient: &PublicKey,
                after: u64,
                limit: u32,
            ) -> storage::Result<Vec<storage::StoredMessage>> {
                storage::IdempotentMailboxStore::read(&*self.0, sender, recipient, after, limit)
                    .await
            }
            async fn read_bounded(
                &self,
                sender: &PublicKey,
                recipient: &PublicKey,
                after: u64,
                limit: u32,
                max_size: usize,
            ) -> storage::Result<Vec<storage::StoredMessage>> {
                storage::IdempotentMailboxStore::read_bounded(
                    &*self.0, sender, recipient, after, limit, max_size,
                )
                .await
            }
        }

        fn make_pq_prekey(
            identity: &XEdDSAPrivateKey,
            suite: PqSuite,
            seed_byte: u8,
            last_resort: bool,
        ) -> PqPrekey {
            let ek = vec![seed_byte; suite.ek_len()];
            let id = pq_prekey_id(suite.as_u8(), &ek);
            let sig = if last_resort {
                sign_pq_spk(identity, suite, &ek).unwrap()
            } else {
                sign_pq_opk(identity, suite, &ek).unwrap()
            };
            PqPrekey {
                suite: u32::from(suite.as_u8()),
                prekey_id: Bytes::copy_from_slice(&id),
                encapsulation_key: Bytes::from(ek),
                signature: Bytes::copy_from_slice(&sig),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn signed_manifest(
            identity: &XEdDSAPrivateKey,
            audience: &str,
            seq: u64,
            generation: u64,
            pq_enabled: bool,
            strict_pq: bool,
            spk: PublicKey,
            lr: &[PqPrekey],
            now: u64,
        ) -> CapabilityManifest {
            let mut m = CapabilityManifest {
                audience: audience.to_string(),
                identity_key: Bytes::new(),
                manifest_seq: seq,
                generation,
                issued_at: now,
                expires_at: now + 3_600_000,
                pq_enabled,
                strict_pq,
                pq_ratchet_supported: pq_enabled,
                offered_suites: lr.iter().map(|k| k.suite).collect(),
                signed_prekey: Bytes::copy_from_slice(&spk),
                pq_last_resort: lr
                    .iter()
                    .map(|k| PqLastResortCommitment {
                        suite: k.suite,
                        prekey_id: k.prekey_id.clone(),
                    })
                    .collect(),
                signature: Bytes::new(),
            };
            sign_manifest(identity, &mut m).unwrap();
            m
        }

        #[tokio::test]
        async fn manifest_publish_refill_claim_and_toggle_flow() {
            let shared = SharedStore(Arc::new(MemoryStore::default()));
            let v1 = HandshakeServer::new(shared.clone());
            let v2 = HandshakeV2Server::new(shared.clone(), ServerInfoConfig::new("relay.example"));
            let now = now_millis();

            let info = v2.get_server_info(GetServerInfoRequest {}).await.unwrap();
            assert!(info.pq_enabled);
            assert_eq!(info.supported_suites, vec![1, 2]);
            assert_eq!(info.server_id, "relay.example");
            assert!(!info.legacy_v1_enabled);
            assert!(!info.allow_unsigned_fetch);

            let bob = XEdDSAPrivateKey::generate();
            let bob_pk = bob.compute_public_key().to_bytes();
            let spk1 = crate::test_public_key(0x11);
            let opk1 = crate::test_public_key(0x41);
            let opk2 = crate::test_public_key(0x42);
            let opk3 = crate::test_public_key(0x43);
            let opk4 = crate::test_public_key(0x44);
            let opk5 = crate::test_public_key(0x45);
            let opk6 = crate::test_public_key(0x46);
            let spk2 = crate::test_public_key(0x12);
            let spk3 = crate::test_public_key(0x13);
            let v1_spk = crate::test_public_key(0x55);
            let v1_opk = crate::test_public_key(0x56);
            let carol_spk = crate::test_public_key(0x61);
            let carol_opk = crate::test_public_key(0x62);
            let lr1024 = make_pq_prekey(&bob, PqSuite::MlKem1024, 0x21, true);
            let lr768 = make_pq_prekey(&bob, PqSuite::MlKem768, 0x22, true);
            let opk1024 = make_pq_prekey(&bob, PqSuite::MlKem1024, 0x31, false);
            let opk768 = make_pq_prekey(&bob, PqSuite::MlKem768, 0x32, false);

            // Wrong audience fails signature verification.
            let bad_aud = signed_manifest(
                &bob,
                "other.example",
                1,
                1,
                true,
                false,
                spk1,
                std::slice::from_ref(&lr1024),
                now,
            );
            assert_eq!(
                verify_manifest(&bad_aud, "relay.example")
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSignature
            );

            // Publish compat v2 bundle with both ML-KEM-1024 and ML-KEM-768.
            let m1 = signed_manifest(
                &bob,
                "relay.example",
                1,
                1,
                true,
                false,
                spk1,
                &[lr1024.clone(), lr768.clone()],
                now,
            );
            let req1 = PublishV2Request::sign(
                &bob,
                m1.clone(),
                Some(bob.sign(spk1)),
                &[opk1, opk2],
                vec![lr1024.clone(), lr768.clone()],
                vec![opk1024.clone(), opk768.clone()],
                now,
            )
            .unwrap();
            v2.publish_v2(req1).await.unwrap();

            // Non-consuming GetManifest returns exact signed manifest.
            let got = v2
                .get_manifest(GetManifestRequest {
                    identity_key: Bytes::copy_from_slice(&bob_pk),
                })
                .await
                .unwrap();
            assert_eq!(got.manifest, Some(m1.clone()));

            // Re-publishing with same manifest_seq fails as StaleTimestamp.
            let stale_req = PublishV2Request::sign(
                &bob,
                m1.clone(),
                Some(bob.sign(spk1)),
                &[opk3],
                vec![lr1024.clone(), lr768.clone()],
                vec![],
                now,
            )
            .unwrap();
            assert_eq!(
                v2.publish_v2(stale_req).await.unwrap_err().kind(),
                ErrorKind::StaleTimestamp
            );

            // Claim ML-KEM-1024 pops opk1024; Claim ML-KEM-768 pops opk768.
            let c1 = v2
                .claim_bundle(ClaimBundleRequest {
                    identity_key: Bytes::copy_from_slice(&bob_pk),
                    preferred_suites: vec![1],
                })
                .await
                .unwrap();
            assert_eq!(c1.pq_one_time_prekey, Some(opk1024.clone()));
            assert_eq!(c1.pq_last_resort, Some(lr1024.clone()));
            let bundle1 = PqPrekeyBundle::try_from(&c1).unwrap();
            assert!(!bundle1.pq_last_resort);
            assert_eq!(bundle1.pq_suite, PqSuite::MlKem1024);

            let c2 = v2
                .claim_bundle(ClaimBundleRequest {
                    identity_key: Bytes::copy_from_slice(&bob_pk),
                    preferred_suites: vec![2],
                })
                .await
                .unwrap();
            assert_eq!(c2.pq_one_time_prekey, Some(opk768.clone()));
            assert_eq!(c2.pq_last_resort, Some(lr768.clone()));

            // Exhausted PQOPKs fall back to last-resort PQSPK.
            let c3 = v2
                .claim_bundle(ClaimBundleRequest {
                    identity_key: Bytes::copy_from_slice(&bob_pk),
                    preferred_suites: vec![1, 2],
                })
                .await
                .unwrap();
            assert_eq!(c3.pq_one_time_prekey, None);
            assert_eq!(c3.pq_last_resort, Some(lr1024.clone()));
            let bundle3 = PqPrekeyBundle::try_from(&c3).unwrap();
            assert!(bundle3.pq_last_resort);

            // RefillPrekeys adds fresh OPK + PQOPK to current generation 1 without rotating SPK.
            let fresh_opk768 = make_pq_prekey(&bob, PqSuite::MlKem768, 0x33, false);
            let refill = RefillPrekeysRequest::sign(
                &bob,
                "relay.example",
                1,
                &[opk4],
                vec![fresh_opk768.clone()],
                now,
            )
            .unwrap();
            let refilled = v2.refill_prekeys(refill.clone()).await.unwrap();
            assert_eq!(refilled.classical_one_time_count, 1);
            assert_eq!(
                refilled.pq_one_time_counts,
                vec![SuiteCount { suite: 2, count: 1 }]
            );
            // Claim the refilled OPK & PQOPK, then replay the exact RefillPrekeysRequest:
            // monotonic refill timestamp MUST reject the replay so consumed keys cannot return.
            let claimed_refill = v2
                .claim_bundle(ClaimBundleRequest {
                    identity_key: Bytes::copy_from_slice(&bob_pk),
                    preferred_suites: vec![2],
                })
                .await
                .unwrap();
            assert_eq!(claimed_refill.one_time_prekey.as_deref(), Some(&opk4[..]));
            assert_eq!(claimed_refill.pq_one_time_prekey, Some(fresh_opk768));
            assert_eq!(
                v2.refill_prekeys(refill).await.unwrap_err().kind(),
                ErrorKind::StaleTimestamp
            );

            // Legacy v1 publish MUST be refused once a v2 manifest exists (neither wiping v2
            // manifest/PQ prekeys nor corrupting the shared classical OPK pool).
            let v1_prekeys = x3dh::PublishedPrekeys {
                signed_prekey: v1_spk,
                signed_prekey_signature: bob.sign(v1_spk),
                one_time_prekeys: vec![v1_opk],
            };
            assert_eq!(
                v1.publish(PublishRequest::sign(&bob, &v1_prekeys, now + 1).unwrap())
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::StaleTimestamp
            );
            assert_eq!(
                v2.get_manifest(GetManifestRequest {
                    identity_key: Bytes::copy_from_slice(&bob_pk),
                })
                .await
                .unwrap()
                .manifest,
                Some(m1)
            );

            // Strict PQ publish clears legacy v1 bundle so v1 FetchBundle returns NotFound;
            // replaying an old captured v1 PublishRequest MUST remain rejected and leave strict
            // PQ bundle & OPKs intact.
            let m2 = signed_manifest(
                &bob,
                "relay.example",
                2,
                2,
                true,
                true,
                spk2,
                std::slice::from_ref(&lr1024),
                now,
            );
            let strict_req =
                PublishV2Request::sign(&bob, m2, None, &[opk5], vec![lr1024], vec![], now).unwrap();
            v2.publish_v2(strict_req).await.unwrap();
            assert_eq!(
                v1.publish(PublishRequest::sign(&bob, &v1_prekeys, 100).unwrap())
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::StaleTimestamp
            );
            assert_eq!(
                v1.fetch_bundle(FetchBundleRequest {
                    identity_key: Bytes::copy_from_slice(&bob_pk),
                })
                .await
                .unwrap_err()
                .kind(),
                ErrorKind::NotFound
            );

            // Affirmative OFF without a raw SPK signature is rejected as Malformed (otherwise
            // classical peers cannot verify the SPK and the identity becomes unreachable).
            let m3 = signed_manifest(&bob, "relay.example", 3, 3, false, false, spk3, &[], now);
            let off_no_sig =
                PublishV2Request::sign(&bob, m3.clone(), None, &[opk6], vec![], vec![], now)
                    .unwrap();
            assert_eq!(
                v2.publish_v2(off_no_sig).await.unwrap_err().kind(),
                ErrorKind::Malformed
            );

            // Affirmative OFF with raw SPK signature clears PQ prekeys while persisting OFF manifest.
            let off_req = PublishV2Request::sign(
                &bob,
                m3.clone(),
                Some(bob.sign(spk3)),
                &[opk6],
                vec![],
                vec![],
                now,
            )
            .unwrap();
            v2.publish_v2(off_req).await.unwrap();
            let after_off = v2
                .claim_bundle(ClaimBundleRequest {
                    identity_key: Bytes::copy_from_slice(&bob_pk),
                    preferred_suites: vec![1, 2],
                })
                .await
                .unwrap();
            assert_eq!(after_off.manifest, Some(m3));
            assert_eq!(after_off.pq_last_resort, None);
            assert_eq!(after_off.pq_one_time_prekey, None);

            // Classical-only v1 peer falls back gracefully in ClaimBundle with manifest = None.
            let carol = XEdDSAPrivateKey::generate();
            let carol_pk = carol.compute_public_key().to_bytes();
            let carol_prekeys = x3dh::PublishedPrekeys {
                signed_prekey: carol_spk,
                signed_prekey_signature: carol.sign(carol_spk),
                one_time_prekeys: vec![carol_opk],
            };
            v1.publish(PublishRequest::sign(&carol, &carol_prekeys, now).unwrap())
                .await
                .unwrap();
            let carol_claim = v2
                .claim_bundle(ClaimBundleRequest {
                    identity_key: Bytes::copy_from_slice(&carol_pk),
                    preferred_suites: vec![1, 2],
                })
                .await
                .unwrap();
            assert_eq!(carol_claim.manifest, None);
            assert_eq!(carol_claim.signed_prekey.as_ref(), &carol_spk);
            assert_eq!(carol_claim.one_time_prekey.as_deref(), Some(&carol_opk[..]));
        }

        #[tokio::test]
        async fn two_phase_inbox_isolates_v1_take_from_v2_pq_initials() {
            let shared = SharedStore(Arc::new(MemoryStore::default()));
            let v1 = HandshakeServer::new(shared.clone());
            let v2 = HandshakeV2Server::new(shared.clone(), ServerInfoConfig::new("relay.example"));
            let now = now_millis();

            let alice = XEdDSAPrivateKey::generate();
            let bob = XEdDSAPrivateKey::generate();
            let alice_pk = alice.compute_public_key().to_bytes();
            let bob_pk = bob.compute_public_key().to_bytes();
            let eph1 = crate::test_public_key(0x11);
            let eph2 = crate::test_public_key(0x12);
            let spk = crate::test_public_key(0x22);

            // Register Bob so Bob has an inbox.
            v1.publish(
                PublishRequest::sign(
                    &bob,
                    &x3dh::PublishedPrekeys {
                        signed_prekey: spk,
                        signed_prekey_signature: bob.sign(spk),
                        one_time_prekeys: vec![],
                    },
                    now,
                )
                .unwrap(),
            )
            .await
            .unwrap();

            // Send 1 classical v1 initial via v1 service.
            v1.send_initial_message(SendInitialMessageRequest {
                recipient: Bytes::copy_from_slice(&bob_pk),
                message: Some(crate::handshake::InitialMessage {
                    identity_key: Bytes::copy_from_slice(&alice_pk),
                    ephemeral_key: Bytes::copy_from_slice(&eph1),
                    signed_prekey: Bytes::copy_from_slice(&spk),
                    one_time_prekey: None,
                    first_message: Some(EncryptedMessage {
                        header: Bytes::from_static(b"v1-h"),
                        content: Bytes::from_static(b"v1-c"),
                    }),
                }),
            })
            .await
            .unwrap();

            let classical_with_digest = InitialMessageV2 {
                version: 1,
                identity_key: Bytes::copy_from_slice(&alice_pk),
                ephemeral_key: Bytes::copy_from_slice(&eph1),
                signed_prekey: Bytes::copy_from_slice(&spk),
                first_message: Some(EncryptedMessage::default()),
                manifest_digest: Bytes::from_static(&[0x44; 32]),
                ..Default::default()
            };
            assert_eq!(
                x3dh::InitialMessage::try_from(&classical_with_digest)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
            );
            assert_eq!(
                v2.send_initial_v2(SendInitialV2Request {
                    recipient: Bytes::copy_from_slice(&bob_pk),
                    message: Some(classical_with_digest)
                })
                .await
                .unwrap_err()
                .kind(),
                ErrorKind::Malformed
            );

            // Bad PQ ciphertext length is rejected.
            let bad_ct = SendInitialV2Request {
                recipient: Bytes::copy_from_slice(&bob_pk),
                message: Some(InitialMessageV2 {
                    id: 0,
                    version: PQXDH_VERSION,
                    identity_key: Bytes::copy_from_slice(&alice_pk),
                    ephemeral_key: Bytes::copy_from_slice(&eph2),
                    signed_prekey: Bytes::copy_from_slice(&spk),
                    one_time_prekey: None,
                    first_message: Some(EncryptedMessage {
                        header: Bytes::from_static(b"v2-h"),
                        content: Bytes::from_static(b"v2-c"),
                    }),
                    pq_suite: u32::from(PqSuite::MlKem1024.as_u8()),
                    pq_last_resort: false,
                    pq_prekey_id: Bytes::from_static(&[0x33; 32]),
                    pq_ciphertext: Bytes::from(vec![0xAA; 100]), // wrong length!
                    manifest_digest: Bytes::from_static(&[0x44; 32]),
                }),
            };
            assert_eq!(
                v2.send_initial_v2(bad_ct).await.unwrap_err().kind(),
                ErrorKind::Malformed
            );

            // Send valid PQXDH v2 initial (exact 1568 B ciphertext for ML-KEM-1024).
            let sent = v2
                .send_initial_v2(SendInitialV2Request {
                    recipient: Bytes::copy_from_slice(&bob_pk),
                    message: Some(InitialMessageV2 {
                        id: 0,
                        version: PQXDH_VERSION,
                        identity_key: Bytes::copy_from_slice(&alice_pk),
                        ephemeral_key: Bytes::copy_from_slice(&eph2),
                        signed_prekey: Bytes::copy_from_slice(&spk),
                        one_time_prekey: None,
                        first_message: Some(EncryptedMessage {
                            header: Bytes::from_static(b"v2-h"),
                            content: Bytes::from_static(b"v2-c"),
                        }),
                        pq_suite: u32::from(PqSuite::MlKem1024.as_u8()),
                        pq_last_resort: false,
                        pq_prekey_id: Bytes::from_static(&[0x33; 32]),
                        pq_ciphertext: Bytes::from(vec![0xAA; PqSuite::MlKem1024.ct_len()]),
                        manifest_digest: Bytes::from_static(&[0x44; 32]),
                    }),
                })
                .await
                .unwrap();
            assert!(sent.id > 0);

            // v2 ListInitialMessages returns BOTH v1 and v2 non-destructively.
            let listed = v2
                .list_initial_messages(
                    ListInitialMessagesRequest::sign(&bob, "relay.example", 0, now).unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(listed.messages.len(), 2);
            assert_eq!(listed.messages[0].version, 1);
            assert_eq!(listed.messages[1].version, PQXDH_VERSION);

            // Legacy v1 TakeInitialMessages drains ONLY the v1 message; v2 PQ message stays!
            let taken = v1
                .take_initial_messages(TakeInitialMessagesRequest::sign(&bob, now))
                .await
                .unwrap();
            assert_eq!(taken.messages.len(), 1);
            assert_eq!(
                taken.messages[0].first_message.as_ref().unwrap().header,
                Bytes::from_static(b"v1-h")
            );

            let still_there = v2
                .list_initial_messages(
                    ListInitialMessagesRequest::sign(&bob, "relay.example", 0, now).unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(still_there.messages.len(), 1);
            assert_eq!(still_there.messages[0].id, sent.id);

            // Ack deletes only the acked ID.
            let acked = v2
                .ack_initial_messages(
                    AckInitialMessagesRequest::sign(&bob, "relay.example", vec![sent.id], now)
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(acked.deleted, 1);
            let empty = v2
                .list_initial_messages(
                    ListInitialMessagesRequest::sign(&bob, "relay.example", 0, now).unwrap(),
                )
                .await
                .unwrap();
            assert!(empty.messages.is_empty());
        }

        #[tokio::test]
        async fn pq_disabled_runtime_toggle_advertises_off_and_rejects_pq_routes() {
            let mut cfg = ServerInfoConfig::new("relay.example");
            cfg.pq_enabled = false;
            let v2 = HandshakeV2Server::new(MemoryStore::default(), cfg);

            let info = v2.get_server_info(GetServerInfoRequest {}).await.unwrap();
            assert!(!info.pq_enabled);
            assert!(info.supported_suites.is_empty());
            assert!(!info.pq_ratchet_supported);

            let bob = XEdDSAPrivateKey::generate();
            assert_eq!(
                v2.get_manifest(GetManifestRequest {
                    identity_key: Bytes::copy_from_slice(&bob.compute_public_key().to_bytes()),
                })
                .await
                .unwrap_err()
                .kind(),
                ErrorKind::Unimplemented
            );
        }

        #[tokio::test]
        async fn rejects_unsafe_and_future_timestamps_on_v2_requests() {
            let v2 =
                HandshakeV2Server::new(MemoryStore::default(), ServerInfoConfig::new("r.test"));
            let bob = XEdDSAPrivateKey::generate();
            let now = now_millis();
            let future = now + crate::MAX_CLOCK_SKEW + 120_000;

            assert_eq!(
                ListInitialMessagesRequest::sign(&bob, "r.test", 10, crate::MAX_SAFE_INTEGER + 1)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
            );
            let future_list = ListInitialMessagesRequest::sign(&bob, "r.test", 10, future).unwrap();
            assert_eq!(
                v2.list_initial_messages(future_list)
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::StaleTimestamp
            );
            let future_ack =
                AckInitialMessagesRequest::sign(&bob, "r.test", vec![1], future).unwrap();
            assert_eq!(
                v2.ack_initial_messages(future_ack)
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::StaleTimestamp
            );
            let future_refill =
                RefillPrekeysRequest::sign(&bob, "r.test", 1, &[], vec![], future).unwrap();
            assert_eq!(
                v2.refill_prekeys(future_refill).await.unwrap_err().kind(),
                ErrorKind::StaleTimestamp
            );
        }

        #[tokio::test]
        async fn pq_disabled_rollback_allows_drain_off_manifest_and_classical_fallback() {
            use crate::mailbox_v2::{
                CLIENT_MESSAGE_ID_LENGTH, FetchSignedRequest, LocalMailboxV2, MailboxV2Server,
                PushV2Request,
            };

            let shared = SharedStore(Arc::new(MemoryStore::default()));
            let v1 = HandshakeServer::new(shared.clone());
            let v2_on =
                HandshakeV2Server::new(shared.clone(), ServerInfoConfig::new("relay.example"));
            let now = now_millis();

            let alice = XEdDSAPrivateKey::generate();
            let bob = XEdDSAPrivateKey::generate();
            let carol = XEdDSAPrivateKey::generate();
            let dave = XEdDSAPrivateKey::generate();
            let alice_pk = alice.compute_public_key().to_bytes();
            let bob_pk = bob.compute_public_key().to_bytes();
            let carol_pk = carol.compute_public_key().to_bytes();
            let dave_pk = dave.compute_public_key().to_bytes();

            // Bob publishes a strict-PQ v2 manifest (which deletes his legacy v1 bundle).
            let bob_spk1 = crate::test_public_key(0x11);
            let bob_opk1 = crate::test_public_key(0x41);
            let bob_lr1024 = make_pq_prekey(&bob, PqSuite::MlKem1024, 0x21, true);
            let bob_opk1024 = make_pq_prekey(&bob, PqSuite::MlKem1024, 0x31, false);
            let bob_m1 = signed_manifest(
                &bob,
                "relay.example",
                1,
                1,
                true,
                true,
                bob_spk1,
                std::slice::from_ref(&bob_lr1024),
                now,
            );
            v2_on
                .publish_v2(
                    PublishV2Request::sign(
                        &bob,
                        bob_m1,
                        None,
                        &[bob_opk1],
                        vec![bob_lr1024.clone()],
                        vec![bob_opk1024],
                        now,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();

            // Dave publishes a non-strict PQ-ON manifest.
            let dave_spk = crate::test_public_key(0x15);
            let dave_opk_cl = crate::test_public_key(0x45);
            let dave_lr = make_pq_prekey(&dave, PqSuite::MlKem768, 0x25, true);
            let dave_opk = make_pq_prekey(&dave, PqSuite::MlKem768, 0x35, false);
            let dave_m = signed_manifest(
                &dave,
                "relay.example",
                1,
                1,
                true,
                false,
                dave_spk,
                std::slice::from_ref(&dave_lr),
                now,
            );
            v2_on
                .publish_v2(
                    PublishV2Request::sign(
                        &dave,
                        dave_m.clone(),
                        Some(dave.sign(dave_spk)),
                        &[dave_opk_cl],
                        vec![dave_lr],
                        vec![dave_opk],
                        now,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();

            // Carol is a classical v1-only user.
            let carol_spk = crate::test_public_key(0x61);
            let carol_opk = crate::test_public_key(0x62);
            v1.publish(
                PublishRequest::sign(
                    &carol,
                    &x3dh::PublishedPrekeys {
                        signed_prekey: carol_spk,
                        signed_prekey_signature: carol.sign(carol_spk),
                        one_time_prekeys: vec![carol_opk],
                    },
                    now,
                )
                .unwrap(),
            )
            .await
            .unwrap();

            // Alice sends Bob a PQXDH v2 initial while PQ is still ON.
            let pq_init = InitialMessageV2 {
                id: 0,
                version: PQXDH_VERSION,
                identity_key: Bytes::copy_from_slice(&alice_pk),
                ephemeral_key: Bytes::copy_from_slice(&crate::test_public_key(0x12)),
                signed_prekey: Bytes::copy_from_slice(&bob_spk1),
                one_time_prekey: None,
                first_message: Some(EncryptedMessage {
                    header: Bytes::from_static(b"pq-h"),
                    content: Bytes::from_static(b"pq-c"),
                }),
                pq_suite: u32::from(PqSuite::MlKem1024.as_u8()),
                pq_last_resort: false,
                pq_prekey_id: Bytes::from_static(&[0x33; 32]),
                pq_ciphertext: Bytes::from(vec![0xAA; PqSuite::MlKem1024.ct_len()]),
                manifest_digest: Bytes::from_static(&[0x44; 32]),
            };
            let sent_pq = v2_on
                .send_initial_v2(SendInitialV2Request {
                    recipient: Bytes::copy_from_slice(&bob_pk),
                    message: Some(pq_init.clone()),
                })
                .await
                .unwrap();

            // Operator flips PQ_ENABLED="false" at runtime!
            let mut off_cfg = ServerInfoConfig::new("relay.example");
            off_cfg.pq_enabled = false;
            off_cfg.supported_suites.clear();
            off_cfg.pq_ratchet_supported = false;
            let v2_off = HandshakeV2Server::new(shared.clone(), off_cfg);
            let mb_off = MailboxV2Server::builder(shared.clone())
                .server_id("relay.example".to_string())
                .supported_suites(vec![])
                .build();

            let info = v2_off
                .get_server_info(GetServerInfoRequest {})
                .await
                .unwrap();
            assert!(!info.pq_enabled);
            assert!(info.supported_suites.is_empty());
            assert!(!info.pq_ratchet_supported);

            // PQ-only operations are rejected with Unimplemented.
            assert_eq!(
                v2_off
                    .get_manifest(GetManifestRequest {
                        identity_key: Bytes::copy_from_slice(&bob_pk),
                    })
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::Unimplemented
            );
            assert_eq!(
                v2_off
                    .send_initial_v2(SendInitialV2Request {
                        recipient: Bytes::copy_from_slice(&bob_pk),
                        message: Some(pq_init.clone()),
                    })
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::Unimplemented
            );
            let bob_retry_spk = crate::test_public_key(0x19);
            let bob_m_on_retry = signed_manifest(
                &bob,
                "relay.example",
                2,
                2,
                true,
                false,
                bob_retry_spk,
                std::slice::from_ref(&bob_lr1024),
                now,
            );
            assert_eq!(
                v2_off
                    .publish_v2(
                        PublishV2Request::sign(
                            &bob,
                            bob_m_on_retry,
                            Some(bob.sign(bob_retry_spk)),
                            &[],
                            vec![bob_lr1024],
                            vec![],
                            now,
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::Unimplemented
            );
            let pq_refill_key = make_pq_prekey(&bob, PqSuite::MlKem1024, 0x39, false);
            assert_eq!(
                v2_off
                    .refill_prekeys(
                        RefillPrekeysRequest::sign(
                            &bob,
                            "relay.example",
                            1,
                            &[],
                            vec![pq_refill_key],
                            now,
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::Unimplemented
            );

            // ClaimBundle with non-empty preferred_suites against a peer still on a PQ-ON manifest
            // returns Unimplemented WITHOUT wasting their classical OPK.
            assert_eq!(
                v2_off
                    .claim_bundle(ClaimBundleRequest {
                        identity_key: Bytes::copy_from_slice(&bob_pk),
                        preferred_suites: vec![1, 2],
                    })
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::Unimplemented
            );
            assert_eq!(
                shared
                    .pq_snapshot(&bob_pk)
                    .await
                    .unwrap()
                    .classical_one_time_count,
                1
            );

            // ClaimBundle with empty preferred_suites (classical client) against non-strict Dave
            // returns classical bundle without consuming PQ prekeys.
            let dave_claim = v2_off
                .claim_bundle(ClaimBundleRequest {
                    identity_key: Bytes::copy_from_slice(&dave_pk),
                    preferred_suites: vec![],
                })
                .await
                .unwrap();
            assert_eq!(dave_claim.manifest, Some(dave_m));
            assert_eq!(dave_claim.pq_last_resort, None);
            assert_eq!(dave_claim.pq_one_time_prekey, None);
            assert_eq!(
                dave_claim.one_time_prekey.as_deref(),
                Some(&dave_opk_cl[..])
            );
            assert_eq!(
                shared
                    .pq_snapshot(&dave_pk)
                    .await
                    .unwrap()
                    .pq_one_time_counts,
                vec![(2, 1)]
            );

            // ClaimBundle for v1-only Carol works seamlessly even with preferred_suites.
            let carol_claim = v2_off
                .claim_bundle(ClaimBundleRequest {
                    identity_key: Bytes::copy_from_slice(&carol_pk),
                    preferred_suites: vec![1, 2],
                })
                .await
                .unwrap();
            assert_eq!(carol_claim.manifest, None);
            assert_eq!(carol_claim.signed_prekey.as_ref(), &carol_spk);

            // SendInitialV2 with classical version == 1 still succeeds when PQ_ENABLED="false".
            let classical_init = InitialMessageV2 {
                id: 0,
                version: 1,
                identity_key: Bytes::copy_from_slice(&alice_pk),
                ephemeral_key: Bytes::copy_from_slice(&crate::test_public_key(0x13)),
                signed_prekey: Bytes::copy_from_slice(&bob_spk1),
                one_time_prekey: None,
                first_message: Some(EncryptedMessage {
                    header: Bytes::from_static(b"v1-h"),
                    content: Bytes::from_static(b"v1-c"),
                }),
                pq_suite: 0,
                pq_last_resort: false,
                pq_prekey_id: Bytes::new(),
                pq_ciphertext: Bytes::new(),
                manifest_digest: Bytes::new(),
            };
            let sent_v1 = v2_off
                .send_initial_v2(SendInitialV2Request {
                    recipient: Bytes::copy_from_slice(&bob_pk),
                    message: Some(classical_init),
                })
                .await
                .unwrap();

            // 1. Bob drains his v2 inbox (both queued PQXDH v2 initial and v1 initial) and acks them!
            let listed = v2_off
                .list_initial_messages(
                    ListInitialMessagesRequest::sign(&bob, "relay.example", 0, now).unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(listed.messages.len(), 2);
            assert_eq!(listed.messages[0].id, sent_pq.id);
            assert_eq!(listed.messages[0].version, PQXDH_VERSION);
            assert_eq!(listed.messages[1].id, sent_v1.id);
            assert_eq!(listed.messages[1].version, 1);
            let acked = v2_off
                .ack_initial_messages(
                    AckInitialMessagesRequest::sign(
                        &bob,
                        "relay.example",
                        vec![sent_pq.id, sent_v1.id],
                        now,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(acked.deleted, 2);
            assert!(
                v2_off
                    .list_initial_messages(
                        ListInitialMessagesRequest::sign(&bob, "relay.example", 0, now).unwrap(),
                    )
                    .await
                    .unwrap()
                    .messages
                    .is_empty()
            );

            // 2. Alice flushes an in-flight carried PQ initial via PushV2 while PQ_ENABLED="false",
            //    and Bob reads it via FetchSigned without HTTP 400!
            let carried_pq = InitialMessageV2 {
                first_message: None,
                ..pq_init.clone()
            };
            let pushed = mb_off
                .push_v2(PushV2Request {
                    sender: Bytes::copy_from_slice(&alice_pk),
                    recipient: Bytes::copy_from_slice(&bob_pk),
                    message: Some(EncryptedMessage {
                        header: Bytes::from_static(b"drain-h"),
                        content: Bytes::from_static(b"drain-c"),
                    }),
                    initial_message: Some(carried_pq.clone()),
                    delivery_hash: Bytes::new(),
                    client_message_id: Bytes::from_static(&[0x88; CLIENT_MESSAGE_ID_LENGTH]),
                })
                .await
                .unwrap();
            assert_eq!(pushed.sequence, 1);
            let fetched = mb_off
                .fetch_signed(
                    FetchSignedRequest::sign(
                        &bob,
                        "relay.example",
                        &alice_pk,
                        0,
                        10,
                        0,
                        vec![],
                        now,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(fetched.messages.len(), 1);
            assert_eq!(fetched.messages[0].initial_message, Some(carried_pq));

            // 3. Previously strict-PQ Bob publishes a signed OFF manifest via PublishV2, which
            //    clears his PQ prekeys, persists the OFF manifest, and restores his classical v1
            //    bundle so he is never locked out or stranded!
            let bob_spk2 = crate::test_public_key(0x14);
            let bob_opk_71 = crate::test_public_key(0x71);
            let bob_opk_72 = crate::test_public_key(0x72);
            let bob_off = signed_manifest(
                &bob,
                "relay.example",
                2,
                2,
                false,
                false,
                bob_spk2,
                &[],
                now,
            );
            v2_off
                .publish_v2(
                    PublishV2Request::sign(
                        &bob,
                        bob_off.clone(),
                        Some(bob.sign(bob_spk2)),
                        &[bob_opk_71],
                        vec![],
                        vec![],
                        now,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let snap = shared.pq_snapshot(&bob_pk).await.unwrap();
            assert!(!snap.manifest.as_ref().unwrap().pq_enabled);
            assert!(snap.pq_last_resort_suites.is_empty());
            assert!(snap.pq_one_time_counts.is_empty());

            // Classical-only RefillPrekeys works on Bob's OFF manifest generation!
            let refill_resp = v2_off
                .refill_prekeys(
                    RefillPrekeysRequest::sign(
                        &bob,
                        "relay.example",
                        2,
                        &[bob_opk_72],
                        vec![],
                        now + 1,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(refill_resp.classical_one_time_count, 2);

            // ClaimBundle for Bob now returns his signed OFF manifest + classical bundle!
            let claimed_off = v2_off
                .claim_bundle(ClaimBundleRequest {
                    identity_key: Bytes::copy_from_slice(&bob_pk),
                    preferred_suites: vec![1, 2],
                })
                .await
                .unwrap();
            assert_eq!(claimed_off.manifest, Some(bob_off));
            assert_eq!(claimed_off.signed_prekey.as_ref(), &bob_spk2);
            assert!(claimed_off.signed_prekey_signature.is_some());
            assert_eq!(
                claimed_off.one_time_prekey.as_deref(),
                Some(&bob_opk_71[..])
            );
            assert_eq!(claimed_off.pq_last_resort, None);
            assert_eq!(claimed_off.pq_one_time_prekey, None);

            // Even legacy v1 FetchBundle now succeeds again for Bob!
            let v1_bundle = v1
                .fetch_bundle(FetchBundleRequest {
                    identity_key: Bytes::copy_from_slice(&bob_pk),
                })
                .await
                .unwrap();
            assert_eq!(v1_bundle.signed_prekey.as_ref(), &bob_spk2);
            assert_eq!(v1_bundle.one_time_prekey.as_deref(), Some(&bob_opk_72[..]));
        }
    }
}
