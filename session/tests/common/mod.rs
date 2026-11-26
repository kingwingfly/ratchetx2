//! Shared in-process storage, v2 handshake, unified v2 mailbox, and fault-injection harnesses
//! for `session` integration tests.

#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use protocol::{
    content::{Hello, Kind as ContentKind},
    handshake_v2::{
        AckInitialMessagesRequest, AckInitialMessagesResponse, ClaimBundleRequest,
        ClaimBundleResponse, GetManifestRequest, GetManifestResponse, GetServerInfoRequest,
        GetServerInfoResponse, HandshakeV2Server, ListInitialMessagesRequest,
        ListInitialMessagesResponse, LocalHandshakeV2, PublishV2Request, PublishV2Response,
        RefillPrekeysRequest, RefillPrekeysResponse, SendInitialV2Request, SendInitialV2Response,
        ServerInfoConfig,
    },
    mailbox_v2::{
        AckMessagesRequest, AckMessagesResponse, FetchSignedRequest, FetchSignedResponse,
        LocalMailboxV2, MailboxLimits, MailboxV2Server, PushV2Request, PushV2Response,
        RegisterWriteTokenRequest, RegisterWriteTokenResponse, RevokeWriteTokenRequest,
        RevokeWriteTokenResponse,
    },
};
use session::{Client, DecryptedMessage, PublicKey, Session};
use storage::MemoryStore;

pub const AUDIENCE: &str = "relay.example";

pub fn hello_bytes(name: &str, session_seq: u64, pq_capable: bool) -> Vec<u8> {
    ContentKind::Hello(Hello {
        name: name.into(),
        pq_capable,
        max_version: if pq_capable { 2 } else { 1 },
        session_seq,
        offered_suites: if pq_capable { vec![1, 2] } else { vec![] },
        pq_ratchet_capable: pq_capable,
    })
    .to_bytes()
}

/// Register `session`'s active inbound write token on `client`'s relay mailbox, pinning it active.
pub async fn register_active_grant<H, M>(
    client: &mut Client<H>,
    session: &Session<M>,
    mailbox: &impl LocalMailboxV2,
) {
    let token_hash = session
        .active_inbound_token_hash()
        .expect("session must have an active inbound token hash");
    let grant_version = client.allocate_grant_version().unwrap();
    client
        .register_write_token_v2(
            mailbox,
            AUDIENCE,
            session.peer(),
            &token_hash,
            grant_version,
            true,
        )
        .await
        .unwrap();
}

/// Fetch one unified mailbox page for `client`, decrypt envelopes whose `token_hash` belongs to
/// `session`, commit the page cursor/pending ACK, and ACK on the relay.
pub async fn receive_for<H, M>(
    client: &mut Client<H>,
    session: &mut Session<M>,
    mailbox: &impl LocalMailboxV2,
) -> Vec<session::Result<DecryptedMessage>> {
    let page = client
        .fetch_mailbox_v2(mailbox, AUDIENCE, 100)
        .await
        .unwrap();
    let hashes: Vec<[u8; 32]> = session.inbound_token_hashes().collect();
    let mut out = Vec::new();
    for env in &page.messages {
        if hashes
            .iter()
            .any(|h| h.as_slice() == env.token_hash.as_ref())
        {
            let msg = env.message.as_ref().expect("validated inline message");
            out.push(session.decrypt_envelope(msg));
        }
    }
    if let Some(last) = page.last_sequence() {
        client.commit_mailbox_page(last, last).unwrap();
        client.ack_mailbox_v2(mailbox, AUDIENCE).await.unwrap();
    }
    out
}

/// Shared `Arc<MemoryStore>` implementing v2 handshake and unified idempotent mailbox traits.
#[derive(Debug, Clone, Default)]
pub struct SharedStore(pub Arc<MemoryStore>);

impl storage::LocalPqHandshakeStore for SharedStore {
    async fn publish_v2(
        &self,
        record: storage::PublishV2Record,
    ) -> storage::Result<storage::PublishV2Status> {
        storage::PqHandshakeStore::publish_v2(&*self.0, record).await
    }

    async fn refill_prekeys(
        &self,
        record: storage::RefillPrekeysRecord,
    ) -> storage::Result<storage::RefillStatus> {
        storage::PqHandshakeStore::refill_prekeys(&*self.0, record).await
    }

    async fn get_manifest(
        &self,
        identity_key: &PublicKey,
    ) -> storage::Result<Option<storage::StoredCapabilityManifest>> {
        storage::PqHandshakeStore::get_manifest(&*self.0, identity_key).await
    }

    async fn claim_bundle(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
    ) -> storage::Result<Option<storage::ClaimedPqBundle>> {
        storage::PqHandshakeStore::claim_bundle(&*self.0, identity_key, preferred_suites).await
    }

    async fn claim_bundle_checked(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
        allow_pq: bool,
    ) -> storage::Result<storage::ClaimOutcome> {
        storage::PqHandshakeStore::claim_bundle_checked(
            &*self.0,
            identity_key,
            preferred_suites,
            allow_pq,
        )
        .await
    }

    async fn add_initial_message_v2(
        &self,
        initial_message: storage::StoredInitialMessageV2,
        limit: usize,
    ) -> storage::Result<Option<u64>> {
        storage::PqHandshakeStore::add_initial_message_v2(&*self.0, initial_message, limit).await
    }

    async fn list_initial_messages(
        &self,
        recipient: &PublicKey,
        after_id: u64,
        limit: usize,
    ) -> storage::Result<Vec<storage::StoredInitialMessageV2>> {
        storage::PqHandshakeStore::list_initial_messages(&*self.0, recipient, after_id, limit).await
    }

    async fn ack_initial_messages(
        &self,
        recipient: &PublicKey,
        ids: &[u64],
    ) -> storage::Result<usize> {
        storage::PqHandshakeStore::ack_initial_messages(&*self.0, recipient, ids).await
    }

    async fn pq_snapshot(
        &self,
        identity_key: &PublicKey,
    ) -> storage::Result<storage::PqStorageSnapshot> {
        storage::PqHandshakeStore::pq_snapshot(&*self.0, identity_key).await
    }
}

impl storage::LocalIdempotentMailboxStore for SharedStore {
    async fn append_idempotent(
        &self,
        recipient: &PublicKey,
        token_hash: &[u8; 32],
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        client_message_id: Option<[u8; 16]>,
    ) -> storage::Result<u64> {
        storage::IdempotentMailboxStore::append_idempotent(
            &*self.0,
            recipient,
            token_hash,
            header,
            content,
            initial_message,
            client_message_id,
        )
        .await
    }

    async fn read_mailbox(
        &self,
        recipient: &PublicKey,
        after_sequence: u64,
        limit: u32,
        max_size: usize,
        ack_up_to_sequence: u64,
    ) -> storage::Result<storage::MailboxPage> {
        storage::IdempotentMailboxStore::read_mailbox(
            &*self.0,
            recipient,
            after_sequence,
            limit,
            max_size,
            ack_up_to_sequence,
        )
        .await
    }

    async fn ack_messages(
        &self,
        recipient: &PublicKey,
        up_to_sequence: u64,
    ) -> storage::Result<u64> {
        storage::IdempotentMailboxStore::ack_messages(&*self.0, recipient, up_to_sequence).await
    }

    async fn register_write_token(
        &self,
        record: storage::RegisterWriteTokenRecord,
    ) -> storage::Result<()> {
        storage::IdempotentMailboxStore::register_write_token(&*self.0, record).await
    }

    async fn revoke_write_token(
        &self,
        record: storage::RevokeWriteTokenRecord,
    ) -> storage::Result<u32> {
        storage::IdempotentMailboxStore::revoke_write_token(&*self.0, record).await
    }
}

#[derive(Debug, Clone)]
pub struct V2OnlyHandshake(pub Arc<HandshakeV2Server<SharedStore>>);

impl V2OnlyHandshake {
    pub fn new(store: SharedStore, audience: &str) -> Self {
        Self(Arc::new(HandshakeV2Server::new(
            store,
            ServerInfoConfig::new(audience),
        )))
    }
}

impl LocalHandshakeV2 for V2OnlyHandshake {
    async fn get_server_info(
        &self,
        request: GetServerInfoRequest,
    ) -> protocol::Result<GetServerInfoResponse> {
        self.0.get_server_info(request).await
    }
    async fn publish_v2(&self, request: PublishV2Request) -> protocol::Result<PublishV2Response> {
        self.0.publish_v2(request).await
    }
    async fn refill_prekeys(
        &self,
        request: RefillPrekeysRequest,
    ) -> protocol::Result<RefillPrekeysResponse> {
        self.0.refill_prekeys(request).await
    }
    async fn get_manifest(
        &self,
        request: GetManifestRequest,
    ) -> protocol::Result<GetManifestResponse> {
        self.0.get_manifest(request).await
    }
    async fn claim_bundle(
        &self,
        request: ClaimBundleRequest,
    ) -> protocol::Result<ClaimBundleResponse> {
        self.0.claim_bundle(request).await
    }
    async fn send_initial_v2(
        &self,
        request: SendInitialV2Request,
    ) -> protocol::Result<SendInitialV2Response> {
        self.0.send_initial_v2(request).await
    }
    async fn list_initial_messages(
        &self,
        request: ListInitialMessagesRequest,
    ) -> protocol::Result<ListInitialMessagesResponse> {
        self.0.list_initial_messages(request).await
    }
    async fn ack_initial_messages(
        &self,
        request: AckInitialMessagesRequest,
    ) -> protocol::Result<AckInitialMessagesResponse> {
        self.0.ack_initial_messages(request).await
    }
}

#[derive(Debug, Clone)]
pub struct V2OnlyMailbox(pub Arc<MailboxV2Server<SharedStore>>);

impl V2OnlyMailbox {
    pub fn new(store: SharedStore, audience: &str) -> Self {
        Self::with_limits(store, audience, MailboxLimits::default())
    }

    pub fn with_limits(store: SharedStore, audience: &str, limits: MailboxLimits) -> Self {
        Self(Arc::new(
            MailboxV2Server::builder(store)
                .server_id(audience.to_string())
                .limits(limits)
                .build(),
        ))
    }
}

impl LocalMailboxV2 for V2OnlyMailbox {
    async fn push_v2(&self, request: PushV2Request) -> protocol::Result<PushV2Response> {
        self.0.push_v2(request).await
    }
    async fn fetch_signed(
        &self,
        request: FetchSignedRequest,
    ) -> protocol::Result<FetchSignedResponse> {
        self.0.fetch_signed(request).await
    }
    async fn ack_messages(
        &self,
        request: AckMessagesRequest,
    ) -> protocol::Result<AckMessagesResponse> {
        self.0.ack_messages(request).await
    }
    async fn register_write_token(
        &self,
        request: RegisterWriteTokenRequest,
    ) -> protocol::Result<RegisterWriteTokenResponse> {
        self.0.register_write_token(request).await
    }
    async fn revoke_write_token(
        &self,
        request: RevokeWriteTokenRequest,
    ) -> protocol::Result<RevokeWriteTokenResponse> {
        self.0.revoke_write_token(request).await
    }
}

/// Scripted fault injector for v2 handshake & mailbox RPCs. Each expected RPC fails with its
/// supplied error; optionally replies with a fixed `GetServerInfoResponse` for `get_server_info`.
pub struct RpcErrors {
    pub queue: RefCell<VecDeque<(&'static str, protocol::Error)>>,
    pub server_info: Option<GetServerInfoResponse>,
}

impl RpcErrors {
    pub fn new<const N: usize>(calls: [(&'static str, protocol::Error); N]) -> Self {
        Self {
            queue: RefCell::new(calls.into()),
            server_info: None,
        }
    }

    pub fn with_server_info<const N: usize>(
        info: GetServerInfoResponse,
        calls: [(&'static str, protocol::Error); N],
    ) -> Self {
        Self {
            queue: RefCell::new(calls.into()),
            server_info: Some(info),
        }
    }

    pub fn fail<T>(&self, call: &str) -> protocol::Result<T> {
        let (expected, error) = self.queue.borrow_mut().pop_front().expect("unexpected RPC");
        assert_eq!(call, expected);
        Err(error)
    }

    pub fn is_empty(&self) -> bool {
        self.queue.borrow().is_empty()
    }
}

impl LocalHandshakeV2 for &RpcErrors {
    async fn publish_v2(&self, request: PublishV2Request) -> protocol::Result<PublishV2Response> {
        self.fail(if request.manifest.unwrap().pq_enabled {
            "publish_on"
        } else {
            "publish_off"
        })
    }
    async fn get_server_info(
        &self,
        _: GetServerInfoRequest,
    ) -> protocol::Result<GetServerInfoResponse> {
        if let Some(info) = &self.server_info {
            return Ok(info.clone());
        }
        self.fail("get_server_info")
    }
    async fn refill_prekeys(
        &self,
        _: RefillPrekeysRequest,
    ) -> protocol::Result<RefillPrekeysResponse> {
        self.fail("refill_prekeys")
    }
    async fn get_manifest(&self, _: GetManifestRequest) -> protocol::Result<GetManifestResponse> {
        self.fail("get_manifest")
    }
    async fn claim_bundle(&self, _: ClaimBundleRequest) -> protocol::Result<ClaimBundleResponse> {
        self.fail("claim_bundle")
    }
    async fn send_initial_v2(
        &self,
        _: SendInitialV2Request,
    ) -> protocol::Result<SendInitialV2Response> {
        self.fail("send_initial_v2")
    }
    async fn list_initial_messages(
        &self,
        _: ListInitialMessagesRequest,
    ) -> protocol::Result<ListInitialMessagesResponse> {
        self.fail("list_initial_messages")
    }
    async fn ack_initial_messages(
        &self,
        _: AckInitialMessagesRequest,
    ) -> protocol::Result<AckInitialMessagesResponse> {
        self.fail("ack_initial_messages")
    }
}

impl LocalMailboxV2 for &RpcErrors {
    async fn push_v2(&self, _: PushV2Request) -> protocol::Result<PushV2Response> {
        self.fail("push_v2")
    }
    async fn fetch_signed(&self, _: FetchSignedRequest) -> protocol::Result<FetchSignedResponse> {
        self.fail("fetch_signed")
    }
    async fn ack_messages(&self, _: AckMessagesRequest) -> protocol::Result<AckMessagesResponse> {
        self.fail("ack_messages")
    }
    async fn register_write_token(
        &self,
        _: RegisterWriteTokenRequest,
    ) -> protocol::Result<RegisterWriteTokenResponse> {
        self.fail("register_write_token")
    }
    async fn revoke_write_token(
        &self,
        _: RevokeWriteTokenRequest,
    ) -> protocol::Result<RevokeWriteTokenResponse> {
        self.fail("revoke_write_token")
    }
}

#[derive(Clone, Copy)]
pub enum LostReply {
    CorruptBody,
    Transport,
}

impl protocol::connect::LocalPost for LostReply {
    async fn post(&self, _: &str, _: Vec<u8>) -> protocol::Result<(u16, Vec<u8>)> {
        match self {
            Self::CorruptBody => Ok((200, vec![0xff])),
            Self::Transport => Err(protocol::ErrorKind::Connect.into()),
        }
    }
}

/// Pure v2 server stub returning `Unimplemented` for all v2 procedures.
#[derive(Debug, Clone, Copy)]
pub struct UnimplementedV2Server;

impl LocalHandshakeV2 for UnimplementedV2Server {
    async fn get_server_info(
        &self,
        _: GetServerInfoRequest,
    ) -> protocol::Result<GetServerInfoResponse> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
    async fn publish_v2(&self, _: PublishV2Request) -> protocol::Result<PublishV2Response> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
    async fn refill_prekeys(
        &self,
        _: RefillPrekeysRequest,
    ) -> protocol::Result<RefillPrekeysResponse> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
    async fn get_manifest(&self, _: GetManifestRequest) -> protocol::Result<GetManifestResponse> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
    async fn claim_bundle(&self, _: ClaimBundleRequest) -> protocol::Result<ClaimBundleResponse> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
    async fn send_initial_v2(
        &self,
        _: SendInitialV2Request,
    ) -> protocol::Result<SendInitialV2Response> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
    async fn list_initial_messages(
        &self,
        _: ListInitialMessagesRequest,
    ) -> protocol::Result<ListInitialMessagesResponse> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
    async fn ack_initial_messages(
        &self,
        _: AckInitialMessagesRequest,
    ) -> protocol::Result<AckInitialMessagesResponse> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
}

impl LocalMailboxV2 for UnimplementedV2Server {
    async fn push_v2(&self, _: PushV2Request) -> protocol::Result<PushV2Response> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
    async fn fetch_signed(&self, _: FetchSignedRequest) -> protocol::Result<FetchSignedResponse> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
    async fn ack_messages(&self, _: AckMessagesRequest) -> protocol::Result<AckMessagesResponse> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
    async fn register_write_token(
        &self,
        _: RegisterWriteTokenRequest,
    ) -> protocol::Result<RegisterWriteTokenResponse> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
    async fn revoke_write_token(
        &self,
        _: RevokeWriteTokenRequest,
    ) -> protocol::Result<RevokeWriteTokenResponse> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
}

/// V2 handshake switching dynamically between `PQ_ENABLED=true` and `PQ_ENABLED=false`.
#[derive(Clone)]
pub struct ToggleableHandshake {
    pub pq_on: V2OnlyHandshake,
    pub pq_off: V2OnlyHandshake,
    pub enabled: Arc<AtomicBool>,
}

impl ToggleableHandshake {
    pub fn new(store: SharedStore, audience: &str) -> (Self, Arc<AtomicBool>) {
        let pq_on = V2OnlyHandshake::new(store.clone(), audience);
        let mut off_info = ServerInfoConfig::new(audience);
        off_info.pq_enabled = false;
        off_info.supported_suites.clear();
        off_info.pq_ratchet_supported = false;
        let pq_off = V2OnlyHandshake(Arc::new(HandshakeV2Server::new(store, off_info)));
        let enabled = Arc::new(AtomicBool::new(true));
        (
            Self {
                pq_on,
                pq_off,
                enabled: enabled.clone(),
            },
            enabled,
        )
    }

    fn current(&self) -> &V2OnlyHandshake {
        if self.enabled.load(Ordering::Relaxed) {
            &self.pq_on
        } else {
            &self.pq_off
        }
    }
}

impl LocalHandshakeV2 for ToggleableHandshake {
    async fn get_server_info(
        &self,
        r: GetServerInfoRequest,
    ) -> protocol::Result<GetServerInfoResponse> {
        self.current().get_server_info(r).await
    }
    async fn publish_v2(&self, r: PublishV2Request) -> protocol::Result<PublishV2Response> {
        self.current().publish_v2(r).await
    }
    async fn refill_prekeys(
        &self,
        r: RefillPrekeysRequest,
    ) -> protocol::Result<RefillPrekeysResponse> {
        self.current().refill_prekeys(r).await
    }
    async fn get_manifest(&self, r: GetManifestRequest) -> protocol::Result<GetManifestResponse> {
        self.current().get_manifest(r).await
    }
    async fn claim_bundle(&self, r: ClaimBundleRequest) -> protocol::Result<ClaimBundleResponse> {
        self.current().claim_bundle(r).await
    }
    async fn send_initial_v2(
        &self,
        r: SendInitialV2Request,
    ) -> protocol::Result<SendInitialV2Response> {
        self.current().send_initial_v2(r).await
    }
    async fn list_initial_messages(
        &self,
        r: ListInitialMessagesRequest,
    ) -> protocol::Result<ListInitialMessagesResponse> {
        self.current().list_initial_messages(r).await
    }
    async fn ack_initial_messages(
        &self,
        r: AckInitialMessagesRequest,
    ) -> protocol::Result<AckInitialMessagesResponse> {
        self.current().ack_initial_messages(r).await
    }
}

/// Malicious server wrapper simulating active downgrade attacks and corrupted inbox listings.
#[derive(Clone)]
pub struct AttackingHandshake {
    pub inner: V2OnlyHandshake,
    pub attack: AttackMode,
}

#[derive(Clone)]
pub enum AttackMode {
    StripPqPrekeys,
    StripManifest,
    StripSpkSignature,
    ForgeSpkSignature,
    ReplayBundle(Box<ClaimBundleResponse>),
    MixedInboxIds,
    #[cfg(all(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    DowngradeSuiteTo768,
}

impl LocalHandshakeV2 for AttackingHandshake {
    async fn get_server_info(
        &self,
        request: GetServerInfoRequest,
    ) -> protocol::Result<GetServerInfoResponse> {
        self.inner.get_server_info(request).await
    }
    async fn publish_v2(&self, request: PublishV2Request) -> protocol::Result<PublishV2Response> {
        self.inner.publish_v2(request).await
    }
    async fn refill_prekeys(
        &self,
        request: RefillPrekeysRequest,
    ) -> protocol::Result<RefillPrekeysResponse> {
        self.inner.refill_prekeys(request).await
    }
    async fn get_manifest(
        &self,
        request: GetManifestRequest,
    ) -> protocol::Result<GetManifestResponse> {
        self.inner.get_manifest(request).await
    }
    async fn claim_bundle(
        &self,
        request: ClaimBundleRequest,
    ) -> protocol::Result<ClaimBundleResponse> {
        match &self.attack {
            AttackMode::StripPqPrekeys => {
                let mut resp = self.inner.claim_bundle(request).await?;
                resp.pq_last_resort = None;
                resp.pq_one_time_prekey = None;
                Ok(resp)
            }
            AttackMode::StripManifest => {
                let mut resp = self.inner.claim_bundle(request).await?;
                resp.manifest = None;
                resp.pq_last_resort = None;
                resp.pq_one_time_prekey = None;
                Ok(resp)
            }
            AttackMode::StripSpkSignature => {
                let mut resp = self.inner.claim_bundle(request).await?;
                resp.signed_prekey_signature = None;
                Ok(resp)
            }
            AttackMode::ForgeSpkSignature => {
                let mut resp = self.inner.claim_bundle(request).await?;
                resp.signed_prekey_signature = Some(Bytes::from(vec![0xAB; 64]));
                Ok(resp)
            }
            AttackMode::ReplayBundle(captured) => Ok((**captured).clone()),
            AttackMode::MixedInboxIds => self.inner.claim_bundle(request).await,
            #[cfg(all(feature = "ml-kem-1024", feature = "ml-kem-768"))]
            AttackMode::DowngradeSuiteTo768 => {
                let mut request = request;
                request.preferred_suites = vec![u32::from(session::PqSuite::MlKem768.as_u8())];
                self.inner.claim_bundle(request).await
            }
        }
    }
    async fn send_initial_v2(
        &self,
        request: SendInitialV2Request,
    ) -> protocol::Result<SendInitialV2Response> {
        self.inner.send_initial_v2(request).await
    }
    async fn list_initial_messages(
        &self,
        request: ListInitialMessagesRequest,
    ) -> protocol::Result<ListInitialMessagesResponse> {
        let mut response = self.inner.list_initial_messages(request).await?;
        if let AttackMode::MixedInboxIds = self.attack
            && let Some(first) = response.messages.first().cloned()
        {
            assert_eq!(first.id, 1);
            let malformed = protocol::handshake_v2::InitialMessageV2 {
                id: 2,
                first_message: None,
                ..first.clone()
            };
            response.messages.extend([
                malformed.clone(),
                protocol::handshake_v2::InitialMessageV2 {
                    id: protocol::MAX_SAFE_INTEGER + 1,
                    ..malformed
                },
                protocol::handshake_v2::InitialMessageV2 {
                    id: u64::MAX,
                    ..first
                },
            ]);
        }
        Ok(response)
    }
    async fn ack_initial_messages(
        &self,
        request: AckInitialMessagesRequest,
    ) -> protocol::Result<AckInitialMessagesResponse> {
        if let AttackMode::MixedInboxIds = self.attack {
            assert_eq!(request.ids, [2, 1]);
        }
        self.inner.ack_initial_messages(request).await
    }
}

/// Runs Connect requests against real in-process v2 servers with configurable response faults.
pub struct InterruptedPost {
    pub hs: V2OnlyHandshake,
    pub mb: V2OnlyMailbox,
    pub fail_ack_on: Option<usize>,
    pub acknowledgements: Cell<usize>,
    pub lose_refill_response: bool,
}

impl protocol::connect::LocalPost for InterruptedPost {
    async fn post(&self, path: &str, body: Vec<u8>) -> protocol::Result<(u16, Vec<u8>)> {
        use protocol::connect::{CONTENT_TYPE, ProcedureV2, handle_v2};
        let procedure = ProcedureV2::from_path(path).unwrap();
        if procedure == ProcedureV2::AckInitialMessages {
            let call = self.acknowledgements.get() + 1;
            self.acknowledgements.set(call);
            if self.fail_ack_on == Some(call) {
                return Err(protocol::ErrorKind::Connect.into());
            }
        }
        let response = handle_v2(
            &self.hs,
            &self.mb,
            procedure,
            Some(CONTENT_TYPE),
            Bytes::from(body),
        )
        .await;
        if procedure == ProcedureV2::RefillPrekeys && self.lose_refill_response {
            assert_eq!(response.status, 200);
            return Ok((200, vec![0xff]));
        }
        Ok((response.status, response.body))
    }
}
