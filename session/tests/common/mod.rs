//! Shared in-process storage, handshake, mailbox, and fault-injection harnesses for `session`
//! integration tests.

#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
#[allow(deprecated)]
use protocol::{
    content::{Hello, Kind as ContentKind},
    handshake::{
        FetchBundleRequest, FetchBundleResponse, HandshakeServer, LocalHandshake, PublishRequest,
        PublishResponse, SendInitialMessageRequest, SendInitialMessageResponse,
        TakeInitialMessagesRequest, TakeInitialMessagesResponse,
    },
    handshake_v2::{
        AckInitialMessagesRequest, AckInitialMessagesResponse, ClaimBundleRequest,
        ClaimBundleResponse, GetManifestRequest, GetManifestResponse, GetServerInfoRequest,
        GetServerInfoResponse, HandshakeV2Server, ListInitialMessagesRequest,
        ListInitialMessagesResponse, LocalHandshakeV2, PublishV2Request, PublishV2Response,
        RefillPrekeysRequest, RefillPrekeysResponse, SendInitialV2Request, SendInitialV2Response,
        ServerInfoConfig,
    },
    mailbox::{
        FetchRequest, FetchResponse, LocalMailbox, MailboxLimits, MailboxServer, PushRequest,
        PushResponse,
    },
    mailbox_v2::{
        FetchSignedRequest, FetchSignedResponse, LocalMailboxV2, MailboxV2Server, PushV2Request,
        PushV2Response,
    },
};
use session::PublicKey;
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

/// Shared `Arc<MemoryStore>` implementing both v1 and v2 storage traits, including atomic
/// `claim_bundle_checked` and byte-bounded `read_bounded`.
#[derive(Debug, Clone, Default)]
pub struct SharedStore(pub Arc<MemoryStore>);

#[allow(deprecated)]
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

#[allow(deprecated)]
impl storage::LocalMailboxStore for SharedStore {
    async fn append(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        delivery_hash: Option<[u8; 32]>,
    ) -> storage::Result<u64> {
        storage::MailboxStore::append(
            &*self.0,
            sender,
            recipient,
            header,
            content,
            initial_message,
            delivery_hash,
        )
        .await
    }

    async fn delete_delivered(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        hashes: &[[u8; 32]],
    ) -> storage::Result<()> {
        storage::MailboxStore::delete_delivered(&*self.0, sender, recipient, hashes).await
    }

    async fn read(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
    ) -> storage::Result<Vec<storage::StoredMessage>> {
        storage::MailboxStore::read(&*self.0, sender, recipient, after, limit).await
    }
}

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
        limit: usize,
    ) -> storage::Result<Vec<storage::StoredInitialMessageV2>> {
        storage::PqHandshakeStore::list_initial_messages(&*self.0, recipient, limit).await
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
        storage::IdempotentMailboxStore::delete_delivered(&*self.0, sender, recipient, hashes).await
    }

    async fn read(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
    ) -> storage::Result<Vec<storage::StoredMessage>> {
        storage::IdempotentMailboxStore::read(&*self.0, sender, recipient, after, limit).await
    }

    async fn read_bounded(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
        max_bytes: usize,
    ) -> storage::Result<Vec<storage::StoredMessage>> {
        storage::IdempotentMailboxStore::read_bounded(
            &*self.0, sender, recipient, after, limit, max_bytes,
        )
        .await
    }
}

#[allow(deprecated)]
#[derive(Debug, Clone)]
pub struct V1Handshake(pub Arc<HandshakeServer<SharedStore>>);

#[allow(deprecated)]
impl LocalHandshake for V1Handshake {
    async fn publish(&self, request: PublishRequest) -> protocol::Result<PublishResponse> {
        self.0.publish(request).await
    }
    async fn fetch_bundle(
        &self,
        request: FetchBundleRequest,
    ) -> protocol::Result<FetchBundleResponse> {
        self.0.fetch_bundle(request).await
    }
    async fn send_initial_message(
        &self,
        request: SendInitialMessageRequest,
    ) -> protocol::Result<SendInitialMessageResponse> {
        self.0.send_initial_message(request).await
    }
    async fn take_initial_messages(
        &self,
        request: TakeInitialMessagesRequest,
    ) -> protocol::Result<TakeInitialMessagesResponse> {
        self.0.take_initial_messages(request).await
    }
}

#[allow(deprecated)]
#[derive(Debug, Clone)]
pub struct V1Mailbox(pub Arc<MailboxServer<SharedStore>>);

#[allow(deprecated)]
impl LocalMailbox for V1Mailbox {
    async fn push(&self, request: PushRequest) -> protocol::Result<PushResponse> {
        self.0.push(request).await
    }
    async fn fetch(&self, request: FetchRequest) -> protocol::Result<FetchResponse> {
        self.0.fetch(request).await
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
        Self(Arc::new(
            MailboxV2Server::builder(store)
                .server_id(audience.to_string())
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
}

#[allow(deprecated)]
#[derive(Clone)]
pub struct DualHandshake {
    pub v1: Arc<HandshakeServer<SharedStore>>,
    pub v2: Arc<HandshakeV2Server<SharedStore>>,
}

#[allow(deprecated)]
impl DualHandshake {
    pub fn new(store: SharedStore, audience: &str) -> Self {
        Self {
            v1: Arc::new(HandshakeServer::new(store.clone())),
            v2: Arc::new(HandshakeV2Server::new(
                store,
                ServerInfoConfig::new(audience),
            )),
        }
    }
}

#[allow(deprecated)]
impl LocalHandshake for DualHandshake {
    async fn publish(&self, request: PublishRequest) -> protocol::Result<PublishResponse> {
        self.v1.publish(request).await
    }
    async fn fetch_bundle(
        &self,
        request: FetchBundleRequest,
    ) -> protocol::Result<FetchBundleResponse> {
        self.v1.fetch_bundle(request).await
    }
    async fn send_initial_message(
        &self,
        request: SendInitialMessageRequest,
    ) -> protocol::Result<SendInitialMessageResponse> {
        self.v1.send_initial_message(request).await
    }
    async fn take_initial_messages(
        &self,
        request: TakeInitialMessagesRequest,
    ) -> protocol::Result<TakeInitialMessagesResponse> {
        self.v1.take_initial_messages(request).await
    }
}

impl LocalHandshakeV2 for DualHandshake {
    async fn get_server_info(
        &self,
        request: GetServerInfoRequest,
    ) -> protocol::Result<GetServerInfoResponse> {
        self.v2.get_server_info(request).await
    }
    async fn publish_v2(&self, request: PublishV2Request) -> protocol::Result<PublishV2Response> {
        self.v2.publish_v2(request).await
    }
    async fn refill_prekeys(
        &self,
        request: RefillPrekeysRequest,
    ) -> protocol::Result<RefillPrekeysResponse> {
        self.v2.refill_prekeys(request).await
    }
    async fn get_manifest(
        &self,
        request: GetManifestRequest,
    ) -> protocol::Result<GetManifestResponse> {
        self.v2.get_manifest(request).await
    }
    async fn claim_bundle(
        &self,
        request: ClaimBundleRequest,
    ) -> protocol::Result<ClaimBundleResponse> {
        self.v2.claim_bundle(request).await
    }
    async fn send_initial_v2(
        &self,
        request: SendInitialV2Request,
    ) -> protocol::Result<SendInitialV2Response> {
        self.v2.send_initial_v2(request).await
    }
    async fn list_initial_messages(
        &self,
        request: ListInitialMessagesRequest,
    ) -> protocol::Result<ListInitialMessagesResponse> {
        self.v2.list_initial_messages(request).await
    }
    async fn ack_initial_messages(
        &self,
        request: AckInitialMessagesRequest,
    ) -> protocol::Result<AckInitialMessagesResponse> {
        self.v2.ack_initial_messages(request).await
    }
}

#[allow(deprecated)]
#[derive(Debug, Clone)]
pub struct DualMailbox {
    pub v1: Arc<MailboxServer<SharedStore>>,
    pub v2: Arc<MailboxV2Server<SharedStore>>,
}

#[allow(deprecated)]
impl DualMailbox {
    pub fn new(store: SharedStore, audience: &str) -> Self {
        Self::with_limits(store, audience, MailboxLimits::default())
    }

    pub fn with_limits(store: SharedStore, audience: &str, limits: MailboxLimits) -> Self {
        Self {
            v1: Arc::new(MailboxServer::builder(store.clone()).limits(limits).build()),
            v2: Arc::new(
                MailboxV2Server::builder(store)
                    .server_id(audience.to_string())
                    .limits(limits)
                    .build(),
            ),
        }
    }
}

#[allow(deprecated)]
impl LocalMailbox for DualMailbox {
    async fn push(&self, request: PushRequest) -> protocol::Result<PushResponse> {
        self.v1.push(request).await
    }
    async fn fetch(&self, request: FetchRequest) -> protocol::Result<FetchResponse> {
        self.v1.fetch(request).await
    }
}

impl LocalMailboxV2 for DualMailbox {
    async fn push_v2(&self, request: PushV2Request) -> protocol::Result<PushV2Response> {
        self.v2.push_v2(request).await
    }
    async fn fetch_signed(
        &self,
        request: FetchSignedRequest,
    ) -> protocol::Result<FetchSignedResponse> {
        self.v2.fetch_signed(request).await
    }
}

/// Scripted fault injector for handshake & mailbox RPCs. Each expected RPC fails with its supplied
/// error; optionally replies with a fixed `GetServerInfoResponse` for `get_server_info`.
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

#[allow(deprecated)]
impl LocalHandshake for &RpcErrors {
    async fn publish(&self, _: PublishRequest) -> protocol::Result<PublishResponse> {
        self.fail("publish")
    }
    async fn fetch_bundle(&self, _: FetchBundleRequest) -> protocol::Result<FetchBundleResponse> {
        self.fail("fetch_bundle")
    }
    async fn send_initial_message(
        &self,
        _: SendInitialMessageRequest,
    ) -> protocol::Result<SendInitialMessageResponse> {
        self.fail("send_initial_message")
    }
    async fn take_initial_messages(
        &self,
        _: TakeInitialMessagesRequest,
    ) -> protocol::Result<TakeInitialMessagesResponse> {
        self.fail("take_initial_messages")
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

#[allow(deprecated)]
impl LocalMailbox for &RpcErrors {
    async fn push(&self, _: PushRequest) -> protocol::Result<PushResponse> {
        self.fail("push")
    }
    async fn fetch(&self, _: FetchRequest) -> protocol::Result<FetchResponse> {
        self.fail("fetch")
    }
}

impl LocalMailboxV2 for &RpcErrors {
    async fn push_v2(&self, _: PushV2Request) -> protocol::Result<PushV2Response> {
        self.fail("push_v2")
    }
    async fn fetch_signed(&self, _: FetchSignedRequest) -> protocol::Result<FetchSignedResponse> {
        self.fail("fetch_signed")
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

/// Generic expiring wrapper for both v1 and v2 mailboxes.
#[derive(Clone)]
pub struct ExpiringMailbox<M> {
    pub inner: M,
    pub expired_seqs: Arc<Mutex<Vec<u64>>>,
    pub fetches: Arc<AtomicUsize>,
}

impl<M> ExpiringMailbox<M> {
    pub fn new(inner: M, expired_seqs: Vec<u64>) -> Self {
        Self {
            inner,
            expired_seqs: Arc::new(Mutex::new(expired_seqs)),
            fetches: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn with_shared(inner: M, expired_seqs: Arc<Mutex<Vec<u64>>>) -> Self {
        Self {
            inner,
            expired_seqs,
            fetches: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[allow(deprecated)]
impl<M: LocalMailbox> LocalMailbox for ExpiringMailbox<M> {
    async fn push(&self, request: PushRequest) -> protocol::Result<PushResponse> {
        self.inner.push(request).await
    }

    async fn fetch(&self, request: FetchRequest) -> protocol::Result<FetchResponse> {
        self.fetches.fetch_add(1, Ordering::Relaxed);
        let mut resp = self.inner.fetch(request).await?;
        let expired = self.expired_seqs.lock().unwrap().clone();
        for env in &mut resp.messages {
            if expired.contains(&env.sequence) {
                env.message = None;
            }
        }
        Ok(resp)
    }
}

impl<M: LocalMailboxV2> LocalMailboxV2 for ExpiringMailbox<M> {
    async fn push_v2(&self, request: PushV2Request) -> protocol::Result<PushV2Response> {
        self.inner.push_v2(request).await
    }

    async fn fetch_signed(
        &self,
        request: FetchSignedRequest,
    ) -> protocol::Result<FetchSignedResponse> {
        self.fetches.fetch_add(1, Ordering::Relaxed);
        let mut resp = self.inner.fetch_signed(request).await?;
        let expired = self.expired_seqs.lock().unwrap().clone();
        for env in &mut resp.messages {
            if expired.contains(&env.sequence) {
                env.message = None;
            }
        }
        Ok(resp)
    }
}

/// Mailbox that returns an endless stream of expired envelopes (for both v1 and v2).
#[derive(Debug, Clone)]
pub struct InfiniteExpiredMailbox {
    pub fetches: Arc<AtomicUsize>,
}

#[allow(deprecated)]
impl LocalMailbox for InfiniteExpiredMailbox {
    async fn push(&self, _: PushRequest) -> protocol::Result<PushResponse> {
        Ok(PushResponse::default())
    }
    async fn fetch(&self, request: FetchRequest) -> protocol::Result<FetchResponse> {
        assert_eq!(request.limit, 100);
        self.fetches.fetch_add(1, Ordering::Relaxed);
        Ok(FetchResponse {
            messages: vec![protocol::mailbox::Envelope {
                sequence: request.after + 1,
                message: None,
                initial_message: None,
            }],
        })
    }
}

impl LocalMailboxV2 for InfiniteExpiredMailbox {
    async fn push_v2(&self, _: PushV2Request) -> protocol::Result<PushV2Response> {
        Ok(PushV2Response::default())
    }
    async fn fetch_signed(
        &self,
        request: FetchSignedRequest,
    ) -> protocol::Result<FetchSignedResponse> {
        assert_eq!(request.limit, 100);
        self.fetches.fetch_add(1, Ordering::Relaxed);
        Ok(FetchSignedResponse {
            messages: vec![protocol::mailbox_v2::EnvelopeV2 {
                sequence: request.after + 1,
                message: None,
                initial_message: None,
            }],
        })
    }
}

/// Legacy v1-only server returning `Unimplemented` for all v2 procedures.
#[allow(deprecated)]
#[derive(Debug, Clone)]
pub struct V1OnlyServer {
    pub hs: V1Handshake,
    pub mb: V1Mailbox,
}

#[allow(deprecated)]
impl V1OnlyServer {
    pub fn new(store: SharedStore) -> Self {
        Self {
            hs: V1Handshake(Arc::new(HandshakeServer::new(store.clone()))),
            mb: V1Mailbox(Arc::new(MailboxServer::new(store))),
        }
    }
}

#[allow(deprecated)]
impl LocalHandshake for V1OnlyServer {
    async fn publish(&self, r: PublishRequest) -> protocol::Result<PublishResponse> {
        self.hs.publish(r).await
    }
    async fn fetch_bundle(&self, r: FetchBundleRequest) -> protocol::Result<FetchBundleResponse> {
        self.hs.fetch_bundle(r).await
    }
    async fn send_initial_message(
        &self,
        r: SendInitialMessageRequest,
    ) -> protocol::Result<SendInitialMessageResponse> {
        self.hs.send_initial_message(r).await
    }
    async fn take_initial_messages(
        &self,
        r: TakeInitialMessagesRequest,
    ) -> protocol::Result<TakeInitialMessagesResponse> {
        self.hs.take_initial_messages(r).await
    }
}

impl LocalHandshakeV2 for V1OnlyServer {
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

#[allow(deprecated)]
impl LocalMailbox for V1OnlyServer {
    async fn push(&self, r: PushRequest) -> protocol::Result<PushResponse> {
        self.mb.push(r).await
    }
    async fn fetch(&self, r: FetchRequest) -> protocol::Result<FetchResponse> {
        self.mb.fetch(r).await
    }
}

impl LocalMailboxV2 for V1OnlyServer {
    async fn push_v2(&self, _: PushV2Request) -> protocol::Result<PushV2Response> {
        Err(protocol::ErrorKind::Unimplemented.into())
    }
    async fn fetch_signed(&self, _: FetchSignedRequest) -> protocol::Result<FetchSignedResponse> {
        Err(protocol::ErrorKind::Unimplemented.into())
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
}

/// Dual handshake switching dynamically between `PQ_ENABLED=true` and `PQ_ENABLED=false`.
#[allow(deprecated)]
#[derive(Clone)]
pub struct ToggleableHandshake {
    pub pq_on: DualHandshake,
    pub pq_off: DualHandshake,
    pub enabled: Arc<AtomicBool>,
}

#[allow(deprecated)]
impl ToggleableHandshake {
    pub fn new(store: SharedStore, audience: &str) -> (Self, Arc<AtomicBool>) {
        let pq_on = DualHandshake::new(store.clone(), audience);
        let mut off_info = ServerInfoConfig::new(audience);
        off_info.pq_enabled = false;
        off_info.supported_suites.clear();
        off_info.pq_ratchet_supported = false;
        let pq_off = DualHandshake {
            v1: Arc::new(HandshakeServer::new(store.clone())),
            v2: Arc::new(HandshakeV2Server::new(store, off_info)),
        };
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

    fn current(&self) -> &DualHandshake {
        if self.enabled.load(Ordering::Relaxed) {
            &self.pq_on
        } else {
            &self.pq_off
        }
    }
}

#[allow(deprecated)]
impl LocalHandshake for ToggleableHandshake {
    async fn publish(&self, r: PublishRequest) -> protocol::Result<PublishResponse> {
        self.current().publish(r).await
    }
    async fn fetch_bundle(&self, r: FetchBundleRequest) -> protocol::Result<FetchBundleResponse> {
        self.current().fetch_bundle(r).await
    }
    async fn send_initial_message(
        &self,
        r: SendInitialMessageRequest,
    ) -> protocol::Result<SendInitialMessageResponse> {
        self.current().send_initial_message(r).await
    }
    async fn take_initial_messages(
        &self,
        r: TakeInitialMessagesRequest,
    ) -> protocol::Result<TakeInitialMessagesResponse> {
        self.current().take_initial_messages(r).await
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
#[allow(deprecated)]
#[derive(Clone)]
pub struct AttackingHandshake {
    pub inner: DualHandshake,
    pub attack: AttackMode,
}

#[derive(Clone)]
pub enum AttackMode {
    StripPqPrekeys,
    StripManifest,
    ReplayBundle(Box<ClaimBundleResponse>),
    MixedInboxIds,
    #[cfg(all(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    DowngradeSuiteTo768,
}

#[allow(deprecated)]
impl LocalHandshake for AttackingHandshake {
    async fn publish(&self, request: PublishRequest) -> protocol::Result<PublishResponse> {
        self.inner.publish(request).await
    }
    async fn fetch_bundle(
        &self,
        request: FetchBundleRequest,
    ) -> protocol::Result<FetchBundleResponse> {
        self.inner.fetch_bundle(request).await
    }
    async fn send_initial_message(
        &self,
        request: SendInitialMessageRequest,
    ) -> protocol::Result<SendInitialMessageResponse> {
        self.inner.send_initial_message(request).await
    }
    async fn take_initial_messages(
        &self,
        request: TakeInitialMessagesRequest,
    ) -> protocol::Result<TakeInitialMessagesResponse> {
        self.inner.take_initial_messages(request).await
    }
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
#[allow(deprecated)]
pub struct InterruptedPost {
    pub hs: DualHandshake,
    pub mb: DualMailbox,
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
        let response = handle_v2(&self.hs, &self.mb, procedure, Some(CONTENT_TYPE), &body).await;
        if procedure == ProcedureV2::RefillPrekeys && self.lose_refill_response {
            assert_eq!(response.status, 200);
            return Ok((200, vec![0xff]));
        }
        Ok((response.status, response.body))
    }
}
