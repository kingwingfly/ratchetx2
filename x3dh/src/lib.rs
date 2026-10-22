#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod error;
pub mod server;

/// Re-export tonic.
pub use tonic::transport::{Certificate, Identity, Uri};

pub use server::RpcServer;

/// Tonic generated gRPC module.
pub(crate) mod x3dh_rpc {
    tonic::include_proto!("x3dh");
}

use std::{collections::HashMap, iter::repeat_with};

use hkdf::Hkdf;
use parking_lot::RwLock;
use primitives::{
    Party,
    transport::{RpcTransport, Transport},
};
use prost::Message as _;
use ratchetx2::{DhPrivateKey, SharedKeys};
use sha2::Sha256;
use tonic::{
    Request, Response, Result as RpcResult, Status,
    transport::{Channel, ClientTlsConfig, Server, ServerTlsConfig},
};
use x3dh_rpc::{
    AddAttemptRequest, AddAttemptResponse, FetchKeysRequest, FetchKeysResponse, ListAttemptRequest,
    ListAttemptResponse, PublishKeysRequest, PublishKeysResponse,
    x3dh_service_client::X3dhServiceClient,
    x3dh_service_server::{X3dhService, X3dhServiceServer},
};
use xeddsa::{XEdDSAPrivateKey, XEdDSAPublicKey};
use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind, Result};

/// X3DH gRPC client.
pub struct X3DHClient {
    rpc_client: X3dhServiceClient<Channel>,
    private_identity_key: XEdDSAPrivateKey,
    prekeys: HashMap<Vec<u8>, DhPrivateKey>,
    one_time_prekeys: HashMap<Vec<u8>, DhPrivateKey>,
    ca: Option<Certificate>,
}

impl X3DHClient {
    /// Connect to a X3DH gRPC server, generate XEdDSA private_identity_key randomly.
    ///
    /// If x3dh_server_addr scheme is https, native root certificate will be used.
    ///
    /// # Args:
    /// - x3dh_server_addr
    /// - private_identity_key: use provided private key instead of the randomly generated
    /// - ca: self-signed ca certificate if it's needed and x3dh_server_addr scheme is https
    pub async fn connect(
        x3dh_server_addr: impl TryInto<Uri>,
        private_identity_key: Option<XEdDSAPrivateKey>,
        ca: Option<Certificate>,
    ) -> Result<Self> {
        let uri: Uri = x3dh_server_addr
            .try_into()
            .map_err(|_| ErrorKind::InvalidAddress)?;
        let mut endpoint = Channel::builder(uri.clone());
        if uri.scheme_str() == Some("https") {
            endpoint = endpoint
                .tls_config({
                    let mut config = ClientTlsConfig::new().with_native_roots();
                    if let Some(ca) = ca.clone() {
                        config = config.ca_certificate(ca);
                    }
                    config
                })
                .map_err(|e| Error::new(ErrorKind::Connect, e))?;
        }
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| Error::new(ErrorKind::Connect, e))?;
        let rpc_client = X3dhServiceClient::new(channel);
        Ok(Self {
            rpc_client,
            private_identity_key: private_identity_key.unwrap_or_else(XEdDSAPrivateKey::generate),
            prekeys: HashMap::new(),
            one_time_prekeys: HashMap::new(),
            ca,
        })
    }

    /// Get public identity key.
    pub fn public_identity_key(&self) -> Vec<u8> {
        self.private_identity_key
            .compute_public_key()
            .as_ref()
            .to_vec()
    }

    /// Publish keys to X3DH server.
    pub async fn publish_keys(&mut self) -> Result<()> {
        let private_prekey = DhPrivateKey::generate();
        let public_prekey = private_prekey.public_key().to_vec();
        let prekey_signature = self.private_identity_key.sign(&public_prekey);
        let one_time_keys = repeat_with(|| {
            let private_one_time_key = DhPrivateKey::generate();
            let public_one_time_key = private_one_time_key.public_key().to_vec();
            (public_one_time_key, private_one_time_key)
        })
        .take(16)
        .collect::<Vec<_>>();
        let req = PublishKeysRequest {
            identity_key_bob: self.public_identity_key(),
            prekey: public_prekey.clone(),
            prekey_signature,
            one_time_keys: one_time_keys
                .iter()
                .map(|(public_key, _)| public_key.clone())
                .collect(),
        };
        let _resp = self
            .rpc_client
            .publish_keys(req)
            .await
            .map_err(|status| Error::new(ErrorKind::Push, status))?;
        self.prekeys.insert(public_prekey, private_prekey);
        self.one_time_prekeys.extend(one_time_keys);
        Ok(())
    }

    /// Fetch keys from X3DH server
    async fn fetch_keys(&mut self, identity_key_bob: &[u8]) -> Result<FetchKeysResponse> {
        Ok(self
            .rpc_client
            .fetch_keys(FetchKeysRequest {
                identity_key_bob: identity_key_bob.to_vec(),
            })
            .await
            .map_err(|status| Error::new(ErrorKind::Fetch, status))?
            .into_inner())
    }

    /// Perform X3DH, push the initial message, return Alice Party.
    ///
    /// Alice fetches Bob's "prekey bundle" from the X3DH server,
    /// and derive shared keys, push the initial message and the associated data to message server.
    pub async fn push_initial_message(
        &mut self,
        identity_key_bob: &[u8],
        message_server_addr: impl TryInto<Uri>,
    ) -> Result<Party<RpcTransport>> {
        let keys = self.fetch_keys(identity_key_bob).await?;

        // Use the identity key Alice asked for, never the one the server sends back.
        XEdDSAPublicKey::new(identity_key_bob)?.verify(&keys.prekey, &keys.prekey_signature)?;

        // Alice deletes her ephemeral private key and the DH outputs once SK is derived: they
        // live only in this block, which ends before any network round-trip.
        let (ephemeral_public_key, shared_keys) = {
            let ephemeral_private_key = DhPrivateKey::generate();
            let mut key_meterial = new_key_meterial();
            key_meterial
                .extend_from_slice(&*self.private_identity_key.diffie_hellman(&keys.prekey)?);
            key_meterial
                .extend_from_slice(&*ephemeral_private_key.diffie_hellman(identity_key_bob)?);
            key_meterial.extend_from_slice(&*ephemeral_private_key.diffie_hellman(&keys.prekey)?);
            if let Some(one_time_key) = keys.one_time_key.as_ref() {
                key_meterial
                    .extend_from_slice(&*ephemeral_private_key.diffie_hellman(one_time_key)?);
            }
            (
                ephemeral_private_key.public_key().to_vec(),
                derive_shared_keys(&key_meterial),
            )
        };

        let mut associated_data: Vec<u8> = vec![];
        let my_identity_key = self.public_identity_key();
        associated_data.extend(&my_identity_key);
        associated_data.extend(identity_key_bob);
        let init_msg = InitMassage {
            identity_key_alice: self.public_identity_key(),
            ephemeral_public_key_alice: ephemeral_public_key,
            prekey_bob: keys.prekey.clone(),
            one_time_prekey_bob: keys.one_time_key,
        };
        let mut messgae_transport = RpcTransport::connect(
            message_server_addr,
            &my_identity_key,
            identity_key_bob,
            self.ca.clone(),
        )
        .await?;
        messgae_transport
            .push_bytes(init_msg.encode_to_vec())
            .await?;
        self.rpc_client
            .add_attempt(Request::new(AddAttemptRequest {
                identity_key_alice: my_identity_key,
                identity_key_bob: identity_key_bob.to_vec(),
            }))
            .await
            .map_err(|status| Error::new(ErrorKind::Push, status))?;

        let alice = Party::new(
            shared_keys.alice(&keys.prekey)?,
            messgae_transport,
            associated_data,
        );
        Ok(alice)
    }

    /// List identity keys of Alices who want to connect to Bob with provided identity_key_bob.
    pub async fn list_attempt(&mut self, identity_key_bob: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.rpc_client
            .list_attempt(Request::new(ListAttemptRequest {
                identity_key_bob: identity_key_bob.to_vec(),
            }))
            .await
            .map_err(|status| Error::new(ErrorKind::Fetch, status))
            .map(|resp| resp.into_inner().identity_key_alice)
    }

    /// Perform X3DH, handle the initial message, return Bob Party.
    ///
    /// After publishing keys and Alice's pushing initial message,
    /// Bob should initialize itself with the initial message.
    pub async fn handle_initial_message(
        &mut self,
        identity_key_alice: &[u8],
        message_server_addr: impl TryInto<Uri>,
    ) -> Result<Party<RpcTransport>> {
        let my_identity_key = self.public_identity_key();
        let mut associated_data: Vec<u8> = vec![];
        associated_data.extend(identity_key_alice);
        associated_data.extend(&my_identity_key);

        let mut message_transport = RpcTransport::connect(
            message_server_addr,
            &my_identity_key,
            identity_key_alice,
            self.ca.clone(),
        )
        .await?;
        let initial_message = InitMassage::decode(
            message_transport
                .fetch_bytes(Some(1))
                .await?
                .first()
                .ok_or(ErrorKind::InitialMessageNotFound)?
                .as_slice(),
        )
        .map_err(|e| Error::new(ErrorKind::InvalidInitialMessage, e))?;
        // X3DH authenticates Alice through DH1 with her identity key, so it must be the one
        // Bob expects; otherwise anyone could start a session as Alice.
        if initial_message.identity_key_alice != identity_key_alice {
            return Err(ErrorKind::UnexpectedIdentity.into());
        }

        let mut key_meterial = new_key_meterial();
        let private_prekey = self
            .prekeys
            .get(&initial_message.prekey_bob)
            .ok_or(ErrorKind::PrekeyNotFound)?;
        key_meterial.extend_from_slice(&*private_prekey.diffie_hellman(identity_key_alice)?);
        key_meterial.extend_from_slice(
            &*self
                .private_identity_key
                .diffie_hellman(&initial_message.ephemeral_public_key_alice)?,
        );
        key_meterial.extend_from_slice(
            &*private_prekey.diffie_hellman(&initial_message.ephemeral_public_key_alice)?,
        );
        if let Some(one_time_public_prekey) = initial_message.one_time_prekey_bob {
            key_meterial.extend_from_slice(
                &*self
                    .one_time_prekeys
                    .remove(&one_time_public_prekey)
                    .ok_or(ErrorKind::OneTimePrekeyNotFound)?
                    .diffie_hellman(&initial_message.ephemeral_public_key_alice)?,
            );
        }
        // The signed prekey stays published for other Alices, so Bob's ratchet gets a copy.
        let private_prekey = private_prekey.clone();
        let shared_keys = derive_shared_keys(&key_meterial);

        Ok(Party::new(
            shared_keys.bob(private_prekey),
            message_transport,
            associated_data,
        ))
    }
}

/// X3DH key material, starting with the 32 0xFF bytes of the X25519 domain separator.
fn new_key_meterial() -> Zeroizing<Vec<u8>> {
    // Room for the separator and all four DH outputs, so growing never leaves unzeroized copies.
    let mut key_meterial = Zeroizing::new(Vec::with_capacity(32 * 5));
    key_meterial.extend([0xFF; 32]);
    key_meterial
}

/// Derive SK from the key material and split it into the root key and both header keys.
fn derive_shared_keys(key_meterial: &[u8]) -> SharedKeys {
    let mut secret_key = Zeroizing::new([0; 96]);
    Hkdf::<Sha256>::new(Some(&[0; 96]), key_meterial)
        .expand(b"X3DH", secret_key.as_mut_slice())
        .unwrap();
    SharedKeys {
        secret_key: secret_key[..32].try_into().unwrap(),
        header_key_alice: secret_key[32..64].try_into().unwrap(),
        header_key_bob: secret_key[64..].try_into().unwrap(),
    }
}

/// The gRPC server to store and distribute the public keys.
pub struct RpcX3DHServer {}

impl RpcX3DHServer {
    /// Run a RpcX3DHServer listening on addr.
    pub async fn run(addr: impl AsRef<str>, identity: Option<Identity>) -> Result<()> {
        let addr = addr
            .as_ref()
            .parse()
            .map_err(|e| Error::new(ErrorKind::InvalidAddress, e))?;
        let mut server = Server::builder();
        if let Some(identity) = identity {
            server = server
                .tls_config(ServerTlsConfig::new().identity(identity))
                .map_err(|e| Error::new(ErrorKind::Server, e))?;
        }
        server
            .add_service(X3dhServiceServer::new(RpcX3DHInner::default()))
            .serve(addr)
            .await
            .map_err(|e| Error::new(ErrorKind::Server, e))?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(crate) struct RpcX3DHInner {
    published_keys: RwLock<HashMap<Vec<u8>, PublishedKeys>>,
    attempts: RwLock<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
}

#[derive(Debug)]
struct PublishedKeys {
    prekey: Vec<u8>,
    prekey_signature: Vec<u8>,
    one_time_keys: Vec<Vec<u8>>,
}

#[tonic::async_trait]
impl X3dhService for RpcX3DHInner {
    async fn publish_keys(
        &self,
        request: Request<PublishKeysRequest>,
    ) -> RpcResult<Response<PublishKeysResponse>> {
        let keys = request.into_inner();
        self.published_keys.write().insert(
            keys.identity_key_bob.clone(),
            PublishedKeys {
                prekey: keys.prekey,
                prekey_signature: keys.prekey_signature,
                one_time_keys: keys.one_time_keys,
            },
        );
        Ok(Response::new(PublishKeysResponse {}))
    }

    async fn fetch_keys(
        &self,
        request: Request<FetchKeysRequest>,
    ) -> RpcResult<Response<FetchKeysResponse>> {
        let identity_key_bob = request.into_inner().identity_key_bob;
        match self.published_keys.write().get_mut(&identity_key_bob) {
            Some(keys) => Ok(Response::new(FetchKeysResponse {
                identity_key_bob,
                prekey: keys.prekey.clone(),
                prekey_signature: keys.prekey_signature.clone(),
                one_time_key: keys.one_time_keys.pop(),
            })),
            None => Err(Status::not_found("identity_key_bob not found".to_string())),
        }
    }

    async fn add_attempt(
        &self,
        request: Request<AddAttemptRequest>,
    ) -> RpcResult<Response<AddAttemptResponse>> {
        let AddAttemptRequest {
            identity_key_alice,
            identity_key_bob,
        } = request.into_inner();
        self.attempts
            .write()
            .entry(identity_key_bob)
            .or_default()
            .push(identity_key_alice);
        Ok(Response::new(AddAttemptResponse {}))
    }

    async fn list_attempt(
        &self,
        request: Request<ListAttemptRequest>,
    ) -> RpcResult<Response<ListAttemptResponse>> {
        let identity_key_bob = request.into_inner().identity_key_bob;
        Ok(Response::new(ListAttemptResponse {
            identity_key_alice: self
                .attempts
                .read()
                .get(&identity_key_bob)
                .cloned()
                .unwrap_or_default(),
        }))
    }
}

/// The initial message.
#[derive(prost::Message)]
pub struct InitMassage {
    #[prost(bytes = "vec", tag = "1")]
    identity_key_alice: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    ephemeral_public_key_alice: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    prekey_bob: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "4")]
    one_time_prekey_bob: Option<Vec<u8>>,
}
