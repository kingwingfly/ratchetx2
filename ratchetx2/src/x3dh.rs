//! Initialize the shared keys between two parties with [Extended Triple Diffie-Hellman](https://signal.org/docs/specifications/x3dh/).
//!
//! # Example
//! ```
//! use ratchetx2::server::RpcServer;
//! use ratchetx2::x3dh::X3DHClient;
//!
//! # #[tokio::main]
//! # async fn main() {
//! tokio::spawn(async {
//!     RpcServer::run("127.0.0.1:3001", None).await.unwrap();
//! });
//! // wait server start
//! tokio::time::sleep(std::time::Duration::from_millis(100)).await;
//!
//! const SERVER_ADDR: &str = "http://127.0.0.1:3001";
//!
//! let mut alice_x3dh = X3DHClient::connect(SERVER_ADDR, None, None).await.unwrap();
//! let mut bob_x3dh = X3DHClient::connect(SERVER_ADDR, None, None).await.unwrap();
//! bob_x3dh.publish_keys().await.unwrap();
//! let mut alice = alice_x3dh
//!     .push_initial_message(&bob_x3dh.public_identity_key(), SERVER_ADDR)
//!     .await
//!     .unwrap();
//! assert_eq!(
//!     bob_x3dh.list_attempt(&bob_x3dh.public_identity_key()).await.unwrap().pop().unwrap(),
//!     alice_x3dh.public_identity_key()
//! );
//! let mut bob = bob_x3dh
//!     .handle_initial_message(&alice_x3dh.public_identity_key(), SERVER_ADDR)
//!     .await
//!     .unwrap();
//! alice.push("hello world").await.unwrap();
//! assert_eq!(
//!     bob.fetch().await.unwrap().remove(0).unwrap(),
//!     b"hello world"
//! );
//! alice.push("hello Bob").await.unwrap();
//! assert_eq!(
//!     bob.fetch().await.unwrap().remove(0).unwrap(),
//!     b"hello Bob"
//! );
//! bob.push("hello Alice").await.unwrap();
//! assert_eq!(
//!     alice.fetch().await.unwrap().remove(0).unwrap(),
//!     b"hello Alice"
//! );
//! # }
//! ```

/// Tonic generated gRPC module.
pub(crate) mod x3dh_rpc {
    tonic::include_proto!("x3dh");
}

use std::collections::HashMap;

use bincode::{Decode, Encode};
use parking_lot::RwLock;
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral};
use ring::hkdf::{HKDF_SHA256, KeyType, Salt};
use ring::rand::SystemRandom;
use tonic::Status;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig, Uri};
use tonic::transport::{Channel, ClientTlsConfig};
use tonic::{Request, Response, Result as RpcResult};
use x3dh_rpc::x3dh_service_client::X3dhServiceClient;
use x3dh_rpc::x3dh_service_server::{X3dhService, X3dhServiceServer};
use x3dh_rpc::{
    AddAttemptRequest, AddAttemptResponse, FetchKeysRequest, FetchKeysResponse, ListAttemptRequest,
    ListAttemptResponse, PublishKeysRequest, PublishKeysResponse,
};

use crate::error::Error;
use crate::error::{Result, TransportError};
use crate::transport::RpcTransport;
use crate::xeddsa::{XEdDSAPrivateKey, XEdDSAPublicKey};
use crate::{Party, SharedKeys, transport::Transport};

/// X3DH gRPC client.
pub struct X3DHClient {
    rpc_client: X3dhServiceClient<Channel>,
    private_identity_key: XEdDSAPrivateKey,
    prekeys: HashMap<Vec<u8>, EphemeralPrivateKey>,
    one_time_prekeys: HashMap<Vec<u8>, EphemeralPrivateKey>,
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
    /// - ca: self-signed ca certificate if x3dh_server_addr scheme is https
    pub async fn connect(
        x3dh_server_addr: impl TryInto<Uri>,
        private_identity_key: Option<XEdDSAPrivateKey>,
        ca: Option<Certificate>,
    ) -> Result<Self> {
        let uri: Uri = x3dh_server_addr
            .try_into()
            .unwrap_or_else(|_| panic!("Invalid x3dh server address."));
        let mut endpoint = Channel::builder(uri.clone());
        if uri.scheme_str() == Some("https") {
            endpoint = endpoint
                .tls_config({
                    let mut config = ClientTlsConfig::new().with_native_roots();
                    if let Some(ca) = ca.clone() {
                        config = config.ca_certificate(ca).domain_name("127.0.0.1");
                    }
                    config
                })
                .unwrap();
        }
        let channel = endpoint
            .connect()
            .await
            .map_err(|_| TransportError::Connect)?;
        let rpc_client = X3dhServiceClient::new(channel);
        Ok(Self {
            rpc_client,
            private_identity_key: private_identity_key
                .unwrap_or(XEdDSAPrivateKey::generate(&SystemRandom::new())),
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
        let private_prekey = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).unwrap();
        let public_prekey = private_prekey
            .compute_public_key()
            .unwrap()
            .as_ref()
            .to_vec();
        let prekey_signature = self.private_identity_key.sign(&public_prekey);
        let mut one_time_keys = vec![];
        for _ in 0..16 {
            let private_one_time_key =
                EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).unwrap();
            let public_one_time_key = private_one_time_key
                .compute_public_key()
                .unwrap()
                .as_ref()
                .to_vec();
            one_time_keys.push((public_one_time_key, private_one_time_key));
        }
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
            .map_err(|_| TransportError::Push)?;
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
            .map_err(|_| TransportError::Fetch)?
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

        let xeddsa_public_key = XEdDSAPublicKey::new(&keys.identity_key_bob);
        xeddsa_public_key.verify(&keys.prekey, &keys.prekey_signature)?;

        let mut key_meterial = vec![0xFF; 32];
        key_meterial.extend(self.private_identity_key.agree_ephemeral(&keys.prekey)?);
        let ephemeral_private_key =
            EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).unwrap();
        let ephemeral_public_key = ephemeral_private_key
            .compute_public_key()
            .unwrap()
            .as_ref()
            .to_vec();
        key_meterial.extend(agree_ephemeral(
            unsafe { core::mem::transmute_copy(&ephemeral_private_key) },
            &UnparsedPublicKey::new(&X25519, &xeddsa_public_key),
            |k| k.to_vec(),
        )?);
        key_meterial.extend(agree_ephemeral(
            unsafe { core::mem::transmute_copy(&ephemeral_private_key) },
            &UnparsedPublicKey::new(&X25519, &keys.prekey),
            |k| k.to_vec(),
        )?);
        if let Some(one_time_key) = keys.one_time_key.as_ref() {
            key_meterial.extend(agree_ephemeral(
                ephemeral_private_key,
                &UnparsedPublicKey::new(&X25519, one_time_key),
                |k| k.to_vec(),
            )?);
        }

        let mut secret_key = [0; 96];
        Salt::new(HKDF_SHA256, &[0; 96])
            .extract(&key_meterial)
            .expand(&[b"X3DH"], HkdfBytes96)
            .unwrap()
            .fill(&mut secret_key)
            .unwrap();
        let shared_keys = SharedKeys {
            secret_key: secret_key[..32].try_into().unwrap(),
            header_key_alice: secret_key[32..64].try_into().unwrap(),
            header_key_bob: secret_key[64..].try_into().unwrap(),
        };

        let mut associated_data: Vec<u8> = vec![];
        let my_identity_key = self.public_identity_key();
        associated_data.extend(&my_identity_key);
        associated_data.extend(&keys.identity_key_bob);
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
            .push_bytes(bincode::encode_to_vec(&init_msg, bincode::config::standard()).unwrap())
            .await?;
        self.rpc_client
            .add_attempt(Request::new(AddAttemptRequest {
                identity_key_alice: my_identity_key,
                identity_key_bob: identity_key_bob.to_vec(),
            }))
            .await
            .map_err(|_| Error::Transport(TransportError::Push))?;

        let alice = Party::new(
            shared_keys.alice(&keys.prekey),
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
            .map_err(|_| Error::Transport(TransportError::Fetch))
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
        let (initial_message, _): (InitMassage, _) = bincode::decode_from_slice(
            message_transport
                .fetch_bytes(Some(1))
                .await?
                .first()
                .ok_or(Error::Failed("No initial message found.".to_string()))?,
            bincode::config::standard(),
        )
        .map_err(|_| Error::Failed("Invalid initial message.".to_string()))?;

        let mut key_meterial = vec![0xFF; 32];
        let private_prekey: EphemeralPrivateKey = unsafe {
            core::mem::transmute_copy(
                self.prekeys
                    .get(&initial_message.prekey_bob)
                    .ok_or(Error::Failed("Prekey not found.".to_string()))?,
            )
        };
        key_meterial.extend(agree_ephemeral(
            unsafe { core::mem::transmute_copy(&private_prekey) },
            &UnparsedPublicKey::new(&X25519, initial_message.identity_key_alice),
            |k| k.to_vec(),
        )?);
        key_meterial.extend(
            self.private_identity_key
                .agree_ephemeral(&initial_message.ephemeral_public_key_alice)?,
        );
        key_meterial.extend(
            agree_ephemeral(
                unsafe { core::mem::transmute_copy(&private_prekey) },
                &UnparsedPublicKey::new(&X25519, &initial_message.ephemeral_public_key_alice),
                |k| k.to_vec(),
            )
            .unwrap(),
        );
        if let Some(one_time_public_prekey) = initial_message.one_time_prekey_bob {
            key_meterial.extend(
                agree_ephemeral(
                    self.one_time_prekeys
                        .remove(&one_time_public_prekey)
                        .ok_or(Error::Failed("One-time prekey not found.".to_string()))?,
                    &UnparsedPublicKey::new(&X25519, &initial_message.ephemeral_public_key_alice),
                    |k| k.to_vec(),
                )
                .unwrap(),
            );
        }

        let mut secret_key = [0; 96];
        Salt::new(HKDF_SHA256, &[0; 96])
            .extract(&key_meterial)
            .expand(&[b"X3DH"], HkdfBytes96)
            .unwrap()
            .fill(&mut secret_key)
            .unwrap();
        let shared_keys = SharedKeys {
            secret_key: secret_key[..32].try_into().unwrap(),
            header_key_alice: secret_key[32..64].try_into().unwrap(),
            header_key_bob: secret_key[64..].try_into().unwrap(),
        };

        Ok(Party::new(
            shared_keys.bob(private_prekey),
            message_transport,
            associated_data,
        ))
    }
}

/// The gRPC server to store and distribute the public keys.
pub struct RpcX3DHServer {}

impl RpcX3DHServer {
    /// Run a RpcX3DHServer listening on addr.
    pub async fn run(addr: impl AsRef<str>, identity: Option<Identity>) -> Result<()> {
        let addr = addr.as_ref().parse().unwrap();
        let mut server = Server::builder();
        if let Some(identity) = identity {
            server = server
                .tls_config(ServerTlsConfig::new().identity(identity))
                .unwrap()
        }
        server
            .add_service(X3dhServiceServer::new(RpcX3DHInner::default()))
            .serve(addr)
            .await
            .map_err(|_| TransportError::Server)?;
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

struct HkdfBytes96;

impl KeyType for HkdfBytes96 {
    fn len(&self) -> usize {
        96
    }
}

/// The initial message.
#[derive(Debug, Encode, Decode)]
pub struct InitMassage {
    identity_key_alice: Vec<u8>,
    ephemeral_public_key_alice: Vec<u8>,
    prekey_bob: Vec<u8>,
    one_time_prekey_bob: Option<Vec<u8>>,
}
