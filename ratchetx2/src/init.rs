//! Initialize the shared keys between two parties with [Extended Triple Diffie-Hellman])(https://signal.org/docs/specifications/x3dh/).

/// Tonic generated gRPC module.
pub(crate) mod x3dh {
    tonic::include_proto!("x3dh");
}

use std::collections::HashMap;

use ring::agreement::{
    EphemeralPrivateKey, UnparsedPublicKey as DHUnparsedPublicKey, X25519, agree_ephemeral,
};
use ring::hkdf::{HKDF_SHA256, KeyType, Salt};
use ring::rand::SystemRandom;
use tonic::Status;
use tonic::transport::Channel;
use tonic::transport::Server;
use tonic::{Request, Response, Result as RpcResult};
use x3dh::x3dh_service_client::X3dhServiceClient;
use x3dh::x3dh_service_server::{X3dhService, X3dhServiceServer};
use x3dh::{FetchKeysRequest, FetchKeysResponse, PublishKeysRequest, PublishKeysResponse};

use super::error::{Result, TransportError};
use crate::xdedsa::{XEdDSAPrivateKey, XEdDSAPublicKey};

/// X3DH gRPC client.
pub struct X3DHClient {
    rpc_client: X3dhServiceClient<Channel>,
    private_identity_key: XEdDSAPrivateKey,
    prekeys: HashMap<Vec<u8>, EphemeralPrivateKey>,
    one_time_prekeys: HashMap<Vec<u8>, EphemeralPrivateKey>,
}

impl X3DHClient {
    /// Connect to a X3DH gRPC server.
    pub async fn new(dst: impl AsRef<str>) -> Self {
        Self {
            rpc_client: X3dhServiceClient::connect(dst.as_ref().to_owned())
                .await
                .unwrap(),
            private_identity_key: XEdDSAPrivateKey::generate(&SystemRandom::new()),
            prekeys: HashMap::new(),
            one_time_prekeys: HashMap::new(),
        }
    }

    /// Publish keys to server
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
            identity_key_bob: self
                .private_identity_key
                .compute_public_key()
                .as_ref()
                .to_vec(),
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

    /// Fetch keys from server
    async fn fetch_keys(&mut self, identity_key_bob: Vec<u8>) -> Result<FetchKeysResponse> {
        Ok(self
            .rpc_client
            .fetch_keys(FetchKeysRequest { identity_key_bob })
            .await
            .map_err(|_| TransportError::Fetch)?
            .into_inner())
    }

    /// Alice fetches a "prekey bundle" from the server, and constructs an initial message to Bob.
    pub async fn initial_message(&mut self, identity_key_bob: Vec<u8>) -> Result<Vec<u8>> {
        let keys = self.fetch_keys(identity_key_bob).await?;
        let xdedsa_public_key = XEdDSAPublicKey::new(&keys.identity_key_bob);
        xdedsa_public_key.verify(&keys.prekey, &keys.prekey_signature)?;
        let mut key_meterial = vec![0xFF; 32];
        key_meterial.extend(
            self.private_identity_key
                .agree_ephemeral(&xdedsa_public_key),
        );
        let ephemeral_private_key =
            EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).unwrap();
        let ephemeral_public_key = ephemeral_private_key
            .compute_public_key()
            .unwrap()
            .as_ref()
            .to_vec();
        key_meterial.extend(
            agree_ephemeral(
                unsafe { core::mem::transmute_copy(&ephemeral_private_key) },
                &DHUnparsedPublicKey::new(&X25519, &keys.identity_key_bob),
                |k| k.to_vec(),
            )
            .unwrap(),
        );
        key_meterial.extend(
            agree_ephemeral(
                unsafe { core::mem::transmute_copy(&ephemeral_private_key) },
                &DHUnparsedPublicKey::new(&X25519, &keys.prekey),
                |k| k.to_vec(),
            )
            .unwrap(),
        );
        if let Some(one_time_key) = keys.one_time_key {
            key_meterial.extend(
                agree_ephemeral(
                    ephemeral_private_key,
                    &DHUnparsedPublicKey::new(&X25519, &one_time_key),
                    |k| k.to_vec(),
                )
                .unwrap(),
            );
        }
        let mut secret_key = [0; 32];
        Salt::new(HKDF_SHA256, &[0; 32])
            .extract(&key_meterial)
            .expand(&[b"X3DH"], HkdfBytes32)
            .unwrap()
            .fill(&mut secret_key)
            .unwrap();
        let mut associated_data: Vec<u8> = vec![];
        associated_data.extend(
            &self
                .private_identity_key
                .compute_public_key()
                .as_ref()
                .to_vec(),
        );
        associated_data.extend(&keys.identity_key_bob);

        todo!()
    }
}

/// The gRPC server to store and distribute the public keys.
pub struct RpcX3DHServer {}

impl RpcX3DHServer {
    /// Run a RpcX3DHServer listening on addr.
    pub async fn run(addr: impl AsRef<str>) -> Result<()> {
        let addr = addr.as_ref().parse().unwrap();
        Server::builder()
            .add_service(X3dhServiceServer::new(RpcX3DHInner::default()))
            .serve(addr)
            .await
            .map_err(|_| TransportError::Server)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(crate) struct RpcX3DHInner {
    db: std::sync::RwLock<HashMap<Vec<u8>, PublishedKeys>>,
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
        self.db.write().unwrap().insert(
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
        match self.db.write().unwrap().get_mut(&identity_key_bob) {
            Some(keys) => Ok(Response::new(FetchKeysResponse {
                identity_key_bob,
                prekey: keys.prekey.clone(),
                prekey_signature: keys.prekey_signature.clone(),
                one_time_key: keys.one_time_keys.pop(),
            })),
            None => Err(Status::not_found("identity_key_bob not found".to_string())),
        }
    }
}

struct HkdfBytes32;

impl KeyType for HkdfBytes32 {
    fn len(&self) -> usize {
        32
    }
}
