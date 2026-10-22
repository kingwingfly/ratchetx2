//! Signed handshake requests.
//!
//! Bob signs his requests with his identity key (XEdDSA). The signature covers fixed bytes
//! rather than the protobuf encoding, so every implementation signs exactly the same bytes:
//!
//! - publish: `"handshake.v1/publish"` ‖ identity key ‖ signed prekey ‖ its signature ‖
//!   number of one-time prekeys (u32, little-endian) ‖ the one-time prekeys ‖ timestamp
//!   (u64, little-endian)
//! - take introductions: `"handshake.v1/take-introductions"` ‖ identity key ‖ timestamp
//!   (u64, little-endian)
//!
//! Keys are 32 bytes and signatures 64, so fields cannot shift into each other.

use bytes::Bytes;
use x3dh::{PublicKey, PublishedPrekeys};
use xeddsa::{XEdDSAPrivateKey, XEdDSAPublicKey};

use crate::error::{ErrorKind, Result};
use crate::fixed;
use crate::handshake::{PublishRequest, TakeIntroductionsRequest};

/// Sign `request` with `identity`, setting its `signature`.
pub fn sign_publish(identity: &XEdDSAPrivateKey, request: &mut PublishRequest) -> Result<()> {
    request.signature = Bytes::copy_from_slice(&identity.sign(publish_message(request)?));
    Ok(())
}

/// Verify `request.signature` with `request.identity_key`.
pub fn verify_publish(request: &PublishRequest) -> Result<()> {
    verify(
        &request.identity_key,
        publish_message(request)?,
        &request.signature,
    )
}

/// Sign `request` with `identity`, setting its `signature`.
pub fn sign_take_introductions(
    identity: &XEdDSAPrivateKey,
    request: &mut TakeIntroductionsRequest,
) -> Result<()> {
    request.signature =
        Bytes::copy_from_slice(&identity.sign(take_introductions_message(request)?));
    Ok(())
}

/// Verify `request.signature` with `request.identity_key`.
pub fn verify_take_introductions(request: &TakeIntroductionsRequest) -> Result<()> {
    verify(
        &request.identity_key,
        take_introductions_message(request)?,
        &request.signature,
    )
}

fn publish_message(request: &PublishRequest) -> Result<Vec<u8>> {
    let identity_key: PublicKey = fixed(&request.identity_key)?;
    let prekeys = PublishedPrekeys::try_from(request)?;
    let mut message = b"handshake.v1/publish".to_vec();
    message.extend(identity_key);
    message.extend(prekeys.signed_prekey);
    message.extend(prekeys.signed_prekey_signature);
    let count = u32::try_from(prekeys.one_time_prekeys.len()).map_err(|_| ErrorKind::Malformed)?;
    message.extend(count.to_le_bytes());
    for one_time_prekey in prekeys.one_time_prekeys {
        message.extend(one_time_prekey);
    }
    message.extend(request.timestamp.to_le_bytes());
    Ok(message)
}

fn take_introductions_message(request: &TakeIntroductionsRequest) -> Result<Vec<u8>> {
    let identity_key: PublicKey = fixed(&request.identity_key)?;
    let mut message = b"handshake.v1/take-introductions".to_vec();
    message.extend(identity_key);
    message.extend(request.timestamp.to_le_bytes());
    Ok(message)
}

fn verify(identity_key: &[u8], message: Vec<u8>, signature: &[u8]) -> Result<()> {
    XEdDSAPublicKey::new(identity_key)?.verify(message, signature)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    fn identity_key(identity: &XEdDSAPrivateKey) -> Bytes {
        Bytes::copy_from_slice(identity.compute_public_key().as_ref())
    }

    #[test]
    fn sign_and_verify() {
        let bob = XEdDSAPrivateKey::generate();
        let mut request = PublishRequest {
            identity_key: identity_key(&bob),
            signed_prekey: Bytes::from_static(&[3; 32]),
            signed_prekey_signature: Bytes::from_static(&[4; 64]),
            one_time_prekeys: vec![Bytes::from_static(&[5; 32])],
            timestamp: 7,
            signature: Bytes::new(),
        };
        sign_publish(&bob, &mut request).unwrap();
        verify_publish(&request).unwrap();
        // Any change breaks the signature.
        let mut changed = request.clone();
        changed.timestamp = 8;
        assert_eq!(
            verify_publish(&changed).unwrap_err().kind(),
            ErrorKind::InvalidSignature
        );
        let mut changed = request.clone();
        changed.one_time_prekeys.clear();
        assert_eq!(
            verify_publish(&changed).unwrap_err().kind(),
            ErrorKind::InvalidSignature
        );
        // Another identity cannot sign for Bob.
        let mut forged = request.clone();
        sign_publish(&XEdDSAPrivateKey::generate(), &mut forged).unwrap();
        assert_eq!(
            verify_publish(&forged).unwrap_err().kind(),
            ErrorKind::InvalidSignature
        );
        // Malformed fields are rejected before signing.
        let mut malformed = request.clone();
        malformed.signed_prekey = Bytes::from_static(&[3; 31]);
        assert_eq!(
            sign_publish(&bob, &mut malformed).unwrap_err().kind(),
            ErrorKind::Malformed
        );

        let mut request = TakeIntroductionsRequest {
            identity_key: identity_key(&bob),
            timestamp: 9,
            signature: Bytes::new(),
        };
        sign_take_introductions(&bob, &mut request).unwrap();
        verify_take_introductions(&request).unwrap();
        request.timestamp = 10;
        assert_eq!(
            verify_take_introductions(&request).unwrap_err().kind(),
            ErrorKind::InvalidSignature
        );
    }
}
