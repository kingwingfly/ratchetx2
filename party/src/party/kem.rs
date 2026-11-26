//! Post-quantum KEM ratchet integration state for [`Party`](super::Party).
//!
//! When `cfg(has_pq)` is enabled (`ml-kem-1024` or `ml-kem-768`), [`KemState`] wraps
//! `Option<KemRatchet>` and [`KemStepSecrets`] holds the optional decapsulated/encapsulated
//! ML-KEM shared secrets for a DH-root transition. When neither feature is enabled, both types
//! collapse to zero-sized types so `party.rs` keeps a single unconditional code path.

use bytes::Bytes;

use crate::{
    error::{ErrorKind, Result},
    proto::Header,
};

/// Optional post-quantum wire fields produced for an outbound [`Header`].
#[derive(Default)]
pub(super) struct KemHeaderFields {
    pub(super) pq_suite: Option<u32>,
    pub(super) pq_public_key: Option<Bytes>,
    pub(super) pq_ciphertext: Option<Bytes>,
    pub(super) pq_key_id: Option<Bytes>,
}

/// Reject any PQ header fields when PQ ratcheting is disabled.
fn ensure_no_pq_header(header: &Header) -> Result<()> {
    if header.pq_suite.is_some()
        || header.pq_public_key.is_some()
        || header.pq_ciphertext.is_some()
        || header.pq_key_id.is_some()
    {
        return Err(ErrorKind::InvalidHeader.into());
    }
    Ok(())
}

#[cfg(has_pq)]
mod inner {
    use bytes::Bytes;
    use ratchetx2::pq::{
        KEM_KEY_ID_LENGTH, KemHeader, KemRatchet, KemRatchetConfig, KemSharedSecret, PqSuite,
    };
    use zeroize::Zeroize;

    use super::{KemHeaderFields, ensure_no_pq_header};
    use crate::{
        error::{Error, ErrorKind, Result},
        proto::Header,
    };

    /// Convert wire protobuf PQ header fields to [`KemHeader`].
    fn kem_header_from_proto(header: &Header) -> Result<KemHeader> {
        let suite = match header.pq_suite {
            Some(v) => Some(u8::try_from(v).map_err(|_| ErrorKind::InvalidHeader)?),
            None => None,
        };
        let ek_id = match &header.pq_key_id {
            Some(bytes) => Some(
                <[u8; KEM_KEY_ID_LENGTH]>::try_from(bytes.as_ref())
                    .map_err(|_| ErrorKind::InvalidHeader)?,
            ),
            None => None,
        };
        Ok(KemHeader {
            suite,
            ek: header.pq_public_key.as_ref().map(|b| b.to_vec()),
            ct: header.pq_ciphertext.as_ref().map(|b| b.to_vec()),
            ek_id,
        })
    }

    /// Optional ML-KEM shared secrets mixed into the two DH-root steps of a receiving chain turn.
    pub(in crate::party) struct KemStepSecrets {
        recv: Option<KemSharedSecret>,
        send: Option<KemSharedSecret>,
    }

    impl KemStepSecrets {
        pub(in crate::party) fn recv(&self) -> &[u8] {
            self.recv.as_deref().map_or(&[], |s| s.as_slice())
        }

        pub(in crate::party) fn send(&self) -> &[u8] {
            self.send.as_deref().map_or(&[], |s| s.as_slice())
        }
    }

    /// Optional post-quantum KEM ratchet state; `None` in classical sessions.
    #[derive(Clone, Default)]
    pub(in crate::party) struct KemState(Option<KemRatchet>);

    impl Zeroize for KemState {
        fn zeroize(&mut self) {
            if let Some(kem) = self.0.as_mut() {
                kem.zeroize();
            }
            self.0 = None;
        }
    }

    impl KemState {
        pub(in crate::party) fn disabled() -> Self {
            Self(None)
        }

        pub(in crate::party) fn enabled(suite: PqSuite, config: KemRatchetConfig) -> Self {
            Self(Some(KemRatchet::with_config(suite, config)))
        }

        #[cfg(feature = "serde")]
        pub(in crate::party) fn from_option(kem: Option<KemRatchet>) -> Self {
            Self(kem)
        }

        #[cfg(feature = "serde")]
        pub(in crate::party) fn as_option(&self) -> Option<&KemRatchet> {
            self.0.as_ref()
        }

        pub(in crate::party) fn enable(
            &mut self,
            suite: PqSuite,
            config: KemRatchetConfig,
        ) -> Result<()> {
            if let Some(existing) = &self.0 {
                if existing.suite() == suite {
                    return Ok(());
                }
                return Err(ErrorKind::Crypto.into());
            }
            self.0 = Some(KemRatchet::with_config(suite, config));
            Ok(())
        }

        pub(in crate::party) fn suite(&self) -> Option<PqSuite> {
            self.0.as_ref().map(KemRatchet::suite)
        }

        pub(in crate::party) fn suite_id(&self) -> Option<u8> {
            self.suite().map(PqSuite::id)
        }

        pub(in crate::party) fn is_active(&self) -> bool {
            self.0.is_some()
        }

        pub(in crate::party) fn prepare_send(&mut self) -> Result<KemHeaderFields> {
            let Some(kem) = &mut self.0 else {
                return Ok(KemHeaderFields::default());
            };
            let kh = kem.prepare_send()?;
            Ok(KemHeaderFields {
                pq_suite: kh.suite.map(u32::from),
                pq_public_key: kh.ek.map(Bytes::from),
                pq_ciphertext: kh.ct.map(Bytes::from),
                pq_key_id: kh.ek_id.map(|id| Bytes::copy_from_slice(&id)),
            })
        }

        pub(in crate::party) fn receive_skipped(&mut self, header: &Header) -> Result<()> {
            match &mut self.0 {
                Some(kem) => {
                    let kem_header = kem_header_from_proto(header)?;
                    kem.receive_skipped_header(&kem_header)
                        .map_err(|e| Error::new(ErrorKind::InvalidHeader, e))
                }
                None => ensure_no_pq_header(header),
            }
        }

        pub(in crate::party) fn receive_current_chain(&mut self, header: &Header) -> Result<()> {
            match &mut self.0 {
                Some(kem) => {
                    let kem_header = kem_header_from_proto(header)?;
                    kem.receive_current_chain(&kem_header)
                        .map_err(|e| Error::new(ErrorKind::InvalidHeader, e))
                }
                None => ensure_no_pq_header(header),
            }
        }

        pub(in crate::party) fn receive_chain_step(
            &mut self,
            header: &Header,
        ) -> Result<KemStepSecrets> {
            match &mut self.0 {
                Some(kem) => {
                    let kem_header = kem_header_from_proto(header)?;
                    let (recv, send) = kem
                        .receive_chain_step(&kem_header)
                        .map_err(|e| Error::new(ErrorKind::InvalidHeader, e))?;
                    Ok(KemStepSecrets { recv, send })
                }
                None => {
                    ensure_no_pq_header(header)?;
                    Ok(KemStepSecrets {
                        recv: None,
                        send: None,
                    })
                }
            }
        }

        #[cfg(feature = "prost")]
        pub(in crate::party) fn to_proto(&self) -> Option<ratchetx2::proto::KemRatchet> {
            self.0.as_ref().map(Into::into)
        }

        #[cfg(feature = "prost")]
        pub(in crate::party) fn from_proto(
            proto: Option<&ratchetx2::proto::KemRatchet>,
        ) -> Result<Self> {
            match proto {
                Some(kem) => Ok(Self(Some(
                    KemRatchet::try_from(kem)
                        .map_err(|e| Error::new(ErrorKind::MalformedState, e))?,
                ))),
                None => Ok(Self(None)),
            }
        }

        #[cfg(test)]
        pub(in crate::party) fn as_ref(&self) -> Option<&KemRatchet> {
            self.0.as_ref()
        }

        #[cfg(test)]
        pub(in crate::party) fn as_mut(&mut self) -> Option<&mut KemRatchet> {
            self.0.as_mut()
        }

        #[cfg(test)]
        pub(in crate::party) fn test_snapshot(&self) -> Option<usize> {
            self.0.as_ref().map(KemRatchet::pending_offer_count)
        }
    }
}

#[cfg(not(has_pq))]
mod inner {
    use zeroize::Zeroize;

    use super::{KemHeaderFields, ensure_no_pq_header};
    use crate::{error::Result, proto::Header};

    /// Zero-sized placeholder for ML-KEM step secrets when PQ features are disabled.
    pub(in crate::party) struct KemStepSecrets;

    const _: () = assert!(core::mem::size_of::<KemStepSecrets>() == 0);

    impl KemStepSecrets {
        pub(in crate::party) fn recv(&self) -> &[u8] {
            &[]
        }

        pub(in crate::party) fn send(&self) -> &[u8] {
            &[]
        }
    }

    /// Zero-sized KEM ratchet state when no post-quantum suite is compiled in.
    #[derive(Clone, Default)]
    pub(in crate::party) struct KemState;

    const _: () = assert!(core::mem::size_of::<KemState>() == 0);

    impl Zeroize for KemState {
        fn zeroize(&mut self) {}
    }

    impl KemState {
        pub(in crate::party) fn disabled() -> Self {
            Self
        }

        pub(in crate::party) fn suite_id(&self) -> Option<u8> {
            None
        }

        pub(in crate::party) fn is_active(&self) -> bool {
            false
        }

        pub(in crate::party) fn prepare_send(&mut self) -> Result<KemHeaderFields> {
            Ok(KemHeaderFields::default())
        }

        pub(in crate::party) fn receive_skipped(&mut self, header: &Header) -> Result<()> {
            ensure_no_pq_header(header)
        }

        pub(in crate::party) fn receive_current_chain(&mut self, header: &Header) -> Result<()> {
            ensure_no_pq_header(header)
        }

        pub(in crate::party) fn receive_chain_step(
            &mut self,
            header: &Header,
        ) -> Result<KemStepSecrets> {
            ensure_no_pq_header(header)?;
            Ok(KemStepSecrets)
        }

        #[cfg(feature = "prost")]
        pub(in crate::party) fn to_proto(&self) -> Option<ratchetx2::proto::KemRatchet> {
            None
        }

        #[cfg(feature = "prost")]
        pub(in crate::party) fn from_proto(
            proto: Option<&ratchetx2::proto::KemRatchet>,
        ) -> Result<Self> {
            if proto.is_some() {
                // Fail closed: never silently drop PQ ratchet state on a non-PQ build.
                return Err(crate::error::ErrorKind::MalformedState.into());
            }
            Ok(Self)
        }

        #[cfg(test)]
        pub(in crate::party) fn test_snapshot(&self) -> Option<usize> {
            None
        }
    }
}

pub(super) use inner::KemState;
