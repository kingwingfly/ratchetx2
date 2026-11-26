//! Serde storage formats for a party.

use std::{collections::HashSet, fmt};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{
        self, DeserializeSeed, IntoDeserializer, MapAccess, SeqAccess,
        value::{MapAccessDeserializer, SeqAccessDeserializer},
    },
    ser::SerializeStruct,
};

use super::{EvictedSet, KemState, Party, Ratchet, SkippedKeys, skipped::LegacySkippedKeys};
use crate::error::{Error, Result};

#[cfg(has_pq)]
use super::{KemRatchet, PqSuite};

const VERSION: u8 = 2;
const CLASSICAL: u8 = 0;
/// Maximum number of unknown extension fields accepted when deserializing a human-readable Party.
const MAX_EXTENSION_FIELDS: usize = 32;
/// Maximum byte length of an unknown extension field name.
const MAX_EXTENSION_NAME_LEN: usize = 128;
/// Maximum byte length of `Party.associated_data` when deserializing with Serde.
const MAX_ASSOCIATED_DATA_LEN: usize = 4096;

fn deserialize_bounded_ad<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> core::result::Result<Vec<u8>, D::Error> {
    struct BoundedBytesVisitor;

    impl<'de> de::Visitor<'de> for BoundedBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {MAX_ASSOCIATED_DATA_LEN} bytes")
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> core::result::Result<Vec<u8>, E> {
            if v.len() > MAX_ASSOCIATED_DATA_LEN {
                return Err(E::invalid_length(v.len(), &self));
            }
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> core::result::Result<Vec<u8>, E> {
            if v.len() > MAX_ASSOCIATED_DATA_LEN {
                return Err(E::invalid_length(v.len(), &self));
            }
            Ok(v)
        }

        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> core::result::Result<Vec<u8>, A::Error> {
            if let Some(hint) = seq.size_hint()
                && hint > MAX_ASSOCIATED_DATA_LEN
            {
                return Err(de::Error::invalid_length(hint, &self));
            }
            let cap = seq.size_hint().unwrap_or(0).min(MAX_ASSOCIATED_DATA_LEN);
            let mut out = Vec::with_capacity(cap);
            while let Some(byte) = seq.next_element::<u8>()? {
                if out.len() >= MAX_ASSOCIATED_DATA_LEN {
                    return Err(de::Error::invalid_length(
                        MAX_ASSOCIATED_DATA_LEN + 1,
                        &self,
                    ));
                }
                out.push(byte);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(BoundedBytesVisitor)
}

#[derive(Deserialize)]
#[serde(transparent)]
struct BoundedAd(#[serde(deserialize_with = "deserialize_bounded_ad")] Vec<u8>);
const FIELDS: &[&str] = &[
    "version",
    "capability",
    "ratchet",
    "skipped_message_keys",
    "previous_chain_length",
    "message_number_sender",
    "message_number_receiver",
    "associated_data",
    "current_chain_evicted",
    "kem_ratchet",
];

impl Serialize for Party {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let capability = self.pq_suite_id().unwrap_or(CLASSICAL);
        #[cfg(has_pq)]
        let kem_ratchet = self.kem_ratchet.as_option();
        #[cfg(not(has_pq))]
        let kem_ratchet = None::<()>;

        let mut state = serializer.serialize_struct("Party", FIELDS.len())?;
        state.serialize_field("version", &VERSION)?;
        state.serialize_field("capability", &capability)?;
        state.serialize_field("ratchet", &self.ratchet)?;
        state.serialize_field("skipped_message_keys", &self.skipped_message_keys)?;
        state.serialize_field("previous_chain_length", &self.previous_chain_length)?;
        state.serialize_field("message_number_sender", &self.message_number_sender)?;
        state.serialize_field("message_number_receiver", &self.message_number_receiver)?;
        state.serialize_field("associated_data", &self.associated_data)?;
        state.serialize_field("current_chain_evicted", &self.current_chain_evicted)?;
        state.serialize_field("kem_ratchet", &kem_ratchet)?;
        state.end()
    }
}

// Deserialize the field itself, without adding an Option discriminant to the wire.
// The outer Option distinguishes an absent map key from an explicitly encoded value.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> core::result::Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[cfg(not(has_pq))]
enum KemRatchet {}

#[cfg(not(has_pq))]
impl<'de> Deserialize<'de> for KemRatchet {
    fn deserialize<D: Deserializer<'de>>(_: D) -> core::result::Result<Self, D::Error> {
        Err(de::Error::custom(
            "malformed party state: ML-KEM is disabled",
        ))
    }
}

#[derive(Deserialize)]
#[serde(rename = "Party")]
struct PartyWire {
    #[serde(default, deserialize_with = "present")]
    version: Option<u8>,
    #[serde(default, deserialize_with = "present")]
    capability: Option<u8>,
    ratchet: Ratchet,
    skipped_message_keys: SkippedKeys,
    previous_chain_length: u64,
    message_number_sender: u64,
    message_number_receiver: u64,
    #[serde(deserialize_with = "deserialize_bounded_ad")]
    associated_data: Vec<u8>,
    #[serde(default, deserialize_with = "present")]
    current_chain_evicted: Option<EvictedSet>,
    #[serde(default, deserialize_with = "present")]
    kem_ratchet: Option<Option<KemRatchet>>,
}

// Serde's derived struct reader rejects repeated known fields. Preserve its handling of
// future map fields while bounding extension count and key length and rejecting duplicates.
struct NamedFields<A> {
    map: A,
    extensions: HashSet<String>,
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for NamedFields<A> {
    type Error = A::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> core::result::Result<Option<K::Value>, A::Error> {
        let Some(name) = self.map.next_key::<String>()? else {
            return Ok(None);
        };
        if !FIELDS.contains(&name.as_str()) {
            if name.len() > MAX_EXTENSION_NAME_LEN {
                return Err(de::Error::custom("party extension field name too long"));
            }
            if self.extensions.len() >= MAX_EXTENSION_FIELDS {
                return Err(de::Error::custom("too many party extension fields"));
            }
            if !self.extensions.insert(name.clone()) {
                return Err(de::Error::custom("duplicate party extension field"));
            }
        }
        let field = seed.deserialize(name.as_str().into_deserializer())?;
        Ok(Some(field))
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> core::result::Result<V::Value, A::Error> {
        self.map.next_value_seed(seed)
    }
}

struct NamedParty;

impl<'de> de::Visitor<'de> for NamedParty {
    type Value = PartyWire;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a party state")
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> core::result::Result<PartyWire, A::Error> {
        PartyWire::deserialize(MapAccessDeserializer::new(NamedFields {
            map,
            extensions: HashSet::new(),
        }))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> core::result::Result<PartyWire, A::Error> {
        PartyWire::deserialize(SeqAccessDeserializer::new(seq))
    }
}

impl<'de> Deserialize<'de> for Party {
    fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        let raw = if d.is_human_readable() {
            d.deserialize_struct("Party", FIELDS, NamedParty)?
        } else {
            PartyWire::deserialize(d)?
        };
        match (raw.version, raw.capability) {
            (None, None) => {} // Unversioned map, possibly from a PQ build.
            (Some(VERSION), Some(capability)) => {
                #[cfg(has_pq)]
                let actual = raw
                    .kem_ratchet
                    .as_ref()
                    .and_then(Option::as_ref)
                    .map_or(CLASSICAL, |kem| kem.suite().id());
                #[cfg(not(has_pq))]
                let actual = CLASSICAL;
                if capability != actual {
                    return Err(de::Error::custom(
                        "party capability disagrees with KEM state",
                    ));
                }
                if raw.kem_ratchet.is_none() {
                    return Err(de::Error::missing_field("kem_ratchet"));
                }
                if raw.current_chain_evicted.is_none() {
                    return Err(de::Error::missing_field("current_chain_evicted"));
                }
            }
            _ => {
                return Err(de::Error::custom(
                    "unsupported party version or missing discriminator",
                ));
            }
        }
        #[cfg(has_pq)]
        let kem_ratchet = KemState::from_option(raw.kem_ratchet.flatten());
        #[cfg(not(has_pq))]
        let kem_ratchet = KemState::disabled();
        let party = Self {
            ratchet: raw.ratchet,
            skipped_message_keys: raw.skipped_message_keys,
            previous_chain_length: raw.previous_chain_length,
            message_number_sender: raw.message_number_sender,
            message_number_receiver: raw.message_number_receiver,
            associated_data: raw.associated_data,
            current_chain_evicted: raw.current_chain_evicted.unwrap_or_default(),
            kem_ratchet,
        };
        party.validate().map_err(de::Error::custom)?;
        Ok(party)
    }
}

type SixFields = (Ratchet, LegacySkippedKeys, u64, u64, u64, BoundedAd);
type SevenFields = (Ratchet, SkippedKeys, u64, u64, u64, BoundedAd, EvictedSet);

/// Serde reader for the six-field classical positional format predating eviction tracking.
///
/// Select this reader using the version of the enclosing storage record. The old format
/// starts with arbitrary root-key bytes. It has no tag identifying it as a six-field record.
#[derive(Deserialize)]
#[serde(try_from = "SixFields")]
pub struct LegacyPartyV0(Party);

impl LegacyPartyV0 {
    /// Returns the validated classical party, with empty eviction history.
    pub fn into_party(self) -> Party {
        self.0
    }
}

impl TryFrom<SixFields> for LegacyPartyV0 {
    type Error = Error;

    fn try_from((ratchet, skipped, previous, sent, received, ad): SixFields) -> Result<Self> {
        let party = LegacyPartyV1::try_from((
            ratchet,
            skipped.into(),
            previous,
            sent,
            received,
            ad,
            EvictedSet::default(),
        ))?;
        Ok(Self(party.into_party()))
    }
}

/// Serde reader for the seven-field classical positional format with eviction tracking.
///
/// Select this reader only for records known to use the classical seven-field layout.
/// Unversioned positional records carry neither a field count nor a capability tag in postcard.
#[derive(Deserialize)]
#[serde(try_from = "SevenFields")]
pub struct LegacyPartyV1(Party);

impl LegacyPartyV1 {
    /// Returns the validated classical party, including its eviction history.
    pub fn into_party(self) -> Party {
        self.0
    }
}

impl TryFrom<SevenFields> for LegacyPartyV1 {
    type Error = Error;

    fn try_from(
        (
            ratchet,
            skipped_message_keys,
            previous_chain_length,
            message_number_sender,
            message_number_receiver,
            associated_data,
            current_chain_evicted,
        ): SevenFields,
    ) -> Result<Self> {
        let party = Party {
            ratchet,
            skipped_message_keys,
            previous_chain_length,
            message_number_sender,
            message_number_receiver,
            associated_data: associated_data.0,
            current_chain_evicted,
            kem_ratchet: KemState::disabled(),
        };
        party.validate()?;
        Ok(Self(party))
    }
}

#[cfg(has_pq)]
pub use legacy_pq::LegacyPartyPqV1;

#[cfg(has_pq)]
mod legacy_pq {
    use super::*;
    use serde::de::Visitor;

    type EightFields = (
        Ratchet,
        SkippedKeys,
        u64,
        u64,
        u64,
        BoundedAd,
        EvictedSet,
        Option<LegacyKemRatchet>,
    );

    /// Serde reader for the eight-field positional format written by pre-version-2 PQ builds.
    ///
    /// These builds encoded the KEM suite as Serde's build-dependent enum variant index.
    /// Migrate under the same ML-KEM feature set that wrote the record. Use `pq` for a
    /// dual-suite build, or `ml-kem-1024` or `ml-kem-768` for the original single suite.
    /// The eight-field layout also covers classical sessions saved by those builds.
    #[derive(Deserialize)]
    #[serde(try_from = "EightFields")]
    pub struct LegacyPartyPqV1(Party);

    impl LegacyPartyPqV1 {
        /// Returns the validated party with its original KEM state and eviction history.
        pub fn into_party(self) -> Party {
            self.0
        }
    }

    impl TryFrom<EightFields> for LegacyPartyPqV1 {
        type Error = Error;

        fn try_from(
            (
                ratchet,
                skipped_message_keys,
                previous_chain_length,
                message_number_sender,
                message_number_receiver,
                associated_data,
                current_chain_evicted,
                kem,
            ): EightFields,
        ) -> Result<Self> {
            let party = Party {
                ratchet,
                skipped_message_keys,
                previous_chain_length,
                message_number_sender,
                message_number_receiver,
                associated_data: associated_data.0,
                current_chain_evicted,
                kem_ratchet: KemState::from_option(kem.map(|legacy| legacy.0)),
            };
            party.validate()?;
            Ok(Self(party))
        }
    }

    // Preserve the historical feature gates and declaration order for the positional enum.
    #[derive(Deserialize)]
    enum LegacyPqSuite {
        #[cfg(feature = "ml-kem-1024")]
        MlKem1024,
        #[cfg(feature = "ml-kem-768")]
        MlKem768,
    }

    struct LegacyKemRatchet(KemRatchet);

    impl<'de> Deserialize<'de> for LegacyKemRatchet {
        fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
            struct LegacyKemVisitor;

            impl<'de> Visitor<'de> for LegacyKemVisitor {
                type Value = LegacyKemRatchet;

                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an eleven-field legacy KEM ratchet")
                }

                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    mut fields: A,
                ) -> core::result::Result<Self::Value, A::Error> {
                    let suite = match fields
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(0, &self))?
                    {
                        #[cfg(feature = "ml-kem-1024")]
                        LegacyPqSuite::MlKem1024 => PqSuite::MlKem1024,
                        #[cfg(feature = "ml-kem-768")]
                        LegacyPqSuite::MlKem768 => PqSuite::MlKem768,
                    };
                    let translated = KemFields {
                        suite_id: Some(suite.id()),
                        fields,
                    };
                    KemRatchet::deserialize(BinaryValue(SeqAccessDeserializer::new(translated)))
                        .map(LegacyKemRatchet)
                }
            }

            d.deserialize_tuple(11, LegacyKemVisitor)
        }
    }

    // Replay the translated suite, then let the current KEM reader consume and validate
    // the remaining fields directly from the original binary deserializer.
    struct KemFields<A> {
        suite_id: Option<u8>,
        fields: A,
    }

    impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for KemFields<A> {
        type Error = A::Error;

        fn next_element_seed<T: DeserializeSeed<'de>>(
            &mut self,
            seed: T,
        ) -> core::result::Result<Option<T::Value>, A::Error> {
            if let Some(id) = self.suite_id.take() {
                return seed
                    .deserialize(BinaryValue(id.into_deserializer()))
                    .map(Some);
            }
            self.fields.next_element_seed(seed)
        }
    }

    // Serde's sequence and u8 value adapters both default to human-readable mode.
    struct BinaryValue<D>(D);

    impl<'de, D: Deserializer<'de>> Deserializer<'de> for BinaryValue<D> {
        type Error = D::Error;

        fn is_human_readable(&self) -> bool {
            false
        }

        fn deserialize_any<V: Visitor<'de>>(
            self,
            visitor: V,
        ) -> core::result::Result<V::Value, D::Error> {
            self.0.deserialize_any(visitor)
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes
            byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct map
            struct enum identifier ignored_any
        }
    }
}

#[cfg(test)]
mod tests;
