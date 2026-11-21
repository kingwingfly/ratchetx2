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

use super::{EvictedSet, Party, Ratchet, SkippedKeys, skipped::LegacySkippedKeys};
use crate::error::{Error, Result};

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
use super::{KemRatchet, PqSuite};

const VERSION: u8 = 2;
const CLASSICAL: u8 = 0;
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
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        let (capability, kem_ratchet) = (
            self.pq_suite().map_or(CLASSICAL, PqSuite::id),
            self.kem_ratchet.as_ref(),
        );
        #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
        let (capability, kem_ratchet) = (CLASSICAL, None::<()>);

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

#[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
enum KemRatchet {}

#[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
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
    associated_data: Vec<u8>,
    #[serde(default, deserialize_with = "present")]
    current_chain_evicted: Option<EvictedSet>,
    #[serde(default, deserialize_with = "present")]
    kem_ratchet: Option<Option<KemRatchet>>,
}

// Serde's derived struct reader rejects repeated known fields. Preserve its handling of
// future map fields while also rejecting repeated names among those extensions.
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
        let field = seed.deserialize(name.as_str().into_deserializer())?;
        if !FIELDS.contains(&name.as_str()) && !self.extensions.insert(name) {
            return Err(de::Error::custom("duplicate party extension field"));
        }
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
                #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
                let actual = raw
                    .kem_ratchet
                    .as_ref()
                    .and_then(Option::as_ref)
                    .map_or(CLASSICAL, |kem| kem.suite().id());
                #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
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
        let party = Self {
            ratchet: raw.ratchet,
            skipped_message_keys: raw.skipped_message_keys,
            previous_chain_length: raw.previous_chain_length,
            message_number_sender: raw.message_number_sender,
            message_number_receiver: raw.message_number_receiver,
            associated_data: raw.associated_data,
            current_chain_evicted: raw.current_chain_evicted.unwrap_or_default(),
            #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
            kem_ratchet: raw.kem_ratchet.flatten(),
        };
        party.validate().map_err(de::Error::custom)?;
        Ok(party)
    }
}

type SixFields = (Ratchet, LegacySkippedKeys, u64, u64, u64, Vec<u8>);
type SevenFields = (Ratchet, SkippedKeys, u64, u64, u64, Vec<u8>, EvictedSet);

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
            associated_data,
            current_chain_evicted,
            #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
            kem_ratchet: None,
        };
        party.validate()?;
        Ok(Self(party))
    }
}

#[cfg(test)]
mod tests;
