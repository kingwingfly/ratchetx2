//! Message keys skipped over while receiving, kept to decrypt the messages if they arrive late.

use std::collections::{BTreeMap, VecDeque};

use ratchetx2::key::{HeaderKey, MessageKey};

use super::{MAX_SKIPPED_CHAINS, SKIP_MAX};

/// The message keys skipped in one of the peer's chains.
#[cfg_attr(test, derive(Debug, Clone, PartialEq))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(super) struct SkippedChain {
    header_key: HeaderKey,
    /// By message number, so the oldest comes first.
    keys: BTreeMap<u64, MessageKey>,
    /// Number of the peer's chains received after this one.
    age: usize,
}

impl SkippedChain {
    /// No keys yet, in the peer's current chain, whose header key is `header_key`.
    pub(super) fn new(header_key: HeaderKey) -> Self {
        Self {
            header_key,
            keys: BTreeMap::new(),
            age: 0,
        }
    }

    pub(super) fn insert(&mut self, message_number: u64, message_key: MessageKey) {
        self.keys.insert(message_number, message_key);
    }
}

/// The skipped message keys of the peer's last [`MAX_SKIPPED_CHAINS`] chains, at most
/// [`SKIP_MAX`] of them: the keys of lost messages neither stay forever nor take the room of later
/// ones.
///
/// It keeps no count of its keys besides the chains, so a state restored with serde or rkyv,
/// however corrupt, cannot disagree with itself.
#[derive(Default)]
#[cfg_attr(test, derive(Debug, Clone, PartialEq))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(super) struct SkippedKeys {
    /// The chains with keys left, oldest first.
    chains: VecDeque<SkippedChain>,
}

impl SkippedKeys {
    /// Number of keys kept, over at most a few chains.
    pub(super) fn len(&self) -> u64 {
        self.chains
            .iter()
            .map(|chain| chain.keys.len() as u64)
            .sum()
    }

    /// The header keys of the chains with keys left.
    pub(super) fn header_keys(&self) -> impl Iterator<Item = HeaderKey> + '_ {
        self.chains.iter().map(|chain| chain.header_key)
    }

    /// The key of message `message_number` in the chain of `header_key`, if it was skipped.
    pub(super) fn get(&self, header_key: &HeaderKey, message_number: u64) -> Option<MessageKey> {
        let chain = self
            .chains
            .iter()
            .find(|chain| chain.header_key == *header_key)?;
        chain.keys.get(&message_number).copied()
    }

    /// Forget the key of message `message_number` in the chain of `header_key`, once used. A
    /// chain with no keys left goes too, so its header key is no longer tried.
    pub(super) fn remove(&mut self, header_key: &HeaderKey, message_number: u64) {
        let Some(index) = self
            .chains
            .iter()
            .position(|chain| chain.header_key == *header_key)
        else {
            return;
        };
        self.chains[index].keys.remove(&message_number);
        if self.chains[index].keys.is_empty() {
            self.chains.remove(index);
        }
    }

    /// The peer has moved on to its next chain: forget the chains that are now too old.
    pub(super) fn next_chain(&mut self) {
        for chain in &mut self.chains {
            chain.age = chain.age.saturating_add(1);
        }
        while let Some(oldest) = self.chains.front()
            && oldest.age >= MAX_SKIPPED_CHAINS
        {
            self.chains.pop_front();
        }
    }
}

/// The keys as the party's protobuf state.
#[cfg(feature = "prost")]
mod state {
    use ratchetx2::key::KEY_LENGTH;

    use super::{SkippedChain, SkippedKeys};
    use crate::{
        error::{ErrorKind, Result},
        proto,
    };

    impl SkippedKeys {
        /// The chains as protobuf messages, oldest first.
        pub(in crate::party) fn to_proto(&self) -> Vec<proto::SkippedChain> {
            self.chains
                .iter()
                .map(|chain| proto::SkippedChain {
                    header_key: chain.header_key.to_vec(),
                    message_keys: chain
                        .keys
                        .iter()
                        .map(|(message_number, message_key)| proto::MessageKey {
                            message_number: *message_number,
                            key: message_key.to_vec(),
                        })
                        .collect(),
                    age: chain.age as u64,
                })
                .collect()
        }

        /// The keys of `chains`, from [`to_proto`](Self::to_proto). Like [`extend`](Self::extend),
        /// it leaves out empty chains and keeps at most [`SKIP_MAX`](super::SKIP_MAX) keys.
        pub(in crate::party) fn from_proto(chains: &[proto::SkippedChain]) -> Result<Self> {
            let chains = chains
                .iter()
                .map(|chain| {
                    Ok(SkippedChain {
                        header_key: key(&chain.header_key)?,
                        keys: chain
                            .message_keys
                            .iter()
                            .map(|message_key| {
                                Ok((message_key.message_number, key(&message_key.key)?))
                            })
                            .collect::<Result<_>>()?,
                        age: usize::try_from(chain.age).map_err(|_| ErrorKind::MalformedState)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let mut skipped = Self::default();
            skipped.extend(chains);
            Ok(skipped)
        }
    }

    /// A key field, which must be [`KEY_LENGTH`] bytes.
    fn key(bytes: &[u8]) -> Result<[u8; KEY_LENGTH]> {
        bytes
            .try_into()
            .map_err(|_| ErrorKind::MalformedState.into())
    }
}

impl Extend<SkippedChain> for SkippedKeys {
    /// Keep keys skipped in the peer's current chain, then drop the oldest keys beyond
    /// [`SKIP_MAX`].
    fn extend<T: IntoIterator<Item = SkippedChain>>(&mut self, chains: T) {
        for chain in chains {
            match self
                .chains
                .iter_mut()
                .find(|kept| kept.header_key == chain.header_key)
            {
                Some(kept) => kept.keys.extend(chain.keys),
                None if chain.keys.is_empty() => {}
                None => self.chains.push_back(chain),
            }
        }
        let mut len = self.len();
        while len > SKIP_MAX
            && let Some(oldest) = self.chains.front_mut()
        {
            if oldest.keys.pop_first().is_some() {
                len -= 1;
            }
            if oldest.keys.is_empty() {
                self.chains.pop_front();
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::ops::Range;

    use super::*;

    /// Keys for `message_numbers` in the chain of header key `[header_key; 32]`.
    fn chain(header_key: u8, message_numbers: Range<u64>) -> SkippedChain {
        let mut chain = SkippedChain::new([header_key; 32]);
        for message_number in message_numbers {
            chain.insert(message_number, [message_number as u8; 32]);
        }
        chain
    }

    #[test]
    fn len_follows_every_change() {
        let mut skipped = SkippedKeys::default();
        skipped.extend([chain(1, 0..3)]);
        skipped.extend([chain(1, 5..7), chain(2, 0..0)]);
        assert_eq!(skipped.len(), 5);
        // A key kept already is not counted twice.
        skipped.extend([chain(1, 2..3)]);
        assert_eq!(skipped.len(), 5);
        assert_eq!(skipped.get(&[1; 32], 5), Some([5; 32]));
        assert_eq!(skipped.get(&[1; 32], 3), None);
        assert_eq!(skipped.get(&[2; 32], 0), None);
        // An empty chain is not kept.
        assert_eq!(skipped.header_keys().collect::<Vec<_>>(), [[1; 32]]);

        skipped.remove(&[1; 32], 5);
        skipped.remove(&[1; 32], 5);
        skipped.remove(&[2; 32], 0);
        assert_eq!(skipped.len(), 4);
        assert_eq!(skipped.get(&[1; 32], 5), None);

        for message_number in [0, 1, 2, 6] {
            skipped.remove(&[1; 32], message_number);
        }
        assert_eq!(skipped.len(), 0);
        // Its last key used, the chain goes.
        assert_eq!(skipped.header_keys().count(), 0);
    }
}
