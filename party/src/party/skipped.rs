//! Message keys skipped over while receiving, kept to decrypt the messages if they arrive late.

use std::collections::{BTreeMap, VecDeque};

use ratchetx2::key::{HeaderKey, MessageKey};

use super::{MAX_SKIPPED_CHAINS, SKIP_MAX};

/// The message keys skipped in one of the peer's chains.
#[cfg_attr(test, derive(Debug, Clone, PartialEq))]
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
#[derive(Default)]
#[cfg_attr(test, derive(Debug, Clone, PartialEq))]
pub(super) struct SkippedKeys {
    /// The chains with keys left, oldest first.
    chains: VecDeque<SkippedChain>,
    /// Number of keys over all chains.
    len: u64,
}

impl SkippedKeys {
    /// Number of keys kept.
    pub(super) fn len(&self) -> u64 {
        self.len
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
        if self.chains[index].keys.remove(&message_number).is_some() {
            self.len -= 1;
        }
        if self.chains[index].keys.is_empty() {
            self.chains.remove(index);
        }
    }

    /// The peer has moved on to its next chain: forget the chains that are now too old.
    pub(super) fn next_chain(&mut self) {
        for chain in &mut self.chains {
            chain.age += 1;
        }
        while let Some(oldest) = self.chains.front()
            && oldest.age >= MAX_SKIPPED_CHAINS
        {
            self.len -= oldest.keys.len() as u64;
            self.chains.pop_front();
        }
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
                Some(kept) => {
                    for (message_number, message_key) in chain.keys {
                        if kept.keys.insert(message_number, message_key).is_none() {
                            self.len += 1;
                        }
                    }
                }
                None if chain.keys.is_empty() => {}
                None => {
                    self.len += chain.keys.len() as u64;
                    self.chains.push_back(chain);
                }
            }
        }
        while self.len > SKIP_MAX {
            let oldest = self.chains.front_mut().expect("the chains hold `len` keys");
            oldest.keys.pop_first();
            self.len -= 1;
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

    #[test]
    fn oldest_keys_go_beyond_skip_max() {
        let mut skipped = SkippedKeys::default();
        skipped.extend([chain(1, 0..2)]);
        skipped.next_chain();
        skipped.extend([chain(2, 10..10 + SKIP_MAX - 2)]);
        assert_eq!(skipped.len(), SKIP_MAX);

        skipped.extend([chain(2, 2000..2002)]);
        assert_eq!(skipped.len(), SKIP_MAX);
        // The older chain went first, with its keys; then the oldest keys of the next.
        assert_eq!(skipped.header_keys().collect::<Vec<_>>(), [[2; 32]]);
        skipped.extend([chain(2, 3000..3001)]);
        assert_eq!(skipped.len(), SKIP_MAX);
        assert_eq!(skipped.get(&[2; 32], 10), None);
        assert!(skipped.get(&[2; 32], 11).is_some());
    }

    #[test]
    fn chains_go_after_max_skipped_chains() {
        let mut skipped = SkippedKeys::default();
        skipped.extend([chain(1, 0..2)]);
        skipped.next_chain();
        skipped.extend([chain(2, 0..1)]);
        for _ in 1..MAX_SKIPPED_CHAINS {
            skipped.next_chain();
        }
        // The first chain is now MAX_SKIPPED_CHAINS chains old.
        assert_eq!(skipped.header_keys().collect::<Vec<_>>(), [[2; 32]]);
        assert_eq!(skipped.len(), 1);
        skipped.next_chain();
        assert_eq!(skipped.header_keys().count(), 0);
        assert_eq!(skipped.len(), 0);
    }
}
