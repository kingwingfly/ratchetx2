//! Message keys skipped over while receiving, kept to decrypt the messages if they arrive late.

use std::collections::{BTreeMap, VecDeque};

use ratchetx2::key::{HeaderKey, MessageKey};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{MAX_SKIPPED_CHAINS, SKIP_MAX};
#[cfg(any(feature = "serde", feature = "prost", test))]
use crate::error::{ErrorKind, Result};

/// Maximum skipped chain count as `u32`, matching [`SkippedChain::age`].
const MAX_SKIPPED_CHAINS_U32: u32 = MAX_SKIPPED_CHAINS as u32;
const _: () = assert!(MAX_SKIPPED_CHAINS <= u32::MAX as usize);

/// Maximum number of disjoint evicted message-number intervals tracked per chain.
pub(super) const MAX_EVICTED_RANGES: usize = 128;

/// Bounded tracker of message numbers whose skipped keys were evicted on a chain, so late arrivals
/// are reported as [`ErrorKind::EvictedMessage`] instead of [`ErrorKind::DuplicateMessage`].
#[derive(Default, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "EvictedSetUnchecked")
)]
pub(super) struct EvictedSet {
    /// Sorted, disjoint, coalesced inclusive intervals `(start, end)` of evicted message numbers.
    ranges: Vec<(u64, u64)>,
    /// Watermark below which any missing message number is conservatively treated as evicted
    /// (used only if more than [`MAX_EVICTED_RANGES`] disjoint eviction bursts occur on one chain).
    collapsed_below: u64,
}

impl EvictedSet {
    /// Clear all recorded evicted message numbers.
    pub(super) fn clear(&mut self) {
        self.ranges.clear();
        self.collapsed_below = 0;
    }

    /// Record that `message_number` had its skipped key evicted.
    pub(super) fn insert(&mut self, message_number: u64) {
        if message_number < self.collapsed_below {
            return;
        }
        // Fast path: most evictions arrive in strictly increasing order (`pop_first`).
        if let Some(last) = self.ranges.last_mut() {
            if message_number <= last.1 && message_number >= last.0 {
                return;
            }
            if last.1.checked_add(1) == Some(message_number) {
                last.1 = message_number;
                return;
            }
            if message_number > last.1 {
                self.ranges.push((message_number, message_number));
                self.enforce_bound();
                return;
            }
        }
        self.ranges.push((message_number, message_number));
        self.normalize();
        self.enforce_bound();
    }

    /// Merge all evicted numbers from `other` into `self`.
    pub(super) fn merge_from(&mut self, other: &Self) {
        if other.is_empty() {
            return;
        }
        self.collapsed_below = self.collapsed_below.max(other.collapsed_below);
        self.ranges.extend_from_slice(&other.ranges);
        self.normalize();
        self.enforce_bound();
    }

    /// Whether `message_number` was evicted (or falls under the collapsed watermark).
    pub(super) fn contains(&self, message_number: u64) -> bool {
        if message_number < self.collapsed_below {
            return true;
        }
        self.ranges
            .binary_search_by(|&(start, end)| {
                if message_number < start {
                    std::cmp::Ordering::Greater
                } else if message_number > end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    fn normalize(&mut self) {
        self.ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.ranges.len());
        for (start, end) in self.ranges.drain(..) {
            if end < self.collapsed_below {
                continue;
            }
            let start = start.max(self.collapsed_below);
            if let Some(last) = merged.last_mut()
                && start <= last.1.saturating_add(1)
            {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        self.ranges = merged;
    }

    fn enforce_bound(&mut self) {
        while self.ranges.len() > MAX_EVICTED_RANGES {
            let (_start, end) = self.ranges.remove(0);
            self.collapsed_below = self.collapsed_below.max(end.saturating_add(1));
        }
    }
    pub(super) fn is_empty(&self) -> bool {
        self.collapsed_below == 0 && self.ranges.is_empty()
    }

    #[cfg(any(feature = "serde", feature = "prost", test))]
    pub(super) fn validate(&self, exclusive_upper_bound: Option<u64>) -> Result<()> {
        if self.ranges.len() > MAX_EVICTED_RANGES {
            return Err(ErrorKind::MalformedState.into());
        }
        if let Some(bound) = exclusive_upper_bound
            && self.collapsed_below > bound
        {
            return Err(ErrorKind::MalformedState.into());
        }
        let mut prev_end: Option<u64> = None;
        for &(start, end) in &self.ranges {
            if start > end || start < self.collapsed_below {
                return Err(ErrorKind::MalformedState.into());
            }
            if let Some(prev) = prev_end
                && start <= prev
            {
                return Err(ErrorKind::MalformedState.into());
            }
            if let Some(bound) = exclusive_upper_bound
                && end >= bound
            {
                return Err(ErrorKind::MalformedState.into());
            }
            prev_end = Some(end);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_bounded_vec<'de, D, T, const MAX: usize>(
    deserializer: D,
) -> core::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct BoundedVecVisitor<T, const MAX: usize>(core::marker::PhantomData<T>);

    impl<'de, T, const MAX: usize> serde::de::Visitor<'de> for BoundedVecVisitor<T, MAX>
    where
        T: serde::Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "a sequence of at most {MAX} items")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> core::result::Result<Vec<T>, A::Error> {
            let cap = seq.size_hint().unwrap_or(0).min(MAX);
            let mut out = Vec::with_capacity(cap);
            while let Some(item) = seq.next_element::<T>()? {
                if out.len() >= MAX {
                    return Err(serde::de::Error::invalid_length(MAX + 1, &self));
                }
                out.push(item);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor::<T, MAX>(core::marker::PhantomData))
}

#[cfg(feature = "serde")]
fn deserialize_bounded_vecdeque<'de, D, T, const MAX: usize>(
    deserializer: D,
) -> core::result::Result<VecDeque<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct BoundedDequeVisitor<T, const MAX: usize>(core::marker::PhantomData<T>);

    impl<'de, T, const MAX: usize> serde::de::Visitor<'de> for BoundedDequeVisitor<T, MAX>
    where
        T: serde::Deserialize<'de>,
    {
        type Value = VecDeque<T>;

        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "a sequence of at most {MAX} items")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> core::result::Result<VecDeque<T>, A::Error> {
            let cap = seq.size_hint().unwrap_or(0).min(MAX);
            let mut out = VecDeque::with_capacity(cap);
            while let Some(item) = seq.next_element::<T>()? {
                if out.len() >= MAX {
                    return Err(serde::de::Error::invalid_length(MAX + 1, &self));
                }
                out.push_back(item);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(BoundedDequeVisitor::<T, MAX>(core::marker::PhantomData))
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(rename = "EvictedSet")]
struct EvictedSetUnchecked {
    #[serde(deserialize_with = "deserialize_bounded_vec::<_, _, MAX_EVICTED_RANGES>")]
    ranges: Vec<(u64, u64)>,
    collapsed_below: u64,
}

#[cfg(feature = "serde")]
impl TryFrom<EvictedSetUnchecked> for EvictedSet {
    type Error = crate::error::Error;

    fn try_from(raw: EvictedSetUnchecked) -> Result<Self> {
        let set = Self {
            ranges: raw.ranges,
            collapsed_below: raw.collapsed_below,
        };
        set.validate(None)?;
        Ok(set)
    }
}

#[cfg(feature = "serde")]
fn deserialize_unique_message_keys<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<u64, MessageKey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct KeyMapGuard(BTreeMap<u64, MessageKey>);
    impl Drop for KeyMapGuard {
        fn drop(&mut self) {
            for key in self.0.values_mut() {
                key.zeroize();
            }
        }
    }
    struct UniqueKeysVisitor;
    impl<'de> serde::de::Visitor<'de> for UniqueKeysVisitor {
        type Value = BTreeMap<u64, MessageKey>;

        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("a map of unique message numbers to message keys")
        }

        fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut guard = KeyMapGuard(BTreeMap::new());
            while let Some((number, value)) = map.next_entry::<u64, MessageKey>()? {
                let mut value = Zeroizing::new(value);
                if guard.0.len() >= SKIP_MAX as usize {
                    value.zeroize();
                    return Err(serde::de::Error::custom("too many skipped message keys"));
                }
                if guard.0.contains_key(&number) {
                    value.zeroize();
                    return Err(serde::de::Error::custom("duplicate skipped message number"));
                }
                guard.0.insert(number, *value);
            }
            Ok(core::mem::take(&mut guard.0))
        }
    }
    deserializer.deserialize_map(UniqueKeysVisitor)
}

/// The message keys skipped in one of the peer's chains.
#[cfg_attr(test, derive(Debug, Clone, PartialEq))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(super) struct SkippedChain {
    header_key: HeaderKey,
    /// By message number, so the oldest comes first.
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "deserialize_unique_message_keys")
    )]
    keys: BTreeMap<u64, MessageKey>,
    /// Number of the peer's chains received after this one.
    age: u32,
    /// Message numbers evicted from this chain before they arrived.
    #[cfg_attr(feature = "serde", serde(default))]
    evicted: EvictedSet,
}

impl Zeroize for SkippedChain {
    fn zeroize(&mut self) {
        self.header_key.zeroize();
        for key in self.keys.values_mut() {
            key.zeroize();
        }
        self.keys.clear();
        self.age.zeroize();
        self.evicted.clear();
    }
}

impl Drop for SkippedChain {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SkippedChain {}

impl SkippedChain {
    /// No keys yet, in the peer's current chain, whose header key is `header_key`.
    pub(super) fn new(header_key: Zeroizing<HeaderKey>) -> Self {
        Self {
            header_key: *header_key,
            keys: BTreeMap::new(),
            age: 0,
            evicted: EvictedSet::default(),
        }
    }

    pub(super) fn insert(&mut self, message_number: u64, message_key: Zeroizing<MessageKey>) {
        if let Some(existing) = self.keys.get_mut(&message_number) {
            existing.zeroize();
        }
        self.keys.insert(message_number, *message_key);
    }
}

/// The skipped message keys of the peer's last [`MAX_SKIPPED_CHAINS`] chains, at most
/// [`SKIP_MAX`] of them: the keys of lost messages neither stay forever nor take the room of later
/// ones.
///
/// It keeps no count of its keys besides the chains, so a state restored with prost or serde,
/// however corrupt, cannot disagree with itself.
#[derive(Default)]
#[cfg_attr(test, derive(Debug, Clone, PartialEq))]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "SkippedKeysUnchecked")
)]
pub(super) struct SkippedKeys {
    /// The chains with keys left, oldest first.
    chains: VecDeque<SkippedChain>,
}

impl Zeroize for SkippedKeys {
    fn zeroize(&mut self) {
        for chain in &mut self.chains {
            chain.zeroize();
        }
        self.chains.clear();
    }
}

impl Drop for SkippedKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SkippedKeys {}

impl SkippedKeys {
    /// Number of keys kept, over at most a few chains.
    pub(super) fn len(&self) -> u64 {
        self.chains
            .iter()
            .map(|chain| chain.keys.len() as u64)
            .sum()
    }

    /// The header keys of the chains with keys left.
    pub(super) fn header_keys(&self) -> impl Iterator<Item = &HeaderKey> + '_ {
        self.chains.iter().map(|chain| &chain.header_key)
    }

    /// The key of message `message_number` in the chain of `header_key`, if it was skipped.
    pub(super) fn get(
        &self,
        header_key: &HeaderKey,
        message_number: u64,
    ) -> Option<Zeroizing<MessageKey>> {
        let chain = self
            .chains
            .iter()
            .find(|chain| bool::from(chain.header_key.ct_eq(header_key)))?;
        chain.keys.get(&message_number).copied().map(Zeroizing::new)
    }

    /// Whether `message_number` in the skipped chain of `header_key` was previously evicted.
    pub(super) fn is_evicted(&self, header_key: &HeaderKey, message_number: u64) -> bool {
        self.chains
            .iter()
            .find(|chain| bool::from(chain.header_key.ct_eq(header_key)))
            .is_some_and(|chain| chain.evicted.contains(message_number))
    }

    /// Merge evicted message numbers from the current receiving chain onto its [`SkippedChain`]
    /// before moving to the next chain.
    pub(super) fn attach_evicted(&mut self, header_key: &HeaderKey, evicted: &EvictedSet) {
        if evicted.is_empty() {
            return;
        }
        if let Some(chain) = self
            .chains
            .iter_mut()
            .find(|chain| bool::from(chain.header_key.ct_eq(header_key)))
        {
            chain.evicted.merge_from(evicted);
        }
    }

    /// Forget and zeroize the key of message `message_number` in the chain of `header_key`, once
    /// used. A chain with no keys left goes too, so its header key is no longer tried.
    pub(super) fn remove(&mut self, header_key: &HeaderKey, message_number: u64) {
        let Some(index) = self
            .chains
            .iter()
            .position(|chain| bool::from(chain.header_key.ct_eq(header_key)))
        else {
            return;
        };
        if let Some(key) = self.chains[index].keys.get_mut(&message_number) {
            key.zeroize();
        }
        self.chains[index].keys.remove(&message_number);
        if self.chains[index].keys.is_empty() {
            // Removing drops the SkippedChain, whose Drop impl zeroizes header_key.
            self.chains.remove(index);
        }
    }

    /// The peer has moved on to its next chain: forget and zeroize the chains that are now too old.
    pub(super) fn next_chain(&mut self) {
        for chain in &mut self.chains {
            chain.age = chain.age.saturating_add(1);
        }
        while let Some(oldest) = self.chains.front()
            && oldest.age >= MAX_SKIPPED_CHAINS_U32
        {
            // Dropping the popped SkippedChain zeroizes its header_key and all message keys.
            self.chains.pop_front();
        }
    }

    /// Keep keys skipped in the peer's chains, then drop and zeroize the oldest keys beyond
    /// [`SKIP_MAX`], invoking `on_evict(header_key, message_number)` for each evicted key.
    pub(super) fn extend_with_evictions<T: IntoIterator<Item = SkippedChain>>(
        &mut self,
        chains: T,
        mut on_evict: impl FnMut(&HeaderKey, u64),
    ) {
        for mut chain in chains {
            match self
                .chains
                .iter_mut()
                .find(|kept| bool::from(kept.header_key.ct_eq(&chain.header_key)))
            {
                Some(kept) => {
                    for (&num, &key) in &chain.keys {
                        if let Some(existing) = kept.keys.get_mut(&num) {
                            existing.zeroize();
                        }
                        kept.keys.insert(num, key);
                    }
                    kept.evicted.merge_from(&chain.evicted);
                    chain.zeroize();
                }
                None if chain.keys.is_empty() => {
                    chain.zeroize();
                }
                None => self.chains.push_back(chain),
            }
        }
        let mut len = self.len();
        while len > SKIP_MAX
            && let Some(oldest) = self.chains.front_mut()
        {
            if let Some(mut entry) = oldest.keys.first_entry() {
                let message_number = *entry.key();
                entry.get_mut().zeroize();
                entry.remove();
                oldest.evicted.insert(message_number);
                let hk = Zeroizing::new(oldest.header_key);
                on_evict(&hk, message_number);
                len -= 1;
            }
            if oldest.keys.is_empty() {
                self.chains.pop_front();
            }
        }
    }
    #[cfg(any(feature = "serde", feature = "prost"))]
    pub(super) fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }

    #[cfg(any(feature = "serde", feature = "prost"))]
    pub(super) fn validate(
        &self,
        current_receiver: Option<(&HeaderKey, u64)>,
        next_receiver: Option<&HeaderKey>,
    ) -> Result<()> {
        if self.chains.len() > MAX_SKIPPED_CHAINS {
            return Err(ErrorKind::MalformedState.into());
        }
        let mut seen: Vec<&HeaderKey> = Vec::with_capacity(self.chains.len());
        let mut previous_age = MAX_SKIPPED_CHAINS_U32;
        let mut remaining = SKIP_MAX;
        for chain in &self.chains {
            let count = chain.keys.len() as u64;
            if count == 0
                || count > remaining
                || chain.age >= MAX_SKIPPED_CHAINS_U32
                || chain.age >= previous_age
                || next_receiver.is_some_and(|key| bool::from(key.ct_eq(&chain.header_key)))
                || seen
                    .iter()
                    .any(|key| bool::from(key.ct_eq(&chain.header_key)))
            {
                return Err(ErrorKind::MalformedState.into());
            }
            seen.push(&chain.header_key);
            previous_age = chain.age;
            remaining -= count;

            let bound = current_receiver
                .filter(|(key, _)| bool::from(key.ct_eq(&chain.header_key)))
                .map(|(_, next)| next);
            if bound.is_some() {
                if chain.age != 0 {
                    return Err(ErrorKind::MalformedState.into());
                }
            } else if current_receiver.is_some() && chain.age == 0 {
                return Err(ErrorKind::MalformedState.into());
            }
            let mut prev_number: Option<u64> = None;
            for &number in chain.keys.keys() {
                if prev_number.is_some_and(|prev| number <= prev)
                    || bound.is_some_and(|next| number >= next)
                {
                    return Err(ErrorKind::MalformedState.into());
                }
                prev_number = Some(number);
            }
            chain.evicted.validate(bound)?;
        }
        Ok(())
    }
}

// Before eviction tracking, each skipped chain had exactly three positional fields.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct LegacySkippedChain(
    HeaderKey,
    #[serde(deserialize_with = "deserialize_unique_message_keys")] BTreeMap<u64, MessageKey>,
    u32,
);

#[cfg(feature = "serde")]
impl Drop for LegacySkippedChain {
    fn drop(&mut self) {
        self.0.zeroize();
        for key in self.1.values_mut() {
            key.zeroize();
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
pub(super) struct LegacySkippedKeys {
    #[serde(deserialize_with = "deserialize_bounded_vecdeque::<_, _, MAX_SKIPPED_CHAINS>")]
    chains: VecDeque<LegacySkippedChain>,
}

#[cfg(feature = "serde")]
impl From<LegacySkippedKeys> for SkippedKeys {
    fn from(mut old: LegacySkippedKeys) -> Self {
        Self {
            chains: old
                .chains
                .iter_mut()
                .map(|chain| SkippedChain {
                    header_key: chain.0,
                    keys: core::mem::take(&mut chain.1),
                    age: chain.2,
                    evicted: EvictedSet::default(),
                })
                .collect(),
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(rename = "SkippedKeys")]
struct SkippedKeysUnchecked {
    #[serde(deserialize_with = "deserialize_bounded_vecdeque::<_, _, MAX_SKIPPED_CHAINS>")]
    chains: VecDeque<SkippedChain>,
}

#[cfg(feature = "serde")]
impl TryFrom<SkippedKeysUnchecked> for SkippedKeys {
    type Error = crate::error::Error;

    fn try_from(raw: SkippedKeysUnchecked) -> Result<Self> {
        let skipped = Self { chains: raw.chains };
        skipped.validate(None, None)?;
        Ok(skipped)
    }
}

/// The keys as the party's protobuf state.
#[cfg(feature = "prost")]
mod state {
    use std::collections::{BTreeMap, VecDeque};

    use ratchetx2::key::KEY_LENGTH;

    use super::{EvictedSet, MAX_EVICTED_RANGES, SkippedChain, SkippedKeys};
    use crate::{
        error::{ErrorKind, Result},
        party::{MAX_SKIPPED_CHAINS, SKIP_MAX},
        proto,
    };

    impl EvictedSet {
        pub(in crate::party) fn to_proto(&self) -> (Vec<proto::EvictedRange>, u64) {
            let ranges = self
                .ranges
                .iter()
                .map(|&(start, end)| proto::EvictedRange { start, end })
                .collect();
            (ranges, self.collapsed_below)
        }

        pub(in crate::party) fn from_proto(
            ranges: &[proto::EvictedRange],
            collapsed_below: u64,
        ) -> Result<Self> {
            if ranges.len() > MAX_EVICTED_RANGES {
                return Err(ErrorKind::MalformedState.into());
            }
            let set = Self {
                ranges: ranges.iter().map(|r| (r.start, r.end)).collect(),
                collapsed_below,
            };
            set.validate(None)?;
            Ok(set)
        }
    }

    impl SkippedKeys {
        /// The chains as protobuf messages, oldest first.
        pub(in crate::party) fn to_proto(&self) -> Vec<proto::SkippedChain> {
            self.chains
                .iter()
                .map(|chain| {
                    let (evicted, evicted_below) = chain.evicted.to_proto();
                    proto::SkippedChain {
                        header_key: chain.header_key.to_vec(),
                        message_keys: chain
                            .keys
                            .iter()
                            .map(|(message_number, message_key)| proto::MessageKey {
                                message_number: *message_number,
                                key: message_key.to_vec(),
                            })
                            .collect(),
                        age: u64::from(chain.age),
                        evicted,
                        evicted_below,
                    }
                })
                .collect()
        }

        /// The keys of `chains`, from [`to_proto`](Self::to_proto), enforcing
        /// [`MAX_SKIPPED_CHAINS`] and [`SKIP_MAX`] before allocating key maps.
        pub(in crate::party) fn from_proto(chains: &[proto::SkippedChain]) -> Result<Self> {
            if chains.len() > MAX_SKIPPED_CHAINS {
                return Err(ErrorKind::MalformedState.into());
            }
            // Enforce total key budget before allocating any BTreeMaps.
            let mut total_keys: u64 = 0;
            for chain in chains {
                if chain.message_keys.is_empty() {
                    return Err(ErrorKind::MalformedState.into());
                }
                total_keys = total_keys
                    .checked_add(chain.message_keys.len() as u64)
                    .ok_or(ErrorKind::MalformedState)?;
                if total_keys > SKIP_MAX {
                    return Err(ErrorKind::MalformedState.into());
                }
            }

            let mut skipped = Self {
                chains: VecDeque::with_capacity(chains.len()),
            };
            for chain in chains {
                let mut decoded_chain = SkippedChain {
                    header_key: key(&chain.header_key)?,
                    keys: BTreeMap::new(),
                    age: u32::try_from(chain.age).map_err(|_| ErrorKind::MalformedState)?,
                    evicted: EvictedSet::from_proto(&chain.evicted, chain.evicted_below)?,
                };
                for message_key in &chain.message_keys {
                    let next_key = zeroize::Zeroizing::new(key(&message_key.key)?);
                    if let Some(mut duplicate) = decoded_chain
                        .keys
                        .insert(message_key.message_number, *next_key)
                    {
                        zeroize::Zeroize::zeroize(&mut duplicate);
                        return Err(ErrorKind::MalformedState.into());
                    }
                }
                skipped.chains.push_back(decoded_chain);
            }
            skipped.validate(None, None)?;
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
        self.extend_with_evictions(chains, |_, _| {});
    }
}

#[cfg(test)]
mod test {
    use std::ops::Range;

    use super::*;

    /// Keys for `message_numbers` in the chain of header key `[header_key; 32]`.
    fn chain(header_key: u8, message_numbers: Range<u64>) -> SkippedChain {
        let mut chain = SkippedChain::new(Zeroizing::new([header_key; 32]));
        for message_number in message_numbers {
            chain.insert(message_number, Zeroizing::new([message_number as u8; 32]));
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
        assert_eq!(skipped.get(&[1; 32], 5).as_deref(), Some(&[5; 32]));
        assert_eq!(skipped.get(&[1; 32], 3), None);
        assert_eq!(skipped.get(&[2; 32], 0), None);
        // An empty chain is not kept.
        assert_eq!(
            skipped.header_keys().copied().collect::<Vec<_>>(),
            [[1; 32]]
        );

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
    fn evicted_set_coalesces_and_bounds() {
        let mut set = EvictedSet::default();
        for i in 0..500 {
            set.insert(i);
        }
        assert_eq!(set.ranges, vec![(0, 499)]);
        assert!(set.contains(0));
        assert!(set.contains(499));
        assert!(!set.contains(500));

        // Exceeding MAX_EVICTED_RANGES collapses oldest ranges into collapsed_below safely.
        let mut disjoint = EvictedSet::default();
        for i in 0..(MAX_EVICTED_RANGES as u64 + 10) {
            disjoint.insert(i * 2);
        }
        assert_eq!(disjoint.ranges.len(), MAX_EVICTED_RANGES);
        assert!(disjoint.collapsed_below > 0);
        assert!(disjoint.contains(0));
        assert!(disjoint.contains((MAX_EVICTED_RANGES as u64 + 9) * 2));
        disjoint.validate(None).unwrap();
    }

    #[cfg(any(feature = "serde", feature = "prost"))]
    #[test]
    fn validate_rejects_duplicate_ages_and_non_current_age_zero() {
        // Duplicate ages must be rejected so `next_chain` + `extend` cannot exceed MAX_SKIPPED_CHAINS.
        let mut dup_a = chain(1, 0..1);
        dup_a.age = 1;
        let mut dup_b = chain(2, 0..1);
        dup_b.age = 1;
        let dup_skipped = SkippedKeys {
            chains: VecDeque::from([dup_a, dup_b]),
        };
        assert_eq!(
            dup_skipped.validate(None, None).unwrap_err().kind(),
            ErrorKind::MalformedState
        );

        // Non-current chain with age == 0 must be rejected when current_receiver is present.
        let current = [9u8; 32];
        let next = [8u8; 32];
        let mut non_current = chain(3, 0..1);
        non_current.age = 0;
        let non_current_skipped = SkippedKeys {
            chains: VecDeque::from([non_current]),
        };
        assert_eq!(
            non_current_skipped
                .validate(Some((&current, 2)), Some(&next))
                .unwrap_err()
                .kind(),
            ErrorKind::MalformedState
        );

        // Skipped chain colliding with next_header_key_receiver must be rejected.
        let mut collides_next = chain(8, 0..1);
        collides_next.age = 1;
        let colliding = SkippedKeys {
            chains: VecDeque::from([collides_next]),
        };
        assert_eq!(
            colliding
                .validate(Some((&current, 2)), Some(&next))
                .unwrap_err()
                .kind(),
            ErrorKind::MalformedState
        );

        // Strictly decreasing ages with current receiver at age == 0 succeed.
        let mut older = chain(4, 0..1);
        older.age = 1;
        let mut cur_chain = chain(9, 0..1);
        cur_chain.age = 0;
        let valid = SkippedKeys {
            chains: VecDeque::from([older, cur_chain]),
        };
        valid.validate(Some((&current, 2)), Some(&next)).unwrap();
    }
}
