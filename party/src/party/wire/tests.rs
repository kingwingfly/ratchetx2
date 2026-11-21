use std::collections::BTreeMap;

use ratchetx2::{DhPrivateKey, SharedKeys};
use serde_json::json;

use super::*;

// All five captures start from the same Bob, before his first message.
const V0: &[u8] = include_bytes!("../../../tests/fixtures/bob-v0.postcard");
const V1: &[u8] = include_bytes!("../../../tests/fixtures/bob-v1.postcard");
const CLASSIC: &[u8] = include_bytes!("../../../tests/fixtures/bob-v2.postcard");
const PQ_1024: &[u8] = include_bytes!("../../../tests/fixtures/bob-v2-ml-kem-1024.postcard");
const PQ_768: &[u8] = include_bytes!("../../../tests/fixtures/bob-v2-ml-kem-768.postcard");

fn keys() -> SharedKeys {
    SharedKeys {
        secret_key: [2; 32],
        header_key_alice: [2; 32],
        header_key_bob: [3; 32],
    }
}

fn bob() -> Party {
    Party::new(Ratchet::bob(&keys(), DhPrivateKey::from([4; 32])), b"AD")
}

fn alice(bob: &Party) -> Party {
    Party::new(
        Ratchet::alice(&keys(), &bob.ratchet.public_key()).unwrap(),
        b"AD",
    )
}

fn exchange(alice: &mut Party, bob: &mut Party) {
    let msg = alice.encrypt(b"hello").unwrap();
    assert_eq!(bob.decrypt(&msg).unwrap(), b"hello");
    let reply = bob.encrypt(b"world").unwrap();
    assert_eq!(alice.decrypt(&reply).unwrap(), b"world");
}

fn supports(capability: u8) -> bool {
    capability == 0
        || (capability == 1 && cfg!(feature = "ml-kem-1024"))
        || (capability == 2 && cfg!(feature = "ml-kem-768"))
}

#[test]
fn versioned_postcard_fixtures_across_builds() {
    for (capability, fixture) in [(0, CLASSIC), (1, PQ_1024), (2, PQ_768)] {
        let restored = postcard::from_bytes::<Party>(fixture);
        assert_eq!(restored.is_ok(), supports(capability));
        if let Ok(restored) = restored {
            assert_eq!(restored.is_pq_ratchet_active(), capability != 0);
            #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
            assert_eq!(restored.pq_suite().map_or(0, PqSuite::id), capability);
            let expected = bob();
            #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
            let expected = match PqSuite::from_id(capability) {
                Some(suite) => Party::new_pq(expected.ratchet, expected.associated_data, suite),
                None => expected,
            };
            assert_eq!(postcard::to_allocvec(&expected).unwrap(), fixture);
            assert_eq!(postcard::to_allocvec(&restored).unwrap(), fixture);
        }
        for tag in [0, 1, 2, 0xff] {
            let bytes = [fixture, &[tag]].concat();
            let nested = postcard::from_bytes::<(Party, u8)>(&bytes);
            assert_eq!(nested.is_ok(), supports(capability));
            if let Ok((party, actual_tag)) = nested {
                assert_eq!(actual_tag, tag);
                assert_eq!(postcard::to_allocvec(&(party, tag)).unwrap(), bytes);
            }
        }
    }
}

#[test]
fn version_and_capability_must_match_the_payload() {
    for fixture in [CLASSIC, PQ_1024, PQ_768] {
        for version in [0, 1, 3, 255] {
            let mut bytes = fixture.to_vec();
            bytes[0] = version;
            assert!(postcard::from_bytes::<Party>(&bytes).is_err());
        }
        for capability in [0, 1, 2, 3, 255] {
            if capability != fixture[1] {
                let mut bytes = fixture.to_vec();
                bytes[1] = capability;
                assert!(postcard::from_bytes::<Party>(&bytes).is_err());
            }
        }
    }
}

#[test]
fn legacy_classical_fixtures_resume_the_session() {
    let original = bob();
    let first_six = (
        &original.ratchet,
        &original.skipped_message_keys,
        0u64,
        0u64,
        0u64,
        b"AD".as_slice(),
    );
    assert_eq!(postcard::to_allocvec(&first_six).unwrap(), V0);
    assert_eq!(
        postcard::to_allocvec(&(first_six, &original.current_chain_evicted)).unwrap(),
        V1
    );
    let v0 = postcard::from_bytes::<LegacyPartyV0>(V0).unwrap();
    let v1 = postcard::from_bytes::<LegacyPartyV1>(V1).unwrap();
    for mut restored in [v0.into_party(), v1.into_party()] {
        exchange(&mut alice(&original), &mut restored);
    }
    for tag in [0, 1, 2, 255] {
        let (v0, t0) = postcard::from_bytes::<(LegacyPartyV0, u8)>(&[V0, &[tag]].concat()).unwrap();
        let (v1, t1) = postcard::from_bytes::<(LegacyPartyV1, u8)>(&[V1, &[tag]].concat()).unwrap();
        assert_eq!((t0, t1), (tag, tag));
        for restored in [v0.into_party(), v1.into_party()] {
            assert_eq!(postcard::to_allocvec(&restored).unwrap(), CLASSIC);
        }
    }
}

#[test]
fn legacy_skipped_chain_layouts_preserve_delayed_messages() {
    let mut bob = bob();
    let mut alice = alice(&bob);
    let late = alice.encrypt(b"late").unwrap();
    let next = alice.encrypt(b"next").unwrap();
    bob.decrypt(&next).unwrap();

    // The six-field layout also predates the eviction field on each skipped chain.
    let hk = bob.ratchet.header_key_receiver().unwrap();
    let keys = BTreeMap::from([(0u64, *bob.skipped_message_keys.get(&hk, 0).unwrap())]);
    let chains = [(hk, keys, 0usize)];
    let old_skipped = (chains.as_slice(),);
    let v0 = postcard::to_allocvec(&(
        &bob.ratchet,
        old_skipped,
        0u64,
        0u64,
        2u64,
        &bob.associated_data,
    ))
    .unwrap();
    let v1 = postcard::to_allocvec(&(
        &bob.ratchet,
        &bob.skipped_message_keys,
        0u64,
        0u64,
        2u64,
        &bob.associated_data,
        &bob.current_chain_evicted,
    ))
    .unwrap();
    for mut restored in [
        postcard::from_bytes::<LegacyPartyV0>(&v0)
            .unwrap()
            .into_party(),
        postcard::from_bytes::<LegacyPartyV1>(&v1)
            .unwrap()
            .into_party(),
    ] {
        assert_eq!(restored.decrypt(&late).unwrap(), b"late");
        assert!(restored.encrypt(b"reply").is_ok());
    }
}

#[test]
fn legacy_readers_validate_before_conversion() {
    let mut bob = bob();
    let alice = alice(&bob);
    for mid_step in [false, true] {
        if mid_step {
            bob.ratchet
                .step_dh_root(&alice.ratchet.public_key())
                .unwrap();
        }
        // Isolate a counter violation on a fresh Bob, then the DH phase violation alone.
        let sent = u64::from(!mid_step);
        let six = (
            &bob.ratchet,
            &bob.skipped_message_keys,
            0u64,
            sent,
            0u64,
            &bob.associated_data,
        );
        let v0 = postcard::to_allocvec(&six).unwrap();
        let v1 = postcard::to_allocvec(&(six, &bob.current_chain_evicted)).unwrap();
        assert!(postcard::from_bytes::<LegacyPartyV0>(&v0).is_err());
        assert!(postcard::from_bytes::<LegacyPartyV1>(&v1).is_err());
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        assert!(postcard::from_bytes::<LegacyPartyPqV1>(&[v1.as_slice(), &[0]].concat()).is_err());
    }
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
mod pq_legacy {
    use super::*;
    use crate::EncryptedMessage;
    use ratchetx2::pq::MAX_PENDING_OFFERS;

    // Captured with 44b6e39 as (Alice, Bob, Alice's in-flight message). With rekey_messages=2
    // and rekey_turns=0, A0, B0, A1..A3, B1 leave Alice retransmitting a ciphertext and Bob
    // holding a queued peer key. Both have pending local offers and encapsulation history.
    const ACTIVE_1024: &[u8] = include_bytes!("../../../tests/fixtures/active-v1-1024.postcard");
    const ACTIVE_768_DUAL: &[u8] =
        include_bytes!("../../../tests/fixtures/active-v1-768-dual.postcard");
    const ACTIVE_768_SINGLE: &[u8] =
        include_bytes!("../../../tests/fixtures/active-v1-768-single.postcard");

    fn migrate(bytes: &[u8], old_index: u8, suite: PqSuite) -> (Party, &[u8]) {
        let (legacy, rest) = postcard::take_from_bytes::<LegacyPartyPqV1>(bytes).unwrap();
        let record = &bytes[..bytes.len() - rest.len()];
        let (_, kem) = postcard::take_from_bytes::<SevenFields>(record).unwrap();
        assert_eq!(&kem[..2], &[1, old_index]); // Some followed by the old suite enum.
        let mut expected = [&[VERSION, suite.id()][..], record].concat();
        let suite_offset = expected.len() - kem.len() + 1;
        expected[suite_offset] = suite.id();
        let party = legacy.into_party();
        assert_eq!(party.pq_suite(), Some(suite));
        assert_eq!(postcard::to_allocvec(&party).unwrap(), expected);
        for tag in [0, 1, 2, 0xff] {
            let nested = [record, &[tag]].concat();
            let ((party, actual), tail) =
                postcard::take_from_bytes::<(LegacyPartyPqV1, u8)>(&nested).unwrap();
            assert_eq!(actual, tag);
            assert!(tail.is_empty());
            assert_eq!(
                postcard::to_allocvec(&party.into_party()).unwrap(),
                expected
            );
        }
        (postcard::from_bytes(&expected).unwrap(), rest)
    }

    #[test]
    fn live_peers_resume_across_the_positional_migration() {
        for (capture, index, id, enabled) in [
            (ACTIVE_1024, 0, 1, cfg!(feature = "ml-kem-1024")),
            (
                ACTIVE_768_DUAL,
                1,
                2,
                cfg!(all(feature = "ml-kem-1024", feature = "ml-kem-768")),
            ),
            (ACTIVE_768_SINGLE, 0, 2, cfg!(not(feature = "ml-kem-1024"))),
        ] {
            let (_, sender, rest) = unchecked(capture);
            let (_, receiver, _) = unchecked(rest);
            for snapshot in [&sender, &receiver] {
                assert!(!snapshot.pending_offers.is_empty());
                assert!(snapshot.active_offer_id.is_some());
                assert!(!snapshot.encapsulated_ek_ids.is_empty());
                assert!(snapshot.messages_since_rekey > 0);
                assert!(!snapshot.initial_offer_needed);
            }
            assert!(sender.active_send_ct.is_some());
            assert!(receiver.peer_pending_ek.is_some());
            assert!(receiver.turns_since_rekey > 0);
            if !enabled {
                assert!(postcard::from_bytes::<LegacyPartyPqV1>(capture).is_err());
                continue;
            }
            let suite = PqSuite::from_id(id).unwrap();
            let (mut alice, rest) = migrate(capture, index, suite);
            let (mut bob, rest) = migrate(rest, index, suite);
            let (in_flight, tail) = postcard::take_from_bytes::<EncryptedMessage>(rest).unwrap();
            assert!(tail.is_empty());
            assert_eq!(bob.decrypt(&in_flight).unwrap(), b"in flight");
            exchange(&mut bob, &mut alice);
            exchange(&mut bob, &mut alice);
        }
    }

    #[test]
    fn pq_builds_saved_classical_parties_with_an_explicit_none() {
        for tag in [0, 1, 2, 0xff] {
            let bytes = [V1, &[0, tag]].concat();
            let ((party, actual), rest) =
                postcard::take_from_bytes::<(LegacyPartyPqV1, u8)>(&bytes).unwrap();
            assert_eq!(actual, tag);
            assert!(rest.is_empty());
            let mut party = party.into_party();
            assert_eq!(postcard::to_allocvec(&party).unwrap(), CLASSIC);
            exchange(&mut alice(&party), &mut party);
        }
    }

    // An unchecked positional view for changing individual fields of the real captures.
    // All untouched fields still go through the production deserializer, including key seeds.
    #[derive(Clone, Serialize, Deserialize)]
    struct UncheckedKem {
        suite: u32,
        rekey_messages: u64,
        rekey_turns: u64,
        pending_offers: Vec<([u8; 16], Vec<u8>)>,
        active_offer_id: Option<[u8; 16]>,
        active_send_ct: Option<([u8; 16], Vec<u8>)>,
        peer_pending_ek: Option<([u8; 16], Vec<u8>)>,
        encapsulated_ek_ids: Vec<[u8; 16]>,
        messages_since_rekey: u64,
        turns_since_rekey: u64,
        initial_offer_needed: bool,
    }

    fn unchecked(bytes: &[u8]) -> (&[u8], UncheckedKem, &[u8]) {
        let (_, kem) = postcard::take_from_bytes::<SevenFields>(bytes).unwrap();
        let (some, rest) = postcard::take_from_bytes::<Option<UncheckedKem>>(kem).unwrap();
        (&bytes[..bytes.len() - kem.len()], some.unwrap(), rest)
    }

    fn decodes(prefix: &[u8], kem: &UncheckedKem) -> bool {
        let option = postcard::to_allocvec(&Some(kem)).unwrap();
        postcard::from_bytes::<LegacyPartyPqV1>(&[prefix, &option].concat()).is_ok()
    }

    #[test]
    fn legacy_kem_fields_undergo_full_state_validation() {
        let (fixture, id) = if cfg!(feature = "ml-kem-1024") {
            (ACTIVE_1024, 1)
        } else {
            (ACTIVE_768_SINGLE, 2)
        };
        let (prefix, alice, rest) = unchecked(fixture);
        let (bob_prefix, bob, _) = unchecked(rest);
        assert!(decodes(prefix, &alice));
        assert!(decodes(bob_prefix, &bob));
        let mut bad = alice.clone();
        bad.suite = 2; // Above the last variant even in a dual-suite build.
        assert!(!decodes(prefix, &bad));
        let mut bad = alice.clone();
        bad.active_send_ct.as_mut().unwrap().1.pop();
        assert!(!decodes(prefix, &bad));
        let mut bad = bob.clone();
        bad.peer_pending_ek.as_mut().unwrap().1.pop();
        assert!(!decodes(bob_prefix, &bad));
        let mut bad = bob;
        bad.peer_pending_ek.as_mut().unwrap().0[0] ^= 1;
        assert!(!decodes(bob_prefix, &bad));
        let mut bad = alice.clone();
        bad.active_offer_id.as_mut().unwrap()[0] ^= 1;
        assert!(!decodes(prefix, &bad));
        let mut bad = alice.clone();
        bad.pending_offers[0].0[0] ^= 1;
        assert!(!decodes(prefix, &bad));

        // Use distinct valid offers so only the count makes the final record invalid.
        let mut extra = KemRatchet::new(PqSuite::from_id(id).unwrap());
        for _ in 0..MAX_PENDING_OFFERS {
            extra.force_rekey().unwrap();
        }
        let extra: UncheckedKem =
            postcard::from_bytes(&postcard::to_allocvec(&extra).unwrap()).unwrap();
        let mut full = alice;
        for offer in extra.pending_offers {
            full.pending_offers.push(offer);
            assert_eq!(
                decodes(prefix, &full),
                full.pending_offers.len() <= MAX_PENDING_OFFERS
            );
        }
    }

    #[cfg(not(feature = "ml-kem-1024"))]
    #[test]
    fn legacy_index_zero_still_requires_768_ciphertext_and_key_lengths() {
        let (prefix, mut alice, rest) = unchecked(ACTIVE_1024);
        let (bob_prefix, mut bob, _) = unchecked(rest);
        // Isolate the suite-sized fields from the separate seed/ID mismatch.
        for (prefix, kem) in [(prefix, &mut alice), (bob_prefix, &mut bob)] {
            assert_eq!(kem.suite, 0);
            kem.pending_offers.clear();
            kem.active_offer_id = None;
            assert!(!decodes(prefix, kem));
            kem.active_send_ct = None;
            kem.peer_pending_ek = None;
            assert!(decodes(prefix, kem));
        }
    }
}

#[test]
fn json_accepts_legacy_maps_and_checks_versioned_fields() {
    let versioned = serde_json::to_value(bob()).unwrap();
    let duplicate_extension = format!(
        r#"{{"extension":1,"extension":2,{}"#,
        &versioned.to_string()[1..]
    );
    assert!(serde_json::from_str::<Party>(&duplicate_extension).is_err());
    for field in [
        "version",
        "capability",
        "kem_ratchet",
        "current_chain_evicted",
    ] {
        let mut missing = versioned.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<Party>(missing).is_err());
        let duplicate = format!(
            r#"{{"{field}":{},{}"#,
            versioned[field],
            &versioned.to_string()[1..]
        );
        assert!(serde_json::from_str::<Party>(&duplicate).is_err());
    }
    for (field, bad) in [
        ("version", json!(7)),
        ("version", json!(null)),
        ("capability", json!(255)),
        ("capability", json!(1)),
        ("capability", json!(null)),
        ("kem_ratchet", json!(false)),
    ] {
        let mut bad_map = versioned.clone();
        bad_map[field] = bad;
        assert!(serde_json::from_value::<Party>(bad_map).is_err());
    }
    let mut legacy = versioned;
    let map = legacy.as_object_mut().unwrap();
    map.remove("version");
    map.remove("capability");
    legacy["future_field"] = json!({"ignored": true});
    for (id, old_name) in [(1, "MlKem1024"), (2, "MlKem768")] {
        legacy["kem_ratchet"] = json!({
            "suite":old_name, "rekey_messages":20,"rekey_turns":4,"pending_offers":[],
            "active_offer_id":null,"active_send_ct":null,"peer_pending_ek":null,
            "encapsulated_ek_ids":[],"messages_since_rekey":0,"turns_since_rekey":0,"initial_offer_needed":true
        });
        let decoded = serde_json::from_value::<Party>(legacy.clone());
        assert_eq!(decoded.is_ok(), supports(id));
        if let Ok(party) = decoded {
            assert!(party.is_pq_ratchet_active());
        }
        let mut mismatched = legacy.clone();
        mismatched["version"] = json!(2);
        mismatched["capability"] = json!(0);
        assert!(serde_json::from_value::<Party>(mismatched).is_err());
    }
    legacy["kem_ratchet"] = json!(null);
    for remove in [None, Some("kem_ratchet"), Some("current_chain_evicted")] {
        if let Some(key) = remove {
            legacy.as_object_mut().unwrap().remove(key);
        }
        let restored = serde_json::from_value::<Party>(legacy.clone()).unwrap();
        assert_eq!(postcard::to_allocvec(&restored).unwrap(), CLASSIC);
    }
}
