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
