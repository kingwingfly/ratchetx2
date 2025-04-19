use ratchetx2::SharedKeys;

#[test]
fn ratchet_test() {
    let shared_key = SharedKeys {
        secret_key: [0; 32],
        header_key_alice: [1; 32],
        header_key_bob: [2; 32],
    };
    let mut alice = shared_key.alice();
    let mut bob = shared_key.bob();

    alice.step_dh_root(bob.public_key());
    bob.step_dh_root(alice.public_key());
    assert_eq!(alice, bob);
    assert_eq!(alice.step_msgs(), bob.step_msgr());
    assert_eq!(alice.step_msgs(), bob.step_msgr());

    bob.step_dh_root(alice.public_key());
    alice.step_dh_root(bob.public_key());
    assert_eq!(alice, bob);
    assert_eq!(bob.step_msgs(), alice.step_msgr());
    assert_eq!(bob.step_msgs(), alice.step_msgr());

    alice.step_dh_root(bob.public_key());
    bob.step_dh_root(alice.public_key());
    assert_eq!(alice, bob);
    assert_eq!(alice.step_msgs(), bob.step_msgr());
    assert_eq!(alice.step_msgs(), bob.step_msgr());
}
