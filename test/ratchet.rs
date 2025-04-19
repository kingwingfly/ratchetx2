use ratchetx2::Ratchetx2;

#[test]
fn ratchet_test() {
    let secret_key = [0; 32];
    let header_key_alice = [1; 32];
    let header_key_bob = [2; 32];
    let mut alice = Ratchetx2::alice(secret_key, header_key_alice, header_key_bob);
    let mut bob = Ratchetx2::bob(secret_key, header_key_alice, header_key_bob);

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
}
