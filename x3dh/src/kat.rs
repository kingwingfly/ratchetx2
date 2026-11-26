//! Known-answer tests for FIPS 203 and the complete PQXDH transcript.
//! The sequential-seed ML-KEM outputs were generated independently with OpenSSL 3.6.
//! The transcript constants were calculated with a Montgomery ladder, SHA-256 and HMAC
//! in Python, using the same public test inputs.

use super::*;
use ml_kem::kem::Decapsulate;
use sha2::Digest;
use x25519_dalek::PublicKey as X25519PublicKey;

fn hex<const N: usize>(input: &str) -> [u8; N] {
    assert_eq!(input.len(), 2 * N);
    core::array::from_fn(|i| u8::from_str_radix(&input[2 * i..2 * i + 2], 16).unwrap())
}

struct Vector {
    suite: PqSuite,
    id: u8,
    info: &'static [u8],
    ek_prefix: &'static str,
    ek_suffix: &'static str,
    ek_sha256: &'static str,
    ct_prefix: &'static str,
    ct_suffix: &'static str,
    ct_sha256: &'static str,
    ss: &'static str,
    rejection: &'static str,
    prekey_id: &'static str,
    ikm_sha256: &'static str,
    th: &'static str,
    sk: &'static str,
    ad: &'static str,
}

#[cfg(feature = "ml-kem-1024")]
const ML_KEM_1024: Vector = Vector {
    suite: PqSuite::MlKem1024,
    id: 1,
    info: b"pqxdh.v1/X25519/ML-KEM-1024/SHA-256",
    ek_prefix: "4b94c29450111191823b3514c9ac1ea3",
    ek_suffix: "eb0c8701ed58dc628776b983882e1175",
    ek_sha256: "c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530",
    ct_prefix: "9d30c0211a6f4b42f09bd865aa3f377f",
    ct_suffix: "152c35fffe529dc2ac15aa7af619b9b7",
    ct_sha256: "a92b6445ec6e627beec79dac695e8cc172bdb8560d3508cf31e638456849b449",
    ss: "dde5bda1124813a06cdcc735df4926b412e014ec3271a3a2fb0340e667183279",
    rejection: "3cf76b5d88b6b780cb21a8724e3cdc32c1a79c23fb59f401f80f13cedb19fd1a",
    prekey_id: "685337accec06dd90b1ce62f6fbbe0b09b905457424e3f9254d7db4258bf808c",
    ikm_sha256: "39da085a766ae4756677d10a1c7d4d90a59dd8379732e852d1dd0e43a31c0ce5",
    th: "dcf3dc318dbb3a0090b75682927a57a60ec51fb0bee622b6cf923ee654f1e0fa",
    sk: "446fbe8ed9eb27ca415eff62ecc7f538a46e4a83c77f903d4204532469caa862",
    ad: concat!(
        "9dd1240fb713719c3f0cfcd4405b4fe6050ae3375bc44e1a9088b6861b9cae4b",
        "837e6fd29a57e2804823fa25f760d697886cdd953e62bf0b37d7e6585592a153",
        "dcf3dc318dbb3a0090b75682927a57a60ec51fb0bee622b6cf923ee654f1e0fa",
    ),
};

#[cfg(feature = "ml-kem-768")]
const ML_KEM_768: Vector = Vector {
    suite: PqSuite::MlKem768,
    id: 2,
    info: b"pqxdh.v1/X25519/ML-KEM-768/SHA-256",
    ek_prefix: "298aa10d423c8dda069d02bc59e6cdf0",
    ek_suffix: "1ea893c3e2cb32da8bc342fa4dea0578",
    ek_sha256: "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9",
    ct_prefix: "28aba0d0d59bdbb12a8d5925c51d51da",
    ct_suffix: "ad654a3149425f0d63a61bb9d0dad97a",
    ct_sha256: "9c7b2f8d05c70575ec03ed8f93b7bb298e1506b97e54e5e885748965b1466f1c",
    ss: "b83e7f23b33f909715c7a50b0d4b1f6684d53e1f4b9056f803b29f058ccb5566",
    rejection: "3816af13752429d4e8b800fd2c691b3254d09ed953cf287c99453d3d8057b41e",
    prekey_id: "d9043747863ecc975eb2594fdc332a004d0d28ee898e4d70063a2d3f3bb9030b",
    ikm_sha256: "eb25efa5d3951ce1357aeb23795d6b520e80ba514c6f392e86e02cec5877b98c",
    th: "3b8e0922b46aff2d10976ff0d5ef370b11c6bcc0f3d21da93e68f092331dfdf3",
    sk: "48fe0af76ba2cecd21794525049a06e049a0fe4765d92ddb087db88386fae8ab",
    ad: concat!(
        "9dd1240fb713719c3f0cfcd4405b4fe6050ae3375bc44e1a9088b6861b9cae4b",
        "837e6fd29a57e2804823fa25f760d697886cdd953e62bf0b37d7e6585592a153",
        "3b8e0922b46aff2d10976ff0d5ef370b11c6bcc0f3d21da93e68f092331dfdf3",
    ),
};

fn sequential_seed() -> [u8; 64] {
    core::array::from_fn(|i| i as u8)
}

fn check_fips203(v: &Vector) {
    let seed = sequential_seed();
    let m = [0x42; 32];
    let mut ek = kem::derive_ek(v.suite, &seed).unwrap();
    assert_eq!(ek.len(), v.suite.ek_len());
    assert_eq!(ek[..16], hex::<16>(v.ek_prefix));
    assert_eq!(ek[ek.len() - 16..], hex::<16>(v.ek_suffix));
    assert_eq!(Sha256::digest(&ek).as_slice(), hex::<32>(v.ek_sha256));

    let (mut ct, ss) = kem::encapsulate_deterministic(v.suite, &ek, &m).unwrap();
    assert_eq!(ct.len(), v.suite.ct_len());
    assert_eq!(ct[..16], hex::<16>(v.ct_prefix));
    assert_eq!(ct[ct.len() - 16..], hex::<16>(v.ct_suffix));
    assert_eq!(Sha256::digest(&ct).as_slice(), hex::<32>(v.ct_sha256));
    assert_eq!(*ss, hex(v.ss));
    assert_eq!(*kem::decapsulate(v.suite, &seed, &ct).unwrap(), hex(v.ss));

    ct[0] ^= 1;
    assert_eq!(
        *kem::decapsulate(v.suite, &seed, &ct).unwrap(),
        hex(v.rejection)
    );

    ek[..2].fill(0xff); // Coefficient 4095 exceeds the modulus.
    assert_eq!(
        kem::encapsulate_deterministic(v.suite, &ek, &m)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidPublicKey
    );
}

fn check_transcript(v: &Vector) {
    let alice = XEdDSAPrivateKey::from_bytes([1; 32]).unwrap();
    let bob = XEdDSAPrivateKey::from_bytes([2; 32]).unwrap();
    let signed = StaticSecret::from([3; 32]);
    let one_time = StaticSecret::from([4; 32]);
    let ephemeral = StaticSecret::from([5; 32]);
    let ika = alice.compute_public_key().to_bytes();
    let ikb = bob.compute_public_key().to_bytes();
    let spk = X25519PublicKey::from(&signed);
    let opk = X25519PublicKey::from(&one_time);
    let eka = X25519PublicKey::from(&ephemeral);
    let manifest = [0xab; 32];
    let seed = sequential_seed();
    let ek = kem::derive_ek(v.suite, &seed).unwrap();
    let (ct, ss) = kem::encapsulate_deterministic(v.suite, &ek, &[0x42; 32]).unwrap();
    assert_eq!(Sha256::digest(&ct).as_slice(), hex::<32>(v.ct_sha256));
    assert_eq!(*ss, hex(v.ss));

    // Compute Alice's DH outputs directly. accept_pq evaluates them from Bob's side.
    let dh1 = alice.diffie_hellman(spk.as_bytes()).unwrap();
    let dh2 = ephemeral.diffie_hellman(&X25519PublicKey::from(ikb));
    let dh3 = ephemeral.diffie_hellman(&spk);
    let dh4 = ephemeral.diffie_hellman(&opk);
    let ikm = [
        [0xff; 32],
        *dh1,
        dh2.to_bytes(),
        dh3.to_bytes(),
        dh4.to_bytes(),
        *ss,
    ]
    .concat();
    assert_eq!(Sha256::digest(&ikm).as_slice(), hex::<32>(v.ikm_sha256));

    let id: [u8; 32] = Sha256::digest([b"pqxdh.v1/id\0".as_slice(), &[v.id], &ek].concat()).into();
    assert_eq!(id, hex(v.prekey_id));
    assert_eq!(pq_prekey_id(v.suite.as_u8(), &ek), id);
    let transcript = [
        ika.as_slice(),
        &ikb,
        spk.as_bytes(),
        &[1],
        opk.as_bytes(),
        eka.as_bytes(),
        &[v.id, 0],
        &id,
        &ct,
        &2u32.to_be_bytes(),
        &[32],
        &manifest,
    ]
    .concat();
    let th: [u8; 32] = Sha256::digest(transcript).into();
    assert_eq!(th, hex(v.th));
    let mut sk = [0; 32];
    Hkdf::<Sha256>::new(Some(&[0; 32]), &ikm)
        .expand(&[v.info, &th].concat(), &mut sk)
        .unwrap();
    assert_eq!(sk, hex(v.sk));
    let ad = [ika, ikb, th].concat();
    assert_eq!(ad, hex::<96>(v.ad));

    let message = PqInitialMessage {
        version: 2,
        identity_key: ika,
        ephemeral_key: eka.to_bytes(),
        signed_prekey: spk.to_bytes(),
        one_time_prekey: Some(opk.to_bytes()),
        pq_suite: v.suite,
        pq_last_resort: false,
        pq_prekey_id: id,
        pq_ciphertext: ct,
    };
    let mut local = LocalPrekeys::new();
    local.generations.push_back(Generation {
        signed_prekey: spk.to_bytes(),
        signed_secret: signed,
        one_time: BTreeMap::from([(opk.to_bytes(), one_time)]),
        confirmed: BTreeSet::new(),
        pq_last_resort: BTreeMap::new(),
        pq_one_time: BTreeMap::from([(
            id,
            PqPrekeySecret {
                suite: v.suite,
                ek,
                seed: Zeroizing::new(seed),
            },
        )]),
    });
    let (agreement, selected_spk) = local
        .accept_pq(&bob, &ika, &message, Some(&manifest))
        .unwrap();
    assert_eq!(X25519PublicKey::from(&selected_spk), spk);
    assert_eq!(agreement.suite, v.suite);
    assert_eq!(agreement.transcript_hash, th);
    assert_eq!(*agreement.secret_key, sk);
    assert_eq!(agreement.associated_data.as_slice(), ad);
}

// NIST ACVP-Server, commit 65370b861b96efd30dfe0daae607bde26a78a5c8:
// https://github.com/usnistgov/ACVP-Server/tree/65370b861b96efd30dfe0daae607bde26a78a5c8/gen-val/json-files
// Fixtures contain the binary inputs from the FIPS203 internalProjection.json files.
// The expected EK, expanded DK and ciphertext hashes cover the full official outputs.
fn check_acvp_encap(suite: PqSuite, ek: &[u8], m: &str, ct_hash: &str, k: &str) {
    let (ct, ss) = kem::encapsulate_deterministic(suite, ek, &hex(m)).unwrap();
    assert_eq!(Sha256::digest(&ct).as_slice(), hex::<32>(ct_hash));
    assert_eq!(*ss, hex(k));
}

#[cfg(feature = "ml-kem-1024")]
#[test]
fn fips203_kat_ml_kem_1024() {
    check_fips203(&ML_KEM_1024);
}

#[cfg(feature = "ml-kem-1024")]
#[test]
fn pqxdh_transcript_ml_kem_1024() {
    check_transcript(&ML_KEM_1024);
}

// ACVP keyGen tcId 51, encapsulation tcId 51, decapsulation tcId 96.
#[cfg(feature = "ml-kem-1024")]
#[test]
#[allow(
    deprecated,
    reason = "ACVP supplies and checks expanded decapsulation keys"
)]
fn nist_acvp_ml_kem_1024() {
    use ml_kem::{DecapsulationKey1024 as Dk, ExpandedKeyEncoding};
    let seed = hex::<64>(concat!(
        "49ac8b99bb1e6a8ea818261f8be68bdeaa52897e7ec6c40b530bc760ab77dce3",
        "99e3246884181f8e1dd44e0c7629093330221fd67d9b7d6e1510b2dbad8762f7"
    ));
    let ek = kem::derive_ek(PqSuite::MlKem1024, &seed).unwrap();
    assert_eq!(
        Sha256::digest(ek).as_slice(),
        hex::<32>("62fccf5fdf805b110670b39cd5e25b1811172961ea4047bfbd589e323ce7cfbc")
    );
    let dk = Dk::from_seed(seed.into());
    assert_eq!(
        Sha256::digest(dk.to_expanded_bytes()).as_slice(),
        hex::<32>("2f8af73000bd5247a74312ac70386444290bc4b80da6fae05aeb1196dbd8912e")
    );

    check_acvp_encap(
        PqSuite::MlKem1024,
        include_bytes!("../tests/fixtures/acvp-ml-kem-1024-encap.ek"),
        "59c5154c04ae43aaff32700f081700389d54bec4c37c088b1c53f66212b12c72",
        "50ee6d865a34afb897c2d77dcf7744d8c91ce9318947beeb8d3e4578f10e95c4",
        "7264bde5c6cec14849693e2c3c86e48f80958a4f6186fc69333a4148e6e497f3",
    );
    let dk =
        Dk::from_expanded(include_bytes!("../tests/fixtures/acvp-ml-kem-1024-decap.dk").into())
            .unwrap();
    let k = dk
        .decapsulate_slice(include_bytes!(
            "../tests/fixtures/acvp-ml-kem-1024-decap.ct"
        ))
        .unwrap();
    assert_eq!(
        k.as_slice(),
        hex::<32>("8f336e9c28df349e03220af01c42832fefab1f2a74c16faf6f64ad071c1a3394")
    );
}

#[cfg(feature = "ml-kem-768")]
#[test]
fn fips203_kat_ml_kem_768() {
    check_fips203(&ML_KEM_768);
}

#[cfg(feature = "ml-kem-768")]
#[test]
fn pqxdh_transcript_ml_kem_768() {
    check_transcript(&ML_KEM_768);
}

// ACVP keyGen tcId 26, encapsulation tcId 26, decapsulation tcId 88.
#[cfg(feature = "ml-kem-768")]
#[test]
#[allow(
    deprecated,
    reason = "ACVP supplies and checks expanded decapsulation keys"
)]
fn nist_acvp_ml_kem_768() {
    use ml_kem::{DecapsulationKey768 as Dk, ExpandedKeyEncoding};
    let seed = hex::<64>(concat!(
        "e34a701c4c87582f42264ee422d3c684d97611f2523efe0c998af05056d693dc",
        "a85768f3486bd32a01bf9a8f21ea938e648eae4e5448c34c3eb88820b159eedd"
    ));
    let ek = kem::derive_ek(PqSuite::MlKem768, &seed).unwrap();
    assert_eq!(
        Sha256::digest(ek).as_slice(),
        hex::<32>("7799c9d8eef172aa78c073514f2f039c240de8c5cb61bca82ba0bc46041ce279")
    );
    let dk = Dk::from_seed(seed.into());
    assert_eq!(
        Sha256::digest(dk.to_expanded_bytes()).as_slice(),
        hex::<32>("104b3444c3de2b81143788d27e17648f45c80f617f906156db2258da96dead40")
    );

    check_acvp_encap(
        PqSuite::MlKem768,
        include_bytes!("../tests/fixtures/acvp-ml-kem-768-encap.ek"),
        "2ce74ad291133518fe60c7df5d251b9d82add48462ff505c6e547e949e6b6bf7",
        "ac57163b80ead205b8323e1402b8ca66bece40d8df9994b12d43bbb4f6e19bf4",
        "2696d28e9c61c2a01ce9b1608dcb9d292785a0cd58efb7fe13b1de95f0db55b3",
    );
    let dk = Dk::from_expanded(include_bytes!("../tests/fixtures/acvp-ml-kem-768-decap.dk").into())
        .unwrap();
    let k = dk
        .decapsulate_slice(include_bytes!("../tests/fixtures/acvp-ml-kem-768-decap.ct"))
        .unwrap();
    assert_eq!(
        k.as_slice(),
        hex::<32>("dc5b8888bc1eba5c1969c21164ea43e22e7ac0cd012a2f26cb8c487e69ef7ce4")
    );
}
