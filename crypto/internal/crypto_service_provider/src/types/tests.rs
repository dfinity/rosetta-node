use super::*;
use ic_crypto_internal_test_vectors::basic_sig::TESTVEC_ED25519_STABILITY_1_SIG;
use ic_crypto_internal_test_vectors::ed25519::{
    TESTVEC_RFC8032_ED25519_1_SIG, TESTVEC_RFC8032_ED25519_2_SIG,
    TESTVEC_RFC8032_ED25519_SHA_ABC_PK, TESTVEC_RFC8032_ED25519_SHA_ABC_SIG,
    TESTVEC_RFC8032_ED25519_SHA_ABC_SK,
};
use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_1_PK;
use ic_crypto_internal_test_vectors::unhex::hex_to_byte_vec;
use ic_interfaces::crypto::CryptoHashableTestDummy;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_types::crypto::{AlgorithmId, BasicSig, BasicSigOf, UserPublicKey};
use std::convert::TryFrom;

#[test]
fn should_return_correct_ed25519_secret_key_bytes_for_ed25519_secret_key() {
    let ed25519_csp_sk = CspSecretKey::ed25519_from_hex(TESTVEC_RFC8032_ED25519_SHA_ABC_SK);

    assert_eq!(
        ed25519_csp_sk.ed25519_bytes().unwrap().to_vec(),
        hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_SK)
    );
}

#[test]
fn should_return_no_ed25519_secret_key_bytes_for_non_ed25519_secret_key() {
    let secret_key = CspSecretKey::MultiBls12_381(multi_types::SecretKeyBytes(
        [0u8; multi_types::SecretKeyBytes::SIZE],
    ));
    assert!(secret_key.ed25519_bytes().is_none())
}

#[test]
fn should_return_correct_ed25519_pubkey_bytes_for_ed25519_pubkey() {
    let ed25519_csp_pk = CspPublicKey::ed25519_from_hex(TESTVEC_RFC8032_ED25519_SHA_ABC_PK);

    assert_eq!(
        ed25519_csp_pk.ed25519_bytes().unwrap().to_vec(),
        hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_PK)
    );
}

#[test]
fn should_return_no_ed25519_pubkey_bytes_for_non_ed25519_pubkey() {
    assert!(
        CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_1_PK)
            .ed25519_bytes()
            .is_none()
    )
}

#[test]
fn should_return_correct_ed25519_signature_bytes_for_ed25519_signature() {
    let ed25519_csp_sig = CspSignature::ed25519_from_hex(TESTVEC_RFC8032_ED25519_SHA_ABC_SIG);

    assert_eq!(
        ed25519_csp_sig.ed25519_bytes().unwrap().to_vec(),
        hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_SIG)
    );
}

#[test]
fn should_return_no_ed25519_signature_bytes_for_non_ed25519_signature() {
    let signature = CspSignature::MultiBls12_381(MultiBls12_381_Signature::Individual(
        multi_types::IndividualSignatureBytes([0u8; multi_types::IndividualSignatureBytes::SIZE]),
    ));
    assert!(signature.ed25519_bytes().is_none())
}

#[test]
fn should_correctly_convert_basic_signature_to_ed25519_csp_signature() {
    let sig = BasicSigOf::<CryptoHashableTestDummy>::new(BasicSig(hex_to_byte_vec(
        TESTVEC_ED25519_STABILITY_1_SIG,
    )));

    let ed25519_csp_sig = SigConverter::for_target(AlgorithmId::Ed25519)
        .try_from_basic(&sig)
        .unwrap();

    assert_eq!(
        ed25519_csp_sig.ed25519_bytes().unwrap().to_vec(),
        hex_to_byte_vec(TESTVEC_ED25519_STABILITY_1_SIG)
    );
}

#[test]
fn should_correctly_convert_ed25519_csp_pubkey_to_user_public_key() {
    let ed25519_csp_pk = CspPublicKey::ed25519_from_hex(TESTVEC_RFC8032_ED25519_SHA_ABC_PK);

    let user_pk = UserPublicKey::try_from(ed25519_csp_pk).unwrap();

    assert_eq!(
        user_pk.key,
        hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_PK)
    );
}

#[test]
fn should_correctly_convert_ed25519_user_public_key_to_csp_public_key() {
    let user_pk = UserPublicKey {
        key: hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_PK),
        algorithm_id: AlgorithmId::Ed25519,
    };

    let ed25519_csp_pk = CspPublicKey::try_from(&user_pk).unwrap();

    assert_eq!(
        ed25519_csp_pk.ed25519_bytes().unwrap().to_vec(),
        hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_PK)
    );
}

#[test]
fn should_fail_to_convert_ed25519_user_pubkey_with_invalid_length_to_csp_pubkey() {
    let user_pk = UserPublicKey {
        key: vec![],
        algorithm_id: AlgorithmId::Ed25519,
    };

    let err = CspPublicKey::try_from(&user_pk).unwrap_err();

    assert!(err.is_malformed_public_key());
}

#[test]
fn should_correctly_compare_csp_signatures() {
    let ed25519_s1 = CspSignature::ed25519_from_hex(TESTVEC_RFC8032_ED25519_1_SIG);
    let ed25519_s1_2 = CspSignature::ed25519_from_hex(TESTVEC_RFC8032_ED25519_1_SIG);
    let ed25519_s2 = CspSignature::ed25519_from_hex(TESTVEC_RFC8032_ED25519_2_SIG);

    assert_eq!(ed25519_s1, ed25519_s1);
    assert_eq!(ed25519_s1, ed25519_s1_2);
    assert_ne!(ed25519_s1, ed25519_s2);
}

#[test]
fn should_correctly_convert_ed25519_pk_proto_to_csp_public_key() {
    let pk_proto = PublicKeyProto {
        algorithm: AlgorithmId::Ed25519 as i32,
        key_value: hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_PK),
        version: 0,
        proof_data: None,
    };
    let ed25519_csp_pk = CspPublicKey::try_from(pk_proto).unwrap();

    assert_eq!(
        ed25519_csp_pk.ed25519_bytes().unwrap().to_vec(),
        hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_PK)
    );
}

#[test]
fn should_correctly_convert_multi_bls12_381_pk_proto_to_csp_public_key() {
    let pk_proto = PublicKeyProto {
        algorithm: AlgorithmId::MultiBls12_381 as i32,
        key_value: hex_to_byte_vec(TESTVEC_MULTI_BLS12_381_1_PK),
        version: 0,
        proof_data: None,
    };
    let multi_bls_csp_pk = CspPublicKey::try_from(pk_proto).unwrap();

    assert_eq!(
        multi_bls_csp_pk.multi_bls12_381_bytes().unwrap().to_vec(),
        hex_to_byte_vec(TESTVEC_MULTI_BLS12_381_1_PK)
    );
}

#[test]
fn should_fail_conversion_to_csp_public_key_if_ed25519_pk_proto_is_too_short() {
    let pk_proto = PublicKeyProto {
        algorithm: AlgorithmId::Ed25519 as i32,
        key_value: vec![0; ed25519_types::PublicKeyBytes::SIZE - 1],
        version: 0,
        proof_data: None,
    };
    let ed25519_csp_pk_result = CspPublicKey::try_from(pk_proto);
    assert!(ed25519_csp_pk_result.is_err());
    assert!(ed25519_csp_pk_result.unwrap_err().is_malformed_public_key());
}

#[test]
fn should_fail_conversion_to_csp_public_key_if_ed25519_pk_proto_is_too_long() {
    let pk_proto = PublicKeyProto {
        algorithm: AlgorithmId::Ed25519 as i32,
        key_value: vec![0; ed25519_types::PublicKeyBytes::SIZE + 1],
        version: 0,
        proof_data: None,
    };
    let ed25519_csp_pk_result = CspPublicKey::try_from(pk_proto);
    assert!(ed25519_csp_pk_result.is_err());
    assert!(ed25519_csp_pk_result.unwrap_err().is_malformed_public_key());
}

#[test]
fn should_fail_conversion_to_csp_public_key_if_multi_bls12_381_pk_proto_is_too_short() {
    let pk_proto = PublicKeyProto {
        algorithm: AlgorithmId::MultiBls12_381 as i32,
        key_value: vec![0; multi_types::PublicKeyBytes::SIZE - 1],
        version: 0,
        proof_data: None,
    };
    let multi_csp_pk_result = CspPublicKey::try_from(pk_proto);
    assert!(multi_csp_pk_result.is_err());
    assert!(multi_csp_pk_result.unwrap_err().is_malformed_public_key());
}

#[test]
fn should_fail_conversion_to_csp_public_key_if_multi_bls12_381_pk_proto_is_too_long() {
    let pk_proto = PublicKeyProto {
        algorithm: AlgorithmId::MultiBls12_381 as i32,
        key_value: vec![0; multi_types::PublicKeyBytes::SIZE + 1],
        version: 0,
        proof_data: None,
    };
    let multi_csp_pk_result = CspPublicKey::try_from(pk_proto);
    assert!(multi_csp_pk_result.is_err());
    assert!(multi_csp_pk_result.unwrap_err().is_malformed_public_key());
}
