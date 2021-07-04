use ic_crypto_internal_basic_sig_cose::*;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1::*;
use ic_crypto_internal_test_vectors::*;
use ic_types::crypto::CryptoResult;
use openssl::sha::sha256;

// A COSE-encoded ECDSA-P256 public key, with a signature over an example
// message.
const ECDSA_P256_PK_2_COSE_HEX : &str = "a501020326200121582051556cab67bc37cc806d4b0666b2553a35f8a96e1ea0025942a1f140b6e42d4e2258200b203014c786088b3525fd5a41ce16cec81de536186efdbc8f9ab9bf9df2f366";
const MSG_2_HEX : &str = "2f1b671a93f444b8ec77e0211f9624c9c2612182b864f0d4ac9d335f5b4fe50201000000537f91225ffff1e2912a0f8ca7a0ef61df01ae3d8898fca283036239259bab4f82";
const SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX : &str = "3045022100c69c75c6d6c449ea936094476e8bfcad90d831a6437a87117615add6d6a5168802201e2e4535976794286fa264eb81d7b14b3f168ab7f62ad5c0b9d6ebfc64eb0c8c";

#[test]
fn should_correctly_parse_cose_encoded_pk() {
    let pk_cose = hex::decode(ECDSA_P256_PK_2_COSE_HEX).unwrap();
    let _pk = parse_cose_public_key(&pk_cose).unwrap();
}

#[test]
fn should_correctly_parse_webauthn_cose_encoded_pk() {
    let pk_cose = hex::decode(test_data::WEBAUTHN_ECDSA_P256_PK_COSE_HEX).unwrap();
    let _pk = parse_cose_public_key(&pk_cose).unwrap();
}

#[test]
fn should_fail_parsing_a_corrupted_cose_encoded_pk() {
    let mut pk_cose = hex::decode(ECDSA_P256_PK_2_COSE_HEX).unwrap();
    pk_cose[0] += 1;
    let pk_result = parse_cose_public_key(&pk_cose);
    assert!(pk_result.is_err());
    assert!(pk_result.unwrap_err().is_malformed_public_key());
}

#[test]
fn should_correctly_verify_der_signature() {
    let result = get_der_cose_verification_result(
        SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX,
        ECDSA_P256_PK_2_COSE_HEX,
        MSG_2_HEX,
    );
    assert!(result.is_ok());
}

#[test]
fn should_fail_to_verify_on_wrong_message() {
    let mut wrong_msg_hex = String::from(MSG_2_HEX);
    wrong_msg_hex.push_str("ab");
    let result = get_der_cose_verification_result(
        SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX,
        ECDSA_P256_PK_2_COSE_HEX,
        &wrong_msg_hex,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().is_signature_verification_error());
}

#[test]
fn should_fail_to_verify_corrupted_signature() {
    let mut corrupted_der_sig_hex = String::from(SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX);
    corrupted_der_sig_hex.truncate(corrupted_der_sig_hex.len() - 2);
    corrupted_der_sig_hex.push_str("aa");
    assert!(
        corrupted_der_sig_hex != SIG_OF_MSG_2_WITH_ECDSA_P256_PK_1_DER_HEX,
        "Signature should be different"
    );
    let result = get_der_cose_verification_result(
        &corrupted_der_sig_hex,
        ECDSA_P256_PK_2_COSE_HEX,
        MSG_2_HEX,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().is_signature_verification_error());
}

#[test]
fn should_correctly_verify_webauthn_signatures() {
    let result = get_der_cose_verification_result(
        test_data::ECDSA_P256_SIG_1_DER_HEX,
        test_data::ECDSA_P256_PK_1_COSE_HEX,
        test_data::WEBAUTHN_MSG_1_HEX,
    );
    assert!(result.is_ok());

    let result = get_der_cose_verification_result(
        test_data::ECDSA_P256_SIG_2_DER_HEX,
        test_data::ECDSA_P256_PK_2_COSE_HEX,
        test_data::WEBAUTHN_MSG_2_HEX,
    );
    assert!(result.is_ok());
}

// Given a DER-encoded signature, a COSE-encoded ECDSA-P256 public key,
// and a message, computes and returns a signature verification result.
fn get_der_cose_verification_result(
    sig_der_hex: &str,
    pk_cose_hex: &str,
    msg_hex: &str,
) -> CryptoResult<()> {
    let sig_der = hex::decode(sig_der_hex).unwrap();
    let sig = signature_from_der(&sig_der).unwrap();
    let pk_cose = hex::decode(pk_cose_hex).unwrap();
    let (_alg_id, pk) = parse_cose_public_key(&pk_cose).unwrap();
    let pk = public_key_from_der(&pk).unwrap();
    let msg = hex::decode(msg_hex).unwrap();
    let msg_hash = sha256(&msg);
    verify(&sig, &msg_hash, &pk)
}
