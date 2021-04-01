use super::*;
use ic_crypto::utils::generate_dkg_dealing_encryption_keys;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_test_utilities::crypto::temp_dir::temp_dir;

#[test]
fn should_fail_if_pubkey_conversion_fails() {
    let pubkey_proto_with_incorrect_key_value_length = PublicKeyProto {
        key_value: vec![42],
        ..valid_dkg_dealing_encryption_key()
    };

    let result = fs_ni_dkg_pubkey_from_proto(&pubkey_proto_with_incorrect_key_value_length);

    assert_malformed_fs_encryption_pubkey_error_containing(&result, "Wrong data length");
}

#[test]
fn should_fail_if_pok_conversion_fails() {
    let pubkey_proto_without_proof_data = {
        let mut key = valid_dkg_dealing_encryption_key();
        if let Some(pok) = key.proof_data.as_mut() {
            pok.pop();
        }
        key
    };

    let result = fs_ni_dkg_pubkey_from_proto(&pubkey_proto_without_proof_data);

    assert_malformed_fs_encryption_pok_error_containing(
        &result,
        "Malformed proof of knowledge (PoK)",
    );
}

#[test]
fn should_fail_if_internal_conversion_fails() {
    let pubkey_proto_with_corrupted_key_value = {
        let mut key = valid_dkg_dealing_encryption_key();
        key.key_value = vec![0; key.key_value.len()];
        key
    };

    let result = fs_ni_dkg_pubkey_from_proto(&pubkey_proto_with_corrupted_key_value);

    assert_internal_conversion_error(&result);
}

fn valid_dkg_dealing_encryption_key() -> PublicKeyProto {
    let temp_dir = temp_dir();
    generate_dkg_dealing_encryption_keys(temp_dir.path())
}

fn assert_malformed_fs_encryption_pubkey_error_containing(
    result: &Result<ClibFsNiDkgPublicKey, FsNiDkgPubkeyFromPubkeyProtoError>,
    substring: &str,
) {
    let error = result.clone().unwrap_err();
    if let FsNiDkgPubkeyFromPubkeyProtoError::PublicKeyConversion { error } = error {
        assert!(error.contains(substring))
    } else {
        panic!(
            "expected MalformedFsEncryptionPublicKey error, but got {}",
            error
        )
    }
}

fn assert_malformed_fs_encryption_pok_error_containing(
    result: &Result<ClibFsNiDkgPublicKey, FsNiDkgPubkeyFromPubkeyProtoError>,
    substring: &str,
) {
    let error = result.clone().unwrap_err();
    if let FsNiDkgPubkeyFromPubkeyProtoError::PokConversion { error } = error {
        assert!(error.contains(substring))
    } else {
        panic!("expected MalformedFsEncryptionPok error, but got {}", error)
    }
}

#[allow(clippy::assertions_on_constants)]
fn assert_internal_conversion_error(
    result: &Result<ClibFsNiDkgPublicKey, FsNiDkgPubkeyFromPubkeyProtoError>,
) {
    let error = result.clone().unwrap_err();
    if let FsNiDkgPubkeyFromPubkeyProtoError::InternalConversion = error {
        assert!(true)
    } else {
        panic!("expected InternalConversion error, but got {}", error)
    }
}
