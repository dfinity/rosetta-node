use super::*;
use crate::common::test_utils::crypto_component::crypto_component_with;
use crate::common::test_utils::hex_to_32_bytes;
use ic_crypto_internal_csp::secret_key_store::volatile_store::VolatileSecretKeyStore;
use ic_crypto_internal_csp::secret_key_store::SecretKeyStore;
use ic_test_utilities::crypto::empty_fake_registry;

#[test]
fn should_correctly_generate_ed25519_user_keys() {
    let crypto = crypto_component_with(empty_fake_registry(), empty_secret_key_store());

    let (sk_id, pk) = crypto.generate_user_keys_ed25519().unwrap();

    assert_eq!(
        sk_id,
        KeyId::from(hex_to_32_bytes(
            "be652632635fa33651721671afa29c576396beaec8af0d8ba819605fc7dea8e4"
        ))
    );
    assert_eq!(
        pk,
        UserPublicKey {
            key: hex_decode("78eda21ba04a15e2000fe8810fe3e56741d23bb9ae44aa9d5bb21b76675ff34b"),
            algorithm_id: AlgorithmId::Ed25519,
        }
    );
}

#[test]
fn should_correctly_generate_committee_member_keys() {
    let crypto = crypto_component_with(empty_fake_registry(), empty_secret_key_store());

    let (sk_id, pk) = crypto.generate_committee_member_keys().unwrap();

    assert_eq!(
        sk_id,
        KeyId::from(hex_to_32_bytes(
            "250224d6a3e0edbaafd958bb480dc81255ec8744e36ac5eefa83e747d531272b"
        ))
    );
    assert_eq!(
        pk,
        CommitteeMemberPublicKey {
            key: hex_decode(
                "8985344664badd2aa2d24167fa478ec03a6fc76eb05ba1c3fa\
                 c9dd88b74a44ccdd5d088bb6975c06a8df4b1006f8e5350adbf82b3a758613f56d4\
                 519da62f9075adfdd882b35f35a55f532471191348924a5c3858529f83cfb032cc8\
                 962f7922"
            ),
            proof_of_possession: hex_decode(
                "9347f963a3d79d07515d4f1c740d2030226d84f626be4b807b1e4f5c8ec3073a34820ec08c63e5cbda02d3b862cb1570"
            ),
        }
    );
}

fn empty_secret_key_store() -> impl SecretKeyStore {
    VolatileSecretKeyStore::new()
}

fn hex_decode(x: &str) -> Vec<u8> {
    hex::decode(x).unwrap()
}
