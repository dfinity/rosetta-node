use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::secp256k1::EphemeralPublicKeyBytes;
use ic_types::crypto::ListOfLists;
use ic_types::registry::PublicKeyRegistryRecord;
use ic_types_test_utils::arbitrary as arbitrary_types;
use proptest::prelude::*;

prop_compose! {
    pub fn list_of_lists() (seed in any::<Vec<u8>>()) -> ListOfLists {
        // TODO(DFN-793): Make this recursive
        ListOfLists::Leaf(seed)
    }
}

prop_compose! {
    pub fn public_key_registry_record()
        ( node_id in arbitrary_types::node_id()
        , key_purpose in arbitrary_types::key_purpose()
        , key in any::<Vec<u8>>()
        , key_id in arbitrary_types::key_id()
        , algorithm_id in arbitrary_types::algorithm_id()
        , version in arbitrary_types::registry_version()
        ) -> PublicKeyRegistryRecord {
        PublicKeyRegistryRecord {
                node_id,
                key_purpose,
                key,
                key_id,
                algorithm_id,
                version,
            }
    }
}

pub fn arbitrary_ephemeral_public_key_bytes() -> BoxedStrategy<EphemeralPublicKeyBytes> {
    proptest::collection::vec(
        any::<u8>(),
        EphemeralPublicKeyBytes::SIZE..=EphemeralPublicKeyBytes::SIZE,
    )
    .prop_map(|bytes| {
        let mut buffer = [0u8; EphemeralPublicKeyBytes::SIZE];
        buffer.copy_from_slice(&bytes[..]);
        EphemeralPublicKeyBytes(buffer)
    })
    .boxed()
}
