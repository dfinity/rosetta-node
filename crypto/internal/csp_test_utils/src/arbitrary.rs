use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::secp256k1::EphemeralPublicKeyBytes;
use proptest::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ListOfLists {
    Leaf(#[serde(with = "serde_bytes")] Vec<u8>),
    Node(Vec<ListOfLists>),
}

prop_compose! {
    pub fn list_of_lists() (seed in any::<Vec<u8>>()) -> ListOfLists {
        // TODO(DFN-793): Make this recursive
        ListOfLists::Leaf(seed)
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
