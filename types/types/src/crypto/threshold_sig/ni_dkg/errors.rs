use crate::{NodeId, RegistryVersion};
use ic_crypto_internal_types::NodeIndex;
use std::collections::BTreeSet;
use std::fmt;

pub mod create_dealing_error;
pub mod create_transcript_error;
pub mod delete_decryption_key_error;
pub mod delete_threshold_signing_key_error;
pub mod load_transcript_error;
pub mod verify_dealing_error;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NotADealerError {
    pub node_id: NodeId,
}

impl fmt::Display for NotADealerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "This operation requires node ({}) to be a dealer, but it is not.",
            self.node_id
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DealingNodeIdsNotInDealersError {
    pub node_ids: BTreeSet<NodeId>,
}

impl fmt::Display for DealingNodeIdsNotInDealersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Missing node ids in dealers: {:?}.", self.node_ids)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FsEncryptionPublicKeyNotInRegistryError {
    pub registry_version: RegistryVersion,
    pub node_id: NodeId,
}

impl fmt::Display for FsEncryptionPublicKeyNotInRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Dealing encryption public key for node id {} not found in registry for version {}",
            self.node_id, self.registry_version,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MalformedFsEncryptionPublicKeyError {
    pub receiver_index: NodeIndex,
    pub internal_error: String,
}

impl fmt::Display for MalformedFsEncryptionPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The (forward-secure) encryption public key is malformed for receiver index {}: {}",
            &self.receiver_index, &self.internal_error
        )
    }
}
