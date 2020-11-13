use crate::artifact::{ArtifactAttribute, ArtifactId};
use crate::crypto::CryptoHash;
use ic_protobuf::registry::subnet::v1::GossipConfig;
use serde::{Deserialize, Serialize};

/// This is sent to peers to indicate that a node has a certain artifact
/// in its artifact pool. The adverts of different artifact types may differ
/// in their attributes. Upon the reception of an advert, a node can decide
/// if and when to request the corresponding artifact from the sender.
///
/// XXX: FRZ GossipAdvert should not be exposed to clients as its
/// internal to gossip module
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GossipAdvert {
    pub attribute: ArtifactAttribute,
    pub size: usize,
    pub artifact_id: ArtifactId,
    /// the root hash of the Merkle tree of chunks forming the Artifact
    pub integrity_hash: CryptoHash,
}

/// Gossip subnet constants
// Maximum number of artifact chunks that can be downloaded
// simultaneously from one peer
pub const MAX_ARTIFACT_STREAMS_PER_PEER: u32 = 20;

// timeout interval (in millis) within which a chunk request must
// succeed
pub const MAX_CHUNK_WAIT_MS: u32 = 15_000;

//maximum number of peers that one artifact chunk can be
// downloaded from in parallel (MAX_DUPLICITY=1 means no parallel
// downloads)
pub const MAX_DUPLICITY: u32 = 1;

// maximum size in bytes of an artifact chunk (used to compute the
// chunk timeout interval, once universal chunking is implemented
// (https://dfinity.atlassian.net/browse/P2P-292), chunks larger
// than this size will not be requested)
pub const MAX_CHUNK_SIZE: u32 = 4096;

// Size of each receive check hash set for each peer
pub const RECEIVE_CHECK_PEER_SET_SIZE: u32 = 5000;

// Period for priority function evaluation
pub const PFN_EVALUATION_PERIOD_MS: u32 = 3_000;

// Period for polling the registry for changes
pub const REGISTRY_POLL_PERIOD_MS: u32 = 3_000;

// helper function
pub fn build_default_gossip_config() -> GossipConfig {
    GossipConfig {
        max_artifact_streams_per_peer: MAX_ARTIFACT_STREAMS_PER_PEER,
        max_chunk_wait_ms: MAX_CHUNK_WAIT_MS,
        max_duplicity: MAX_DUPLICITY,
        max_chunk_size: MAX_CHUNK_SIZE,
        receive_check_cache_size: RECEIVE_CHECK_PEER_SET_SIZE,
        pfn_evaluation_period_ms: PFN_EVALUATION_PERIOD_MS,
        registry_poll_period_ms: REGISTRY_POLL_PERIOD_MS,
    }
}
