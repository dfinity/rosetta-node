/// Chunkable Artifact Trait
///
/// A de facto trait for P2P assembled/downloadable artifacts. A
/// chunk able artifact lends itself to be downloaded by the P2P layer.
/// This trait has functions that abstract functionality of chunk
/// management for various artifact variants.  P2P needs generic
/// interfaces to perform the following functions.
///
/// - Create Adverts for Artifacts
/// - Create under-construction object stubs on the receive side
/// - Iterate/Request/Receive/Collate chunks
///
/// All variants of the Artifact should implement the "Chunkable"
/// interface.
///
/// Polymorphism is implemented as static dispatch over enumerated variants
/// that implement a common trait.
use crate::{
    artifact::{Artifact, StateSyncMessage},
    consensus::{
        certification::CertificationMessage, dkg::Message as DkgMessage, ConsensusMessage,
    },
    crypto::CryptoHash,
    messages::SignedIngress,
};
use phantom_newtype::Id;
use serde::{Deserialize, Serialize};

/// Error Codes Returned By Chunkabe interface
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactErrorCode {
    ChunksMoreNeeded,
    ChunkVerificationFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkData {
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

/// The chunk type
pub type ChunkId = Id<ArtifactChunk, u32>;
const CHUNKID_UNIT_CHUNK: u32 = 0;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ArtifactChunkData {
    UnitChunkData(Artifact), // Unit chunk data has 1:1 mapping with real artifacts
    SemiStructuredChunkData(ChunkData), // Lets not convert this to enum unless needed
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactChunk {
    // Chunk number/id for this chunk
    pub chunk_id: ChunkId,
    // sibling hashes to be used for Merkle proof verification of this
    // chunk
    pub witness: Vec<CryptoHash>,
    // Size of the chunk
    pub size: usize,
    // Payload for the chunk
    pub artifact_chunk_data: ArtifactChunkData,
}

// Static polymorphic dispatch for chunk tracking.
//
// Chunk trackers give a polymorphic interface over per client chunk
// tracking logic. For artifacts consisting of a single chunk, P2P provides a
// default "Chunkable" trait implementation. Artifact types for which
// this default chunking logic is sufficient are marked using the
// SingleChunked marker trait.
//
// Why Trackers: Rust doesn't allow objects to be partially
// initialized.  i.e we cannot track a under construction
// "Consensusartifact" using the same type as assembled
// Artifact. Tracker types provide an abstract control point implement
// a polymorphic dispatch to per client tracking logic.
//
// Trackers are created from adverts and implement From trait.

// SingleChunked enum to enumerate all variants of artifacts that can
// are composed of a single chunk.
pub enum SingleChunked {
    Consensus,
    Ingress,
    Certification,
    Dkg,
}

///
/// Basic chunking impl of SingleChunked artifacts
pub trait ChunkableArtifact {
    fn get_chunk(self: Box<Self>, chunk_id: ChunkId) -> Option<ArtifactChunk>;
}

/// XXX: FRZ fix repetition use macro
impl ChunkableArtifact for ConsensusMessage {
    fn get_chunk(self: Box<Self>, chunk_id: ChunkId) -> Option<ArtifactChunk> {
        if chunk_id != ChunkId::from(CHUNKID_UNIT_CHUNK) {
            // Single chunked in identified only chunk CHUNKID_UNIT_CHUNK
            None
        } else {
            Some(ArtifactChunk {
                chunk_id,
                witness: Vec::with_capacity(0),
                size: std::mem::size_of::<ConsensusMessage>(),
                artifact_chunk_data: ArtifactChunkData::UnitChunkData(Artifact::ConsensusMessage(
                    *self,
                )),
            })
        }
    }
}

impl ChunkableArtifact for SignedIngress {
    fn get_chunk(self: Box<Self>, chunk_id: ChunkId) -> Option<ArtifactChunk> {
        if chunk_id != ChunkId::from(CHUNKID_UNIT_CHUNK) {
            // Single chunked in identified only chunk CHUNKID_UNIT_CHUNK
            None
        } else {
            Some(ArtifactChunk {
                chunk_id,
                witness: Vec::with_capacity(0),
                size: std::mem::size_of::<SignedIngress>(),
                artifact_chunk_data: ArtifactChunkData::UnitChunkData(Artifact::IngressMessage(
                    *self,
                )),
            })
        }
    }
}

impl ChunkableArtifact for CertificationMessage {
    fn get_chunk(self: Box<Self>, chunk_id: ChunkId) -> Option<ArtifactChunk> {
        if chunk_id != ChunkId::from(CHUNKID_UNIT_CHUNK) {
            // Single chunked in identified only chunk CHUNKID_UNIT_CHUNK
            None
        } else {
            Some(ArtifactChunk {
                chunk_id,
                witness: Vec::with_capacity(0),
                size: std::mem::size_of::<CertificationMessage>(),
                artifact_chunk_data: ArtifactChunkData::UnitChunkData(
                    Artifact::CertificationMessage(*self),
                ),
            })
        }
    }
}

impl ChunkableArtifact for DkgMessage {
    fn get_chunk(self: Box<Self>, chunk_id: ChunkId) -> Option<ArtifactChunk> {
        if chunk_id != ChunkId::from(CHUNKID_UNIT_CHUNK) {
            // Single chunked in identified only chunk CHUNKID_UNIT_CHUNK
            None
        } else {
            Some(ArtifactChunk {
                chunk_id,
                witness: Vec::with_capacity(0),
                size: std::mem::size_of::<DkgMessage>(),
                artifact_chunk_data: ArtifactChunkData::UnitChunkData(Artifact::DkgMessage(*self)),
            })
        }
    }
}

impl ChunkableArtifact for StateSyncMessage {
    fn get_chunk(self: Box<Self>, chunk_id: ChunkId) -> Option<ArtifactChunk> {
        fn byte_chunk(chunk_id: ChunkId, payload: Vec<u8>) -> ArtifactChunk {
            ArtifactChunk {
                chunk_id,
                witness: vec![],
                size: payload.len(),
                artifact_chunk_data: ArtifactChunkData::SemiStructuredChunkData(ChunkData {
                    payload,
                }),
            }
        }

        if chunk_id == crate::state_sync::MANIFEST_CHUNK {
            let payload = crate::state_sync::encode_manifest(&self.manifest);
            return Some(byte_chunk(chunk_id, payload));
        }

        let chunk_table_index = (chunk_id.get() - 1) as usize;

        if chunk_table_index >= self.manifest.chunk_table.len() {
            return None;
        }

        let chunk = self.manifest.chunk_table[chunk_table_index].clone();
        let path = self
            .checkpoint_root
            .join(&self.manifest.file_table[chunk.file_index as usize].relative_path);
        let get_state_sync_chunk = self.get_state_sync_chunk.unwrap();
        let buf = get_state_sync_chunk(path, chunk.offset, chunk.size_bytes).ok()?;
        Some(byte_chunk(chunk_id, buf))
    }
}

// End repetition

///
/// Basic chunking impl for Singlechunked artifact tracker
pub trait Chunkable {
    fn get_artifact_hash(&self) -> CryptoHash;
    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>>;
    fn get_artifact_indentifier(&self) -> CryptoHash;
    fn add_chunk(&mut self, artifact_chunk: ArtifactChunk) -> Result<Artifact, ArtifactErrorCode>;
    fn is_complete(&self) -> bool;
    fn get_chunk_size(&self, chunk_id: ChunkId) -> usize;
}

// Basic chunking impl for SingleChunked object tracking
impl Chunkable for SingleChunked {
    fn get_artifact_hash(&self) -> CryptoHash {
        unimplemented!("")
    }

    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>> {
        let v: Vec<ChunkId> = vec![ChunkId::from(CHUNKID_UNIT_CHUNK)];
        Box::new(v.into_iter())
    }

    fn get_artifact_indentifier(&self) -> CryptoHash {
        unimplemented!("")
    }

    fn add_chunk(&mut self, artifact_chunk: ArtifactChunk) -> Result<Artifact, ArtifactErrorCode> {
        if artifact_chunk.chunk_id != ChunkId::from(CHUNKID_UNIT_CHUNK) {
            return Err(ArtifactErrorCode::ChunkVerificationFailed);
        }

        match artifact_chunk.artifact_chunk_data {
            ArtifactChunkData::UnitChunkData(artifact) => Ok(artifact),
            _ => {
                // DOCUMENTATION: unreachable!();
                panic!("Type Error: Trait bound Single chunked not satisfied for for artifact");
            }
        }
    }

    fn is_complete(&self) -> bool {
        unimplemented!("")
    }

    fn get_chunk_size(&self, _chunk_id: ChunkId) -> usize {
        unimplemented!("")
    }
}

// -----------------------------------------------------------------------------
