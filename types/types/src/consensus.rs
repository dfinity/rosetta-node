//! Defines types used internally by consensus components.
use crate::{
    batch::{BatchPayload, ValidationContext},
    crypto::threshold_sig::ni_dkg::NiDkgId,
    crypto::*,
    replica_version::ReplicaVersion,
    *,
};
use ic_protobuf::log::block_log_entry::v1::BlockLogEntry;
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::cmp::PartialOrd;
use std::hash::Hash;
use std::sync::Arc;

pub mod catchup;
pub mod certification;
pub mod dkg;
pub mod hashed;
pub mod thunk;

pub use catchup::*;
use hashed::Hashed;
use thunk::Thunk;

/// A lazily loaded `BatchPayload` that is also internally shared via an `Arc`
/// pointer so that it is cheap to clone.
///
/// It serializes to both the crypto hash and value of a `BatchPayload`.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Payload {
    payload: Arc<Hashed<CryptoHashOf<BatchPayload>, Thunk<BatchPayload>>>,
}

impl Payload {
    /// Return a Payload using the given hash function and a `BatchPayload`.
    pub fn new<F: FnOnce(&BatchPayload) -> CryptoHashOf<BatchPayload> + Send + 'static>(
        hash_func: F,
        payload: BatchPayload,
    ) -> Self {
        Payload {
            payload: Arc::new(Hashed::new(
                move |thunk: &Thunk<BatchPayload>| hash_func(thunk.as_ref()),
                Thunk::from(payload),
            )),
        }
    }

    /// Return a Payload with the given hash, and an intialization function that
    /// will be use for lazily loading the actual `BatchPayload` matching
    /// the given hash. This function does not check if the eventually loaded
    /// `BatchPayload` with match the given hash, so it must be used with care.
    pub fn new_with(
        hash: CryptoHashOf<BatchPayload>,
        init: Box<dyn FnOnce() -> BatchPayload + Send>,
    ) -> Self {
        Payload {
            payload: Arc::new(Hashed {
                hash,
                value: Thunk::new(init),
            }),
        }
    }

    /// Return the crypto hash of the enclosed `BatchPayload`.
    pub fn get_hash(&self) -> &CryptoHashOf<BatchPayload> {
        self.payload.get_hash()
    }
}

impl AsRef<BatchPayload> for Payload {
    fn as_ref(&self) -> &BatchPayload {
        self.payload.get_value().as_ref()
    }
}

impl From<Payload> for BatchPayload {
    fn from(from: Payload) -> BatchPayload {
        match Arc::try_unwrap(from.payload) {
            Ok(payload) => payload.into_inner().into_inner(),
            Err(payload) => payload.get_value().as_ref().clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BasicSignature<T> {
    pub signature: BasicSigOf<T>,
    pub signer: NodeId,
}

pub type BasicSigned<T> = Signed<T, BasicSignature<T>>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdSignature<T> {
    pub signature: CombinedThresholdSigOf<T>,
    pub signer: NiDkgId,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdSignatureShare<T> {
    pub signature: ThresholdSigShareOf<T>,
    pub signer: NodeId,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MultiSignature<T> {
    pub signature: CombinedMultiSigOf<T>,
    pub signers: Vec<NodeId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MultiSignatureShare<T> {
    pub signature: IndividualMultiSigOf<T>,
    pub signer: NodeId,
}

/// Abstract messages with height attribute
pub trait HasHeight {
    fn height(&self) -> Height;
}

/// Abstract messages with block hash
pub trait HasBlockHash {
    fn block_hash(&self) -> &CryptoHashOf<Block>;
}

/// Abstract messages with rank attribute
pub trait HasRank {
    fn rank(&self) -> Rank;
}

/// Abstract messages with role attribute
pub trait HasCommittee {
    fn committee() -> Committee;
}

/// Abstract messages with version attribute
pub trait HasVersion {
    fn version(&self) -> &ReplicaVersion;
}

impl<T: HasHeight, S> HasHeight for Signed<T, S> {
    fn height(&self) -> Height {
        self.content.height()
    }
}

impl<T: HasBlockHash, S> HasBlockHash for Signed<T, S> {
    fn block_hash(&self) -> &CryptoHashOf<Block> {
        self.content.block_hash()
    }
}

impl<T: HasRank, S> HasRank for Signed<T, S> {
    fn rank(&self) -> Rank {
        self.content.rank()
    }
}

impl<T: HasCommittee, S> HasCommittee for Signed<T, S> {
    fn committee() -> Committee {
        T::committee()
    }
}

impl<T: HasVersion, S> HasVersion for Signed<T, S> {
    fn version(&self) -> &ReplicaVersion {
        self.content.version()
    }
}

impl HasVersion for Block {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl HasVersion for HashedBlock {
    fn version(&self) -> &ReplicaVersion {
        &self.value.version
    }
}

impl HasHeight for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl HasHeight for HashedBlock {
    fn height(&self) -> Height {
        self.value.height
    }
}

impl HasRank for Block {
    fn rank(&self) -> Rank {
        self.rank
    }
}

impl HasRank for HashedBlock {
    fn rank(&self) -> Rank {
        self.value.rank
    }
}

impl HasVersion for NotarizationContent {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl HasHeight for NotarizationContent {
    fn height(&self) -> Height {
        self.height
    }
}

impl HasBlockHash for HashedBlock {
    fn block_hash(&self) -> &CryptoHashOf<Block> {
        &self.hash
    }
}

impl HasBlockHash for NotarizationContent {
    fn block_hash(&self) -> &CryptoHashOf<Block> {
        &self.block
    }
}

impl HasCommittee for NotarizationContent {
    fn committee() -> Committee {
        Committee::Notarization
    }
}

impl HasVersion for FinalizationContent {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl HasHeight for FinalizationContent {
    fn height(&self) -> Height {
        self.height
    }
}

impl HasBlockHash for FinalizationContent {
    fn block_hash(&self) -> &CryptoHashOf<Block> {
        &self.block
    }
}

impl HasCommittee for FinalizationContent {
    fn committee() -> Committee {
        Committee::Notarization
    }
}

impl HasVersion for RandomBeaconContent {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl HasHeight for RandomBeaconContent {
    fn height(&self) -> Height {
        self.height
    }
}

impl HasCommittee for RandomBeaconContent {
    fn committee() -> Committee {
        Committee::LowThreshold
    }
}

impl HasVersion for RandomTapeContent {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl HasHeight for RandomTapeContent {
    fn height(&self) -> Height {
        self.height
    }
}

impl HasCommittee for RandomTapeContent {
    fn committee() -> Committee {
        Committee::LowThreshold
    }
}

// tag::types[]
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Rank(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Block {
    version: ReplicaVersion,
    pub parent: CryptoHashOf<Block>,
    pub payload: Payload,
    pub dkg_payload: dkg::Payload,
    pub height: Height,
    pub rank: Rank,
    pub context: ValidationContext,
}

impl Block {
    pub fn new(
        parent: CryptoHashOf<Block>,
        payload: Payload,
        dkg_payload: dkg::Payload,
        height: Height,
        rank: Rank,
        context: ValidationContext,
    ) -> Self {
        Block {
            version: ReplicaVersion::default(),
            parent,
            payload,
            dkg_payload,
            height,
            rank,
            context,
        }
    }

    pub fn log_entry(&self, block_hash: String) -> BlockLogEntry {
        BlockLogEntry {
            byte_size: None,
            certified_height: Some(self.context.certified_height.get()),
            dkg_payload_type: Some(self.dkg_payload.payload_type().to_string()),
            hash: Some(block_hash),
            height: Some(self.height.get()),
            parent_hash: Some(hex::encode(self.parent.get_ref().0.clone())),
            rank: Some(self.rank.0),
            registry_version: Some(self.context.registry_version.get()),
            time: Some(self.context.time.as_nanos_since_unix_epoch()),
            version: Some(self.version().to_string()),
        }
    }
}

pub type HashedBlock = Hashed<CryptoHashOf<Block>, Block>;

/// We store the hash of block in block proposal too.
pub type BlockProposal = Signed<HashedBlock, BasicSignature<Block>>;

impl From<BlockProposal> for Block {
    fn from(proposal: BlockProposal) -> Block {
        proposal.content.value
    }
}

impl AsRef<Block> for BlockProposal {
    fn as_ref(&self) -> &Block {
        self.content.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NotarizationContent {
    version: ReplicaVersion,
    pub height: Height,
    pub block: CryptoHashOf<Block>,
}

impl NotarizationContent {
    pub fn new(height: Height, block: CryptoHashOf<Block>) -> Self {
        NotarizationContent {
            version: ReplicaVersion::default(),
            height,
            block,
        }
    }
}

pub type Notarization = Signed<NotarizationContent, MultiSignature<NotarizationContent>>;

pub type NotarizationShare = Signed<NotarizationContent, MultiSignatureShare<NotarizationContent>>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FinalizationContent {
    version: ReplicaVersion,
    pub height: Height,
    pub block: CryptoHashOf<Block>,
}

impl FinalizationContent {
    pub fn new(height: Height, block: CryptoHashOf<Block>) -> Self {
        FinalizationContent {
            version: ReplicaVersion::default(),
            height,
            block,
        }
    }
}

pub type Finalization = Signed<FinalizationContent, MultiSignature<FinalizationContent>>;

pub type FinalizationShare = Signed<FinalizationContent, MultiSignatureShare<FinalizationContent>>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RandomBeaconContent {
    version: ReplicaVersion,
    pub height: Height,
    pub parent: CryptoHashOf<RandomBeacon>,
}

impl RandomBeaconContent {
    pub fn new(height: Height, parent: CryptoHashOf<RandomBeacon>) -> Self {
        RandomBeaconContent {
            version: ReplicaVersion::default(),
            height,
            parent,
        }
    }
}

impl SignedBytesWithoutDomainSeparator for RandomBeaconContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

pub type RandomBeacon = Signed<RandomBeaconContent, ThresholdSignature<RandomBeaconContent>>;

impl From<&RandomBeacon> for pb::RandomBeacon {
    fn from(random_beacon: &RandomBeacon) -> Self {
        Self {
            version: random_beacon.content.version.to_string(),
            height: random_beacon.content.height.get(),
            parent: random_beacon.content.parent.clone().get().0,
            signature: random_beacon.signature.signature.clone().get().0,
            signer: Some(pb::NiDkgId::from(random_beacon.signature.signer)),
        }
    }
}

impl TryFrom<pb::RandomBeacon> for RandomBeacon {
    type Error = String;
    fn try_from(beacon: pb::RandomBeacon) -> Result<Self, Self::Error> {
        Ok(Signed {
            content: RandomBeaconContent {
                version: ReplicaVersion::try_from(beacon.version.as_str())
                    .map_err(|e| format!("RandomBeacon replica version failed to parse {:?}", e))?,
                height: Height::from(beacon.height),
                parent: CryptoHashOf::from(CryptoHash(beacon.parent)),
            },
            signature: ThresholdSignature {
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(beacon.signature)),
                signer: NiDkgId::try_from(
                    beacon
                        .signer
                        .ok_or_else(|| String::from("Error: RandomBeacon signer not present"))?,
                )
                .map_err(|e| format!("Unable to decode Random beacon signer {:?}", e))?,
            },
        })
    }
}

pub type RandomBeaconShare =
    Signed<RandomBeaconContent, ThresholdSignatureShare<RandomBeaconContent>>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RandomTapeContent {
    version: ReplicaVersion,
    pub height: Height,
}

impl SignedBytesWithoutDomainSeparator for RandomTapeContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

impl RandomTapeContent {
    pub fn new(height: Height) -> Self {
        RandomTapeContent {
            version: ReplicaVersion::default(),
            height,
        }
    }
}

pub type RandomTape = Signed<RandomTapeContent, ThresholdSignature<RandomTapeContent>>;

pub type RandomTapeShare = Signed<RandomTapeContent, ThresholdSignatureShare<RandomTapeContent>>;

// TODO(CON-272): Remove this clippy exception
/// The enum encompassing all of the consensus artifacts exchanged between
/// nodes.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum ConsensusMessage {
    RandomBeacon(RandomBeacon),
    Finalization(Finalization),
    Notarization(Notarization),
    BlockProposal(BlockProposal),
    RandomBeaconShare(RandomBeaconShare),
    NotarizationShare(NotarizationShare),
    FinalizationShare(FinalizationShare),
    RandomTape(RandomTape),
    RandomTapeShare(RandomTapeShare),
    CatchUpPackage(CatchUpPackage),
    CatchUpPackageShare(CatchUpPackageShare),
}

/// Message hash. Enum order should be consistent with ConsensusMessage.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsensusMessageHash {
    RandomBeacon(CryptoHashOf<RandomBeacon>),
    Finalization(CryptoHashOf<Finalization>),
    Notarization(CryptoHashOf<Notarization>),
    BlockProposal(CryptoHashOf<BlockProposal>),
    RandomBeaconShare(CryptoHashOf<RandomBeaconShare>),
    NotarizationShare(CryptoHashOf<NotarizationShare>),
    FinalizationShare(CryptoHashOf<FinalizationShare>),
    RandomTape(CryptoHashOf<RandomTape>),
    RandomTapeShare(CryptoHashOf<RandomTapeShare>),
    CatchUpPackage(CryptoHashOf<CatchUpPackage>),
    CatchUpPackageShare(CryptoHashOf<CatchUpPackageShare>),
}

/// Message Attribute. Enum order should be consistent with ConsensusMessage.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsensusMessageAttribute {
    RandomBeacon(Height),
    Finalization(CryptoHashOf<Block>, Height),
    Notarization(CryptoHashOf<Block>, Height),
    BlockProposal(Rank, Height),
    RandomBeaconShare(Height),
    NotarizationShare(Height),
    FinalizationShare(Height),
    RandomTape(Height),
    RandomTapeShare(Height),
    CatchUpPackage(Height),
    CatchUpPackageShare(Height),
}
// end::types[]

/// Useful to compare equality by content, for example Signed<C,S> can be
/// compared by equality on C.
pub trait ContentEq {
    fn content_eq(&self, other: &Self) -> bool;
}

impl<C: PartialEq, S> ContentEq for Signed<C, S> {
    fn content_eq(&self, other: &Self) -> bool {
        self.content.eq(&other.content)
    }
}

impl ContentEq for ConsensusMessage {
    fn content_eq(&self, other: &ConsensusMessage) -> bool {
        match (self, other) {
            (ConsensusMessage::RandomBeacon(x), ConsensusMessage::RandomBeacon(y)) => {
                x.content_eq(y)
            }
            (ConsensusMessage::Finalization(x), ConsensusMessage::Finalization(y)) => {
                x.content_eq(y)
            }
            (ConsensusMessage::Notarization(x), ConsensusMessage::Notarization(y)) => {
                x.content_eq(y)
            }
            (ConsensusMessage::BlockProposal(x), ConsensusMessage::BlockProposal(y)) => {
                x.content_eq(y)
            }
            (ConsensusMessage::RandomBeaconShare(x), ConsensusMessage::RandomBeaconShare(y)) => {
                x.content_eq(y)
            }
            (ConsensusMessage::NotarizationShare(x), ConsensusMessage::NotarizationShare(y)) => {
                x.content_eq(y)
            }
            (ConsensusMessage::FinalizationShare(x), ConsensusMessage::FinalizationShare(y)) => {
                x.content_eq(y)
            }
            (ConsensusMessage::RandomTape(x), ConsensusMessage::RandomTape(y)) => x.content_eq(y),
            (ConsensusMessage::RandomTapeShare(x), ConsensusMessage::RandomTapeShare(y)) => {
                x.content_eq(y)
            }

            // Default to false when comparing messages of different type
            _ => false,
        }
    }
}

impl HasVersion for ConsensusMessage {
    fn version(&self) -> &ReplicaVersion {
        match self {
            ConsensusMessage::RandomBeacon(x) => x.version(),
            ConsensusMessage::Finalization(x) => x.version(),
            ConsensusMessage::Notarization(x) => x.version(),
            ConsensusMessage::BlockProposal(x) => x.version(),
            ConsensusMessage::RandomBeaconShare(x) => x.version(),
            ConsensusMessage::NotarizationShare(x) => x.version(),
            ConsensusMessage::FinalizationShare(x) => x.version(),
            ConsensusMessage::RandomTape(x) => x.version(),
            ConsensusMessage::RandomTapeShare(x) => x.version(),
            ConsensusMessage::CatchUpPackage(x) => x.version(),
            ConsensusMessage::CatchUpPackageShare(x) => x.version(),
        }
    }
}

impl HasHeight for ConsensusMessage {
    fn height(&self) -> Height {
        match self {
            ConsensusMessage::RandomBeacon(x) => x.height(),
            ConsensusMessage::Finalization(x) => x.height(),
            ConsensusMessage::Notarization(x) => x.height(),
            ConsensusMessage::BlockProposal(x) => x.height(),
            ConsensusMessage::RandomBeaconShare(x) => x.height(),
            ConsensusMessage::NotarizationShare(x) => x.height(),
            ConsensusMessage::FinalizationShare(x) => x.height(),
            ConsensusMessage::RandomTape(x) => x.height(),
            ConsensusMessage::RandomTapeShare(x) => x.height(),
            ConsensusMessage::CatchUpPackage(x) => x.height(),
            ConsensusMessage::CatchUpPackageShare(x) => x.height(),
        }
    }
}

impl HasHeight for ConsensusMessageAttribute {
    fn height(&self) -> Height {
        match self {
            ConsensusMessageAttribute::RandomBeacon(h) => *h,
            ConsensusMessageAttribute::Finalization(_, h) => *h,
            ConsensusMessageAttribute::Notarization(_, h) => *h,
            ConsensusMessageAttribute::BlockProposal(_, h) => *h,
            ConsensusMessageAttribute::RandomBeaconShare(h) => *h,
            ConsensusMessageAttribute::NotarizationShare(h) => *h,
            ConsensusMessageAttribute::FinalizationShare(h) => *h,
            ConsensusMessageAttribute::RandomTape(h) => *h,
            ConsensusMessageAttribute::RandomTapeShare(h) => *h,
            ConsensusMessageAttribute::CatchUpPackage(h) => *h,
            ConsensusMessageAttribute::CatchUpPackageShare(h) => *h,
        }
    }
}

impl ConsensusMessageHash {
    pub fn digest(&self) -> &CryptoHash {
        match self {
            ConsensusMessageHash::RandomBeacon(hash) => hash.get_ref(),
            ConsensusMessageHash::Finalization(hash) => hash.get_ref(),
            ConsensusMessageHash::Notarization(hash) => hash.get_ref(),
            ConsensusMessageHash::BlockProposal(hash) => hash.get_ref(),
            ConsensusMessageHash::RandomBeaconShare(hash) => hash.get_ref(),
            ConsensusMessageHash::NotarizationShare(hash) => hash.get_ref(),
            ConsensusMessageHash::FinalizationShare(hash) => hash.get_ref(),
            ConsensusMessageHash::RandomTape(hash) => hash.get_ref(),
            ConsensusMessageHash::RandomTapeShare(hash) => hash.get_ref(),
            ConsensusMessageHash::CatchUpPackage(hash) => hash.get_ref(),
            ConsensusMessageHash::CatchUpPackageShare(hash) => hash.get_ref(),
        }
    }

    pub fn from_attribute(hash: CryptoHash, attr: &ConsensusMessageAttribute) -> Self {
        match attr {
            ConsensusMessageAttribute::RandomBeacon(_) => {
                ConsensusMessageHash::RandomBeacon(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::Finalization(_, _) => {
                ConsensusMessageHash::Finalization(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::Notarization(_, _) => {
                ConsensusMessageHash::Notarization(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::BlockProposal(_, _) => {
                ConsensusMessageHash::BlockProposal(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::RandomBeaconShare(_) => {
                ConsensusMessageHash::RandomBeaconShare(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::NotarizationShare(_) => {
                ConsensusMessageHash::NotarizationShare(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::FinalizationShare(_) => {
                ConsensusMessageHash::FinalizationShare(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::RandomTape(_) => {
                ConsensusMessageHash::RandomTape(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::RandomTapeShare(_) => {
                ConsensusMessageHash::RandomTapeShare(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::CatchUpPackage(_) => {
                ConsensusMessageHash::CatchUpPackage(CryptoHashOf::from(hash))
            }
            ConsensusMessageAttribute::CatchUpPackageShare(_) => {
                ConsensusMessageHash::CatchUpPackageShare(CryptoHashOf::from(hash))
            }
        }
    }
}

impl From<&ConsensusMessage> for ConsensusMessageAttribute {
    fn from(msg: &ConsensusMessage) -> ConsensusMessageAttribute {
        let height = msg.height();
        match msg {
            ConsensusMessage::RandomBeacon(_) => ConsensusMessageAttribute::RandomBeacon(height),
            ConsensusMessage::Finalization(x) => {
                ConsensusMessageAttribute::Finalization(x.content.block.clone(), height)
            }
            ConsensusMessage::Notarization(x) => {
                ConsensusMessageAttribute::Notarization(x.content.block.clone(), height)
            }
            ConsensusMessage::BlockProposal(x) => {
                ConsensusMessageAttribute::BlockProposal(x.rank(), height)
            }

            ConsensusMessage::RandomBeaconShare(_) => {
                ConsensusMessageAttribute::RandomBeaconShare(height)
            }

            ConsensusMessage::NotarizationShare(_) => {
                ConsensusMessageAttribute::NotarizationShare(height)
            }

            ConsensusMessage::FinalizationShare(_) => {
                ConsensusMessageAttribute::FinalizationShare(height)
            }
            ConsensusMessage::RandomTape(_) => ConsensusMessageAttribute::RandomTape(height),
            ConsensusMessage::RandomTapeShare(_) => {
                ConsensusMessageAttribute::RandomTapeShare(height)
            }
            ConsensusMessage::CatchUpPackage(_) => {
                ConsensusMessageAttribute::CatchUpPackage(height)
            }
            ConsensusMessage::CatchUpPackageShare(_) => {
                ConsensusMessageAttribute::CatchUpPackageShare(height)
            }
        }
    }
}

/// Indicates one of the consensus committees that are responsible for creating
/// signature shares on various types of artifacts
#[derive(Debug, PartialEq)]
pub enum Committee {
    LowThreshold,
    HighThreshold,
    Notarization,
}

pub type Threshold = usize;

/// Compute the size of the committee given the total amount of nodes on the
/// subnet
pub fn get_committee_size(nodes_on_subnet: usize) -> usize {
    let f = get_faults_tolerated(nodes_on_subnet);
    3 * f + 1
}

/// Returns the upper limit of faulty participants for `n` participants.
pub fn get_faults_tolerated(n: usize) -> usize {
    (n.max(1) - 1) / 3
}

impl From<&Block> for pb::Block {
    fn from(block: &Block) -> Self {
        Self {
            version: block.version.to_string(),
            parent: block.parent.clone().get().0,
            dkg_payload: Some(pb::DkgPayload::from(&block.dkg_payload)),
            height: block.height().get(),
            rank: block.rank.0,
            registry_version: block.context.registry_version.get(),
            certified_height: block.context.certified_height.get(),
            time: block.context.time.as_nanos_since_unix_epoch(),
            xnet_payload: Some(pb::XNetPayload::from(&block.payload.as_ref().xnet)),
            ingress_payload: Some(pb::IngressPayload::from(&block.payload.as_ref().ingress)),
        }
    }
}

pub fn block_from_protobuf<
    F: FnOnce(&BatchPayload) -> CryptoHashOf<BatchPayload> + Send + 'static,
>(
    hash_func: F,
    block: pb::Block,
) -> Result<Block, String> {
    Ok(Block {
        version: ReplicaVersion::try_from(block.version.as_str())
            .map_err(|e| format!("Block replica version failed to parse {:?}", e))?,
        parent: CryptoHashOf::from(CryptoHash(block.parent)),
        height: Height::from(block.height),
        rank: Rank(block.rank),
        context: ValidationContext {
            registry_version: RegistryVersion::from(block.registry_version),
            certified_height: Height::from(block.certified_height),
            time: Time::from_nanos_since_unix_epoch(block.time),
        },
        dkg_payload: dkg::Payload::try_from(
            block
                .dkg_payload
                .ok_or_else(|| String::from("Error: Block missing dkg_payload"))?,
        )?,
        payload: Payload::new(
            hash_func,
            BatchPayload::new(
                crate::batch::IngressPayload::try_from(
                    block
                        .ingress_payload
                        .ok_or_else(|| String::from("Error: Block missing ingress_payload"))?,
                )?,
                crate::batch::XNetPayload::try_from(
                    block
                        .xnet_payload
                        .ok_or_else(|| String::from("Error: Block missing xnet_payload"))?,
                )?,
            ),
        ),
    })
}
