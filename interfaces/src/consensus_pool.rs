use crate::{
    artifact_pool::{UnvalidatedArtifact, ValidatedArtifact},
    time_source::TimeSource,
};
use ic_types::{
    artifact::ConsensusMessageId,
    consensus::{
        BlockProposal, CatchUpPackage, CatchUpPackageShare, ConsensusMessage, ContentEq,
        Finalization, FinalizationShare, Notarization, NotarizationShare, RandomBeacon,
        RandomBeaconShare, RandomTape, RandomTapeShare,
    },
    time::Time,
    Height,
};

// tag::change_set[]
pub type ChangeSet = Vec<ChangeAction>;

// TODO(CON-272): Remove this clippy exception
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ChangeAction {
    AddToValidated(ConsensusMessage),
    MoveToValidated(ConsensusMessage),
    RemoveFromValidated(ConsensusMessage),
    RemoveFromUnvalidated(ConsensusMessage),
    HandleInvalid(ConsensusMessage, String),
    PurgeValidatedBelow(Height),
    PurgeUnvalidatedBelow(Height),
}
// end::change_set[]

impl ChangeAction {
    pub fn into_change_set(self) -> ChangeSet {
        vec![self]
    }
}

pub trait ChangeSetOperation: Sized {
    /// Conditional composition when self is empty. Similar to Option::or_else.
    fn or_else<F: FnOnce() -> Self>(self, f: F) -> Self;
    /// Append a change action only when it is not a duplicate of what already
    /// exists in the ChangeSet. Return the rejected action as error when it
    /// is considered as duplicate.
    fn dedup_push(&mut self, action: ChangeAction) -> Result<(), ChangeAction>;
}

impl ChangeSetOperation for ChangeSet {
    fn or_else<F: FnOnce() -> ChangeSet>(self, f: F) -> ChangeSet {
        if self.is_empty() {
            f()
        } else {
            self
        }
    }

    fn dedup_push(&mut self, action: ChangeAction) -> Result<(), ChangeAction> {
        if self.iter().find(|x| x.content_eq(&action)).is_none() {
            self.push(action);
            Ok(())
        } else {
            Err(action)
        }
    }
}

impl ContentEq for ChangeAction {
    fn content_eq(&self, other: &ChangeAction) -> bool {
        match (self, other) {
            (ChangeAction::AddToValidated(x), ChangeAction::AddToValidated(y)) => x.content_eq(y),
            (ChangeAction::MoveToValidated(x), ChangeAction::MoveToValidated(y)) => x.content_eq(y),
            (ChangeAction::RemoveFromValidated(x), ChangeAction::RemoveFromValidated(y)) => {
                x.content_eq(y)
            }
            (ChangeAction::RemoveFromUnvalidated(x), ChangeAction::RemoveFromUnvalidated(y)) => {
                x.content_eq(y)
            }
            (ChangeAction::HandleInvalid(x, _), ChangeAction::HandleInvalid(y, _)) => {
                x.content_eq(y)
            }
            // Also compare between MoveToValidated and AddToValidated to help remove duplicates
            (ChangeAction::AddToValidated(x), ChangeAction::MoveToValidated(y)) => x.content_eq(y),
            (ChangeAction::MoveToValidated(x), ChangeAction::AddToValidated(y)) => x.content_eq(y),
            (ChangeAction::PurgeValidatedBelow(x), ChangeAction::PurgeValidatedBelow(y)) => x == y,
            // Default to false when comparing actions of different type
            _ => false,
        }
    }
}

/// Validated consensus artifact.
pub type ValidatedConsensusArtifact = ValidatedArtifact<ConsensusMessage>;

/// Unvalidated consensus artifact.
pub type UnvalidatedConsensusArtifact = UnvalidatedArtifact<ConsensusMessage>;

pub struct HeightRange {
    pub min: Height,
    pub max: Height,
}

impl HeightRange {
    pub fn new(min: Height, max: Height) -> HeightRange {
        HeightRange { min, max }
    }
}

#[derive(Debug)]
pub enum OnlyError {
    NoneAvailable,
    MultipleValues,
}

// tag::interface[]

/// A Pool section is a part of the consensus pool which contains
/// artifacts.
///
/// Artifacts in the pool are accessible by their hash or by their
/// type and height.
pub trait PoolSection<T> {
    /// Checks if the artifact with the given Id is present in the pool
    fn contains(&self, msg_id: &ConsensusMessageId) -> bool;

    /// Lookup an artifact by ConsensusMessageId. Return the consensus message
    /// if it exists, or None otherwise.
    fn get(&self, msg_id: &ConsensusMessageId) -> Option<T>;

    /// Lookup the timestamp of an artifact by its ConsensusMessageId.
    fn get_timestamp(&self, msg_id: &ConsensusMessageId) -> Option<Time>;

    /// Return the HeightIndexedPool for RandomBeacon.
    fn random_beacon(&self) -> &dyn HeightIndexedPool<RandomBeacon>;

    /// Return the HeightIndexedPool for BlockProposal.
    fn block_proposal(&self) -> &dyn HeightIndexedPool<BlockProposal>;

    /// Return the HeightIndexedPool for Notarization.
    fn notarization(&self) -> &dyn HeightIndexedPool<Notarization>;

    /// Return the HeightIndexedPool for Finalization.
    fn finalization(&self) -> &dyn HeightIndexedPool<Finalization>;

    /// Return the HeightIndexedPool for RandomBeaconShare.
    fn random_beacon_share(&self) -> &dyn HeightIndexedPool<RandomBeaconShare>;

    /// Return the HeightIndexedPool for NotarizationShare.
    fn notarization_share(&self) -> &dyn HeightIndexedPool<NotarizationShare>;

    /// Return the HeightIndexedPool for FinalizationShare.
    fn finalization_share(&self) -> &dyn HeightIndexedPool<FinalizationShare>;

    /// Return the HeightIndexedPool for RandomTape.
    fn random_tape(&self) -> &dyn HeightIndexedPool<RandomTape>;

    /// Return the HeightIndexedPool for RandomTapeShare.
    fn random_tape_share(&self) -> &dyn HeightIndexedPool<RandomTapeShare>;

    /// Return the HeightIndexedPool for CatchUpPackage.
    fn catch_up_package(&self) -> &dyn HeightIndexedPool<CatchUpPackage>;

    /// Return the HeightIndexedPool for CatchUpPackageShare.
    fn catch_up_package_share(&self) -> &dyn HeightIndexedPool<CatchUpPackageShare>;

    fn size(&self) -> u64;
}

/// The consensus pool contains all the artifacts received by P2P and
/// produced by the local node.
///
/// It contains two sections:
/// - The validated section contains artifacts that have been validated by
///   consensus. To support resumability this section must be persistent.
///
/// - The unvalidated section contains artifacts that have been received but
///   haven't yet been validated. This section is in-memory only and thus
///   volatile.
pub trait ConsensusPool {
    /// Return a reference to the validated PoolSection.
    fn validated(&self) -> &dyn PoolSection<ValidatedConsensusArtifact>;

    /// Return a reference to the unvalidated PoolSection.
    fn unvalidated(&self) -> &dyn PoolSection<UnvalidatedConsensusArtifact>;
}

/// Mutation operations on top of ConsensusPool.
pub trait MutableConsensusPool: ConsensusPool {
    /// Insert an unvalidated artifact.
    fn insert(&mut self, unvalidated_artifact: UnvalidatedConsensusArtifact);

    /// Apply the change set.
    fn apply_changes(&mut self, time_source: &dyn TimeSource, change_set: ChangeSet);
}

/// HeightIndexedPool provides a set of interfaces for the Consensus component
/// to query artifacts. The same interface is applicable to both validated and
/// unvalidated partitions of consensus artifacts in the overall ArtifactPool.
pub trait HeightIndexedPool<T> {
    /// Returns the height range of artifacts of type T currently in the pool.
    fn height_range(&self) -> Option<HeightRange>;

    /// Returns the max height across all artifacts of type T currently in the
    /// pool.
    fn max_height(&self) -> Option<Height>;

    /// Return an iterator over all of the artifacts of type T.
    fn get_all(&self) -> Box<dyn Iterator<Item = T>>;

    /// Return an iterator over the artifacts of type T at height
    /// 'h'.
    fn get_by_height(&self, h: Height) -> Box<dyn Iterator<Item = T>>;

    /// Return an iterator over the artifacts of type T
    /// in range range.min, range.max, inclusive. The items must be sorted
    /// by height in ascending order.
    fn get_by_height_range(&self, range: HeightRange) -> Box<dyn Iterator<Item = T>>;

    /// Return a single instance of artifact of type T, at height 'h', returning
    /// an error if there isn't one, or if there are more than one.
    fn get_only_by_height(&self, h: Height) -> Result<T, OnlyError>;

    /// Return a single instance of artifact of type T at the highest height
    /// currently in the pool. Returns an error if there isn't one, or if there
    /// are more than one.
    fn get_highest(&self) -> Result<T, OnlyError>;

    /// Return an iterator over instances of artifact of type T at the highest
    /// height currently in the pool. Returns an error if there isn't one, or
    /// if there are more than one.
    fn get_highest_iter(&self) -> Box<dyn Iterator<Item = T>>;
}
// end::interface[]
