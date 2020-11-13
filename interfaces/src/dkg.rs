use crate::{artifact_pool::UnvalidatedArtifact, consensus_pool::ConsensusPool};
use ic_types::{
    artifact::{DkgArtifact, PriorityFn},
    consensus::dkg,
    crypto::CryptoHashOf,
    Height,
};

pub trait Dkg: Send {
    fn on_state_change(
        &self,
        consensus_pool: &dyn ConsensusPool,
        dkg_pool: &dyn DkgPool,
    ) -> ChangeSet;
}

pub trait DkgGossip: Send + Sync {
    fn get_priority_function(&self, dkg_pool: &dyn DkgPool) -> PriorityFn<DkgArtifact>;
}

/// The DkgPool is used to store messages that are exchanged between nodes in
/// the process of executing dkg.
pub trait DkgPool: Send + Sync {
    fn get_validated(&self) -> Box<dyn Iterator<Item = &dkg::Message> + '_>;
    fn get_unvalidated(&self) -> Box<dyn Iterator<Item = &dkg::Message> + '_>;
    /// The start height of the currently _computed_ DKG interval; the invariant
    /// we want to maintain for all messages in validated and unvalidated
    /// sections is that they correspond to a DKG Id with the start height
    /// equal to current_start_height.
    fn get_current_start_height(&self) -> Height;
}

/// Trait containing only mutable functions wrt. DkgPool
pub trait MutableDkgPool: DkgPool {
    /// Inserts a dkg message into the unvalidated part of the pool.
    fn insert(&mut self, msg: UnvalidatedArtifact<dkg::Message>);

    /// Applies a set of change actions to the pool.
    fn apply_changes(&mut self, change_set: ChangeSet);
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ChangeAction {
    AddToValidated(dkg::Message),
    MoveToValidated(dkg::Message),
    HandleInvalid(CryptoHashOf<dkg::Message>, String),
    Purge(Height),
}

pub type ChangeSet = Vec<ChangeAction>;

impl From<ChangeAction> for ChangeSet {
    fn from(change_action: ChangeAction) -> Self {
        vec![change_action]
    }
}
