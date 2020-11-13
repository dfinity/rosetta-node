use crate::{
    consensus_pool::{ChangeAction, ChangeSet, ConsensusPool},
    crypto::ErrorReplication,
    ingress_manager::IngressSelectorError,
    ingress_pool::IngressPoolSelect,
};
use ic_types::{
    artifact::{ConsensusArtifact, ConsensusMessageFilter, PriorityFn},
    consensus::CatchUpPackage,
    crypto::{CryptoError, CryptoResult},
    registry::RegistryClientError,
    Height, NodeId, Time,
};

/// Consensus artifact processing interface.
pub trait Consensus: Send {
    /// Inspect the input [ConsensusPool] to build a [ChangeSet] of actions to
    /// be executed.
    ///
    /// The caller is then expected to apply the returned [ChangeSet] to the
    /// input of this call, namely [ConsensusPool]. The reason that consensus
    /// does not directly mutate the objects are:
    ///
    /// 1. The actual mutation may need to be coupled with other things,
    /// performed in a single transaction, and so on. So it is better to leave
    /// it to the caller to decide.
    ///
    /// 2. Because [ConsensusPool] is passed as an read-only reference, the
    /// caller is free to run other readers concurrently should it choose to.
    /// But this is a minor point.
    fn on_state_change(
        &self,
        consensus_pool: &dyn ConsensusPool,
        ingress_pool: &dyn IngressPoolSelect,
    ) -> ChangeSet;
}

/// Consensus to gossip interface.
pub trait ConsensusGossip: Send + Sync {
    /// Return a priority function that matches the given consensus pool.
    fn get_priority_function(
        &self,
        consensus_pool: &dyn ConsensusPool,
    ) -> PriorityFn<ConsensusArtifact>;

    /// Return a filter that represents what artifacts are needed.
    fn get_filter(&self) -> ConsensusMessageFilter;
}

/// Reader of consensus related states.
pub trait ConsensusStateReader: Send + Sync {
    /// Return the height of the latest/highest finalized block.
    fn finalized_height(&self) -> Height;

    /// Return the time as recorded in the latest/highest finalized block.
    /// Return None if there has not been any finalized block since genesis.
    fn consensus_time(&self) -> Option<Time>;

    /// Return the latest/highest CatchUpPackage.
    fn catch_up_package(&self) -> CatchUpPackage;
}

/// Things that can be updated in the consensus cache.
#[derive(Debug, PartialEq, Eq)]
pub enum CacheUpdateAction {
    Finalization,
    CatchUpPackage,
}

/// Consensus cache interface.
pub trait ConsensusCache: ConsensusStateReader {
    /// Check if the cache has to be updated given the set of ChangeActions
    /// to be applied to the ConsensusPool.
    ///
    /// Return a list of CacheUpdateAction.
    fn prepare(&self, change_set: &[ChangeAction]) -> Vec<CacheUpdateAction>;

    /// Update the cache with the list of CacheUpdateAction.
    fn update(&self, pool: &dyn ConsensusPool, updates: Vec<CacheUpdateAction>);
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MembershipError {
    RandomBeaconNotFound,
    NodeNotFound(NodeId),
    RegistryClientError(RegistryClientError),
    UnableToRetrieveRegistryVersion(Height),
    UnableToRetrieveDkgTranscript(Height),
}

#[derive(Debug)]
pub enum PayloadValidationError {
    Permanent(String),
    Temporary(String),
    IngressSelectorError(IngressSelectorError),
}

/// Contains all possible errors, which can occur during a validation of a Dkg
/// message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DkgMessageValidatorError {
    /// Crypto related errors.
    CryptoError(CryptoError),
    /// This error will be returned, if we validate a message for some phase,
    /// while the previous phase was not finaized yet. For example, if we
    /// validate a response while the dealing phase is still not finalized,
    /// we reject the response with this error.
    PriorPhaseIncomplete,
}

/// Possible validator errors. All of them must be transient.
#[derive(Debug)]
pub enum ValidatorError {
    CryptoError(CryptoError),
    RegistryClientError(RegistryClientError),
    MembershipError(MembershipError),
    PayloadValidationError(PayloadValidationError),
    DkgMessageValidatorError(DkgMessageValidatorError),
    DkgTranscriptNotFound(Height),
    DkgPayloadValidationError(String),
    OtherTransientError(String),
}

/// Note that Valid and Invalid variants are deterministic and final validation
/// results, while if an error was returned, this _might_ indicate a retryable
/// error and needs to be inspected by the receiver if more details are
/// required.
#[derive(Debug)]
pub enum ValidationResult<T> {
    /// The validation was successful.
    Valid,
    /// The validation was not successful.
    Invalid(String),
    /// An error happened during the validation.
    Error(T),
}

impl<T> ValidationResult<T> {
    /// Maps a `ValidationResult<T>` to `ValidationResult<U>` by appplying the
    /// given function to a contained `Error` value, leaving `Valid` and
    /// `Invalid` untouched.
    pub fn map_err<U, F>(self, f: F) -> ValidationResult<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            ValidationResult::Valid => ValidationResult::Valid,
            ValidationResult::Invalid(s) => ValidationResult::Invalid(s),
            ValidationResult::Error(err) => ValidationResult::Error(f(err)),
        }
    }

    /// Return true if it is valid.
    pub fn is_valid(&self) -> bool {
        match self {
            ValidationResult::Valid => true,
            _ => false,
        }
    }
}

impl<T> From<CryptoResult<T>> for ValidationResult<CryptoError> {
    fn from(result: CryptoResult<T>) -> ValidationResult<CryptoError> {
        match result {
            // We consider the validation as successful.
            Ok(_) => ValidationResult::Valid,
            // If an error was returned, which is not a transient one, we consider the validation
            // as failed. There is no reason to retry such a validation.
            Err(err) if err.is_replicated() => ValidationResult::Invalid(std::format!("{:?}", err)),
            // A transient re-triable error.
            Err(err) => ValidationResult::Error(err),
        }
    }
}

impl From<ValidationResult<CryptoError>> for ValidationResult<ValidatorError> {
    fn from(result: ValidationResult<CryptoError>) -> ValidationResult<ValidatorError> {
        result.map_err(ValidatorError::CryptoError)
    }
}
