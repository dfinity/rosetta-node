//! The consensus public interface.
use crate::{
    consensus_pool::{ChangeSet, ConsensusPool},
    ingress_manager::{
        IngressPayloadValidationError, IngressPermanentError, IngressTransientError,
    },
    ingress_pool::IngressPoolSelect,
    messaging::{InvalidXNetPayload, XNetPayloadValidationError, XNetTransientValidationError},
    self_validating_payload::{
        InvalidSelfValidatingPayload, SelfValidatingPayloadValidationError,
        SelfValidatingTransientValidationError,
    },
    validation::ValidationError,
};
use ic_base_types::NumBytes;
use ic_types::artifact::{
    ConsensusMessageAttribute, ConsensusMessageFilter, ConsensusMessageId, PriorityFn,
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
    ) -> PriorityFn<ConsensusMessageId, ConsensusMessageAttribute>;

    /// Return a filter that represents what artifacts are needed.
    fn get_filter(&self) -> ConsensusMessageFilter;
}

/// Error that can occur during invocation of the `PayloadBuilder`.
/// All errors are transient.
#[derive(Clone, Debug)]
pub enum PayloadBuilderError {
    RegistryUnavailable,
}

#[derive(Debug)]
pub enum PayloadPermanentError {
    XNetPayloadValidationError(InvalidXNetPayload),
    IngressPayloadValidationError(IngressPermanentError),
    PayloadTooBig {
        expected: NumBytes,
        received: NumBytes,
    },
    SelfValidatingPayloadValidationError(InvalidSelfValidatingPayload),
}

#[derive(Debug)]
pub enum PayloadTransientError {
    XNetPayloadValidationError(XNetTransientValidationError),
    IngressPayloadValidationError(IngressTransientError),
    RegistryUnavailable,
    SelfValidatingPayloadValidationError(SelfValidatingTransientValidationError),
}

/// Payload validation error
pub type PayloadValidationError = ValidationError<PayloadPermanentError, PayloadTransientError>;

impl From<IngressPayloadValidationError> for PayloadValidationError {
    fn from(err: IngressPayloadValidationError) -> Self {
        err.map(
            PayloadPermanentError::IngressPayloadValidationError,
            PayloadTransientError::IngressPayloadValidationError,
        )
    }
}

impl From<XNetPayloadValidationError> for PayloadValidationError {
    fn from(err: XNetPayloadValidationError) -> Self {
        err.map(
            PayloadPermanentError::XNetPayloadValidationError,
            PayloadTransientError::XNetPayloadValidationError,
        )
    }
}

impl From<SelfValidatingPayloadValidationError> for PayloadValidationError {
    fn from(err: SelfValidatingPayloadValidationError) -> Self {
        err.map(
            PayloadPermanentError::SelfValidatingPayloadValidationError,
            PayloadTransientError::SelfValidatingPayloadValidationError,
        )
    }
}
