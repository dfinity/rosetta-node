#![allow(clippy::ptr_arg)]
pub mod fake;
use mockall::predicate::*;
use mockall::*;

use crate::crypto::empty_ni_dkg_transcripts_with_committee;
use ic_consensus_message::{make_genesis, ConsensusMessageHashable};
use ic_interfaces::{
    consensus::*,
    consensus_pool::{ChangeAction, ChangeSet, ConsensusPool, ConsensusPoolCache},
    ingress_pool::IngressPoolSelect,
    registry::RegistryClient,
    validation::*,
};
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_types::{
    artifact::*,
    consensus::{catchup::CUPWithOriginalProtobuf, Block, CatchUpPackage},
    SubnetId, Time,
};
use std::sync::Arc;

#[macro_export]
macro_rules! assert_changeset_matches_pattern {
    ($v:expr, $p:pat) => {
        assert_eq!($v.len(), 1);
        assert!(matches_pattern!($v[0], $p));
    };
}

#[macro_export]
macro_rules! matches_pattern {
    ($v:expr, $p:pat) => {
        if let $p = $v {
            true
        } else {
            false
        }
    };
}

pub fn assert_result_invalid<P, T>(result: ValidationResult<ValidationError<P, T>>) {
    assert!(matches_pattern!(result, Err(ValidationError::Permanent(_))));
}

pub fn assert_action_invalid<T: ConsensusMessageHashable>(action: ChangeAction, msg: &T) {
    match action {
        ChangeAction::HandleInvalid(actual, _) => assert_eq!(actual, msg.clone().to_message()),
        _ => panic!("Expected HandleInvalid ChangeAction"),
    }
}

mock! {
    pub Consensus {}

    pub trait ConsensusGossip: Send + Sync {
        fn get_priority_function<'a>(
            &'a self,
            consensus_pool: &'a (dyn ConsensusPool + 'a),
        ) -> PriorityFn<ConsensusMessageId, ConsensusMessageAttribute>;

        fn get_filter(&self) -> ConsensusMessageFilter;
    }

    pub trait Consensus: Send {
        fn on_state_change<'a>(
            &'a self,
            consensus_pool: &'a (dyn ConsensusPool + 'a),
            ingress_pool: &'a (dyn IngressPoolSelect + 'a),
        ) -> ChangeSet;
    }
}

mock! {

    pub ConsensusCache {}

    pub trait ConsensusPoolCache: Send + Sync {
        fn finalized_block(&self) -> Block;

        fn consensus_time(&self) -> Option<Time>;

        fn catch_up_package(&self) -> CatchUpPackage;

        fn summary_block(&self) -> Block;

        fn cup_with_protobuf(&self) -> CUPWithOriginalProtobuf;
    }
}

/// Return a CatchUpPackage created with empty transcript, from the given
/// committee.
pub fn make_catch_up_package_with_empty_transcript(
    registry_client: Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
) -> CatchUpPackage {
    let version = ic_types::RegistryVersion::from(1);
    let subnet_members: Vec<_> = registry_client
        .get_node_ids_on_subnet(subnet_id, version)
        .expect("Could not get node ids from registry")
        .expect("Node ids not available at given registry version");
    let ni_transcripts = empty_ni_dkg_transcripts_with_committee(subnet_members);
    let summary = ic_consensus::dkg::make_genesis_summary(&*registry_client, subnet_id, None)
        .with_current_transcripts(ni_transcripts);
    make_genesis(summary)
}
