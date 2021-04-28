use ic_interfaces::{
    execution_environment::{
        CanisterHeartbeatError, ExecResult, ExecuteMessageResult, ExecutionEnvironment,
        MessageAcceptanceError, SubnetAvailableMemory,
    },
    messages::CanisterInputMessage,
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterState, ReplicatedState};
use ic_types::{messages::SignedIngressContent, NumBytes, NumInstructions, SubnetId, Time};
use mockall::*;
use rand::RngCore;
use std::{collections::BTreeMap, sync::Arc};

mock! {
    pub ExecutionEnvironment {}

    trait ExecutionEnvironment: Sync {
        type State = ReplicatedState;
        type CanisterState = CanisterState;

        #[allow(clippy::too_many_arguments)]
        fn execute_subnet_message(
            &self,
            msg: CanisterInputMessage,
            state: ReplicatedState,
            instructions_limit: NumInstructions,
            rng: &mut (dyn RngCore + 'static),
            provisional_whitelist: &ProvisionalWhitelist,
            subnet_available_memory: SubnetAvailableMemory,
        ) -> ReplicatedState;

        #[allow(clippy::too_many_arguments)]
        fn execute_canister_message(
            &self,
            canister_state: CanisterState,
            instructions_limit: NumInstructions,
            msg: CanisterInputMessage,
            time: Time,
            routing_table: Arc<RoutingTable>,
            subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
            subnet_available_memory: SubnetAvailableMemory,
        ) -> ExecResult<ExecuteMessageResult<CanisterState>>;

        fn should_accept_ingress_message(
            &self,
            state: Arc<ReplicatedState>,
            provisional_whitelist: &ProvisionalWhitelist,
            ingress: &SignedIngressContent,
        ) -> Result<(), MessageAcceptanceError>;

        fn execute_canister_heartbeat(
            &self,
            canister_state: CanisterState,
            instructions_limit: NumInstructions,
            routing_table: Arc<RoutingTable>,
            subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
            time: Time,
            subnet_available_memory: SubnetAvailableMemory,
        ) -> ExecResult<(CanisterState, NumInstructions, Result<NumBytes, CanisterHeartbeatError>)>;

        fn subnet_available_memory(&self, state: &ReplicatedState) -> NumBytes;
    }
}
