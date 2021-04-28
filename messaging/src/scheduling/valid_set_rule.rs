// Including this clippy allow to circumvent clippy errors spawned by MockAll
// internal expansion.  Should be removed when DFN-860 is resolved.
// Specifically relevant to the Vec<> parameter.
#![allow(clippy::ptr_arg)]

use ic_cycles_account_manager::{
    CyclesAccountManager, IngressInductionCost, IngressInductionCostError,
};
use ic_interfaces::execution_environment::IngressHistoryWriter;
use ic_logger::{debug, error, trace, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_replicated_state::{
    replicated_state::{
        LABEL_VALUE_CANISTER_NOT_FOUND, LABEL_VALUE_CANISTER_OUT_OF_CYCLES,
        LABEL_VALUE_CANISTER_STOPPED, LABEL_VALUE_CANISTER_STOPPING,
        LABEL_VALUE_INVALID_SUBNET_PAYLOAD, LABEL_VALUE_UNKNOWN_SUBNET_METHOD,
    },
    CyclesAccountError, ReplicatedState, StateError,
};
use ic_types::messages::HttpRequestContent;
use ic_types::{
    ingress::IngressStatus,
    messages::{is_subnet_message, SignedIngressContent},
    user_error::{ErrorCode, UserError},
    CanisterStatusType, SubnetId,
};
use prometheus::{Histogram, IntCounterVec};
use std::sync::Arc;

struct VsrMetrics {
    /// Counts of ingress message induction attempts, by status.
    inducted_ingress_messages: IntCounterVec,
    /// Successfully inducted ingress message payload sizes.
    inducted_ingress_payload_sizes: Histogram,
}

const METRIC_INDUCTED_INGRESS_MESSAGES: &str = "mr_inducted_ingress_message_count";
const METRIC_INDUCTED_INGRESS_PAYLOAD_SIZES: &str = "mr_inducted_ingress_payload_size_bytes";

const LABEL_STATUS: &str = "status";

const LABEL_VALUE_SUCCESS: &str = "success";
const LABEL_VALUE_DUPLICATE: &str = "duplicate";

impl VsrMetrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
        let inducted_ingress_messages = metrics_registry.int_counter_vec(
            METRIC_INDUCTED_INGRESS_MESSAGES,
            "Counts of ingress message induction attempts, by status.",
            &[LABEL_STATUS],
        );
        let inducted_ingress_payload_sizes = metrics_registry.histogram(
            METRIC_INDUCTED_INGRESS_PAYLOAD_SIZES,
            "Successfully inducted ingress message payload sizes.",
            // 10 B - 5 MB
            decimal_buckets(1, 6),
        );

        // Initialize all `inducted_ingress_messages` counters with zero, so they are
        // all exported from process start (`IntCounterVec` is really a map).
        for status in &[
            LABEL_VALUE_SUCCESS,
            LABEL_VALUE_DUPLICATE,
            LABEL_VALUE_CANISTER_NOT_FOUND,
            LABEL_VALUE_CANISTER_STOPPED,
            LABEL_VALUE_CANISTER_STOPPING,
            LABEL_VALUE_CANISTER_OUT_OF_CYCLES,
            LABEL_VALUE_UNKNOWN_SUBNET_METHOD,
            LABEL_VALUE_INVALID_SUBNET_PAYLOAD,
        ] {
            inducted_ingress_messages.with_label_values(&[status]);
        }

        Self {
            inducted_ingress_messages,
            inducted_ingress_payload_sizes,
        }
    }
}

pub(crate) trait ValidSetRule: Send {
    /// Inducts the provided messages into the ReplicatedState.
    fn induct_messages(&self, state: &mut ReplicatedState, msgs: Vec<SignedIngressContent>);
}

pub(crate) struct ValidSetRuleImpl {
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    cycles_account_manager: Arc<CyclesAccountManager>,
    metrics: VsrMetrics,
    own_subnet_id: SubnetId,
    log: ReplicaLogger,
}

impl ValidSetRuleImpl {
    pub(crate) fn new(
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
        cycles_account_manager: Arc<CyclesAccountManager>,
        metrics_registry: &MetricsRegistry,
        own_subnet_id: SubnetId,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            ingress_history_writer,
            metrics: VsrMetrics::new(metrics_registry),
            own_subnet_id,
            cycles_account_manager,
            log,
        }
    }

    /// Tries to induct a single ingress message and sets the message status in
    /// `state` accordingly (to `Received` if successful; or to `Failed` with
    /// the relevant error code on failure).
    fn induct_message(&self, mut state: &mut ReplicatedState, msg: SignedIngressContent) {
        trace!(self.log, "induct_message");
        let message_id = msg.id();
        let source = msg.sender();
        let receiver = msg.canister_id();
        let payload_bytes = msg.arg().len();
        let time = state.time();

        match self.enqueue(state, msg) {
            Ok(()) => {
                self.observe_inducted_ingress_status(LABEL_VALUE_SUCCESS);
                self.observe_inducted_ingress_payload_size(payload_bytes);
                self.ingress_history_writer.set_status(
                    &mut state,
                    message_id,
                    IngressStatus::Received {
                        receiver: receiver.get(),
                        user_id: source,
                        time,
                    },
                );
            }

            Err(err) => {
                let error_code = match err {
                    StateError::CanisterNotFound(canister_id) => {
                        error!(
                            self.log,
                            "Failed to induct message: canister does not exist";
                            messaging.message_id => format!("{}", message_id),
                            messaging.canister_id => format!("{}", canister_id),
                        );
                        ErrorCode::CanisterNotFound
                    }
                    StateError::CanisterStopped(_) => ErrorCode::CanisterStopped,
                    StateError::CanisterStopping(_) => ErrorCode::CanisterStopping,
                    StateError::CanisterOutOfCycles { .. } => ErrorCode::CanisterOutOfCycles,
                    StateError::UnknownSubnetMethod(_) => ErrorCode::CanisterOutOfCycles,
                    StateError::InvalidSubnetPayload => ErrorCode::CanisterOutOfCycles,
                    StateError::QueueFull { .. } => unreachable!("Unexpected error: {}", err),
                };
                self.observe_inducted_ingress_status(err.to_label_value());

                self.ingress_history_writer.set_status(
                    &mut state,
                    message_id,
                    IngressStatus::Failed {
                        receiver: receiver.get(),
                        user_id: source,
                        error: UserError::new(error_code, err.to_string()),
                        time,
                    },
                );
            }
        }
    }

    /// Checks whether the given message has already been inducted.
    fn is_duplicate(&self, state: &ReplicatedState, msg: &SignedIngressContent) -> bool {
        state.get_ingress_status(&msg.id()) != IngressStatus::Unknown
    }

    /// Records the result of inducting an ingress message.
    fn observe_inducted_ingress_status(&self, status: &str) {
        self.metrics
            .inducted_ingress_messages
            .with_label_values(&[status])
            .inc();
    }

    /// Records the size of a successfully inducted ingress message payload.
    fn observe_inducted_ingress_payload_size(&self, bytes: usize) {
        self.metrics
            .inducted_ingress_payload_sizes
            .observe(bytes as f64);
    }

    // Enqueues an ingress message into input queues.
    fn enqueue(
        &self,
        state: &mut ReplicatedState,
        msg: SignedIngressContent,
    ) -> Result<(), StateError> {
        // Compute the cost of induction.
        let induction_cost = match self.cycles_account_manager.ingress_induction_cost(&msg) {
            Ok(induction_cost) => induction_cost,
            Err(IngressInductionCostError::UnknownSubnetMethod) => {
                return Err(StateError::UnknownSubnetMethod(
                    msg.method_name().to_string(),
                ))
            }
            Err(IngressInductionCostError::InvalidSubnetPayload) => {
                return Err(StateError::InvalidSubnetPayload)
            }
        };

        match induction_cost {
            IngressInductionCost::Free => {
                // Only subnet methods can be free. These are enqueued directly.
                assert!(is_subnet_message(&msg, self.own_subnet_id));
                state.subnet_queues.push_ingress(msg.into());
            }
            IngressInductionCost::Fee { payer, cost } => {
                // Get the paying canister from the state.
                let canister = match state.canister_states.get_mut(&payer) {
                    Some(canister) => canister,
                    None => return Err(StateError::CanisterNotFound(payer)),
                };

                // Ensure the canister is running if the message isn't to a subnet.
                if !is_subnet_message(&msg, self.own_subnet_id) {
                    match canister.status() {
                        CanisterStatusType::Running => {}
                        CanisterStatusType::Stopping => {
                            return Err(StateError::CanisterStopping(canister.canister_id()))
                        }
                        CanisterStatusType::Stopped => {
                            return Err(StateError::CanisterStopped(canister.canister_id()))
                        }
                    }
                }

                // Withdraw cost of inducting the message.
                let memory_usage = canister.memory_usage();
                let compute_allocation = canister.scheduler_state.compute_allocation;
                if let Err(err) = self.cycles_account_manager.withdraw_cycles(
                    &mut canister.system_state,
                    memory_usage,
                    compute_allocation,
                    cost,
                ) {
                    match err {
                        CyclesAccountError::CanisterOutOfCycles {
                            available,
                            requested,
                        } => {
                            return Err(StateError::CanisterOutOfCycles {
                                canister_id: payer,
                                available,
                                requested,
                            });
                        }
                    }
                }

                // Add message to the appropriate queue.
                if is_subnet_message(&msg, self.own_subnet_id) {
                    state.subnet_queues.push_ingress(msg.into());
                } else {
                    let canister = match state.canister_states.get_mut(&payer) {
                        Some(canister) => canister,
                        None => return Err(StateError::CanisterNotFound(payer)),
                    };
                    canister.system_state.queues.push_ingress(msg.into());
                }
            }
        }

        Ok(())
    }
}

impl ValidSetRule for ValidSetRuleImpl {
    fn induct_messages(&self, state: &mut ReplicatedState, msgs: Vec<SignedIngressContent>) {
        for msg in msgs {
            let message_id = msg.id();
            if !self.is_duplicate(&state, &msg) {
                self.induct_message(state, msg);
            } else {
                self.observe_inducted_ingress_status(LABEL_VALUE_DUPLICATE);
                debug!(self.log, "Didn't induct duplicate message {}", message_id);
            }
        }
    }
}

#[cfg(test)]
mod test;
