use ic_base_types::NumBytes;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Cycles, NumInstructions};
use serde::{Deserialize, Serialize};

// We assume 1 cycles unit ≅ 1 CPU cycle, so on a 2 GHz CPU one message has
// approximately 2.5 seconds to be processed.
pub(crate) const MAX_INSTRUCTIONS_PER_MESSAGE: NumInstructions =
    NumInstructions::new((1 << 30) * 5);

// TODO(EXE-153): address special cased handling of scheduler cores for nns and
// non nns subnets.
#[derive(Clone, Deserialize, Debug, PartialEq, Eq, Serialize)]
#[serde(default)]
pub struct Config {
    /// Number of canisters that the scheduler is allowed to schedule in
    /// parallel on the NNS subnet.
    pub nns_subnet_scheduler_cores: usize,

    /// Number of canisters that the scheduler is allowed to schedule in
    /// parallel on the non-NNS subnet.
    pub non_nns_subnet_scheduler_cores: usize,

    /// Maximum amount of instructions a single round can consume (on one
    /// thread).
    pub max_instructions_per_round: NumInstructions,
    /// Maximum amount of instructions a single message's execution can consume.
    /// This should be significantly smaller than `max_instructions_per_round`.
    pub max_instructions_per_message: NumInstructions,

    /// This specifies the upper limit on how much delta all the canisters
    /// together on the subnet can produce in between checkpoints. This is a
    /// soft limit in the sense, that we will continue to execute canisters as
    /// long the current delta size is below this limit and stop if the current
    /// size is above this limit. Hence, it is possible that the actual usage of
    /// the subnet goes above this limit.
    pub subnet_state_delta_change_capacity: NumBytes,

    // The fields below are deprecated. They do not have any impact to the
    // current version of the scheduler. They are maintained for backwards
    // compatibility with the deployed `ic.json5`.
    /// Maximum amount of cycles a single round can consume (on one thread).
    pub round_cycles_max: Cycles,
    /// Maximum amount of cycles a single message's execution can consume. This
    /// has to be significantly smaller than `round_cycles_max`.
    pub exec_cycles: Cycles,

    /// Number of cores that the execution component is allowed to schedule
    /// canisters on. This is now deprecated and only exists to keep backwards
    /// compatibility with older `ic.json5`.
    pub scheduler_cores: usize,
}

impl Config {
    /// Based on the type of the subnet, returns the appropriate value for
    /// scheduler cores to use.
    pub fn scheduler_cores(&self, subnet_type: SubnetType) -> usize {
        match subnet_type {
            SubnetType::Application => self.non_nns_subnet_scheduler_cores,
            SubnetType::System => self.nns_subnet_scheduler_cores,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scheduler_cores: 1,
            // This is half of the number of cores that we expect to have in the
            // gen 1 machines on the production network.
            nns_subnet_scheduler_cores: 32,
            non_nns_subnet_scheduler_cores: 32,
            // As this is a soft limit, setting the limit to half the subnet's
            // memory capacity.
            subnet_state_delta_change_capacity: crate::execution_environment::SUBNET_MEMORY_CAPACITY
                / 2,
            max_instructions_per_round: MAX_INSTRUCTIONS_PER_MESSAGE * 5,
            max_instructions_per_message: MAX_INSTRUCTIONS_PER_MESSAGE,
            round_cycles_max: Cycles::from(0),
            exec_cycles: Cycles::from(0),
        }
    }
}
