use crate::embedders::{EmbedderType, PersistenceType, MAX_FUNCTIONS, MAX_GLOBALS};
use ic_types::{Cycles, NumBytes, NumInstructions};
use serde::{Deserialize, Serialize};

// Assuming 3TiB disk size on each node, we believe that we can comfortably
// support two orders of magnitude lower canister states size, i.e. 30GiB.
pub(crate) const SUBNET_MEMORY_CAPACITY: NumBytes = NumBytes::new(30 * 1024 * 1024 * 1024);

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default)]
pub struct Config {
    pub embedder_type: EmbedderType,
    pub persistence_type: PersistenceType,
    /// This is no longer used in the code.  It is not removed yet as removing
    /// this option will be a breaking change.
    pub create_funds_whitelist: String,

    /// The maximum number of instructions that the methods that are invoked to
    /// check message acceptance can run for.
    pub max_instructions_for_message_acceptance_calls: NumInstructions,

    /// The maximum amount of memory that can be utilized by all the canisters.
    pub subnet_memory_capacity: NumBytes,

    /// The maximum amount of memory that can be utilized by a single canister.
    pub max_canister_memory_size: NumBytes,

    /// The maximum amount of cycles a canister can hold.
    /// If set to None, the canisters have no upper limit.
    pub max_cycles_per_canister: Option<Cycles>,

    /// The default value used when provisioning a canister
    /// if amount of cycles was not specified.
    pub default_provisional_cycles_balance: Cycles,

    /// Maximum number of globals allowed in a Wasm module.
    pub max_globals: usize,
    /// Maximum number of functions allowed in a Wasm module.
    pub max_functions: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            embedder_type: EmbedderType::Wasmtime,
            persistence_type: PersistenceType::Sigsegv,
            create_funds_whitelist: String::default(),
            // TODO(akhi): we do not have a good intuition for how long to let
            // the `canister_inspect_message` method so for now we default to
            // the same limit as for executing a normal message.
            max_instructions_for_message_acceptance_calls:
                crate::scheduler::MAX_INSTRUCTIONS_PER_MESSAGE,
            subnet_memory_capacity: SUBNET_MEMORY_CAPACITY,
            // A canister's memory size can be at most 8GiB (4GiB heap + 4GiB stable memory).
            max_canister_memory_size: NumBytes::new(8 * 1024 * 1024 * 1024),
            // Canisters on the system subnet are not capped.
            // They can hold an amount of cycles that goes above this limit.
            // If this limit is set to None, canisters can hold any amount of cycles.
            max_cycles_per_canister: None,
            default_provisional_cycles_balance: Cycles::new(100_000_000_000_000),
            max_globals: MAX_GLOBALS,
            max_functions: MAX_FUNCTIONS,
        }
    }
}
