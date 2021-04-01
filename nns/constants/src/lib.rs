use ic_base_types::CanisterId;

#[cfg(target_arch = "x86_64")]
pub mod ids;

// WARNING: The NNS canisters MUST be installed in the NNS subnet,
// in the following order, otherwise they won't be able to find
// each other.
//
// These constants are used to write a file with the PB below in
// nns/common/build.rs.
//
// NOTES (IMPORTANT!)
// ~~~~~~~~~~~~~~~~~~
// - This is dependent on the implementation of function
//   `CanisterManager::generate_new_canister_id`.
// - Unless you only add at the end, be sure to double check with
//   `rs/nns/canister_ids.json`.
pub const REGISTRY_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 0;
pub const GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 1;
pub const LEDGER_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 2;
pub const ROOT_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 3;
pub const LIFELINE_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 4;
pub const GENESIS_TOKEN_CANISTER_INDEX_IN_NNS_SUBNET: u64 = 5;

/// The names of all expected .wasm files to set up the NNS.
pub const NNS_CANISTER_WASMS: [&str; 6] = [
    // The lifeline is not present! Because its wasm is embedded in the source code using
    // include_bytes, it is not provided on the path. We want to change that, though.
    "registry-canister",
    "governance-canister",
    "ledger-canister",
    "root-canister",
    // The lifeline is built differently, which explains why its wasm has a different name pattern.
    "lifeline",
    "genesis-token-canister",
];

pub const NUM_NNS_CANISTERS: usize = NNS_CANISTER_WASMS.len();

pub const REGISTRY_CANISTER_ID: CanisterId =
    CanisterId::from_u64(REGISTRY_CANISTER_INDEX_IN_NNS_SUBNET);
pub const GOVERNANCE_CANISTER_ID: CanisterId =
    CanisterId::from_u64(GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET);
pub const LEDGER_CANISTER_ID: CanisterId =
    CanisterId::from_u64(LEDGER_CANISTER_INDEX_IN_NNS_SUBNET);
pub const ROOT_CANISTER_ID: CanisterId = CanisterId::from_u64(ROOT_CANISTER_INDEX_IN_NNS_SUBNET);
pub const LIFELINE_CANISTER_ID: CanisterId =
    CanisterId::from_u64(LIFELINE_CANISTER_INDEX_IN_NNS_SUBNET);
pub const GENESIS_TOKEN_CANISTER_ID: CanisterId =
    CanisterId::from_u64(GENESIS_TOKEN_CANISTER_INDEX_IN_NNS_SUBNET);

pub const ALL_NNS_CANISTER_IDS: [&CanisterId; 6] = [
    &REGISTRY_CANISTER_ID,
    &GOVERNANCE_CANISTER_ID,
    &LEDGER_CANISTER_ID,
    &ROOT_CANISTER_ID,
    &LIFELINE_CANISTER_ID,
    &GENESIS_TOKEN_CANISTER_ID,
];

// The memory allocation for the ledger, governance and registry canisters
// (4GiB)
const NNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES: u64 = 4 * 1024 * 1024 * 1024;

// The default memory allocation to set for the remaining NNS canister (1GiB)
const NNS_DEFAULT_CANISTER_MEMORY_ALLOCATION_IN_BYTES: u64 = 1024 * 1024 * 1024;

/// Returns the memory allocation of the given nns canister.
pub fn memory_allocation_of(canister_id: CanisterId) -> u64 {
    if [
        LEDGER_CANISTER_ID,
        GOVERNANCE_CANISTER_ID,
        REGISTRY_CANISTER_ID,
    ]
    .contains(&canister_id)
    {
        NNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES
    } else {
        NNS_DEFAULT_CANISTER_MEMORY_ALLOCATION_IN_BYTES
    }
}