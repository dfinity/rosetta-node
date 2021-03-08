//! Defines types that are useful when handling funds on the IC.

mod cycles;
pub mod icp;

pub use cycles::Cycles;
use ic_protobuf::state::queues::*;
use icp::ICP;
use serde::{Deserialize, Serialize};
use std::convert::From;

/// A struct to hold various types of funds. Currently, only Cycles and ICP are
/// supported.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Funds {
    cycles: Cycles,
    icp: ICP,
}

impl Funds {
    pub fn new(cycles: Cycles, icp: ICP) -> Self {
        Self { cycles, icp }
    }

    /// Returns a new `Funds` object containing zero funds.
    pub fn zero() -> Self {
        Self {
            cycles: Cycles::from(0),
            icp: ICP::zero(),
        }
    }

    /// Returns the amount of cycles contained.
    pub fn cycles(&self) -> Cycles {
        self.cycles
    }

    pub fn cycles_mut(&mut self) -> &mut Cycles {
        &mut self.cycles
    }

    /// Takes the cycles contained and sets the remaining cycles to zero
    pub fn take_cycles(&mut self) -> Cycles {
        let cycles = self.cycles;
        self.cycles = Cycles::from(0);
        cycles
    }

    /// Adds the given cycles to the current funds.
    pub fn add_cycles(&mut self, cycles: Cycles) {
        self.cycles += cycles;
    }

    pub fn icp(&self) -> &ICP {
        &self.icp
    }

    pub fn icp_mut(&mut self) -> &mut ICP {
        &mut self.icp
    }

    /// Takes all the ICP out of the current `Funds`.
    pub fn take_icp(&mut self) -> ICP {
        self.icp_mut().take()
    }

    /// Adds the given ICP to the current funds.
    pub fn add_icp(&mut self, icp: ICP) {
        self.icp.add(icp);
    }

    /// Extracts the funds from the current object into a new `Funds` object.
    pub fn take(&mut self) -> Funds {
        Funds::new(self.cycles, self.icp.take())
    }
}

impl From<&Funds> for v1::Funds {
    fn from(item: &Funds) -> Self {
        Self {
            cycles: item.cycles.get(),
            icp: item.icp.balance(),
        }
    }
}

impl From<v1::Funds> for Funds {
    fn from(item: v1::Funds) -> Self {
        Self {
            cycles: Cycles::from(item.cycles),
            icp: icp::Tap::mint(item.icp),
        }
    }
}
// TODO(EXE-84): Move the following parameters to the registry

//////////////////////////////////////////////////////////////
// Fees
//////////////////////////////////////////////////////////////

/// Cost for using a single WASM page worth of data, for one round.
pub const CYCLES_PER_ACTIVE_WASM_PAGE: Cycles = Cycles::new(1);

/// Cycles charged per 1MiB of the memory allocation.
pub const CYCLES_PER_MEMORY_ALLOCATION_MB: Cycles = Cycles::new(1);

/// Cycles charged for each percent of the reserved compute allocation.
/// Note that reserved compute allocation is a scarce resource, and should be
/// appropriately charged for.
pub const CYCLES_PER_COMPUTE_ALLOCATION_PERCENT: Cycles = Cycles::new(1);

/// Baseline fee, charged for every message execution.
pub const FIXED_FEE_FOR_EXECUTION: Cycles = Cycles::new(10);

/// Baseline fee, charged for sending every message.
pub const FIXED_FEE_FOR_NETWORK_TRANSFER: Cycles = Cycles::new(10);

/// This value controls what is the threshold for being able to execute
/// messages. If the canister doesn't have enough cycles in its balance, then
/// it's frozen and cannot execute more messages until it's topped up with more
/// cycles.
// TODO(EXE-87): Change this constant into a value calculated from resource
// allocation and usage
pub const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(1 << 33);

/// Globals are expensive for us to handle, so we charge more for them than we
/// do for regular data.
pub const CYCLES_PER_WASM_EXPORTED_GLOBAL: Cycles = Cycles::new(100);

/// Creating canisters incurs a "large" fee in order to prevent someone from
/// creating a lot of canisters and thus attempt to DDoS the system. Arbitrarily
/// set to 10^12 cycles which ought to be large enough.
pub const CANISTER_CREATION_FEE: Cycles = Cycles::new(1_000_000_000_000);

//////////////////////////////////////////////////////////////
// Conversions
//////////////////////////////////////////////////////////////

/// Cycles to be paid per byte that's transferred across subnets.
pub const CYCLES_PER_BYTE_RATIO: Cycles = Cycles::new(1);

/// The cost reported by the runtime is divided by this number,
/// before actually charging the canister.
/// This allows us to have different costs per subnets and
/// to charge a fraction of a cycle per executed instruction.
/// This was calculated with the objective to run 2-3 months on 100T cycles.
/// 100 * 10^12 cycles / 100 days = 10^12 cycles / day
/// (86400[sec] * (3 * 10^9)[inst/sec]) / 10^12 = 259
/// The assumption is that storage and network costs can be ignored.
pub const EXECUTED_INSTRUCTIONS_PER_CYCLE: u64 = 250;

//////////////////////////////////////////////////////////////
// Other
//////////////////////////////////////////////////////////////

/// Cycles limit for a canister.
pub const CYCLES_LIMIT_PER_CANISTER: Cycles = Cycles::new(100_000_000_000_000);
