//! Defines types that are useful when handling funds on the IC.

mod cycles;
pub mod icp;

pub use cycles::Cycles;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::queues::v1::Cycles as PbCycles,
    state::queues::v1::Funds as PbFunds,
};
use icp::ICP;
use serde::{Deserialize, Serialize};
use std::convert::{From, TryFrom};

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

impl From<&Funds> for PbFunds {
    fn from(item: &Funds) -> Self {
        Self {
            cycles_struct: Some(PbCycles::from(item.cycles)),
            icp: item.icp.balance(),
        }
    }
}

impl TryFrom<PbFunds> for Funds {
    type Error = ProxyDecodeError;

    fn try_from(item: PbFunds) -> Result<Self, Self::Error> {
        Ok(Self {
            cycles: try_from_option_field(item.cycles_struct, "Funds::cycles_struct")?,
            icp: icp::Tap::mint(item.icp),
        })
    }
}
// TODO(EXE-84): Move the following parameters to the registry

//////////////////////////////////////////////////////////////
// Fees
//////////////////////////////////////////////////////////////

/// Cycles charged per Wasm page (64KiB), for one round.
/// The assumptions used to set the cost are:
/// 1T cycles is about 1USD
/// a round takes ca 3s.
/// The value is set so that storing 1GB/month costs roughly 100 USD
/// This is the intended cost for storage on a 7 node subnetwork at launch.
/// The cost should go down as the protocol storage costs improve.
pub const CYCLES_PER_WASM_PAGE: Cycles = Cycles::new(7500);

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

/// Creating canisters incurs a "large" fee in order to prevent someone from
/// creating a lot of canisters and thus attempt to DDoS the system. Arbitrarily
/// set to 10^12 cycles which ought to be large enough.
pub const CANISTER_CREATION_FEE: Cycles = Cycles::new(1_000_000_000_000);

/// Flat fee to charge for an incoming ingress message.
pub const INGRESS_MESSAGE_RECEIVED_FEE: Cycles = Cycles::new(100);

/// Fee to charge per byte of an ingress message.
pub const INGRESS_BYTE_RECEIVED_FEE: Cycles = Cycles::new(100);

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
