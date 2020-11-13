//! This crate contains assorted types that other component crates
//! depend upon.  The only types that should be included in this crate
//! should be the ones that more than one component crate share.
//! This should generally imply that the types used here should also
//! be getting used in the `interfaces` crate although there might be
//! exceptions to this rule.

// Note [ExecutionRound vs Height]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// A batch received by Message Routing has some `Height` `h` attached to it.
// Once the batch is received, Message Routing needs to retrieve the `State`
// at `Height` `h-1` as a base for the current `ExecutionRound` `h`.
// After `ExecutionRound` `h` is complete, the resulting `State` is going to be
// marked with `Height` `h`.
//
// The main reason to have 2 different types and not use a single one is that
// each type is meaningful in a specific context and represents slightly
// different ideas which cannot always be mapped 1-1 to each other. More
// concretely, `ExecutionRound` which is triggered by batch `Height` `h`
// might process messages that were introduced in previous batch `Height`s.
//
// Furthermore, different subcomponents should have different
// capabilities.  E.g. Message Routing is allowed to
// increment/decrement `Height`s while the Scheduler is not supposed
// to perform any arithmetics on `ExecutionRound`.

// Note [Scheduler and AccumulatedPriority]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Public Specification of IC describes compute allocation. Each canister is
// initiated with an accumulated priority of 0. The scheduler uses these values
// while calculating the priority of a canister at each round. The canisters
// are scheduled at each round in the following way:
//
// * For each canister, we compute the round priority of that canister as the
// sum of its accumulated priority and the multiplication of its compute
// allocation with the multiplier (see the scheduler).
// * We distribute the free capacity equally to all the canisters.
// * We sort the canisters according to their round priorities in descending
// order.
// * The first scheduler_cores many canisters are given the top priority in
// this round. Therefore, they are expected to be executed as the first of
// their threads.
// * As the last step, we update the accumulated priorities of all canisters.
// Canisters which did not get the top priority in this round, have their
// accumulated priority replaced with the value of their round_priority. The
// top scheduler_cores many canisters' accumulated priority is updated with
// the value of their round priorities subtracted by (the sum of compute
// allocations of all canisters times multiplier divided by the number of
// canisters that are given top priority in this round.
//
// As a result, at each round, the sum of accumulated priorities remains 0.
// Similarly, the sum of all round priorities equals to the multiplication of
// the sum of all compute allocations with the multiplier.

pub mod artifact;
pub mod batch;
pub mod chunkable;
pub mod consensus;
pub mod crypto;
pub mod filetree_sync;
pub mod funds;
pub mod ic00;
pub mod ingress;
pub mod malicious_behaviour;
pub mod malicious_flags;
pub mod messages;
pub mod methods;
pub mod node_manager;
pub mod p2p;
pub mod registry;
pub mod replica_config;
pub mod replica_version;
pub mod state_sync;
pub mod time;
pub mod transport;
pub mod user_error;
#[cfg(not(target_arch = "wasm32"))]
pub mod wasm;
pub mod xnet;

use crate::messages::CanisterInstallMode;
pub use crate::replica_version::ReplicaVersion;
pub use crate::time::Time;
pub use funds::icp::{ICPError, ICP};
pub use funds::*;
pub use ic_base_types::{
    subnet_id_into_protobuf, subnet_id_try_from_protobuf, CanisterId, CanisterIdError,
    CanisterStatusType, NodeId, NodeTag, NumBytes, PrincipalId, PrincipalIdBlobParseError,
    RegistryVersion, SubnetId,
};
pub use ic_crypto_internal_types::NodeIndex;
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::InstallCodeArgs;
use ic_protobuf::types::v1 as pb;
use num_traits::cast::ToPrimitive;
use phantom_newtype::{AmountOf, Id};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Display;

pub struct UserTag {}
pub type UserId = Id<UserTag, PrincipalId>;

/// Converts a UserId into its protobuf definition.  Normally, we would use
/// `impl From<UserId> for pb::UserId` here however we cannot as both
/// `Id` and `pb::UserId` are defined in other crates.
pub fn user_id_into_protobuf(id: UserId) -> pb::UserId {
    pb::UserId {
        principal_id: Some(pb::PrincipalId::from(id.get())),
    }
}

/// From its protobuf definition convert to a UserId.  Normally, we would
/// use `impl TryFrom<pb::UserId> for UserId` here however we cannot as
/// both `Id` and `pb::UserId` are defined in other crates.
pub fn user_id_try_from_protobuf(value: pb::UserId) -> Result<UserId, PrincipalIdBlobParseError> {
    // All fields in Protobuf definition are required hence they are encoded in
    // `Option`.  We simply treat them as required here though.
    let principal_id = PrincipalId::try_from(value.principal_id.unwrap())?;
    Ok(UserId::from(principal_id))
}

/// The ID for interactive DKG.
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialOrd, Ord, Hash, PartialEq, Serialize)]
pub struct IDkgId {
    pub instance_id: Height,
    pub subnet_id: SubnetId,
}

impl Display for IDkgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "instance_id: '{}', subnet_id: '{}'",
            self.instance_id, self.subnet_id
        )
    }
}

impl IDkgId {
    pub fn start_height(&self) -> Height {
        self.instance_id
    }
}

pub type NumberOfNodes = AmountOf<NodeTag, NodeIndex>;

pub struct HeightTag {}
// Note [ExecutionRound vs Height]
pub type Height = AmountOf<HeightTag, u64>;

/// Converts a NodeId into its protobuf definition.  Normally, we would use
/// `impl From<NodeId> for pb::NodeId` here however we cannot as both
/// `Id` and `pb::NodeId` are defined in other crates.
pub fn node_id_into_protobuf(id: NodeId) -> pb::NodeId {
    pb::NodeId {
        principal_id: Some(pb::PrincipalId::from(id.get())),
    }
}

/// From its protobuf definition convert to a NodeId.  Normally, we would
/// use `impl TryFrom<pb::NodeId> for NodeId` here however we cannot as
/// both `Id` and `pb::NodeId` are defined in other crates.
pub fn node_id_try_from_protobuf(value: pb::NodeId) -> Result<NodeId, PrincipalIdBlobParseError> {
    // All fields in Protobuf definition are required hence they are encoded in
    // `Option`.  We simply treat them as required here though.
    let principal_id = PrincipalId::try_from(value.principal_id.unwrap())?;
    Ok(NodeId::from(principal_id))
}

pub struct QueueIndexTag;
/// Index into a queue; used in the context of `InputQueue` / `OutputQueue` to
/// define message order.
pub type QueueIndex = AmountOf<QueueIndexTag, u64>;

pub struct RandomnessTag;
pub type Randomness = Id<RandomnessTag, [u8; 32]>;

pub struct ExecutionRoundTag {}
// Note [ExecutionRound vs Height]
pub type ExecutionRound = Id<ExecutionRoundTag, u64>;

pub enum CanonicalPartialStateTag {}
/// A cryptographic hash of the part of the canonical replicated state at some
/// height required for certification (cross-net streams, etc.).
pub type CryptoHashOfPartialState = crypto::CryptoHashOf<CanonicalPartialStateTag>;

pub enum CanonicalStateTag {}
/// A cryptographic hash of a full canonical replicated state at some height.
pub type CryptoHashOfState = crypto::CryptoHashOf<CanonicalStateTag>;

/// `AccumulatedPriority` is a part of the SchedulerState. Kept by each
/// canister, it corresponds to their entry in vector 'd' in the Scheduler
/// Analysis document.
// Note [Scheduler and AccumulatedPriority]
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccumulatedPriority(i64);

impl AccumulatedPriority {
    pub fn value(self) -> i64 {
        self.0
    }
}

// According to the Scheduler Analysis document, the initial Priority is 0.
impl Default for AccumulatedPriority {
    fn default() -> Self {
        AccumulatedPriority(0)
    }
}

impl From<i64> for AccumulatedPriority {
    fn from(value: i64) -> Self {
        AccumulatedPriority(value)
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize, Hash)]
/// Type to track how much budget the IC can spend on executing queries on
/// canisters.  See `execution_environment/rs/query_handler.rs:Charging for
/// queries` for more details.
pub struct QueryAllocation(u64);

impl QueryAllocation {
    /// Returns a 0 `QueryAllocation`.
    pub fn zero() -> QueryAllocation {
        QueryAllocation(0)
    }

    /// Returns the maximum allowed query allocation per message.
    pub fn max_per_message() -> QueryAllocation {
        QueryAllocation(MAX_QUERY_ALLOCATION / 1000)
    }

    pub fn get(&self) -> u64 {
        self.0
    }
}

impl Default for QueryAllocation {
    fn default() -> Self {
        Self(MAX_QUERY_ALLOCATION)
    }
}

impl std::ops::Add for QueryAllocation {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl std::ops::Sub for QueryAllocation {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl Into<Cycles> for QueryAllocation {
    fn into(self) -> Cycles {
        Cycles::from(self.0)
    }
}

impl From<Cycles> for QueryAllocation {
    fn from(cycles: Cycles) -> QueryAllocation {
        QueryAllocation(cycles.get())
    }
}

#[derive(Clone, Debug)]
pub struct InvalidQueryAllocationError {
    pub min: u64,
    pub max: u64,
    pub given: u64,
}

const MIN_QUERY_ALLOCATION: u64 = 0;
// TODO(EXE-63): Reduce query call prices and this number as well
const MAX_QUERY_ALLOCATION: u64 = 1_000_000_000_000_000;

impl InvalidQueryAllocationError {
    pub fn new(given: u64) -> Self {
        Self {
            min: MIN_QUERY_ALLOCATION,
            max: MAX_QUERY_ALLOCATION,
            given,
        }
    }
}

impl TryFrom<u64> for QueryAllocation {
    type Error = InvalidQueryAllocationError;

    fn try_from(given: u64) -> Result<Self, Self::Error> {
        if given > MAX_QUERY_ALLOCATION {
            return Err(InvalidQueryAllocationError::new(given));
        }
        Ok(QueryAllocation(given))
    }
}

impl fmt::Display for QueryAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// `ComputeAllocation` is a percent between 0 and 100 attached to a canister or
/// equivalently a rational number A/100. Having an `ComputeAllocation` of A/100
/// guarantees that the canister will get a full round at least A out of 100
/// execution rounds.
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Hash)]
pub struct ComputeAllocation(u64);

impl ComputeAllocation {
    /// Returns the raw percent contained in this `ComputeAllocation`.
    pub fn as_percent(self) -> u64 {
        self.0
    }
}

// According to the Internet Computer's public spec the default
// `ComputeAllocation` is 0.
impl Default for ComputeAllocation {
    fn default() -> Self {
        ComputeAllocation(0)
    }
}

#[derive(Clone, Debug)]
pub struct InvalidComputeAllocationError {
    min: u64,
    max: u64,
    given: u64,
}

const MIN_COMPUTE_ALLOCATION: u64 = 0;
const MAX_COMPUTE_ALLOCATION: u64 = 100;

impl InvalidComputeAllocationError {
    pub fn new(given: u64) -> Self {
        Self {
            min: MIN_COMPUTE_ALLOCATION,
            max: MAX_COMPUTE_ALLOCATION,
            given,
        }
    }

    pub fn min(&self) -> u64 {
        self.min
    }

    pub fn max(&self) -> u64 {
        self.max
    }

    pub fn given(&self) -> u64 {
        self.given
    }
}

impl TryFrom<u64> for ComputeAllocation {
    type Error = InvalidComputeAllocationError;

    // Constructs a `ComputeAllocation` from a percent in the range [0..100].
    //
    // # Errors
    //
    // Returns an `InvalidComputeAllocationError` if the input percent is not in
    // the expected range.
    fn try_from(percent: u64) -> Result<Self, Self::Error> {
        if percent > MAX_COMPUTE_ALLOCATION {
            return Err(InvalidComputeAllocationError::new(percent));
        }
        Ok(ComputeAllocation(percent))
    }
}

impl fmt::Display for ComputeAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}%", self.0)
    }
}

#[test]
fn display_canister_id() {
    assert_eq!(
        "2chl6-4hpzw-vqaaa-aaaaa-c",
        format!(
            "{}",
            CanisterId::new(
                PrincipalId::try_from(&[0xef, 0xcd, 0xab, 0, 0, 0, 0, 0, 1][..]).unwrap()
            )
            .unwrap()
        )
    );
}

/// `MemoryAllocation` is a number of bytes between 0 and 2^48 inclusively that
/// represents the memory allocation requested by a user during a canister
/// installation/upgrade.
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Hash)]
pub struct MemoryAllocation(NumBytes);

// According to the Internet Computer's public spec the default
// `MemoryAllocation` is 8GiB.
impl Default for MemoryAllocation {
    fn default() -> Self {
        MemoryAllocation(NumBytes::from(8 * 1024 * 1024 * 1024))
    }
}

#[derive(Clone, Debug)]
pub struct InvalidMemoryAllocationError {
    min: u64,
    max: u64,
    given: u64,
}

const MIN_MEMORY_ALLOCATION: u64 = 0;
const MAX_MEMORY_ALLOCATION: u64 = 1 << 48;

impl InvalidMemoryAllocationError {
    pub fn new(given: u64) -> Self {
        Self {
            min: MIN_MEMORY_ALLOCATION,
            max: MAX_MEMORY_ALLOCATION,
            given,
        }
    }

    pub fn min(&self) -> u64 {
        self.min
    }

    pub fn max(&self) -> u64 {
        self.max
    }

    pub fn given(&self) -> u64 {
        self.given
    }
}

impl TryFrom<u64> for MemoryAllocation {
    type Error = InvalidMemoryAllocationError;

    // Constructs a `MemoryAllocation` from a u64 in the range [0..2^48].
    //
    // # Errors
    //
    // Returns an `InvalidMemoryAllocationError` if the input u64 is not in
    // the expected range.
    fn try_from(num: u64) -> Result<Self, Self::Error> {
        if num > MAX_MEMORY_ALLOCATION {
            return Err(InvalidMemoryAllocationError::new(num));
        }
        Ok(MemoryAllocation(NumBytes::from(num)))
    }
}

impl Into<NumBytes> for MemoryAllocation {
    fn into(self) -> NumBytes {
        self.0
    }
}

impl fmt::Display for MemoryAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}B", self.0)
    }
}

// Note [Unit].
pub const CYCLES_UNIT: &str = "00";
pub const ICP_UNIT: &str = "01";

/// Indicates the unit of different tokens on the canister. Only Cycles and ICP
/// tokens are supported currently.
///
/// Note that this struct does not implement `(De)Serialize`. If you need to
/// perform any (de)serialization consider converting to a `ic00::Unit` instead.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Unit {
    Cycles,
    ICP,
}

impl TryFrom<&[u8]> for Unit {
    type Error = ();

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let encoded = hex::encode(input);
        match encoded.as_str() {
            CYCLES_UNIT => Ok(Unit::Cycles),
            ICP_UNIT => Ok(Unit::ICP),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct InstallCodeContext {
    pub sender: PrincipalId,
    pub mode: CanisterInstallMode,
    pub canister_id: CanisterId,
    pub wasm_module: Vec<u8>,
    pub arg: Vec<u8>,
    pub compute_allocation: ComputeAllocation,
    pub memory_allocation: MemoryAllocation,
    pub query_allocation: QueryAllocation,
}

#[derive(Debug)]
pub enum InstallCodeContextError {
    ComputeAllocation(InvalidComputeAllocationError),
    MemoryAllocation(InvalidMemoryAllocationError),
    QueryAllocation(InvalidQueryAllocationError),
    InvalidCanisterId(String),
}

impl From<InstallCodeContextError> for UserError {
    fn from(err: InstallCodeContextError) -> Self {
        match err {
            InstallCodeContextError::ComputeAllocation(err) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "ComputeAllocation expected to be in the range [{}..{}], got {}",
                    err.min(),
                    err.max(),
                    err.given()
                ),
            ),
            InstallCodeContextError::QueryAllocation(err) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "QueryAllocation expected to be in the range [{}..{}], got {}",
                    err.min, err.max, err.given
                ),
            ),
            InstallCodeContextError::MemoryAllocation(err) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "MemoryAllocation expected to be in the range [{}..{}], got {}",
                    err.min(),
                    err.max(),
                    err.given()
                ),
            ),
            InstallCodeContextError::InvalidCanisterId(bytes) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Specified canister id is not a valid principal id {}",
                    hex::encode(&bytes[..])
                ),
            ),
        }
    }
}

impl From<InvalidComputeAllocationError> for InstallCodeContextError {
    fn from(err: InvalidComputeAllocationError) -> Self {
        Self::ComputeAllocation(err)
    }
}

impl From<InvalidQueryAllocationError> for InstallCodeContextError {
    fn from(err: InvalidQueryAllocationError) -> Self {
        Self::QueryAllocation(err)
    }
}

impl From<InvalidMemoryAllocationError> for InstallCodeContextError {
    fn from(err: InvalidMemoryAllocationError) -> Self {
        Self::MemoryAllocation(err)
    }
}

impl TryFrom<(PrincipalId, InstallCodeArgs)> for InstallCodeContext {
    type Error = InstallCodeContextError;

    fn try_from(input: (PrincipalId, InstallCodeArgs)) -> Result<Self, Self::Error> {
        let (sender, args) = input;
        let canister_id = CanisterId::new(args.canister_id).map_err(|err| {
            InstallCodeContextError::InvalidCanisterId(format!(
                "Converting canister id {} failed with {}",
                args.canister_id, err
            ))
        })?;
        let compute_allocation = match args.compute_allocation {
            Some(ca) => ComputeAllocation::try_from(ca.0.to_u64().unwrap())?,
            None => ComputeAllocation::default(),
        };
        let memory_allocation = match args.memory_allocation {
            Some(ma) => MemoryAllocation::try_from(ma.0.to_u64().unwrap())?,
            None => MemoryAllocation::default(),
        };
        let query_allocation = match args.query_allocation {
            Some(qa) => QueryAllocation::try_from(qa.0.to_u64().unwrap())?,
            None => QueryAllocation::default(),
        };

        Ok(InstallCodeContext {
            sender,
            mode: args.mode,
            canister_id,
            wasm_module: args.wasm_module,
            arg: args.arg,
            compute_allocation,
            memory_allocation,
            query_allocation,
        })
    }
}

/// Allow an object to report its own byte size. It is only meant to be an
/// estimate, and not an exact measure of its heap usage or length of serialized
/// bytes.
pub trait CountBytes {
    fn count_bytes(&self) -> usize;
}

impl CountBytes for Time {
    fn count_bytes(&self) -> usize {
        8
    }
}
