//! The execution environment public interface.
mod errors;

use crate::state_manager::StateManagerError;
pub use errors::{CanisterHeartbeatError, MessageAcceptanceError};
pub use errors::{HypervisorError, TrapCode};
use ic_base_types::NumBytes;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_types::{
    ingress::{IngressStatus, WasmResult},
    messages::{MessageId, SignedIngressContent, UserQuery},
    user_error::UserError,
    ExecutionRound, Height, NumInstructions, Randomness, Time,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

/// Instance execution statistics. The stats are cumulative and
/// contain measurements from the point in time when the instance was
/// created up until the moment they are requested.
#[derive(Serialize, Deserialize, Clone)]
pub struct InstanceStats {
    /// Total number of (host) pages accessed (read or written) by the instance
    /// and loaded into the linear memory.
    pub accessed_pages: usize,

    /// Total number of (host) pages modified by the instance.
    /// By definition a page that has been dirtied has also been accessed,
    /// hence this dirtied_pages <= accessed_pages
    pub dirty_pages: usize,
}

/// Errors that can be returned when fetching the available memory on a subnet.
pub enum SubnetAvailableMemoryError {
    InsufficientMemory {
        requested: NumBytes,
        available: NumBytes,
    },
}

/// This struct is used to manage the view of the current amount of memory
/// available on the subnet between multiple canisters executing in parallel.
///
/// The problem is that when canisters with no memory reservations want to
/// expand their memory consumption, we need to ensure that they do not go over
/// subnet's capacity. As we execute canisters in parallel, we need to
/// provide them with a way to view the latest state of memory availble in a
/// thread safe way. Hence, we use `Arc<RwLock<>>` here.
#[derive(Serialize, Deserialize, Clone)]
pub struct SubnetAvailableMemory(Arc<RwLock<NumBytes>>);

impl SubnetAvailableMemory {
    pub fn new(amount: NumBytes) -> Self {
        Self(Arc::new(RwLock::new(amount)))
    }

    /// Try to use some memory capacity and fail if not enough is available
    pub fn try_decrement(&self, requested: NumBytes) -> Result<(), SubnetAvailableMemoryError> {
        let mut available = self.0.write().unwrap();
        if requested <= *available {
            *available -= requested;
            Ok(())
        } else {
            Err(SubnetAvailableMemoryError::InsufficientMemory {
                requested,
                available: *available,
            })
        }
    }

    pub fn increment(&self, amount: NumBytes) {
        let mut available = self.0.write().unwrap();
        *available += amount;
    }

    pub fn get(self) -> NumBytes {
        *self.0.read().unwrap()
    }
}

/// The data structure returned by
/// `ExecutionEnvironment.execute_canister_message()`.
pub struct ExecuteMessageResult<CanisterState> {
    /// The `CanisterState` after message execution
    pub canister: CanisterState,
    /// The amount of instructions left after message execution. This must be <=
    /// to the instructions_limit that `execute_canister_message()` was called
    /// with.
    pub num_instructions_left: NumInstructions,
    /// Optional status for an Ingress message if available.
    pub ingress_status: Option<(MessageId, IngressStatus)>,
    /// The size of the heap delta the canister produced
    pub heap_delta: NumBytes,
}

pub type HypervisorResult<T> = Result<T, HypervisorError>;

/// Interface for the component to execute queries on canisters.  It can be used
/// by the HttpHandler and other system components to execute queries.
pub trait QueryHandler: Send + Sync {
    /// Type of state managed by StateReader.
    ///
    /// Should typically be `ic_replicated_state::ReplicatedState`.
    // Note [Associated Types in Interfaces]
    type State;

    /// Handle a query of type `UserQuery` which was sent by an end user.
    fn query(
        &self,
        q: UserQuery,
        processing_state: Arc<Self::State>,
        data_certificate: Vec<u8>,
    ) -> Result<WasmResult, UserError>;
}

/// Interface for the component to filter out ingress messages that
/// the canister is not willing to accept.
pub trait IngressMessageFilter: Send + Sync {
    /// Type of state managed by StateReader.
    ///
    /// Should typically be `ic_replicated_state::ReplicatedState`.
    // Note [Associated Types in Interfaces]
    type State;

    /// Asks the canister if it is willing to accept the provided ingress
    /// message.
    fn should_accept_ingress_message(
        &self,
        state: Arc<Self::State>,
        provisional_whitelist: &ProvisionalWhitelist,
        ingress: &SignedIngressContent,
    ) -> Result<(), MessageAcceptanceError>;
}

/// Errors that can be returned when reading/writing from/to ingress history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressHistoryError {
    StateRemoved(Height),
    StateNotAvailableYet(Height),
}

impl From<StateManagerError> for IngressHistoryError {
    fn from(source: StateManagerError) -> Self {
        match source {
            StateManagerError::StateRemoved(height) => Self::StateRemoved(height),
            StateManagerError::StateNotCommittedYet(height) => Self::StateNotAvailableYet(height),
        }
    }
}

/// Interface for reading the history of ingress messages.
pub trait IngressHistoryReader: Send + Sync {
    /// Returns a function that can be used to query the status for a given
    /// `message_id` using the latest execution state.
    fn get_latest_status(&self) -> Box<dyn Fn(&MessageId) -> IngressStatus>;

    /// Return a function that can be used to query the status for a given
    /// `message_id` using the state at given `height`.
    ///
    /// Return an error if the the state is not available.
    fn get_status_at_height(
        &self,
        height: Height,
    ) -> Result<Box<dyn Fn(&MessageId) -> IngressStatus>, IngressHistoryError>;
}

/// Interface for updating the history of ingress messages.
pub trait IngressHistoryWriter: Send + Sync {
    /// Type of state this Writer can update.
    ///
    /// Should typically be `ic_replicated_state::ReplicatedState`.
    // Note [Associated Types in Interfaces]
    type State;

    /// Allows to set status on a message.
    ///
    /// The allowed status transitions are:
    /// * "None" -> {"Received", "Processing", "Completed", "Failed"}
    /// * "Received" -> {"Processing", "Completed", "Failed"}
    /// * "Processing" -> {"Processing", "Completed", "Failed"}
    fn set_status(&self, state: &mut Self::State, message_id: MessageId, status: IngressStatus);
}

/// A trait for providing all necessary imports to a Wasm module.
pub trait SystemApi {
    /// Stores the execution error, so that the user can evaluate it later.
    fn set_execution_error(&mut self, error: HypervisorError);

    /// Returns the reference to the execution error.
    fn get_execution_error(&self) -> Option<&HypervisorError>;

    /// Returns the stable memory delta that the canister produced
    fn get_stable_memory_delta_pages(&self) -> usize;

    /// Returns the amount of instructions needed to copy `num_bytes`.
    fn get_num_instructions_from_bytes(&self, num_bytes: NumBytes) -> NumInstructions;

    /// Copies `size` bytes starting from `offset` inside the opaque caller blob
    /// and copies them to heap[dst..dst+size]. The caller is the canister
    /// id in case of requests or the user id in case of an ingress message.
    fn ic0_msg_caller_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Returns the size of the opaque caller blob.
    fn ic0_msg_caller_size(&self) -> HypervisorResult<u32>;

    /// Returns the size of msg.payload.
    fn ic0_msg_arg_data_size(&self) -> HypervisorResult<u32>;

    /// Copies `length` bytes from msg.payload[offset..offset+size] to
    /// memory[dst..dst+size].
    fn ic0_msg_arg_data_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Used to look up the size of the method_name that the message wants to
    /// call. Can only be called in the context of inspecting messages.
    fn ic0_msg_method_name_size(&self) -> HypervisorResult<u32>;

    /// Used to copy the method_name that the message wants to call to heap. Can
    /// only be called in the context of inspecting messages.
    fn ic0_msg_method_name_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    // If the canister calls this method, then the message will be accepted
    // otherwise rejected. Can only be called in the context of accepting
    // messages.
    fn ic0_accept_message(&mut self) -> HypervisorResult<()>;

    /// Copies the data referred to by src/size out of the canister and appends
    /// it to the (initially empty) data reply.
    fn ic0_msg_reply_data_append(
        &mut self,
        src: u32,
        size: u32,
        heap: &[u8],
    ) -> HypervisorResult<()>;

    /// Replies to the sender with the data assembled using
    /// `msg_reply_data_append`.
    fn ic0_msg_reply(&mut self) -> HypervisorResult<()>;

    /// Returns the reject code, if the current function is invoked as a
    /// reject callback.
    ///
    /// It returns the special “no error” code 0 if the callback is not invoked
    /// as a reject callback
    fn ic0_msg_reject_code(&self) -> HypervisorResult<i32>;

    /// Replies to sender with an error message
    fn ic0_msg_reject(&mut self, src: u32, size: u32, heap: &[u8]) -> HypervisorResult<()>;

    /// Returns the length of the reject message in bytes.
    ///
    /// # Panics
    ///
    /// This traps if not invoked from a reject callback.
    fn ic0_msg_reject_msg_size(&self) -> HypervisorResult<u32>;

    /// Copies length bytes from self.reject_msg[offset..offset+size] to
    /// memory[dst..dst+size]
    ///
    /// # Panics
    ///
    /// This traps if offset+size is greater than the size of the reject
    /// message, or if dst+size exceeds the size of the Wasm memory, or if not
    /// called from inside a reject callback.
    fn ic0_msg_reject_msg_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Returns the size of the blob corresponding to the id of the canister.
    fn ic0_canister_self_size(&self) -> HypervisorResult<usize>;

    /// Copies `size` bytes starting from `offset` in the id blob of the
    /// canister to heap[dst..dst+size].
    fn ic0_canister_self_copy(
        &mut self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Returns the size of the blob corresponding to the id of the controller.
    fn ic0_controller_size(&self) -> HypervisorResult<usize>;

    /// Copies `size` bytes starting from `offset` in the id blob of the
    /// controller to heap[dst..dst+size].
    fn ic0_controller_copy(
        &mut self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Outputs the specified bytes on the heap as a string on STDOUT.
    fn ic0_debug_print(&self, src: u32, size: u32, heap: &[u8]);

    /// Traps, with a possibly helpful message
    fn ic0_trap(&self, src: u32, size: u32, heap: &[u8]) -> HypervisorError;

    /// Creates a pending inter-canister message that will be scheduled if the
    /// current message execution completes successfully.
    #[allow(clippy::too_many_arguments)]
    fn ic0_call_simple(
        &mut self,
        callee_src: u32,
        callee_size: u32,
        method_name_src: u32,
        method_name_len: u32,
        reply_fun: u32,
        reply_env: u32,
        reject_fun: u32,
        reject_env: u32,
        data_src: u32,
        data_len: u32,
        heap: &[u8],
    ) -> HypervisorResult<i32>;

    /// Begins assembling a call to the canister specified by
    /// callee_src/callee_size at method name_src/name_size. Two mandatory
    /// callbacks are recorded which will be invoked on success and error
    /// respectively.
    ///
    /// Subsequent calls to other `call_*` apis set further attributes of this
    /// call until the call is concluded (with `ic0.call_perform) or discarded
    /// (by returning without calling `ic0.call_perform` or by starting a new
    /// call with `ic0.call_new`).
    #[allow(clippy::too_many_arguments)]
    fn ic0_call_new(
        &mut self,
        callee_src: u32,
        callee_size: u32,
        name_src: u32,
        name_len: u32,
        reply_fun: u32,
        reply_env: u32,
        reject_fun: u32,
        reject_env: u32,
        heap: &[u8],
    ) -> HypervisorResult<()>;

    /// Appends the specified bytes to the argument of the call. Initially, the
    /// argument is empty. This can be called multiple times between
    /// `ic0.call_new` and `ic0.call_perform`.
    fn ic0_call_data_append(&mut self, src: u32, size: u32, heap: &[u8]) -> HypervisorResult<()>;

    /// Specifies the closure to be called if the reply/reject closures trap.
    /// Can be called at most once between `ic0.call_new` and
    /// `ic0.call_perform`.
    ///
    /// See https://sdk.dfinity.org/docs/interface-spec/index.html#system-api-call
    fn ic0_call_on_cleanup(&mut self, fun: u32, env: u32) -> HypervisorResult<()>;

    /// Adds cycles to a call by moving them from the canister's balance onto
    /// the call under construction. The cycles are deducted immediately
    /// from the canister's balance and moved back if the call cannot be
    /// performed (e.g. if `ic0.call_perform` signals an error or if the
    /// canister invokes `ic0.call_new` or returns without invoking
    /// `ic0.call_perform`).
    ///
    /// This traps if trying to transfer more cycles than are in the current
    /// balance of the canister.
    fn ic0_call_cycles_add(&mut self, amount: u64) -> HypervisorResult<()>;

    /// This call concludes assembling the call. It queues the call message to
    /// the given destination, but does not actually act on it until the current
    /// WebAssembly function returns without trapping.
    ///
    /// If the system returns 0, then the system was able to enqueue the call,
    /// if a non-zero value is returned then the call could not be enqueued.
    ///
    /// After `ic0.call_perform` and before the next `ic0.call_new`, all other
    /// `ic0.call_*` calls trap.
    fn ic0_call_perform(&mut self) -> HypervisorResult<i32>;

    /// Returns the current size of the stable memory in WebAssembly pages.
    fn ic0_stable_size(&self) -> HypervisorResult<u32>;

    /// Tries to grow the stable memory by additional_pages many pages
    /// containing zeros.
    /// If successful, returns the previous size of the memory (in pages).
    /// Otherwise, returns -1
    fn ic0_stable_grow(&mut self, additional_pages: u32) -> HypervisorResult<i32>;

    /// Copies the data referred to by offset/size out of the stable memory and
    /// replaces the corresponding bytes starting at dst in the canister memory.
    ///
    /// This system call traps if dst+size exceeds the size of the WebAssembly
    /// memory or offset+size exceeds the size of the stable memory.
    fn ic0_stable_read(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Copies the data referred to by src/size out of the canister and replaces
    /// the corresponding segment starting at offset in the stable memory.
    ///
    /// This system call traps if src+size exceeds the size of the WebAssembly
    /// memory or offset+size exceeds the size of the stable memory.
    fn ic0_stable_write(
        &mut self,
        offset: u32,
        src: u32,
        size: u32,
        heap: &[u8],
    ) -> HypervisorResult<()>;

    /// Returns the current size of the stable memory in WebAssembly pages.
    ///
    /// It supports bigger stable memory sizes indexed by 64 bit pointers.
    ///
    /// Note: This API is not fully implemented yet.
    fn ic0_stable_size64(&self) -> HypervisorResult<u64>;

    /// Tries to grow the stable memory by additional_pages many pages
    /// containing zeros.
    /// If successful, returns the previous size of the memory (in pages).
    /// Otherwise, returns -1
    ///
    /// It supports bigger stable memory sizes indexed by 64 bit pointers.
    ///
    /// Note: This API is not fully implemented yet.
    fn ic0_stable_grow64(&mut self, additional_pages: u64) -> HypervisorResult<i64>;

    /// Copies the data from location [offset, offset+size) of the stable memory
    /// to the location [dst, dst+size) in the canister memory.
    ///
    /// This system call traps if dst+size exceeds the size of the WebAssembly
    /// memory or offset+size exceeds the size of the stable memory.
    ///
    /// It supports bigger stable memory sizes indexed by 64 bit pointers.
    ///
    /// Note: This API is not fully implemented yet.
    fn ic0_stable_read64(
        &self,
        dst: u64,
        offset: u64,
        size: u64,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Copies the data from location [src, src+size) of the canister memory to
    /// location [offset, offset+size) in the stable memory.
    ///
    /// This system call traps if src+size exceeds the size of the WebAssembly
    /// memory or offset+size exceeds the size of the stable memory.
    ///
    /// It supports bigger stable memory sizes indexed by 64 bit pointers.
    ///
    /// Note: This API is not fully implemented yet.
    fn ic0_stable_write64(
        &mut self,
        offset: u64,
        src: u64,
        size: u64,
        heap: &[u8],
    ) -> HypervisorResult<()>;

    fn ic0_time(&self) -> HypervisorResult<Time>;

    /// This system call is not part of the public spec and used by the
    /// hypervisor, when execution runs out of instructions.
    fn out_of_instructions(&self) -> HypervisorError;

    /// This system call is not part of the public spec. It's called after a
    /// native `memory.grow` has been called to check whether there's enough
    /// available memory left.
    fn update_available_memory(
        &mut self,
        native_memory_grow_res: i32,
        additional_pages: u32,
    ) -> HypervisorResult<i32>;

    /// Returns the current balance in cycles.
    fn ic0_canister_cycle_balance(&self) -> HypervisorResult<u64>;

    /// Cycles sent in the current call and still available.
    fn ic0_msg_cycles_available(&self) -> HypervisorResult<u64>;

    /// Cycles that came back with the response, as a refund.
    fn ic0_msg_cycles_refunded(&self) -> HypervisorResult<u64>;

    /// This moves cycles from the call to the canister balance.
    /// It can be called multiple times, each time adding more cycles to the
    /// balance.
    ///
    /// It moves no more cycles than `max_amount`.
    ///
    /// It moves no more cycles than available according to
    /// `ic0.msg_cycles_available`, and
    ///
    /// The canister balance afterwards does not exceed
    /// maximum amount of cycles it can hold (public spec refers to this
    /// constant as MAX_CANISTER_BALANCE) minus any possible outstanding
    /// balances. However, canisters on system subnets have no balance
    /// limit.
    ///
    /// EXE-117: the last point is not properly handled yet.  In particular, a
    /// refund can come back to the canister after this call finishes which
    /// causes the canister's balance to overflow.
    fn ic0_msg_cycles_accept(&mut self, max_amount: u64) -> HypervisorResult<u64>;

    /// Sets the certified data for the canister.
    /// See: https://sdk.dfinity.org/docs/interface-spec/index.html#system-api-certified-data
    fn ic0_certified_data_set(&mut self, src: u32, size: u32, heap: &[u8]) -> HypervisorResult<()>;

    /// If run in non-replicated execution (i.e. query),
    /// returns 1 if the data certificate is present, 0 otherwise.
    /// If run in replicated execution (i.e. an update call or a certified
    /// query), returns 0.
    fn ic0_data_certificate_present(&self) -> HypervisorResult<i32>;

    /// Returns the size of the data certificate if it is present
    /// (i.e. data_certificate_present returns 1).
    /// Traps if data_certificate_present returns 0.
    fn ic0_data_certificate_size(&self) -> HypervisorResult<i32>;

    /// Copies the data certificate into the heap if it is present
    /// (i.e. data_certificate_present returns 1).
    /// Traps if data_certificate_present returns 0.
    fn ic0_data_certificate_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Returns the current status of the canister.  `1` indicates
    /// running, `2` indicates stopping, and `3` indicates stopped.
    fn ic0_canister_status(&self) -> HypervisorResult<u32>;

    /// Mints the `amount` cycles
    /// Adds cycles to the canister's balance.
    ///
    /// Adds no more cycles than `amount`.
    ///
    /// The canister balance afterwards does not exceed
    /// maximum amount of cycles it can hold.
    /// However, canisters on system subnets have no balance limit.
    ///
    /// Returns the amount of cycles added to the canister's balance.
    fn ic0_mint_cycles(&mut self, amount: u64) -> HypervisorResult<u64>;
}

pub trait Scheduler: Send {
    /// Type modelling the replicated state.
    ///
    /// Should typically be
    /// `ic_replicated_state::ReplicatedState`.
    // Note [Associated Types in Interfaces]
    type State;

    /// Executes a list of messages. Triggered by the Coordinator as part of
    /// processing a batch.
    ///
    /// # Configuration parameters that might affect a round's execution
    ///
    /// * `scheduler_cores`: number of concurrent threads that the scheduler can
    ///   use during an execution round.
    /// * `max_instructions_per_round`: max number of instructions a single
    ///   round on a single thread can
    /// consume.
    /// * `max_instructions_per_message`: max number of instructions a single
    ///   message execution can consume.
    ///
    /// # Walkthrough of a round
    ///
    /// The scheduler decides on a deterministic and fair order of canisters to
    /// execute on each thread (not fully implemented yet).
    /// For each thread we want to schedule **at least** a `pulse` for the first
    /// canister. The canister's `pulse` can consume the entire round of the
    /// thread if it has enough messages or, if not, we can give a `pulse` to
    /// the next canister. Similarly, the second canister can use the rest
    /// of the round of the thread if it has enough messages or we can give
    /// a `pulse` to the next canister and so on.
    ///
    /// # Constraints
    ///
    /// * To be able to start a pulse for a canister we need to have at least
    ///   `max_instructions_per_message` left in the current round (basically we
    ///   need a guarantee that we are able to execute successfully at least one
    ///   message).
    /// * The round (and thus the first `pulse`) starts with a limit of
    ///   `max_instructions_per_round`. When the `pulse` ends it returns how
    ///   many instructions is left which is used to update the limit for the
    ///   next `pulse` and if the above constraint is satisfied, we can start
    ///   the `pulse`. And so on.
    fn execute_round(
        &self,
        state: Self::State,
        randomness: Randomness,
        time_of_previous_batch: Time,
        current_round: ExecutionRound,
        provisional_whitelist: ProvisionalWhitelist,
    ) -> Self::State;
}
