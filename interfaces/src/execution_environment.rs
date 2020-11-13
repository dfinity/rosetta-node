use crate::messages::CanisterInputMessage;
use ic_registry_routing_table::RoutingTable;
use ic_types::{
    ingress::{IngressStatus, WasmResult},
    messages::{MessageId, QueryRequest, UserQuery},
    methods::WasmMethod,
    user_error::UserError,
    CanisterId, Cycles, Height, Time,
};
use rand::RngCore;
use std::sync::Arc;

// Note [Unit]
// ~~~~~~~~~~
// Units for funds are represented as blobs. 0x00 is used for cycles and 0x01
// for ICP tokens. Other units can be added in the future.

#[derive(Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Debug)]
pub enum WasmValidationError {
    UnexpectedEof,
    InvalidMagic,
    UnsupportedVersion(u32),
    InconsistentLength { expected: usize, actual: usize },
    UnknownValueType(i8),
    UnknownTableElementType(i8),
    NonUtf8String,
    UnknownOpcode(u8),
    InvalidVarInt { signed: bool, size_bits: u8 },
    InconsistentMetadata,
    InvalidSectionId(u8),
    SectionsOutOfOrder,
    DuplicatedSections(u8),
    InvalidMemoryReference(u8),
    InvalidTableReference(u8),
    InvalidLimitsFlags(u8),
    UnknownFunctionForm(u8),
    InconsistentCode,
    InvalidSegmentFlags(u32),
    TooManyLocals,
    DuplicatedNameSubsections(u8),
    UnknownNameSubsectionType(u8),
    Other,
}

impl std::fmt::Display for WasmValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of input"),
            Self::InvalidMagic => write!(f, "invalid magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version {}", v),
            Self::InconsistentLength { expected, actual } => write!(
                f,
                "inconsistent length (expected {}, actual {})",
                expected, actual
            ),
            Self::UnknownValueType(t) => {
                write!(f, "invalid/unknown value type declaration {:#x}", t)
            }
            Self::UnknownTableElementType(t) => {
                write!(f, "invalid/unknown table element type declaration {:#x}", t)
            }
            Self::NonUtf8String => write!(f, "non-utf8 string"),
            Self::UnknownOpcode(c) => write!(f, "unknown opcode {:#x}", c),
            Self::InvalidVarInt { signed, size_bits } => write!(
                f,
                "invalid {}{}",
                if *signed { "varint" } else { "varuint" },
                size_bits
            ),
            Self::InconsistentMetadata => write!(f, "inconsistent metadata"),
            Self::InvalidSectionId(id) => write!(f, "invalid section with id {}", id),
            Self::SectionsOutOfOrder => write!(f, "sections are out of order"),
            Self::DuplicatedSections(s) => write!(f, "duplicated sections with id {}", s),
            Self::InvalidMemoryReference(r) => write!(f, "invalid memory reference {}", r),
            Self::InvalidTableReference(r) => write!(f, "invalid table reference {}", r),
            Self::InvalidLimitsFlags(flags) => {
                write!(f, "invalid value {} used for flags in limits type", flags)
            }
            Self::UnknownFunctionForm(form) => {
                write!(f, "unknown function form {:#x} (should be 0x60)", form)
            }
            Self::InconsistentCode => write!(
                f,
                "number of function body entries and signatures does not match"
            ),
            Self::InvalidSegmentFlags(flags) => write!(
                f,
                "invalid segment flags {}, only flags 0, 1, and 2 are accepted on segments",
                flags
            ),
            Self::TooManyLocals => write!(f, "sum of counts of locals is greater than 2^32"),
            Self::DuplicatedNameSubsections(i) => write!(f, "duplicated name subsections {}", i),
            Self::UnknownNameSubsectionType(t) => {
                write!(f, "unknown name subsection type {:#x}", t)
            }
            Self::Other => write!(f, "unknown"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Debug)]
pub enum TrapCode {
    StackOverflow,
    HeapOutOfBounds,
    StableMemoryOutOfBounds,
    IntegerDivByZero,
    Unreachable,
    TableOutOfBounds,
    Other,
}

impl std::fmt::Display for TrapCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StackOverflow => write!(f, "stack overflow"),
            Self::HeapOutOfBounds => write!(f, "heap out of bounds"),
            Self::StableMemoryOutOfBounds => write!(f, "stable memory out of bounds"),
            Self::IntegerDivByZero => write!(f, "integer division by 0"),
            Self::Unreachable => write!(f, "unreachable"),
            Self::TableOutOfBounds => write!(f, "table out of bounds"),
            Self::Other => write!(f, "unknown"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HypervisorError {
    /// The message sent to the canister refers a function not found in the
    /// table. The payload contains the index of the table and the index of the
    /// function.
    FunctionNotFound(u32, u32),
    /// The message sent to the canister refers to a method that is not
    /// exposed by this canister.
    MethodNotFound(WasmMethod),
    /// System API contract was violated. They payload contains a
    /// detailed explanation of the issue suitable for displaying it
    /// to a user of IC.
    ContractViolation(String),
    /// Wasm execution consumed too much cycles. The payload specifies
    /// the amount of cycles consumed by the execution.
    OutOfCycles(Cycles),
    /// User supplied invalid Wasm file.
    InvalidWasm(WasmValidationError),
    /// Canister Wasm trapped (e.g. by executing the `unreachable`
    /// instruction or dividing by zero).
    Trapped(TrapCode),
    /// Canister explicitly called `ic.trap`.
    CalledTrap(String),
    /// An attempt was made to execute a message on a canister that does not
    /// contain a Wasm module.
    WasmModuleNotFound,
    /// An attempt was made to grow the canister's memory above its memory
    /// allocation.
    OutOfMemory,
    /// An attempt to perform an operation that isn't allowed when the canister
    /// is stopped.
    CanisterStopped,
    /// Canister performed an 'exec' system call.
    /// Strictly speaking this is not an error. However, it immediately aborts
    /// the execution in the same manner an error would. And it must be handled
    /// by the Hypervisor. The payload is WASM bytecode.
    /// Thus, it can be thought of as 'recoverable error'.
    CanisterExec(Vec<u8>, Vec<u8>),
    /// An attempt was made to use more cycles than was available in a call
    /// context.
    InsufficientCycles {
        available: Cycles,
        requested: Cycles,
    },
    /// An attempt was made to use more ICP than was available in a call
    /// context.
    InsufficientICP { available: u64, requested: u64 },
    /// The principal ID specified by the canister is invalid.
    InvalidPrincipalId(Vec<u8>),
}

/// ExecutionEnvironment is the component responsible for executing messages
/// on the IC.
pub trait ExecutionEnvironment: Sync + Send {
    /// Type modelling the replicated state.
    ///
    /// Should typically be
    /// `ic_replicated_state::ReplicatedState`.
    // Note [Associated Types in Interfaces]
    type State;

    /// Type modelling the canister state.
    ///
    /// Should typically be
    /// `ic_replicated_state::CanisterState`.
    // Note [Associated Types in Interfaces]
    type CanisterState;

    /// Executes a message sent to a subnet.
    //
    // A deterministic cryptographically secure pseudo-random number generator
    // is created per round and per thread and passed to this method to be used
    // while responding to randomness requests (i.e. raw_rand). Using the type
    // "&mut RngCore" imposes a problem with our usage of "mockall" library in
    // the test_utilities. Mockall's doc states: "The only restrictions on
    // mocking generic methods are that all generic parameters must be 'static,
    // and generic lifetime parameters are not allowed." Hence, the type of the
    // parameter is "&mut (dyn RngCore + 'static)".
    fn execute_subnet_message(
        &self,
        msg: CanisterInputMessage,
        state: Self::State,
        cycles_limit: Cycles,
        rng: &mut (dyn RngCore + 'static),
    ) -> Self::State;

    /// Executes a message sent to a canister.
    fn execute_canister_message(
        &self,
        canister_state: Self::CanisterState,
        cycles_limit: Cycles,
        msg: CanisterInputMessage,
        time: Time,
        routing_table: Arc<RoutingTable>,
    ) -> ExecResult<ExecuteMessageResult<Self::CanisterState>>;
}

/// The data structure returned by
/// `ExecutionEnvironment.execute_canister_message()`.
pub struct ExecuteMessageResult<CanisterState> {
    /// The `CanisterState` after message execution
    pub canister: CanisterState,
    /// The amount of cycles left after message execution.  This must be <= to
    /// the cycles_limit that `execute_canister_message()` was called with.
    pub cycles_left: Cycles,
    /// Optional status for an Ingress message if available.
    pub ingress_status: Option<(MessageId, IngressStatus)>,
}

/// An underlying struct/helper for implementing select() on multiple
/// AsyncResult<T>'s. If an AsyncResult is really an ongoing computation, we
/// have to obtain its result from a channel. However, some AsyncResults are of
/// type EarlyResult, which only emulates being async, but in reality is a ready
/// value (mostly used for early errors). In such case, there is no channel
/// present and we can simply return the value without waiting.
pub enum TrySelect<T> {
    EarlyResult(T),
    // These Box<Any>'s are here only to hide internal data types from the interfaces crate.
    // These are known types (crossbeam channnel, WasmExecutionOutput),
    // and if we restructure our dependency tree we may put the real types here.
    Channel(
        Box<dyn std::any::Any + 'static>,
        Box<dyn FnOnce(Box<dyn std::any::Any + 'static>) -> T>,
    ),
}

/// An execution can finish successfully or get interrupted (out of cycles).
pub enum ExecResultVariant<T> {
    Completed(T),
    Interrupted(Box<dyn InterruptedExec<T>>),
}

// Most likely these traits can be moved to embedders crate if we restructure
// ExecutionEnvironment a little.

/// An async result which allows for sync wait and select.
pub trait AsyncResult<T> {
    fn get(self: Box<Self>) -> ExecResultVariant<T>;
    fn try_select(self: Box<Self>) -> TrySelect<T>;
}

/// Interrupted execution. Can be resumed or canceled.
pub trait InterruptedExec<T> {
    fn resume(self: Box<Self>, cycles_topup: Cycles) -> ExecResult<T>;
    fn cancel(self: Box<Self>) -> ExecResult<T>;
}

impl<A: 'static> dyn InterruptedExec<A> {
    /// Add post-processing on the output received after resume/cancel.
    pub fn and_then<B: 'static, F: 'static + FnOnce(A) -> B>(
        self: Box<Self>,
        f: F,
    ) -> Box<dyn InterruptedExec<B>> {
        Box::new(ResumeTokenWrapper {
            resume_token: self,
            f,
        })
    }
}

// A wrapper which allows for post processing of the ExecResult returned by
// original resume/cancel.
struct ResumeTokenWrapper<A, B, F: FnOnce(A) -> B> {
    resume_token: Box<dyn InterruptedExec<A>>,
    f: F,
}

impl<A, B, F> InterruptedExec<B> for ResumeTokenWrapper<A, B, F>
where
    A: 'static,
    B: 'static,
    F: 'static + FnOnce(A) -> B,
{
    fn resume(self: Box<Self>, cycles_topup: Cycles) -> ExecResult<B> {
        self.resume_token.resume(cycles_topup).and_then(self.f)
    }

    fn cancel(self: Box<Self>) -> ExecResult<B> {
        self.resume_token.cancel().and_then(self.f)
    }
}

// Generic async result of an execution.
pub struct ExecResult<T> {
    result: Box<dyn AsyncResult<T>>,
}

impl<T> ExecResult<T> {
    pub fn new(result: Box<dyn AsyncResult<T>>) -> Self {
        Self { result }
    }

    /// Wait for the result
    pub fn get(self) -> ExecResultVariant<T> {
        self.result.get()
    }

    /// Wait for the final result without allowing for a pause.
    /// If pause occurs, the execution is automatically cancelled.
    pub fn get_no_pause(self) -> T {
        match self.result.get() {
            ExecResultVariant::Completed(x) => x,
            ExecResultVariant::Interrupted(resume_token) => {
                if let ExecResultVariant::Completed(x) = resume_token.cancel().get() {
                    x
                } else {
                    panic!("Unexpected response from execution cancel request");
                }
            }
        }
    }

    /// This function allows to extract an underlying channel to perform a
    /// select. It is used to implement 'ic_embedders::ExecSelect' and is
    /// not meant to be used explicitly.
    pub fn try_select(self) -> TrySelect<T> {
        self.result.try_select()
    }
}

impl<A: 'static> ExecResult<A> {
    /// Add post-processing on the result.
    pub fn and_then<B: 'static, F: 'static + FnOnce(A) -> B>(self, f: F) -> ExecResult<B> {
        ExecResult::new(Box::new(ExecResultWrapper { result: self, f }))
    }
}

// A wrapper which allows for post processing of the original ExecResult.
struct ExecResultWrapper<A, B, F: FnOnce(A) -> B> {
    result: ExecResult<A>,
    f: F,
}

impl<A, B, F> AsyncResult<B> for ExecResultWrapper<A, B, F>
where
    A: 'static,
    B: 'static,
    F: 'static + FnOnce(A) -> B,
{
    fn get(self: Box<Self>) -> ExecResultVariant<B> {
        match self.result.get() {
            ExecResultVariant::Completed(x) => ExecResultVariant::Completed((self.f)(x)),
            ExecResultVariant::Interrupted(resume_token) => {
                ExecResultVariant::Interrupted(resume_token.and_then(self.f))
            }
        }
    }

    fn try_select(self: Box<Self>) -> TrySelect<B> {
        let f = self.f;
        match self.result.try_select() {
            TrySelect::EarlyResult(res) => TrySelect::EarlyResult(f(res)),
            TrySelect::Channel(a, p) => TrySelect::Channel(a, Box::new(move |x| f(p(x)))),
        }
    }
}

/// Sync result implementing async interface.
pub struct EarlyResult<T> {
    result: T,
}

impl<T: 'static> EarlyResult<T> {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(result: T) -> ExecResult<T> {
        ExecResult {
            result: Box::new(Self { result }),
        }
    }
}

impl<T: 'static> AsyncResult<T> for EarlyResult<T> {
    fn get(self: Box<Self>) -> ExecResultVariant<T> {
        ExecResultVariant::Completed(self.result)
    }

    fn try_select(self: Box<Self>) -> TrySelect<T> {
        TrySelect::EarlyResult(self.result)
    }
}

impl std::fmt::Display for HypervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl HypervisorError {
    pub fn into_user_error(self, canister_id: &CanisterId) -> UserError {
        use ic_types::user_error::ErrorCode as E;

        match self {
            Self::FunctionNotFound(table_idx, func_idx) => UserError::new(
                E::CanisterFunctionNotFound,
                format!(
                    "Canister {} requested to invoke a non-existent Wasm function {} from table {}",
                    canister_id, func_idx, table_idx
                ),
            ),
            Self::WasmModuleNotFound => UserError::new(
                E::CanisterWasmModuleNotFound,
                format!(
                    "Attempt to execute a message on canister {} which contains no Wasm module",
                    canister_id,
                ),
            ),
            Self::MethodNotFound(wasm_method) => {
                let kind = match wasm_method {
                    WasmMethod::Update(_) => "update",
                    WasmMethod::Query(_) => "query",
                    WasmMethod::System(_) => "system",
                };

                UserError::new(
                    E::CanisterMethodNotFound,
                    format!(
                        "Canister {} has no {} method '{}'",
                        canister_id,
                        kind,
                        wasm_method.name()
                    ),
                )
            }
            Self::ContractViolation(description) => UserError::new(
                E::CanisterContractViolation,
                format!(
                    "Canister {} violated contract: {}",
                    canister_id, description
                ),
            ),
            Self::OutOfCycles(cycles) => UserError::new(
                E::CanisterOutOfCycles,
                format!("Canister {} ran out of cycles limit {}", canister_id, cycles,),
            ),
            Self::InvalidWasm(err) => UserError::new(
                E::CanisterInvalidWasm,
                format!(
                    "Wasm module of canister {} is not valid: {}",
                    canister_id, err
                ),
            ),
            Self::Trapped(code) => UserError::new(
                E::CanisterTrapped,
                format!("Canister {} trapped: {}", canister_id, code),
            ),
            Self::CalledTrap(msg) => UserError::new(
                E::CanisterCalledTrap,
                format!("Canister {} trapped explicitly: {}", canister_id, msg),
            ),
            Self::OutOfMemory => UserError::new(
                E::CanisterOutOfMemory,
                format!(
                    "Canister {} exceeded its allowed memory allocation",
                    canister_id
                ),
            ),
            Self::CanisterStopped => UserError::new(
                E::CanisterStopped,
                format!("Canister {} is stopped", canister_id,),
            ),
            Self::CanisterExec(_, _) => UserError::new(
                E::CanisterContractViolation,
                "Calling exec is only allowed in the update call".to_string(),
            ),
            Self::InsufficientCycles {
                available,
                requested,
            } => UserError::new(
                E::CanisterTrapped,
                format!(
                    "Canister {} attempted to keep {} cycles from a call when only {} was available",
                    canister_id, requested, available
                ),
            ),
            Self::InsufficientICP {
                available,
                requested,
            } => UserError::new(
                E::CanisterTrapped,
                format!(
                    "Canister {} attempted to keep {} ICP tokens from a call when only {} was available",
                    canister_id, requested, available
                ),
            ),
            Self::InvalidPrincipalId(_) => UserError::new(
                E::CanisterTrapped,
                format!("Canister {} provided invalid principal id", canister_id,),
            ),
        }
    }
}

pub type HypervisorResult<T> = Result<T, HypervisorError>;

/// Interface for the component to execute queries on canisters.  It can be used
/// by the HttpHandler and other system components to execute queries.
///
/// If the said canister issues further queries, then this component handles
/// executing them as well.  At the time of writing, support for this is still
/// being actively added and there are many rough edges.  See the actual structs
/// implementing this trait for more detail.
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

    /// Handle a query of type `QueryRequest` which was sent by a canister using
    /// the http interface.
    fn query_request(
        &self,
        q: QueryRequest,
        processing_state: Arc<Self::State>,
        data_certificate: Vec<u8>,
    ) -> Result<WasmResult, UserError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressHistoryError {
    StateRemoved(Height),
    StateNotAvailableYet(Height),
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

    /// Returns the amount of available cycles.
    fn get_available_cycles(&self) -> Cycles;

    /// Sets the amount of available cycles.
    fn set_available_cycles(&mut self, cycles: Cycles);

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

    /// Accepts the requested amount of funds of the specified unit and
    /// transfers them to the canister's balance.
    ///
    /// This traps if the amount of funds requested exceeds the amount available
    /// in the call context.
    fn ic0_msg_funds_accept(
        &mut self,
        unit_src: u32,
        unit_size: u32,
        amount: u64,
        heap: &[u8],
    ) -> HypervisorResult<()>;

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

    /// Just like `exec` in C replaces the current process with a new process,
    /// this system call replaces the current canister with a new canister.
    fn ic0_exec(&mut self, bytes: Vec<u8>, payload: Vec<u8>) -> HypervisorError;

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

    /// Adds funds to a call by moving them from the canister's balance onto the
    /// call under construction. The funds are deducted immediately from the
    /// canister's balance and moved back if the call cannot be performed (e.g.
    /// if `ic0.call_perform` signals an error or if the canister invokes
    /// `ic0.call_new` or returns without invoking `ic0.call_perform`).
    ///
    /// This traps if trying to transfer more funds than are in the current
    /// balance of the canister.
    fn ic0_call_funds_add(
        &mut self,
        unit_src: u32,
        unit_size: u32,
        amount: u64,
        heap: &[u8],
    ) -> HypervisorResult<()>;

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

    fn ic0_time(&self) -> HypervisorResult<Time>;

    /// This system call is not part of the public spec and used by the
    /// hypervisor, when execution runs out of cycles. Higher levels
    /// can decide how to proceed, by either providing more cycles
    /// or aborting the execution (typically with an out-of-cyles
    /// error).
    fn out_of_cycles(&self) -> HypervisorResult<Cycles>;

    /// This system call is not part of the public spec. It's called after a
    /// native `memory.grow` has been called to check whether there's enough
    /// available memory left.
    fn update_available_memory(
        &mut self,
        native_memory_grow_res: i32,
        additional_pages: u32,
    ) -> HypervisorResult<i32>;

    /// Returns the current balance of `unit`.
    ///
    /// Note [Unit]
    fn ic0_canister_balance(
        &self,
        unit_src: u32,
        unit_size: u32,
        heap: &[u8],
    ) -> HypervisorResult<u64>;

    /// Returns the amount of funds available for the specified unit that was
    /// transferred by the caller of the current call and is still available in
    /// this message.
    ///
    /// Note [Unit]
    fn ic0_msg_funds_available(
        &self,
        unit_src: u32,
        unit_size: u32,
        heap: &[u8],
    ) -> HypervisorResult<u64>;

    /// Indicates the amount of specified unit that came back with the response
    /// as a refund.
    ///
    /// Note [Unit]
    fn ic0_msg_funds_refunded(
        &self,
        unit_src: u32,
        unit_size: u32,
        heap: &[u8],
    ) -> HypervisorResult<u64>;

    /// Sets the certified data for the canister.
    /// See: https://docs.dfinity.systems/public/#system-api-certified-data)
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
}
