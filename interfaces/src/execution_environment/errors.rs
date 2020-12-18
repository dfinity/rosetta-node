use ic_types::{methods::WasmMethod, user_error::UserError, CanisterId, Cycles};
use ic_wasm_types::{WasmInstrumentationError, WasmValidationError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    /// Wasm execution consumed too many instructions.
    OutOfInstructions,
    /// We could not validate the wasm module
    InvalidWasm(WasmValidationError),
    /// We could not instrument the wasm module
    InstrumentationFailed(WasmInstrumentationError),
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

impl From<WasmInstrumentationError> for HypervisorError {
    fn from(err: WasmInstrumentationError) -> Self {
        Self::InstrumentationFailed(err)
    }
}

impl From<WasmValidationError> for HypervisorError {
    fn from(err: WasmValidationError) -> Self {
        Self::InvalidWasm(err)
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
            Self::OutOfInstructions => UserError::new(
                E::CanisterOutOfCycles,
                format!("Canister {} exceeded the cycles limit for single message execution.", canister_id),
            ),
            Self::InvalidWasm(err) => UserError::new(
                E::CanisterInvalidWasm,
                format!(
                    "Wasm module of canister {} is not valid: {}",
                    canister_id, err
                ),
            ),
            Self::InstrumentationFailed(err) => UserError::new(
                E::CanisterInvalidWasm,
                format!(
                    "Could not instrument wasm module of canister {}: {}",
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
