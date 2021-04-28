use crate::protocol::structs;
use serde::{Deserialize, Serialize};

/// This defines the RPC service methods offered by the sandbox process
/// (used by the controller) as well as the expected replies.
///
/// Instruct sandbox process to terminate: Sandbox process should take
/// all necessary steps for graceful termination (sync all files etc.)
/// and quit voluntarily. It is still expected to generate a reply to
/// this RPC (controller may perform a "hard kill" after timeout).
///
/// We do not implement graceful termination.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TerminateRequest {}

/// Ack signal to the controller that termination was complete.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TerminateReply {}

/// Register wasm for a canister that can be executed in the sandbox.
/// Multiple wasms can be registered to the same sandbox (in order to
/// support multiple code states e.g. during upgrades). A single wasm
/// instance can be used concurrently for multiple executions.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenWasmRequest {
    /// Id used to later refer to this canister runner. Must be unique
    /// per sandbox instance.
    pub wasm_id: String,

    /// Path to the wasm file that defines the executable of the
    /// canister.
    /// NB:
    /// - it would actually be preferable to transfer the code by other means
    ///   (either as "data" or by "file descriptor passing") instead of passing
    ///   a file name; this way, filesystem access permission to sandbox can be
    ///   limited further
    /// - it would actually be preferable to move the compilation into native
    ///   code outside the sandbox itself; this way, the sandbox can be further
    ///   constrained such that it is impossible to generate and execute custom
    ///   code and will hamper an attackers ability to exploit wasm jailbreak
    ///   flaws
    pub wasm_file_path: Option<String>,
    /// Contains wasm source code as a sequence of bytes.
    pub wasm_src: Vec<u8>,
}

/// Reply to an `OpenWasmRequest`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenWasmReply {
    pub success: bool,
}

/// Request to close the indicated wasm object.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloseWasmRequest {
    pub wasm_id: String,
}

/// Reply to a `CloseWasm` request.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloseWasmReply {
    pub success: bool,
}

/// We build state on the tip or branch off at some specific round via
/// tagged state.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum StateBranch {
    TipOfTheTip,
    Round(structs::Round),
}

/// Describe a request to open a particular state containing either
/// the state path or utilize a particular state branch.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenStateRequest {
    pub state_id: String,
    /// Path to directory holding state information.
    pub state_path: String,
    /// Point to the particular state to open. State can belong to the
    /// tip set of states, which are non-checkpointed states, or to a
    /// particular tagged read-only past state.
    pub branch: StateBranch,
}

/// Ack to the controller that state was opened or failed to open. A
/// failure to open will lead to a panic in the controller.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenStateReply {
    pub success: bool,
}

/// Request the indicated state session to be purged and dropped.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloseStateRequest {
    pub state_id: String,
}

/// Ack state session was successfully closed or not.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloseStateReply {
    pub success: bool,
}

/// Start execution of a canister.
#[derive(Serialize, Deserialize, Clone)]
pub struct OpenExecutionRequest {
    /// Id of the newly created invocation of this canister. This is
    /// used to identify the running instance in callbacks as well as
    /// other operations (status queries etc.).
    /// Must be unique until this execution is finished.
    pub exec_id: String,

    /// Id of canister to run (see OpenWasm).
    pub wasm_id: String,

    /// State to use (see OpenState).
    pub state_id: String,

    /// Arguments to execution (api type, caller, payload, ...).
    pub exec_input: structs::ExecInput,
}

/// Reply to an `OpenExecutionRequest`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenExecutionReply {
    pub success: bool,
}

/// Request type
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloseExecutionRequest {
    /// Id of execution previously created (see OpenExecution)
    pub exec_id: String,

    /// Whether to apply the changes made during this call to the
    /// underlying state.
    pub commit_state: bool,
}

/// Ack `CloseExecutionRequest`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloseExecutionReply {
    pub success: bool,
}

/// All possible requests to a sandboxed process.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone)]
pub enum Request {
    Terminate(TerminateRequest),
    OpenWasm(OpenWasmRequest),
    CloseWasm(CloseWasmRequest),
    OpenState(OpenStateRequest),
    CloseState(CloseStateRequest),
    OpenExecution(OpenExecutionRequest),
    CloseExecution(CloseExecutionRequest),
}

/// All ack replies by the sandboxed process to the controller.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Reply {
    Terminate(TerminateReply),
    OpenWasm(OpenWasmReply),
    CloseWasm(CloseWasmReply),
    OpenState(OpenStateReply),
    CloseState(CloseStateReply),
    OpenExecution(OpenExecutionReply),
    CloseExecution(CloseExecutionReply),
}
