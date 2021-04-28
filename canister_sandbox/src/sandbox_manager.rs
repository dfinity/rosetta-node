//! The sandbox manager provides the actual functionality of the sandbox
//! process. It allows the replica controller process to manage
//! everything required in order to execute code. It holds three
//! kinds of resources that it manages on behalf of the replica
//! controller process:
//!
//! - CanisterWasm: The (wasm) code corresponding to one canister
//! - State: The heap and other (mutable) user state associated with a canister
//! - Execution: An ongoing execution of a canister, using one wasm and state
//!   object
//!
//! All of the above objects as well as the functionality provided
//! towards the controller are found in this module.
use crate::logging::log;
use crate::system_state_accessor_rpc::SystemStateAccessorRPC;
use ic_canister_sandbox_common::{
    controller_service::ControllerService,
    protocol,
    protocol::logging::{LogLevel, LogRequest},
    protocol::sbxsvc::StateBranch,
    protocol::structs::Round,
};
use ic_config::embedders::{Config, PersistenceType};
use ic_cow_state::{CowMemoryManager, CowMemoryManagerImpl, MappedState, MappedStateImpl};
use ic_embedders::{cow_memory_creator::CowMemoryCreator, Embedder, WasmtimeEmbedder};
use ic_interfaces::execution_environment::{HypervisorError, SystemApi};
use ic_replicated_state::{EmbedderCache, Global, NumWasmPages, PageMap};
use ic_system_api::{PauseHandler, SystemApiImpl};
use ic_types::{
    methods::{FuncRef, WasmMethod},
    NumInstructions,
};
use ic_wasm_types::BinaryEncodedWasm;
use ic_wasm_utils::{
    instrumentation::{instrument, InstructionCostTable},
    validation::{validate_wasm_binary, WasmValidationLimits},
};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Mutex};

struct VolatileState {
    globals: Vec<Global>,
    heap_size: NumWasmPages,
    changed_pages: Vec<u64>,
    is_read_write_state: bool,
}

struct ExecutionInstantiateError;

impl Debug for ExecutionInstantiateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("Failed to instantatiate execution.")
    }
}

/// A canister execution currently in progress.
struct Execution {
    /// Id of the execution. This is used in communicating back to
    /// the replica (e.g. for syscalls) such that replica can associate
    /// events with the correct execution.
    exec_id: String,

    /// The canister wasm used in this execution.
    canister_wasm: Arc<CanisterWasm>,

    /// The (heap) state used in this execution.
    state: Arc<State>,

    /// Handle for RPC service to controller (e.g. for syscalls).
    controller: Arc<dyn ControllerService>,

    /// Internal synchronized state -- the execution object itself
    /// needs to be sychronized because it is accessed from different
    /// threads (incoming RPC handling as well as actual execution
    /// thread).
    internal: Mutex<ExecutionState>,
}
/// Internal execution state. It evolves from Running to
/// {FinishedOk | FinishedError} to Closed.
enum ExecutionState {
    /// The execution thread is running.
    Running,

    /// The execution is finished -- state is "released" from actual
    /// execution thread, and there may be a volatile state that could
    /// be committed.
    FinishedOk {
        /// Run time state that will be returned to the state object
        /// used in the execution.
        runtime_state: Box<RuntimeState>,
        /// State that has been created during execution (e.g. updated
        /// pages, global variables etc.) but that has not yet been
        /// committed to the runtime state.
        volatile_state: VolatileState,
    },

    FinishedError {
        runtime_state: Box<RuntimeState>,
    },

    /// Execution is finished and has been closed. This is an
    /// intermittent state before the object is destroyed -- it should
    /// not really be externally visible, but if it were to (e.g.
    /// due to a race condition) this also guards against illegal
    /// operations.
    Closed,
}

impl Execution {
    /// Creates new execution based on canister wasm and state. In order
    /// to start the execution, the given state object will be "locked" --
    /// if that cannot be done, then creation of execution will fail.
    /// The actual code to be run will be scheduled to the given
    /// thread pool.
    ///
    /// This will *actually* schedule and initiate a new execution.
    pub(crate) fn create(
        exec_id: String,
        canister_wasm: Arc<CanisterWasm>,
        state: Arc<State>,
        controller: Arc<dyn ControllerService>,
        workers: &mut threadpool::ThreadPool,
        exec_input: protocol::structs::ExecInput,
    ) -> Result<Arc<Self>, ExecutionInstantiateError> {
        let runtime_state = state
            .borrow_runtime_state()
            .ok_or_else(|| ExecutionInstantiateError)?;

        let instance = Arc::new(Self {
            exec_id,
            canister_wasm,
            state,
            controller,
            internal: Mutex::new(ExecutionState::Running),
        });

        let instance_copy = Arc::clone(&instance);
        workers.execute(move || instance_copy.entry(exec_input, runtime_state));

        Ok(instance)
    }

    // Actual wasm code execution -- this is run on the target thread
    // in the thread pool.
    fn entry(
        &self,
        exec_input: protocol::structs::ExecInput,
        mut runtime_state: Box<RuntimeState>,
    ) {
        // Currently, copy globals from execution input. The globals
        // are still (somewhat) managed on the replica side (because
        // it needs them for state hashing). Ideally, they should be
        // managed by sandbox process alone, and replica would be able
        // to just read them.
        // This is an implementation compromise that is owed to time
        // pressure.
        runtime_state.globals = exec_input.globals.clone();

        // Prepare instance for running -- memory map, some ancillary
        // parameters and system API.
        let memory_creator = Some(Arc::new(CowMemoryCreator::new(&runtime_state.mapped_state)));

        // This criterion is not terribly helpful -- whether we can
        // commit or not is a function of the state, and not the IC API
        // call. It is ultimately the responsibility of the controller
        // to associate correct states with IC API used.
        let is_read_write_state = match &exec_input.func_ref {
            FuncRef::Method(WasmMethod::Update(_))
            | FuncRef::Method(WasmMethod::System(_))
            | FuncRef::UpdateClosure(_) => true,
            _ => false,
        };
        let memory_init: Option<PageMap> = None;

        let mut instance = self.canister_wasm.embedder.new_instance(
            &self.canister_wasm.compilate,
            &runtime_state.globals,
            runtime_state.heap_size,
            memory_creator,
            memory_init,
        );
        instance.set_num_instructions(exec_input.instructions_limit);
        let system_state_accessor =
            SystemStateAccessorRPC::new(self.exec_id.clone(), self.controller.clone());
        let mut system_api = SystemApiImpl::new(
            exec_input.api_type,
            system_state_accessor,
            exec_input.instructions_limit,
            exec_input.canister_memory_limit,
            exec_input.canister_current_memory_usage,
            exec_input.subnet_available_memory,
            exec_input.compute_allocation,
            Box::new(DummyPauseHandler {}),
        );

        // Run actual code and take out results.
        let run_result = instance.run(&mut system_api, exec_input.func_ref);

        let wasm_result = system_api.take_execution_result();

        let num_instructions_left = instance.get_num_instructions();
        let mut instance_stats = instance.get_stats();
        instance_stats.dirty_pages += system_api.get_stable_memory_delta_pages();

        match run_result {
            Ok(run_result) => {
                let changed_pages: Vec<u64> = if is_read_write_state {
                    run_result.dirty_pages.iter().map(|p| p.get()).collect()
                } else {
                    vec![]
                };

                let exec_output = protocol::structs::ExecOutput {
                    wasm_result,
                    num_instructions_left,
                    globals: run_result.exported_globals.clone(),
                    instance_stats,
                };

                let volatile_state = VolatileState {
                    globals: run_result.exported_globals,
                    heap_size: instance.heap_size(),
                    changed_pages,
                    is_read_write_state,
                };
                *self.internal.lock().unwrap() = ExecutionState::FinishedOk {
                    runtime_state,
                    volatile_state,
                };
                self.controller
                    .exec_finished(protocol::ctlsvc::ExecFinishedRequest {
                        exec_id: self.exec_id.to_string(),
                        exec_output,
                    });
            }
            Err(err) => {
                *self.internal.lock().unwrap() = ExecutionState::FinishedError { runtime_state };
                let exec_output = protocol::structs::ExecOutput {
                    wasm_result: Err(err),
                    num_instructions_left,
                    globals: exec_input.globals,
                    instance_stats,
                };
                self.controller
                    .exec_finished(protocol::ctlsvc::ExecFinishedRequest {
                        exec_id: self.exec_id.to_string(),
                        exec_output,
                    });
            }
        }
    }

    /// Closes the current execution (assuming that it has finished).
    /// Optionally, commits changes made during execution to the state.
    /// The state is finally unlocked.
    pub(crate) fn close(&self, commit_state: bool) -> bool {
        let mut guard = self.internal.lock().unwrap();

        // "Optimistically" replace present state with "Closed" state --
        // this trickery is partially necessary as there is no other
        // way to perform a consuming in-place modification of an
        // enum.
        match std::mem::replace(&mut *guard, ExecutionState::Closed) {
            ExecutionState::FinishedOk {
                mut runtime_state,
                volatile_state,
            } => {
                if commit_state {
                    runtime_state.globals = volatile_state.globals;
                    runtime_state.heap_size = volatile_state.heap_size;
                    runtime_state
                        .mapped_state
                        .soft_commit(&volatile_state.changed_pages);
                }
                if volatile_state.is_read_write_state {
                    // For tip states we need to ensure that mappings
                    // are reset in order for the state to be reused
                    // later.
                    // Strictly speaking, we should require "commit"
                    // also for branch states in order to have the
                    // same semantics. However, controller presently
                    // does not behave this way, but it needs to be
                    // rectified.
                    runtime_state.needs_reset = true;
                }
                self.state.return_runtime_state(runtime_state);
                true
            }
            ExecutionState::FinishedError { mut runtime_state } => {
                // After a failed call (no matter if at tip or branch
                // state), the memory map is not in good shape. If the
                // state object is to be reused, then its mapping needs
                // to be reset as well.
                runtime_state.needs_reset = true;
                self.state.return_runtime_state(runtime_state);
                !commit_state
            }
            ExecutionState::Running => {
                // Restore state to running if it was running before --
                // cannot close yet.
                *guard = ExecutionState::Running;
                false
            }
            _ => false,
        }
    }
}

/// Pause handler that currently just aborts execution. Needs to
/// implement relay via RPC (in the same way as system API) in order
/// to support pausing execution across rounds.
struct DummyPauseHandler {}
impl PauseHandler for DummyPauseHandler {
    fn pause(&self) -> NumInstructions {
        NumInstructions::from(0)
    }
}

/// This represents the state object as it is used in the RPC protocol.
/// It "generally" holds the runtime state required for wasm execution
/// at a given point in time -- it can temporarily be "empty" when
/// there is an execution in progress.
struct State {
    /// The cow manager used in creating this state.
    cow_mgr: CowMemoryManagerImpl,

    /// The branch that this state is on: Mutable tip state for updates,
    /// immutable snapshot state for queries.
    branch: StateBranch,

    /// Actual runtime state -- held here unless state is presently
    /// "locked" in an execution.
    runtime_state: Mutex<Option<Box<RuntimeState>>>,
}
struct RuntimeState {
    /// Global variables.
    globals: Vec<Global>,
    /// Heap.
    mapped_state: MappedStateImpl,
    /// Heap size.
    heap_size: NumWasmPages,

    /// Lazy reset. As of present, "mapped_state" objects are not
    /// supposed to be reused after a soft commit -- but API-wise,
    /// state objects are intentionally allowed to. To expose the
    /// correct semantics, allow to (lazily) reset to well-defined
    /// mapped_state that allows to continue using the state object.
    ///
    /// If and when the implementation of MappedStateImpl changes
    /// such that it supports both explicit commit+discard and can
    /// be reused across multiple update transactions, this reset
    /// can go away and we get a nice performance benefit from not
    /// tearing down and setting up mappings unnecessarily.
    needs_reset: bool,
}

impl State {
    /// Instantiates a new state -- state_root designates where cow
    /// manager locates requisite files, branch identifies at which
    /// point in the "state" tree we want to create our execution state.
    /// Only "tip" states can be committed to.
    pub fn new(state_root: &str, branch: StateBranch) -> Self {
        let (cow_mgr, mapped_state) = match branch {
            StateBranch::TipOfTheTip => {
                let cow_mgr = CowMemoryManagerImpl::open_readwrite(state_root.into());
                eprintln!("State: We are at the Tip!!!! ");
                let mapped_state = cow_mgr.get_map();
                (cow_mgr, mapped_state)
            }
            StateBranch::Round(Round(r)) => {
                let cow_mgr = CowMemoryManagerImpl::open_readonly(state_root.into());
                eprintln!("State: Round: {:?} ", &r);

                let mapped_state = cow_mgr.get_map_for_snapshot(r).unwrap_or_else(|_| panic!("Failed to recover state snapshot while constructing a new state for: {:?} @ {:?}.", state_root, &branch));
                (cow_mgr, mapped_state)
            }
        };

        Self {
            cow_mgr,
            branch,
            runtime_state: Mutex::new(Some(Box::new(RuntimeState {
                globals: Vec::<Global>::new(),
                mapped_state,
                heap_size: NumWasmPages::from(0),
                needs_reset: false,
            }))),
        }
    }

    fn maybe_reset(
        branch: &StateBranch,
        cow_mgr: &CowMemoryManagerImpl,
        runtime_state: &mut RuntimeState,
    ) {
        if runtime_state.needs_reset {
            runtime_state.mapped_state = match branch {
                StateBranch::TipOfTheTip => cow_mgr.get_map(),
                StateBranch::Round(Round(r)) => {
                    cow_mgr.get_map_for_snapshot(*r).unwrap_or_else(|_| {
                        panic!(
                            "Failed to recover state snapshot while resetting for: {:?}.",
                            &branch
                        )
                    })
                }
            };
            runtime_state.needs_reset = false;
        }
    }

    // Internal function used by execution -- borrows actual state
    // internals and marks state as "locked".
    // Precondition: state is "unlocked"
    fn borrow_runtime_state(&self) -> Option<Box<RuntimeState>> {
        let mut runtime_state = {
            let mut guard = self.runtime_state.lock().unwrap();
            guard.take()
        };
        if let Some(runtime_state) = runtime_state.as_mut() {
            Self::maybe_reset(&self.branch, &self.cow_mgr, runtime_state);
        }

        runtime_state
    }

    // Internal function used by execution -- return previously
    // borrowed state, "unlocks" state object.
    // Precondition: state is "locked", and the given runtime state
    // is the one previously obtained through "borrow_runtime_state".
    fn return_runtime_state(&self, runtime_state: Box<RuntimeState>) {
        let mut guard = self.runtime_state.lock().unwrap();

        *guard = Some(runtime_state);
    }
}

/// Represents a wasm object of a canister. This is the executable code
/// of the canister.
struct CanisterWasm {
    embedder: Arc<WasmtimeEmbedder>,
    compilate: Arc<EmbedderCache>,
}

impl CanisterWasm {
    /// Creates new wasm object for given binary encoded wasm.
    pub fn new(wasm: BinaryEncodedWasm) -> Self {
        let log = ic_logger::replica_logger::no_op_logger();
        let mut config = Config::new();
        config.persistence_type = PersistenceType::Pagemap;

        let embedder = Arc::new(WasmtimeEmbedder::new(config, log));
        let compilate = Arc::new(
            validate_wasm_binary(
                &wasm,
                WasmValidationLimits {
                    max_globals: 200,
                    max_functions: 6000,
                },
            )
            .map_err(HypervisorError::from)
            .and_then(|()| {
                instrument(&wasm, &InstructionCostTable::new()).map_err(HypervisorError::from)
            })
            .and_then(|output| embedder.compile(PersistenceType::Pagemap, &output.binary))
            .unwrap(),
        );
        Self {
            embedder,
            compilate,
        }
    }

    /// Creates new wasm object from file.
    pub fn new_from_file_path(wasm_file_path: &str) -> Self {
        let wasm =
            BinaryEncodedWasm::new_from_file(std::path::PathBuf::from(wasm_file_path)).unwrap();

        CanisterWasm::new(wasm)
    }

    /// Creates new wasm object from inline data (binary encoded wasm).
    pub fn new_from_src(wasm_src: Vec<u8>) -> Self {
        let wasm = BinaryEncodedWasm::new(wasm_src);

        CanisterWasm::new(wasm)
    }
}

/// Manages the entirety of the sandbox process. It provides the methods
/// through which the controller process (the replica) manages the
/// sandboxed execution.
pub struct SandboxManager {
    repr: Mutex<SandboxManagerInt>,
    controller: Arc<dyn ControllerService>,
}
struct SandboxManagerInt {
    canister_wasms: std::collections::HashMap<String, Arc<CanisterWasm>>,
    states: std::collections::HashMap<String, Arc<State>>,
    active_execs: std::collections::HashMap<String, Arc<Execution>>,
    workers: threadpool::ThreadPool,
}

impl SandboxManager {
    /// Creates new sandbox manager. In order to operate, it needs
    /// an established backward RPC channel to the controller process
    /// to relay e.g. syscalls and completions.
    pub fn new(controller: Arc<dyn ControllerService>) -> Self {
        SandboxManager {
            repr: Mutex::new(SandboxManagerInt {
                canister_wasms: HashMap::new(),
                states: HashMap::new(),
                active_execs: HashMap::new(),
                workers: threadpool::ThreadPool::new(4),
            }),
            controller,
        }
    }

    /// Opens new wasm instance. Note that if a previous wasm canister
    /// was assigned to this id, we simply update the internal table
    /// with the new wasm canister, and do NOT complain. This is
    /// necessary as we might and likely will keep a wasm execution
    /// open for multiple, requests.
    pub fn open_wasm(
        &self,
        wasm_id: &str,
        wasm_file_path: Option<String>,
        wasm_src: Vec<u8>,
    ) -> bool {
        log(
            &*self.controller,
            LogRequest((
                LogLevel::Debug,
                format!(
                    "Opening wasm session: Wasm id: {:?}; wasm file path: {:?}",
                    &wasm_id, wasm_file_path
                ),
            )),
        );

        let mut guard = self.repr.lock().unwrap();
        // Note that we can override an existing open wasm.
        let wasm = match wasm_file_path.clone() {
            Some(path) => Arc::new(CanisterWasm::new_from_file_path(path.as_ref())),
            None => Arc::new(CanisterWasm::new_from_src(wasm_src)),
        };

        guard.canister_wasms.insert(wasm_id.to_string(), wasm);

        log(
            &*self.controller,
            LogRequest((
                LogLevel::Debug,
                format!(
                    "Opened wasm session: Wasm id: {:?}; wasm file path: {:?}",
                    &wasm_id, wasm_file_path
                ),
            )),
        );

        true
    }

    /// Closes previously opened wasm instance, by id.
    pub fn close_wasm(&self, wasm_id: &str) -> bool {
        let mut guard = self.repr.lock().unwrap();
        log(
            &*self.controller,
            LogRequest((
                LogLevel::Debug,
                format!("Closing wasm session: Wasm id: {:?}", &wasm_id),
            )),
        );
        guard.canister_wasms.remove(wasm_id).is_some()
    }

    /// Opens new state instance.
    pub fn open_state(&self, state_id: &str, state_path: &str, branch: StateBranch) -> bool {
        let mut guard = self.repr.lock().unwrap();
        log(
            &*self.controller,
            LogRequest((
                LogLevel::Debug,
                format!(
                    "Opening session state: State id: {:?} -- {:?}",
                    &state_id, &branch
                ),
            )),
        );

        match guard.states.get(&state_id.to_owned()) {
            Some(_) => false,
            None => {
                let state = Arc::new(State::new(state_path, branch));
                guard.states.insert(state_id.to_owned(), state);
                true
            }
        }
    }

    /// Closes previously opened state instance, by id.
    pub fn close_state(&self, state_id: &str) -> bool {
        let mut guard = self.repr.lock().unwrap();
        log(
            &*self.controller,
            LogRequest((
                LogLevel::Debug,
                format!("Closing state session: state id: {:?}", &state_id),
            )),
        );
        guard.states.remove(state_id).is_some()
    }

    /// Opens new execution using specific code and state, passing
    /// execution input.
    ///
    /// Note that inside here we start a transaction and the state of
    /// execution can not and does not change while we are processing
    /// this particular session.
    pub fn open_execution(
        &self,
        exec_id: &str,
        wasm_id: &str,
        state_id: &str,
        exec_input: protocol::structs::ExecInput,
    ) -> bool {
        let mut guard = self.repr.lock().unwrap();
        eprintln!("Exec: Exec id: {:?}", &exec_id);
        log(
            &*self.controller,
            LogRequest((
                LogLevel::Debug,
                format!(
                    "Opening exec session: Exec id: {:?} on state {:?} with wasm {:?}",
                    &exec_id, &wasm_id, &wasm_id
                ),
            )),
        );

        if let Some(_exec_id) = guard.active_execs.get(&exec_id.to_owned()) {
            // This should be unreachable: if we reach this point
            // we have failed to close an execution.
            //
            // Note that we do not have a lot of options regarding the panic. If we
            // are instructing to start a new execution it means that the replica
            // controller and the sandbox are now out of sync.
            unreachable!();
        }
        eprintln!("To open with wasm id : {:?}", wasm_id);
        let wasm_runner = guard.canister_wasms.get(wasm_id);
        if let Some(wasm_runner) = wasm_runner {
            eprintln!("Found wasm id : {:?}", wasm_id);
            let state = guard.states.get(state_id);
            if let Some(state) = state {
                let exec = Execution::create(
                    exec_id.to_string(),
                    Arc::clone(&wasm_runner),
                    Arc::clone(&state),
                    Arc::clone(&self.controller),
                    &mut guard.workers,
                    exec_input,
                );

                if let Ok(exec) = exec {
                    guard.active_execs.insert(exec_id.to_owned(), exec);
                    log(
                        &*self.controller,
                        LogRequest((
                            LogLevel::Debug,
                            format!(
                                "Opened exec session: Exec id: {:?} on state {:?} with wasm {:?}",
                                &exec_id, &wasm_id, &wasm_id
                            ),
                        )),
                    );

                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            eprintln!("NOT FOUND wasm id : {:?}", wasm_id);
            false
        }
    }

    /// Closes previously opened execution. Execution must have
    /// finished previously.
    ///
    /// If execution has not finished we return false. Disagreement
    /// between replica and sandbox needs to be handled by the
    /// replica, as we assume a malicious sandboxed process. For
    /// stability reasons we should ensure still that sandbox is
    /// robust.
    pub fn close_execution(&self, exec_id: &str, commit_state: bool) -> bool {
        let mut guard = self.repr.lock().unwrap();
        match guard.active_execs.remove(exec_id) {
            Some(exec) => {
                // **Attempt** closing the execution object.
                exec.close(commit_state)
            }
            None => false,
        }
    }
}
