/// This module provides the RPC "glue" code to expose the API
/// functionality of the sandbox towards the controller. There is no
/// actual "logic" in this module, just bridging the interfaces.
use crate::sandbox_manager::SandboxManager;

use ic_canister_sandbox_common::{protocol::sbxsvc::*, rpc, sandbox_service::SandboxService};

/// This is the implementation of the RPC interface exposed by the
/// sandbox process and "binds everything together": All RPCs pass
/// through here and are mapped to the "business" logic code contained
/// in SandboxManager.
pub struct SandboxServer {
    /// The SandboxManager contains the business logic (sets up wasm
    /// runtimes, executes things, ...). RPC calls map to methods in
    /// the manager.
    manager: SandboxManager,
}

impl SandboxServer {
    /// Creates new sandbox server, taking constructed sandbox manager.
    pub fn new(manager: SandboxManager) -> Self {
        SandboxServer { manager }
    }
}

impl SandboxService for SandboxServer {
    fn terminate(&self, req: TerminateRequest) -> rpc::Call<TerminateReply> {
        eprintln!("Wasm Sandbox: Recv'd  TerminateRequest {:?}.", req);
        rpc::Call::new_resolved(Ok(TerminateReply {}))
    }

    fn open_wasm(&self, req: OpenWasmRequest) -> rpc::Call<OpenWasmReply> {
        let result = self
            .manager
            .open_wasm(&req.wasm_id, req.wasm_file_path.clone(), req.wasm_src);
        eprintln!("Wasm Sandbox: Recv'd OpenWasmRequest ({:?}).", req.wasm_id);
        rpc::Call::new_resolved(Ok(OpenWasmReply { success: result }))
    }

    fn close_wasm(&self, req: CloseWasmRequest) -> rpc::Call<CloseWasmReply> {
        let result = self.manager.close_wasm(&req.wasm_id);
        eprintln!("Wasm Sandbox: Recv'd CloseWasmRequest ({:?}).", req.wasm_id);
        rpc::Call::new_resolved(Ok(CloseWasmReply { success: result }))
    }

    fn open_state(&self, req: OpenStateRequest) -> rpc::Call<OpenStateReply> {
        let result = self
            .manager
            .open_state(&req.state_id, &req.state_path, req.branch);
        eprintln!(
            "Wasm Sandbox: Recv'd OpenStateRequest ({:?}).",
            req.state_id
        );

        rpc::Call::new_resolved(Ok(OpenStateReply { success: result }))
    }

    fn close_state(&self, req: CloseStateRequest) -> rpc::Call<CloseStateReply> {
        let result = self.manager.close_state(&req.state_id);
        eprintln!(
            "Wasm Sandbox: Recv'd CloseStateRequest ({:?}).",
            req.state_id
        );

        rpc::Call::new_resolved(Ok(CloseStateReply { success: result }))
    }

    fn open_execution(&self, req: OpenExecutionRequest) -> rpc::Call<OpenExecutionReply> {
        eprintln!(
            "Wasm Sandbox: Recv'd OpenExecutionRequest ({:?}).",
            req.exec_id
        );

        let OpenExecutionRequest {
            exec_id,
            wasm_id,
            state_id,
            exec_input,
        } = req;
        rpc::Call::new_resolved({
            let result = self
                .manager
                .open_execution(&exec_id, &wasm_id, &state_id, exec_input);
            Ok(OpenExecutionReply { success: result })
        })
    }

    fn close_execution(&self, req: CloseExecutionRequest) -> rpc::Call<CloseExecutionReply> {
        eprintln!(
            "Wasm Sandbox: Recv'd CloseExecutionRequest ({:?}).",
            req.exec_id
        );

        let result = self.manager.close_execution(&req.exec_id, req.commit_state);
        rpc::Call::new_resolved(Ok(CloseExecutionReply { success: result }))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use ic_canister_sandbox_common::{controller_service::ControllerService, protocol};
    use ic_interfaces::execution_environment::SubnetAvailableMemory;
    use ic_registry_routing_table::RoutingTable;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::canister_state::execution_state::Global;
    use ic_system_api::ApiType;
    use ic_types::{
        ingress::WasmResult,
        messages::CallContextId,
        methods::{FuncRef, WasmMethod},
        time::Time,
        ComputeAllocation, Cycles, NumBytes, NumInstructions, PrincipalId, SubnetId,
    };
    use lazy_static::lazy_static;
    use mockall::*;
    use std::collections::BTreeMap;
    use std::convert::TryFrom;
    use std::sync::{Arc, Condvar, Mutex};
    use wabt::wat2wasm;

    lazy_static! {
        static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
            SubnetAvailableMemory::new(NumBytes::new(std::u64::MAX));
    }

    mock! {
        pub ControllerService {
        }

        trait ControllerService {
            fn exec_finished(
                &self, req : protocol::ctlsvc::ExecFinishedRequest
            ) -> rpc::Call<protocol::ctlsvc::ExecFinishedReply>;

            fn canister_system_call(
                &self, req : protocol::ctlsvc::CanisterSystemCallRequest
            ) -> rpc::Call<protocol::ctlsvc::CanisterSystemCallReply>;

        fn log_via_replica(&self, log: protocol::logging::LogRequest) -> rpc::Call<()>;
        }
    }

    struct SyncCell<T> {
        item: Mutex<Option<T>>,
        cond: Condvar,
    }

    impl<T> SyncCell<T> {
        pub fn new() -> Self {
            Self {
                item: Mutex::new(None),
                cond: Condvar::new(),
            }
        }
        pub fn get(&self) -> T {
            let mut guard = self.item.lock().unwrap();
            loop {
                if let Some(item) = (*guard).take() {
                    break item;
                } else {
                    guard = self.cond.wait(guard).unwrap();
                }
            }
        }
        pub fn put(&self, item: T) {
            let mut guard = self.item.lock().unwrap();
            *guard = Some(item);
            self.cond.notify_one();
        }
    }

    fn make_counter_canister_wasm() -> Vec<u8> {
        let wat_data = r#"
            ;; Counter with global variable ;;
            (module
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))

              (func $read
                (i32.store
                  (i32.const 0)
                  (global.get 0)
                )
                (call $msg_reply_data_append
                  (i32.const 0)
                  (i32.const 4))
                (call $msg_reply))

              (func $write
                (global.set 0
                  (i32.add
                    (global.get 0)
                    (i32.const 1)
                  )
                )
                (call $read)
              )

              (memory $memory 1)
              (export "memory" (memory $memory))
              (global (export "counter_global") (mut i32) (i32.const 0))
              (export "canister_query read" (func $read))
              (export "canister_query inc_read" (func $write))
              (export "canister_update write" (func $write))
            )
            "#;

        wat2wasm(wat_data).unwrap().as_slice().to_vec()
    }

    /// Verifies that we can create a simple canister and run something on
    /// it.
    #[test]
    fn test_simple_canister() {
        use ic_utils::ic_features::*;
        cow_state_feature::enable(cow_state_feature::cow_state);
        sandboxed_execution_feature::enable(sandboxed_execution_feature::sandboxed_execution);

        let exec_finished_sync = Arc::new(SyncCell::<protocol::ctlsvc::ExecFinishedRequest>::new());
        let exec_finished_sync_clone = Arc::clone(&exec_finished_sync);

        let mut controller = MockControllerService::new();
        controller.expect_exec_finished().returning(move |req| {
            (*exec_finished_sync_clone).put(req);
            rpc::Call::new_resolved(Ok(protocol::ctlsvc::ExecFinishedReply {}))
        });
        controller
            .expect_log_via_replica()
            .returning(move |_req| rpc::Call::new_resolved(Ok(())));
        let controller = Arc::new(controller);

        let srv = SandboxServer::new(SandboxManager::new(controller));

        // Create temporary directory to store state files in.
        let tmp = tempfile::Builder::new()
            .prefix("canister")
            .tempdir()
            .unwrap();

        let rep = srv
            .open_wasm(OpenWasmRequest {
                wasm_id: "foo".to_string(),
                wasm_file_path: None,
                wasm_src: make_counter_canister_wasm(),
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        let rep = srv
            .open_state(OpenStateRequest {
                state_id: "bar".to_string(),
                state_path: tmp.path().to_str().unwrap().to_string(),
                branch: StateBranch::TipOfTheTip,
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        // First time around, issue an update to increase the counter.
        let rep = srv
            .open_execution(protocol::sbxsvc::OpenExecutionRequest {
                exec_id: "exec_foo".to_string(),
                wasm_id: "foo".to_string(),
                state_id: "bar".to_string(),
                exec_input: protocol::structs::ExecInput {
                    func_ref: FuncRef::Method(WasmMethod::Update("write".to_string())),
                    api_type: ApiType::update(
                        Time::from_nanos_since_unix_epoch(0),
                        [].to_vec(),
                        Cycles::from(0),
                        PrincipalId::try_from([0].as_ref()).unwrap(),
                        CallContextId::from(0),
                        SubnetId::from(PrincipalId::new_subnet_test_id(0)),
                        SubnetType::Application,
                        Arc::new(RoutingTable::new(BTreeMap::new())),
                        Arc::new(BTreeMap::new()),
                    ),
                    instructions_limit: NumInstructions::from(1000),
                    globals: vec![],
                    canister_memory_limit: NumBytes::from(4 << 30),
                    canister_current_memory_usage: NumBytes::from(0),
                    subnet_available_memory: MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                    compute_allocation: ComputeAllocation::default(),
                },
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        let result = exec_finished_sync.get();
        assert!(result.exec_output.num_instructions_left < NumInstructions::from(1000));
        let wasm_result = result.exec_output.wasm_result.unwrap().unwrap();
        let globals = result.exec_output.globals;
        assert_eq!(WasmResult::Reply([1, 0, 0, 0].to_vec()), wasm_result);

        let rep = srv
            .close_execution(protocol::sbxsvc::CloseExecutionRequest {
                exec_id: "exec_foo".to_string(),
                commit_state: true,
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        // Second time around, issue a query to read the counter. We
        // expect to be able to read back the modified counter value
        // (since we committed the previous state).
        let rep = srv
            .open_execution(protocol::sbxsvc::OpenExecutionRequest {
                exec_id: "exec_foo".to_string(),
                wasm_id: "foo".to_string(),
                state_id: "bar".to_string(),
                exec_input: protocol::structs::ExecInput {
                    func_ref: FuncRef::Method(WasmMethod::Query("read".to_string())),
                    api_type: ApiType::replicated_query(
                        Time::from_nanos_since_unix_epoch(0),
                        [].to_vec(),
                        PrincipalId::try_from([0].as_ref()).unwrap(),
                        None,
                    ),
                    instructions_limit: NumInstructions::from(500),
                    globals,
                    canister_memory_limit: NumBytes::from(4 << 30),
                    canister_current_memory_usage: NumBytes::from(0),
                    subnet_available_memory: MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                    compute_allocation: ComputeAllocation::default(),
                },
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        let result = exec_finished_sync.get();
        assert!(result.exec_output.num_instructions_left < NumInstructions::from(500));
        let wasm_result = result.exec_output.wasm_result.unwrap().unwrap();
        assert_eq!(WasmResult::Reply([1, 0, 0, 0].to_vec()), wasm_result);

        let rep = srv
            .close_execution(protocol::sbxsvc::CloseExecutionRequest {
                exec_id: "exec_foo".to_string(),
                commit_state: false,
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);
    }

    /// Verifies that we can create a simple canister and run multiple
    /// queries with the same Wasm cache.
    /// TODO: INF-1653 This code triggers EINVAL from lmdb fairly consistently.
    #[test]
    #[ignore]
    fn test_simple_canister_wasm_cache() {
        use ic_utils::ic_features::*;
        cow_state_feature::enable(cow_state_feature::cow_state);
        sandboxed_execution_feature::enable(sandboxed_execution_feature::sandboxed_execution);

        let exec_finished_sync = Arc::new(SyncCell::<protocol::ctlsvc::ExecFinishedRequest>::new());
        let exec_finished_sync_clone = Arc::clone(&exec_finished_sync);

        let mut controller = MockControllerService::new();
        controller.expect_exec_finished().returning(move |req| {
            (*exec_finished_sync_clone).put(req);
            rpc::Call::new_resolved(Ok(protocol::ctlsvc::ExecFinishedReply {}))
        });
        controller
            .expect_log_via_replica()
            .returning(move |_req| rpc::Call::new_resolved(Ok(())));

        let controller = Arc::new(controller);

        let srv = SandboxServer::new(SandboxManager::new(controller));

        // Create temporary directory to store state files in.
        let tmp = tempfile::Builder::new()
            .prefix("canister")
            .tempdir()
            .unwrap();

        let rep = srv
            .open_wasm(OpenWasmRequest {
                wasm_id: "foo".to_string(),
                wasm_file_path: None,
                wasm_src: make_counter_canister_wasm(),
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        let rep = srv
            .open_state(OpenStateRequest {
                state_id: "bar".to_string(),
                state_path: tmp.path().to_str().unwrap().to_string(),
                branch: StateBranch::TipOfTheTip,
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        // First time around, issue an update to increase the counter.
        let rep = srv
            .open_execution(protocol::sbxsvc::OpenExecutionRequest {
                exec_id: "exec_foo".to_string(),
                wasm_id: "foo".to_string(),
                state_id: "bar".to_string(),
                exec_input: protocol::structs::ExecInput {
                    func_ref: FuncRef::Method(WasmMethod::Update("write".to_string())),
                    api_type: ApiType::update(
                        Time::from_nanos_since_unix_epoch(0),
                        [].to_vec(),
                        Cycles::from(0),
                        PrincipalId::try_from([0].as_ref()).unwrap(),
                        CallContextId::from(0),
                        SubnetId::from(PrincipalId::new_subnet_test_id(0)),
                        SubnetType::Application,
                        Arc::new(RoutingTable::new(BTreeMap::new())),
                        Arc::new(BTreeMap::new()),
                    ),
                    instructions_limit: NumInstructions::from(1000),
                    globals: vec![],
                    canister_memory_limit: NumBytes::from(4 << 30),
                    canister_current_memory_usage: NumBytes::from(0),
                    subnet_available_memory: MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                    compute_allocation: ComputeAllocation::default(),
                },
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        let result = exec_finished_sync.get();
        assert!(result.exec_output.num_instructions_left < NumInstructions::from(1000));
        let wasm_result = result.exec_output.wasm_result.unwrap().unwrap();
        let globals = result.exec_output.globals;
        assert_eq!(WasmResult::Reply([1, 0, 0, 0].to_vec()), wasm_result);
        assert_eq!([Global::I32(1), Global::I64(988)].to_vec(), globals);

        let rep = srv
            .close_execution(protocol::sbxsvc::CloseExecutionRequest {
                exec_id: "exec_foo".to_string(),
                commit_state: true,
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        // Ensure we close state.
        let rep = srv
            .close_state(protocol::sbxsvc::CloseStateRequest {
                state_id: "bar".to_string(),
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        // Now re-issue the same call but with the previous cache on.

        let rep = srv
            .open_state(OpenStateRequest {
                state_id: "bar".to_string(),
                state_path: tmp.path().to_str().unwrap().to_string(),
                branch: StateBranch::TipOfTheTip,
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        // First time around, issue an update to increase the counter.
        let rep = srv
            .open_execution(protocol::sbxsvc::OpenExecutionRequest {
                exec_id: "exec_foo".to_string(),
                wasm_id: "foo".to_string(),
                state_id: "bar".to_string(),
                exec_input: protocol::structs::ExecInput {
                    func_ref: FuncRef::Method(WasmMethod::Update("write".to_string())),
                    api_type: ApiType::update(
                        Time::from_nanos_since_unix_epoch(0),
                        [].to_vec(),
                        Cycles::from(0),
                        PrincipalId::try_from([0].as_ref()).unwrap(),
                        CallContextId::from(0),
                        SubnetId::from(PrincipalId::new_subnet_test_id(0)),
                        SubnetType::Application,
                        Arc::new(RoutingTable::new(BTreeMap::new())),
                        Arc::new(BTreeMap::new()),
                    ),
                    instructions_limit: NumInstructions::from(1000),
                    globals: vec![],
                    canister_memory_limit: NumBytes::from(4 << 30),
                    canister_current_memory_usage: NumBytes::from(0),
                    subnet_available_memory: MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                    compute_allocation: ComputeAllocation::default(),
                },
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        let result = exec_finished_sync.get();
        assert!(result.exec_output.num_instructions_left < NumInstructions::from(1000));
        let wasm_result = result.exec_output.wasm_result.unwrap().unwrap();
        let globals = result.exec_output.globals;
        assert_eq!(WasmResult::Reply([1, 0, 0, 0].to_vec()), wasm_result);

        let rep = srv
            .close_execution(protocol::sbxsvc::CloseExecutionRequest {
                exec_id: "exec_foo".to_string(),
                commit_state: true,
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        // Second time around, issue a query to read the counter. We
        // expect to be able to read back the modified counter value
        // (since we committed the previous state).
        let rep = srv
            .open_execution(protocol::sbxsvc::OpenExecutionRequest {
                exec_id: "exec_foo".to_string(),
                wasm_id: "foo".to_string(),
                state_id: "bar".to_string(),
                exec_input: protocol::structs::ExecInput {
                    func_ref: FuncRef::Method(WasmMethod::Query("read".to_string())),
                    api_type: ApiType::replicated_query(
                        Time::from_nanos_since_unix_epoch(0),
                        [].to_vec(),
                        PrincipalId::try_from([0].as_ref()).unwrap(),
                        None,
                    ),
                    instructions_limit: NumInstructions::from(500),
                    globals,
                    canister_memory_limit: NumBytes::from(4 << 30),
                    canister_current_memory_usage: NumBytes::from(0),
                    subnet_available_memory: MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                    compute_allocation: ComputeAllocation::default(),
                },
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);

        let result = exec_finished_sync.get();
        assert!(result.exec_output.num_instructions_left < NumInstructions::from(500));
        let wasm_result = result.exec_output.wasm_result.unwrap().unwrap();
        assert_eq!(WasmResult::Reply([1, 0, 0, 0].to_vec()), wasm_result);

        let rep = srv
            .close_execution(protocol::sbxsvc::CloseExecutionRequest {
                exec_id: "exec_foo".to_string(),
                commit_state: false,
            })
            .sync()
            .unwrap();
        assert_eq!(true, rep.success);
    }
}
