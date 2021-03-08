#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallContext {
    #[prost(bool, tag="5")]
    pub responded: bool,
    #[prost(message, optional, tag="6")]
    pub available_funds: ::std::option::Option<super::super::queues::v1::Funds>,
    #[prost(oneof="call_context::CallOrigin", tags="1, 2, 3, 4, 7")]
    pub call_origin: ::std::option::Option<call_context::CallOrigin>,
}
pub mod call_context {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ingress {
        #[prost(message, optional, tag="1")]
        pub user_id: ::std::option::Option<super::super::super::super::types::v1::UserId>,
        #[prost(bytes, tag="2")]
        pub message_id: std::vec::Vec<u8>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CanisterUpdateOrQuery {
        #[prost(message, optional, tag="1")]
        pub canister_id: ::std::option::Option<super::super::super::super::types::v1::CanisterId>,
        #[prost(uint64, tag="2")]
        pub callback_id: u64,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Heartbeat {
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum CallOrigin {
        #[prost(message, tag="1")]
        Ingress(Ingress),
        #[prost(message, tag="2")]
        CanisterUpdate(CanisterUpdateOrQuery),
        #[prost(message, tag="3")]
        Query(super::super::super::super::types::v1::UserId),
        #[prost(message, tag="4")]
        CanisterQuery(CanisterUpdateOrQuery),
        #[prost(message, tag="7")]
        Heartbeat(Heartbeat),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallContextEntry {
    #[prost(uint64, tag="1")]
    pub call_context_id: u64,
    #[prost(message, optional, tag="2")]
    pub call_context: ::std::option::Option<CallContext>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmClosure {
    #[prost(uint32, tag="1")]
    pub func_idx: u32,
    #[prost(uint32, tag="2")]
    pub env: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Callback {
    #[prost(uint64, tag="1")]
    pub call_context_id: u64,
    #[prost(message, optional, tag="2")]
    pub on_reply: ::std::option::Option<WasmClosure>,
    #[prost(message, optional, tag="3")]
    pub on_reject: ::std::option::Option<WasmClosure>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallbackEntry {
    #[prost(uint64, tag="1")]
    pub callback_id: u64,
    #[prost(message, optional, tag="2")]
    pub callback: ::std::option::Option<Callback>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallContextManager {
    #[prost(uint64, tag="1")]
    pub next_call_context_id: u64,
    #[prost(uint64, tag="2")]
    pub next_callback_id: u64,
    #[prost(message, repeated, tag="3")]
    pub call_contexts: ::std::vec::Vec<CallContextEntry>,
    #[prost(message, repeated, tag="4")]
    pub callbacks: ::std::vec::Vec<CallbackEntry>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CyclesAccount {
    /// Cycle balance is store as BigUint::to_bytes_le()
    #[prost(bytes, tag="1")]
    pub cycles_balance: std::vec::Vec<u8>,
    #[prost(uint64, tag="2")]
    pub max_exec_cycles: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Global {
    #[prost(oneof="global::Global", tags="1, 2, 3, 4")]
    pub global: ::std::option::Option<global::Global>,
}
pub mod global {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Global {
        #[prost(int32, tag="1")]
        I32(i32),
        #[prost(int64, tag="2")]
        I64(i64),
        #[prost(float, tag="3")]
        F32(f32),
        #[prost(double, tag="4")]
        F64(f64),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmMethod {
    #[prost(oneof="wasm_method::WasmMethod", tags="1, 2, 3")]
    pub wasm_method: ::std::option::Option<wasm_method::WasmMethod>,
}
pub mod wasm_method {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum SystemMethod {
        Unspecified = 0,
        CanisterStart = 1,
        CanisterInit = 2,
        CanisterPreUpgrade = 3,
        CanisterPostUpgrade = 4,
        CanisterInspectMessage = 5,
        CanisterHeartbeat = 6,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum WasmMethod {
        #[prost(string, tag="1")]
        Update(std::string::String),
        #[prost(string, tag="2")]
        Query(std::string::String),
        #[prost(enumeration="SystemMethod", tag="3")]
        System(i32),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExecutionStateBits {
    #[prost(message, repeated, tag="1")]
    pub exported_globals: ::std::vec::Vec<Global>,
    #[prost(uint32, tag="2")]
    pub heap_size: u32,
    #[prost(message, repeated, tag="3")]
    pub exports: ::std::vec::Vec<WasmMethod>,
    #[prost(uint64, tag="4")]
    pub last_executed_round: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StopCanisterContext {
    #[prost(oneof="stop_canister_context::Context", tags="1, 2")]
    pub context: ::std::option::Option<stop_canister_context::Context>,
}
pub mod stop_canister_context {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ingress {
        #[prost(message, optional, tag="1")]
        pub sender: ::std::option::Option<super::super::super::super::types::v1::UserId>,
        #[prost(bytes, tag="2")]
        pub message_id: std::vec::Vec<u8>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Canister {
        #[prost(message, optional, tag="1")]
        pub sender: ::std::option::Option<super::super::super::super::types::v1::CanisterId>,
        #[prost(uint64, tag="2")]
        pub reply_callback: u64,
        #[prost(message, optional, tag="3")]
        pub funds: ::std::option::Option<super::super::super::queues::v1::Funds>,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Context {
        #[prost(message, tag="1")]
        Ingress(Ingress),
        #[prost(message, tag="2")]
        Canister(Canister),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStatusRunning {
    #[prost(message, optional, tag="1")]
    pub call_context_manager: ::std::option::Option<CallContextManager>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStatusStopping {
    #[prost(message, optional, tag="1")]
    pub call_context_manager: ::std::option::Option<CallContextManager>,
    #[prost(message, repeated, tag="2")]
    pub stop_contexts: ::std::vec::Vec<StopCanisterContext>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStatusStopped {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStateBits {
    #[prost(message, optional, tag="1")]
    pub controller: ::std::option::Option<super::super::super::types::v1::PrincipalId>,
    #[prost(uint64, tag="2")]
    pub last_full_execution_round: u64,
    #[prost(message, optional, tag="3")]
    pub call_context_manager: ::std::option::Option<CallContextManager>,
    #[prost(uint64, tag="4")]
    pub compute_allocation: u64,
    #[prost(int64, tag="5")]
    pub accumulated_priority: i64,
    #[prost(uint64, tag="6")]
    pub query_allocation: u64,
    #[prost(message, optional, tag="7")]
    pub execution_state_bits: ::std::option::Option<ExecutionStateBits>,
    #[prost(uint64, tag="8")]
    pub memory_allocation: u64,
    #[prost(message, optional, tag="9")]
    pub cycles_account: ::std::option::Option<CyclesAccount>,
    #[prost(uint64, tag="10")]
    pub icp_balance: u64,
    #[prost(uint64, tag="15")]
    pub scheduled_as_first: u64,
    #[prost(uint64, tag="17")]
    pub skipped_round_due_to_no_messages: u64,
    /// In how many rounds a canister is executed.
    #[prost(uint64, tag="18")]
    pub executed: u64,
    #[prost(bytes, tag="20")]
    pub certified_data: std::vec::Vec<u8>,
    #[prost(uint64, tag="21")]
    pub interruped_during_execution: u64,
    #[prost(oneof="canister_state_bits::CanisterStatus", tags="11, 12, 13")]
    pub canister_status: ::std::option::Option<canister_state_bits::CanisterStatus>,
}
pub mod canister_state_bits {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum CanisterStatus {
        #[prost(message, tag="11")]
        Running(super::CanisterStatusRunning),
        #[prost(message, tag="12")]
        Stopping(super::CanisterStatusStopping),
        #[prost(message, tag="13")]
        Stopped(super::CanisterStatusStopped),
    }
}
