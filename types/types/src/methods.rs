//! This module contains a collection of types and structs that define the
//! various types of methods in the IC.

use crate::messages::CallContextId;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::state::canister_state_bits::v1 as pb;
use serde::{Deserialize, Serialize};
use std::{
    convert::{From, TryFrom},
    fmt,
};

/// Represents the types of methods that a Wasm module can export.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WasmMethod {
    /// An exported update method along with its name.
    ///
    /// Modifications by update calls are persisted upon successful execution.
    Update(String),

    /// An exported query method along with its name.
    ///
    /// Modifications by query calls are NOT persisted upon successful
    /// execution.
    Query(String),

    /// An exported system method. Unlike query or update method, there
    /// are a few fixed system methods as defined in `SystemMethod`.
    System(SystemMethod),
}

impl WasmMethod {
    pub fn name(&self) -> String {
        match self {
            WasmMethod::Update(name) => name.to_string(),
            WasmMethod::Query(name) => name.to_string(),
            WasmMethod::System(system_method) => system_method.to_string(),
        }
    }
}

impl fmt::Display for WasmMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            WasmMethod::Update(name) => write!(f, "canister_update {}", name),
            WasmMethod::Query(name) => write!(f, "canister_query {}", name),
            WasmMethod::System(system_method) => system_method.fmt(f),
        }
    }
}

impl TryFrom<String> for WasmMethod {
    type Error = String;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if name.starts_with("canister_update ") {
            // Take the part after the first space
            let parts: Vec<&str> = name.splitn(2, ' ').collect();
            Ok(WasmMethod::Update(parts[1].to_string()))
        } else if name.starts_with("canister_query ") {
            // Take the part after the first space
            let parts: Vec<&str> = name.splitn(2, ' ').collect();
            Ok(WasmMethod::Query(parts[1].to_string()))
        } else {
            match SystemMethod::try_from(name.as_ref()) {
                Ok(system_method) => Ok(WasmMethod::System(system_method)),
                _ => Err(format!("Cannot convert {} to WasmFunction.", name)),
            }
        }
    }
}

impl From<&WasmMethod> for pb::WasmMethod {
    fn from(method: &WasmMethod) -> Self {
        use pb::wasm_method::{SystemMethod as PbSystemMethod, WasmMethod as PbWasmMethod};

        match method {
            WasmMethod::Update(value) => Self {
                wasm_method: Some(PbWasmMethod::Update(value.clone())),
            },
            WasmMethod::Query(value) => Self {
                wasm_method: Some(PbWasmMethod::Query(value.clone())),
            },
            WasmMethod::System(value) => Self {
                wasm_method: Some(PbWasmMethod::System(match value {
                    SystemMethod::CanisterStart => PbSystemMethod::CanisterStart,
                    SystemMethod::CanisterInit => PbSystemMethod::CanisterInit,
                    SystemMethod::CanisterPreUpgrade => PbSystemMethod::CanisterPreUpgrade,
                    SystemMethod::CanisterPostUpgrade => PbSystemMethod::CanisterPostUpgrade,
                } as i32)),
            },
        }
    }
}

impl TryFrom<pb::WasmMethod> for WasmMethod {
    type Error = ProxyDecodeError;

    fn try_from(method: pb::WasmMethod) -> Result<Self, Self::Error> {
        use pb::wasm_method::{SystemMethod as PbSystemMethod, WasmMethod as PbWasmMethod};

        match try_from_option_field(method.wasm_method, "WasmMethod::wasm_method")? {
            PbWasmMethod::Update(update) => Ok(WasmMethod::Update(update)),
            PbWasmMethod::Query(query) => Ok(WasmMethod::Query(query)),
            PbWasmMethod::System(system) => {
                let method =
                    PbSystemMethod::from_i32(system).unwrap_or(PbSystemMethod::Unspecified);

                Ok(WasmMethod::System(match method {
                    PbSystemMethod::Unspecified => {
                        return Err(ProxyDecodeError::ValueOutOfRange {
                            typ: "WasmMethod::System",
                            err: system.to_string(),
                        })
                    }
                    PbSystemMethod::CanisterStart => SystemMethod::CanisterStart,
                    PbSystemMethod::CanisterInit => SystemMethod::CanisterInit,
                    PbSystemMethod::CanisterPreUpgrade => SystemMethod::CanisterPreUpgrade,
                    PbSystemMethod::CanisterPostUpgrade => SystemMethod::CanisterPostUpgrade,
                }))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SystemMethod {
    /// A system method for initializing a Wasm module.
    CanisterStart,
    /// A system method that is run when initializing a canister.
    CanisterInit,
    /// A system method that is run at the beginning of a canister upgrade.
    CanisterPreUpgrade,
    /// A system method that is run at the end of a canister upgrade.
    CanisterPostUpgrade,
}

impl TryFrom<&str> for SystemMethod {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "canister_pre_upgrade" => Ok(SystemMethod::CanisterPreUpgrade),
            "canister_post_upgrade" => Ok(SystemMethod::CanisterPostUpgrade),
            "canister_init" => Ok(SystemMethod::CanisterInit),
            "canister_start" => Ok(SystemMethod::CanisterStart),
            _ => Err(format!("Cannot convert {} to SystemMethod.", value)),
        }
    }
}

impl fmt::Display for SystemMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            SystemMethod::CanisterPreUpgrade => write!(f, "canister_pre_upgrade"),
            SystemMethod::CanisterPostUpgrade => write!(f, "canister_post_upgrade"),
            SystemMethod::CanisterInit => write!(f, "canister_init"),
            SystemMethod::CanisterStart => write!(f, "canister_start"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmClosure {
    pub func_idx: u32,
    pub env: u32,
}

impl WasmClosure {
    pub fn new(func_idx: u32, env: u32) -> Self {
        Self { func_idx, env }
    }
}

/// Every callback references the call context it belongs to. The callback
/// parameters are references to the success & error functions, plus their
/// arguments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Callback {
    pub call_context_id: CallContextId,
    pub on_reply: WasmClosure,
    pub on_reject: WasmClosure,
}

impl Callback {
    pub fn new(
        call_context_id: CallContextId,
        on_reply: WasmClosure,
        on_reject: WasmClosure,
    ) -> Self {
        Self {
            call_context_id,
            on_reply,
            on_reject,
        }
    }
}

impl From<&Callback> for pb::Callback {
    fn from(item: &Callback) -> Self {
        Self {
            call_context_id: item.call_context_id.get(),
            on_reply: Some(pb::WasmClosure {
                func_idx: item.on_reply.func_idx,
                env: item.on_reply.env,
            }),
            on_reject: Some(pb::WasmClosure {
                func_idx: item.on_reject.func_idx,
                env: item.on_reject.env,
            }),
        }
    }
}

impl TryFrom<pb::Callback> for Callback {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::Callback) -> Result<Self, Self::Error> {
        let on_reply: pb::WasmClosure =
            try_from_option_field(value.on_reply, "Callback::on_reply")?;
        let on_reject: pb::WasmClosure =
            try_from_option_field(value.on_reject, "Callback::on_reject")?;

        Ok(Self {
            call_context_id: CallContextId::from(value.call_context_id),
            on_reply: WasmClosure {
                func_idx: on_reply.func_idx,
                env: on_reply.env,
            },
            on_reject: WasmClosure {
                func_idx: on_reject.func_idx,
                env: on_reject.env,
            },
        })
    }
}

/// A reference to a callable function/method in a Wasm module, which can be:
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FuncRef {
    /// A method that a canister can export.
    Method(WasmMethod),

    /// A closure (index + env) pointing to the Wasm function table. Using
    /// indexes here is ok only as long as Wasm code cannot modify their
    /// tables, once that is possible we have to use Wasm `funcref`s.
    UpdateClosure(WasmClosure),

    QueryClosure(WasmClosure),
}
