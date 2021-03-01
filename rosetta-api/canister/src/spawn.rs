use ic_base_types::CanisterInstallMode;
use ic_types::{
    ic00::{CanisterIdRecord, InstallCodeArgs, Method, IC_00},
    CanisterId,
};

use on_wire::IntoWire;

pub async fn install_code<Arg: IntoWire>(
    canister_id: CanisterId,
    wasm_module: Vec<u8>,
    arg: Arg,
    memory_allocation: Option<usize>,
) {
    dfn_core::api::print("[spawn] install_code()");
    let install_code = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module,
        arg: arg.into_bytes().unwrap(),
        compute_allocation: None,
        memory_allocation: memory_allocation.map(candid::Nat::from),
        query_allocation: None,
    };
    dfn_core::api::call_no_reply(
        IC_00,
        &Method::InstallCode.to_string(),
        dfn_candid::candid::<(), (InstallCodeArgs,)>,
        (install_code,),
        dfn_core::api::Funds::zero(),
    )
    .unwrap()
}

pub async fn create_canister() -> CanisterId {
    dfn_core::api::print("[spawn] create_canister()");
    const NUMBER_OF_CYCLES: u64 = 10_000_000_000;
    let result: Result<CanisterIdRecord, _> = dfn_core::api::call_with_funds(
        IC_00,
        &Method::ProvisionalCreateCanisterWithCycles.to_string(),
        dfn_candid::candid_one,
        ic_types::ic00::ProvisionalCreateCanisterWithCyclesArgs::new(Some(NUMBER_OF_CYCLES)),
        dfn_core::api::Funds::new(NUMBER_OF_CYCLES, 0),
    )
    .await;
    dfn_core::api::print(format!("[spawn] create_canister() = {:?}", result));
    result.unwrap().get_canister_id()
}
