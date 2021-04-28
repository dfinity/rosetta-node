use candid::CandidType;
use cycles_minting_canister::*;
use dfn_candid::{candid_one, CandidOne};
use dfn_core::{api::caller, over, over_async_may_reject, over_init, stable, BytesS};
use dfn_protobuf::protobuf;
use ic_types::ic00::{CanisterIdRecord, Method, IC_00};
use ic_types::{CanisterId, Cycles, PrincipalId, SubnetId};
use lazy_static::lazy_static;
use ledger_canister::{
    AccountIdentifier, BlockHeight, ICPTs, Memo, SendArgs, TransactionNotification,
    TransactionNotificationResult, TRANSACTION_FEE,
};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::sync::RwLock;

#[derive(Serialize, Deserialize, Clone, CandidType, Eq, PartialEq, Debug)]
struct State {
    ledger_canister_id: CanisterId,

    governance_canister_id: CanisterId,

    /// Account used to burn funds.
    minting_account_id: Option<AccountIdentifier>,

    authorized_subnets: BTreeMap<PrincipalId, Vec<SubnetId>>,

    default_subnets: Vec<SubnetId>,

    /// How many cycles 1 XDR is worth.
    cycles_per_xdr: Cycles,
}

impl State {
    fn default() -> Self {
        Self {
            ledger_canister_id: CanisterId::ic_00(),
            governance_canister_id: CanisterId::ic_00(),
            minting_account_id: None,
            authorized_subnets: BTreeMap::new(),
            default_subnets: vec![],
            cycles_per_xdr: 1_538_461_538_461u128.into(), // 1T cycles = 0.65 XDR
        }
    }

    fn encode(&self) -> Vec<u8> {
        candid::encode_one(&self).unwrap()
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        candid::decode_one(&bytes)
            .map_err(|err| format!("Decoding cycles minting canister state failed: {}", err))
    }
}

lazy_static! {
    static ref STATE: RwLock<State> = RwLock::new(State::default());
}

// Helper to print messages in yellow
fn print<S: std::convert::AsRef<str>>(s: S)
where
    yansi::Paint<S>: std::string::ToString,
{
    dfn_core::api::print(yansi::Paint::yellow(s).to_string());
}

#[export_name = "canister_init"]
fn main() {
    over_init(|CandidOne(args)| init(args))
}

fn init(args: CyclesCanisterInitPayload) {
    print(format!(
        "[cycles] init() with ledger canister {}, governance canister {} and minting account {}",
        args.ledger_canister_id,
        args.governance_canister_id,
        args.minting_account_id
            .map(|x| x.to_string())
            .unwrap_or_else(|| "<none>".to_string())
    ));

    let mut state = STATE.write().unwrap();

    state.ledger_canister_id = args.ledger_canister_id;
    state.governance_canister_id = args.governance_canister_id;
    state.minting_account_id = args.minting_account_id;
}

#[export_name = "canister_update set_authorized_subnetwork_list"]
fn set_authorized_subnetwork_list_() {
    over(
        candid_one,
        |SetAuthorizedSubnetworkListArgs { who, subnets }| {
            set_authorized_subnetwork_list(who, subnets)
        },
    )
}

/// Set the list of subnets in which a principal is allowed to create
/// canisters. If `subnets` is empty, remove the mapping for a
/// principal. If `who` is None, set the default list of subnets.
fn set_authorized_subnetwork_list(who: Option<PrincipalId>, subnets: Vec<SubnetId>) {
    let mut state = STATE.write().unwrap();

    let governance_canister_id = state.governance_canister_id;

    if CanisterId::new(caller()) != Ok(governance_canister_id) {
        panic!("Only the governance canister can set authorized subnetwork lists.");
    }

    if let Some(who) = who {
        if subnets.is_empty() {
            print(format!("[cycles] removing subnet list for {}", who));
            state.authorized_subnets.remove(&who);
        } else {
            print(format!("[cycles] setting subnet list for {}", who));
            state.authorized_subnets.insert(who, subnets);
        }
    } else {
        print("[cycles] setting default subnet list");
        state.default_subnets = subnets;
    }
}

#[export_name = "canister_update transaction_notification"]
fn transaction_notification_() {
    over_async_may_reject(protobuf, transaction_notification)
}

async fn transaction_notification(
    tn: TransactionNotification,
) -> Result<TransactionNotificationResult, String> {
    let caller = caller();

    print(format!(
        "[cycles] notified about transaction {:?} by {}",
        tn, caller
    ));

    let ledger_canister_id = STATE.read().unwrap().ledger_canister_id;

    if CanisterId::new(caller) != Ok(ledger_canister_id) {
        return Err(format!(
            "This canister can only be notified by the ledger canister ({}), not by {}.",
            ledger_canister_id, caller
        ));
    }

    if tn.memo == MEMO_CREATE_CANISTER {
        let controller = (&tn
            .to_subaccount
            .ok_or_else(|| "Reserving requires a principal.".to_string())?)
            .try_into()
            .map_err(|err| format!("Cannot parse subaccount: {}", err))?;

        let xdr_permyriad_per_icp = get_icp_xdr_conversion_rate().await;

        let cycles = IcptsToCycles {
            xdr_permyriad_per_icp,
            cycles_per_xdr: STATE.read().unwrap().cycles_per_xdr,
        }
        .to_cycles(tn.amount);

        print(format!(
            "Creating canister with controller {} in block {} with {} cycles.",
            controller, tn.block_height, cycles,
        ));

        // Create the canister. If this fails, refund. Either way,
        // return a TransactionNotificationResult so that the
        // notification cannot be retried.
        let res = create_canister(controller, cycles).await;

        let refund_block = burn_or_refund(
            res.is_ok(),
            CREATE_CANISTER_REFUND_FEE,
            &tn,
            &ledger_canister_id,
        )
        .await?;

        let res: CreateCanisterResult = res.map_err(|err| (err, refund_block));

        Ok(TransactionNotificationResult::encode(res)?)
    } else if tn.memo == MEMO_TOP_UP_CANISTER {
        let canister_id = (&tn
            .to_subaccount
            .ok_or_else(|| "Topping up requires a subaccount.".to_string())?)
            .try_into()
            .map_err(|err| format!("Cannot parse subaccount: {}", err))?;

        let xdr_permyriad_per_icp = get_icp_xdr_conversion_rate().await;

        let cycles = IcptsToCycles {
            xdr_permyriad_per_icp,
            cycles_per_xdr: STATE.write().unwrap().cycles_per_xdr,
        }
        .to_cycles(tn.amount);

        print(format!(
            "Topping up canister {} by {} cycles.",
            canister_id, cycles
        ));

        let res = deposit_cycles(canister_id, cycles).await;

        let refund_block = burn_or_refund(
            res.is_ok(),
            TOP_UP_CANISTER_REFUND_FEE,
            &tn,
            &ledger_canister_id,
        )
        .await?;

        let res: TopUpCanisterResult = res.map_err(|err| (err, refund_block));

        Ok(TransactionNotificationResult::encode(res)?)
    } else {
        Err(format!(
            "Don't know what to do with transaction with memo {}.",
            tn.memo.0
        ))
    }
}

async fn burn_or_refund(
    is_ok: bool,
    extra_fee: ICPTs,
    tn: &TransactionNotification,
    ledger_canister_id: &CanisterId,
) -> Result<Option<BlockHeight>, String> {
    if is_ok {
        burn_and_log(
            &tn,
            (tn.amount - TRANSACTION_FEE).unwrap(),
            &ledger_canister_id,
        )
        .await;
        Ok(None)
    } else {
        refund(&tn, &ledger_canister_id, extra_fee).await
    }
}

/// Burn funds and log but ignore any errors. When canister creation /
/// topping up succeeded, we don't want to reject the transaction
/// notification because then it could be retried.
async fn burn_and_log(
    tn: &TransactionNotification,
    amount: ICPTs,
    ledger_canister_id: &CanisterId,
) {
    if let Err(err) = burn(tn, amount, ledger_canister_id).await {
        print(format!("Burning {} ICPTs failed: {}", tn.amount, err));
    }
}

/// Burn the funds for canister creation or top up to prevent
/// accumulating a lot of dead accounts on the ledger.
async fn burn(
    tn: &TransactionNotification,
    amount: ICPTs,
    ledger_canister_id: &CanisterId,
) -> Result<(), String> {
    if let Some(minting_account_id) = STATE.read().unwrap().minting_account_id {
        let send_args = SendArgs {
            memo: Memo::default(),
            amount,
            fee: ICPTs::ZERO,
            from_subaccount: tn.to_subaccount,
            to: minting_account_id,
            created_at_time: None,
        };

        let res: Result<BlockHeight, (Option<i32>, String)> =
            dfn_core::api::call(*ledger_canister_id, "send_pb", protobuf, send_args.clone()).await;

        let block = res.map_err(|(code, msg)| {
            format!(
                "Burning of {} ICPTs from {} failed with code {}: {:?}",
                send_args.amount,
                tn.from,
                code.unwrap_or_default(),
                msg
            )
        })?;

        print(format!(
            "Burning of {} ICPTs from {} done in block {}.",
            send_args.amount, tn.from, block
        ));
    }

    Ok(())
}

/// Send the funds for canister creation or top up back to the sender,
/// minus the transaction fee (which is gone) and the fee for the
/// action (which is burned). Returns the index of the block in which
/// the refund was done.
async fn refund(
    tn: &TransactionNotification,
    ledger_canister_id: &CanisterId,
    extra_fee: ICPTs,
) -> Result<Option<BlockHeight>, String> {
    let mut refund_block_index = None;

    // Don't refund a negative amount.
    let amount_minus_fee = if let Ok(amount) = tn.amount - TRANSACTION_FEE {
        amount
    } else {
        return Ok(None);
    };

    let (refunded, burned) = if let Ok(amount) = amount_minus_fee - extra_fee {
        (amount, extra_fee)
    } else {
        (ICPTs::ZERO, amount_minus_fee)
    };

    assert_eq!(Ok(amount_minus_fee), refunded + burned);

    if refunded != ICPTs::ZERO {
        let send_args = SendArgs {
            memo: Memo::default(),
            amount: refunded,
            fee: TRANSACTION_FEE,
            from_subaccount: tn.to_subaccount,
            to: AccountIdentifier::new(tn.from, tn.from_subaccount),
            created_at_time: None,
        };

        let res: Result<BlockHeight, (Option<i32>, String)> =
            dfn_core::api::call(*ledger_canister_id, "send_pb", protobuf, send_args.clone()).await;

        let block = res.map_err(|(code, msg)| {
            format!(
                "Refund to {} failed with code {}: {:?}",
                send_args.to,
                code.unwrap_or_default(),
                msg
            )
        })?;

        print(format!(
            "Refund to {} done in block {}.",
            send_args.to, block
        ));

        refund_block_index = Some(block);
    }

    if burned != ICPTs::ZERO {
        burn_and_log(tn, burned, ledger_canister_id).await;
    }

    Ok(refund_block_index)
}

async fn deposit_cycles(canister_id: CanisterId, cycles: Cycles) -> Result<(), String> {
    let res: Result<(), (Option<i32>, String)> = dfn_core::api::call_with_funds(
        IC_00,
        &Method::DepositCycles.to_string(),
        dfn_candid::candid_multi_arity,
        (CanisterIdRecord::from(canister_id),),
        dfn_core::api::Funds::new(cycles.into(), 0),
    )
    .await;

    res.map_err(|(code, msg)| {
        format!(
            "Depositing cycles failed with code {}: {:?}",
            code.unwrap_or_default(),
            msg
        )
    })?;

    Ok(())
}

async fn create_canister(controller_id: PrincipalId, cycles: Cycles) -> Result<CanisterId, String> {
    let subnets = get_permuted_subnets_for(&controller_id).await?;

    let mut last_err = None;

    for subnet_id in subnets {
        let result: Result<CanisterIdRecord, _> = dfn_core::api::call_with_funds(
            subnet_id.into(),
            &Method::CreateCanister.to_string(),
            dfn_candid::candid_one,
            (),
            dfn_core::api::Funds::new(cycles.get().try_into().unwrap(), 0),
        )
        .await;

        let canister_id = match result {
            Ok(canister_id) => canister_id.get_canister_id(),
            Err((code, msg)) => {
                let err = format!(
                    "Creating canister in subnet {} failed with code {}: {}",
                    subnet_id,
                    code.unwrap_or_default(),
                    msg
                );
                print(format!("[cycles] {}", err));
                last_err = Some(err);
                continue;
            }
        };

        print(format!(
            "[cycles] created canister {} in subnet {}",
            canister_id, subnet_id
        ));

        let res: Result<(), (Option<i32>, String)> = dfn_core::api::call(
            IC_00,
            &Method::SetController.to_string(),
            dfn_candid::candid_multi_arity,
            (ic_types::ic00::SetControllerArgs::new(
                canister_id,
                controller_id,
            ),),
        )
        .await;

        res.map_err(|(code, msg)| {
            format!(
                "Setting controller failed with code {}: {:?}",
                code.unwrap_or_default(),
                msg
            )
        })?;

        // (ROSETTA1-71): Set the controller atomically, when a
        // canister is created, to avoid dealing with error conditions
        // when setting the controller fails.

        return Ok(canister_id);
    }

    Err(last_err.unwrap_or_else(|| "No subnets in which to create a canister.".to_owned()))
}

/// Return the list of subnets in which this controller is allowed to create
/// canisters
async fn get_permuted_subnets_for(controller_id: &PrincipalId) -> Result<Vec<SubnetId>, String> {
    let state = STATE.read().unwrap();
    let mut subnets = if let Some(subnets) = state.authorized_subnets.get(controller_id) {
        subnets.clone()
    } else {
        state.default_subnets.clone()
    };

    let mut rng = get_rng().await?;
    subnets.shuffle(&mut rng);

    Ok(subnets)
}

async fn get_rng() -> Result<StdRng, String> {
    let res: Result<Vec<u8>, (Option<i32>, String)> = dfn_core::api::call(
        IC_00,
        &Method::RawRand.to_string(),
        dfn_candid::candid_one,
        (),
    )
    .await;

    let bytes = res.map_err(|(code, msg)| {
        format!(
            "Getting random bytes failed with code {}: {:?}",
            code.unwrap_or_default(),
            msg
        )
    })?;

    Ok(StdRng::from_seed(bytes[0..32].try_into().unwrap()))
}

async fn get_icp_xdr_conversion_rate() -> u64 {
    match ic_nns_common::registry::get_icp_xdr_conversion_rate_record().await {
        None => panic!("ICP/XDR conversion rate is not available."),
        Some((rate_record, _)) => rate_record.xdr_permyriad_per_icp,
    }
}

#[export_name = "canister_pre_upgrade"]
fn pre_upgrade() {
    let bytes = &STATE
        .read()
        // This should never happen, but it's better to be safe than sorry
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .encode();
    print(format!(
        "[cycles] serialized state prior to upgrade ({} bytes)",
        bytes.len(),
    ));
    stable::set(&bytes);
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    over_init(|_: BytesS| {
        let bytes = stable::get();
        print(format!(
            "[cycles] deserializing state after upgrade ({} bytes)",
            bytes.len(),
        ));
        *STATE.write().unwrap() = State::decode(&bytes).unwrap();
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_encode() {
        let mut state = State::default();
        state.minting_account_id = Some(AccountIdentifier::new(
            PrincipalId::new_user_test_id(1),
            None,
        ));
        state.authorized_subnets.insert(
            PrincipalId::new_user_test_id(2),
            vec![SubnetId::from(PrincipalId::new_subnet_test_id(3))],
        );
        state.default_subnets = vec![SubnetId::from(PrincipalId::new_subnet_test_id(123))];

        let bytes = state.encode();

        let state2 = State::decode(&bytes).unwrap();

        assert_eq!(state, state2);
    }
}
