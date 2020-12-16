use dfn_candid::{candid, candid_one, Candid};
use dfn_core::{api::caller, over, over_init};
use ic_types::PrincipalId;
use ledger_canister::*;

use std::collections::HashMap;

/// This takes a list of the initial state of balances for individual Principal
/// IDs and a minting canister.
/// The minting canister is given 2^64 - 1 tokens and it then transfers tokens
/// to addresses specified in the initial state. Currently this is the only way
/// to create tokens
fn init(minting_canister: PrincipalId, initial_values: Vec<(PrincipalId, ICPTs)>) {
    let initial_values: HashMap<PrincipalId, ICPTs> = initial_values.into_iter().collect();
    STATE
        .write()
        .unwrap()
        .from_init(initial_values, minting_canister);
}

/// This is the only operation that changes the state of the canister after
/// init. This creates a payment from the callers ID, to the specified recipient
/// with the specified amount of ICPTs. It returns the index of the resulting
/// transaction
fn send(
    memo: Memo,
    amount: ICPTs,
    to: PrincipalId,
    blockheight: Option<BlockHeight>,
) -> BlockHeight {
    let from = caller();
    let transfer = Transfer::Send { from, amount, to };
    add_payment(memo, transfer, blockheight)
}

/// This gives you the index of the last block added to the chain
// Certification isn't implemented yet
fn tip_of_chain() -> (Certification, BlockHeight) {
    let height = &STATE.read().unwrap().transactions.height();
    (0, *height)
}

fn block(block_height: BlockHeight) -> Option<Block> {
    STATE
        .read()
        .unwrap()
        .transactions
        .get(block_height)
        .cloned()
}

/// Get an account balance.
/// If the account does not exist it will return 0 ICPTs
fn account_balance(uid: PrincipalId) -> ICPTs {
    STATE
        .read()
        .unwrap()
        .balances
        .account_balance(&uid)
        .unwrap_or_else(ICPTs::zero)
}

#[export_name = "canister_init"]
fn main() {
    upgrade()
}

// We don't support upgrade, so just run init
#[export_name = "canister_post_upgrade"]
fn upgrade() {
    over_init(|Candid((minting_canister, initial_values))| init(minting_canister, initial_values))
}

#[export_name = "canister_update send"]
fn send_() {
    over(
        candid,
        |(transaction_id, amount, to, blockheight): SubmitArgs| {
            send(transaction_id, amount, to, blockheight)
        },
    );
}

#[export_name = "canister_query block"]
fn block_() {
    over(candid_one, block);
}

#[export_name = "canister_query tip_of_chain"]
fn tip_of_chain_() {
    over(candid, |()| tip_of_chain());
}

#[export_name = "canister_query account_balance"]
fn account_balance_() {
    over(candid, |(user_id,)| account_balance(user_id))
}
