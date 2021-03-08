use dfn_candid::{candid, candid_one, CandidOne};
use dfn_core::{
    api::caller,
    api::{self, call_with_callbacks},
    over, over_init, printer, setup, stable, BytesS,
};
use ic_types::{CanisterId, PrincipalId};
use ledger_canister::*;
use on_wire::IntoWire;

use std::collections::{HashMap, VecDeque};

// Helper to print messages in magenta
fn print<S: std::convert::AsRef<str>>(s: S)
where
    yansi::Paint<S>: std::string::ToString,
{
    dfn_core::api::print(yansi::Paint::magenta(s).to_string());
}

/// Initialize the ledger canister
///
/// # Arguments
///
/// * `minting_account` -  The minting canister is given 2^64 - 1 tokens and it
///   then transfers tokens to addresses specified in the initial state.
///   Currently this is the only way to create tokens.
/// * `initial_values` - The list of accounts that will get balances at genesis.
///   This balances are paid out from the minting canister using 'Send'
///   transfers.
/// * `archive_canister` - The canister that manages the store of old blocks.
/// * `max_message_size_bytes` - The maximum message size that this subnet
///   supports. This is used for egressing block to the archive canister.
fn init(
    minting_account: PrincipalId,
    initial_values: HashMap<PrincipalId, ICPTs>,
    archive_canister: Option<CanisterId>,
    max_message_size_bytes: Option<usize>,
) {
    STATE
        .write()
        .unwrap()
        .from_init(initial_values, minting_account, dfn_core::api::now().into());
    *ARCHIVE_CANISTER.write().unwrap() = archive_canister;
    match max_message_size_bytes {
        None => {
            print(format!(
                "[ledger] init(): using default maximum message size: {}",
                MAX_MESSAGE_SIZE_BYTES.read().unwrap()
            ));
        }
        Some(max_message_size_bytes) => {
            *MAX_MESSAGE_SIZE_BYTES.write().unwrap() = max_message_size_bytes;
            print(format!(
                "[ledger] init(): using maximum message size: {}",
                max_message_size_bytes
            ));
        }
    }
}

/// This is the only operation that changes the state of the canister blocks and
/// balances after init. This creates a payment from the caller's account. It
/// returns the index of the resulting transaction
///
/// # Arguments
///
/// * `memo` -  A 8 byte "message" you can attach to transactions to help the
///   receiver disambiguate transactions
/// * `amount` - The number of ICPTs the recipient gets. The number of ICPTs
///   withdrawn is equal to the amount + the fee
/// * `fee` - The maximum fee that the sender is willing to pay. If the required
///   fee is greater than this the transaction will be rejected otherwise the
///   required fee will be paid. TODO automatically pay a lower fee if possible
///   [ROSETTA1-45]
/// * `from_subaccount` - The subaccount you want to draw funds from
/// * `to` - The account you want to send the funds to
/// * `to_subaccount` - The subaccount you want to send funds to
fn send(
    memo: Memo,
    amount: ICPTs,
    fee: ICPTs,
    from_subaccount: Option<[u8; 32]>,
    to: PrincipalId,
    to_subaccount: Option<[u8; 32]>,
    block_height: Option<BlockHeight>,
) -> BlockHeight {
    let from =
        account_identifier(caller(), from_subaccount).expect("Constructing 'from' address failed");
    let to = account_identifier(to, to_subaccount).expect("Constructing 'to' address failed");

    let minting_acc = STATE
        .read()
        .unwrap()
        .minting_account_id
        .expect("Minting canister id not initialized");

    let transfer = if from == minting_acc {
        assert_eq!(fee, ICPTs::ZERO, "Fee for minting should be zero");
        assert_ne!(
            to, minting_acc,
            "It is illegal to mint to a minting_account"
        );
        Transfer::Mint { to, amount }
    } else if to == minting_acc {
        assert_eq!(fee, ICPTs::ZERO, "Fee for burning should be zero");
        if amount < MIN_BURN_AMOUNT {
            panic!("Burns lower than {} are not allowed", MIN_BURN_AMOUNT);
        }
        Transfer::Burn { from, amount }
    } else {
        if fee != TRANSACTION_FEE {
            panic!("Transaction fee should be {}", TRANSACTION_FEE);
        }
        Transfer::Send {
            from,
            to,
            amount,
            fee,
        }
    };
    add_payment(memo, transfer, block_height)
}

/// You can notify a canister that you have made a payment to it. The
/// payment must have been made to the account of a canister and from the
/// callers account. You cannot notify a canister about a transaction it has
/// already been successfully notified of. If the canister rejects the
/// notification call it is not considered to have been notified.
///
/// # Arguments
///
/// * `block_height` -  The height of the block you would like to send a
///   notification about
/// * `to_canister` - The canister that received the payment
/// * `to_subaccount` - The subaccount that received the payment
pub fn notify(
    block_height: BlockHeight,
    max_fee: ICPTs,
    from_subaccount: Option<[u8; 32]>,
    to_canister: CanisterId,
    to_subaccount: Option<[u8; 32]>,
) {
    let caller_principal = caller();

    let expected_from = account_identifier(caller_principal, from_subaccount)
        .expect("Failed to construct 'from' account identifier");

    let expected_to = account_identifier(to_canister.get(), to_subaccount)
        .expect("Failed to construct 'to' account identifier");

    let block = STATE
        .read()
        .unwrap()
        .blocks
        .get(block_height)
        .unwrap_or_else(|| panic!("Failed to find a block at height {}", block_height))
        .clone();

    let (from, to, amount) = match block.transaction().transfer {
        Transfer::Send {
            from, to, amount, ..
        } => (from, to, amount),
        _ => panic!("Notification failed transfer must be of type send"),
    };

    assert_eq!(
        (from, to),
        (expected_from, expected_to),
        "sender and recipient must match the specified block"
    );

    let transaction_notification_args = TransactionNotification {
        from: caller_principal,
        from_subaccount,
        to: to_canister,
        to_subaccount,
        block_height,
        amount,
        memo: block.transaction().memo,
    };

    let bytes = candid::encode_one(transaction_notification_args)
        .expect("transaction notification serialization failed");

    // reply with () on success
    let on_reply = || api::reply(&CandidOne(()).into_bytes().unwrap());
    let on_reject = move || {
        // discards error which is better than a panic in a callback
        let _ = change_notification_state(block_height, false);
        api::reject(&format!(
            "Notification failed with message '{}'",
            api::reject_message()
        ));
    };

    change_notification_state(block_height, true)
        .expect("There is already an outstanding notification");

    let transfer = Transfer::Send {
        from,
        to,
        amount: ICPTs::ZERO,
        fee: max_fee,
    };
    let _ = add_payment(Memo(block_height), transfer, None);

    // We use this less easy method of
    let err_code = call_with_callbacks(
        to_canister,
        "transaction_notification",
        bytes.as_slice(),
        on_reply,
        on_reject,
    );
    if err_code != 0 {
        panic!("Unable to send transaction notification");
    }
}

/// This gives you the index of the last block added to the chain
// Certification isn't implemented yet
fn tip_of_chain() -> (Certification, BlockHeight) {
    let chain_length = &STATE.read().unwrap().blocks.last_block_index();
    (0, *chain_length)
}

fn block(block_height: BlockHeight) -> Option<RawBlock> {
    STATE
        .read()
        .unwrap()
        .blocks
        .get(block_height)
        .map(|block| block.encode())
}

/// Get an account balance.
/// If the account does not exist it will return 0 ICPTs
fn account_balance(account: PrincipalId, sub_account: Option<[u8; 32]>) -> ICPTs {
    let id = account_identifier(account, sub_account).expect("Account creation failed");
    STATE.read().unwrap().balances.account_balance(&id)
}

/// The total number of ICPTs not inside the minting canister
fn total_supply() -> ICPTs {
    STATE.read().unwrap().balances.total_supply()
}

/// Start and upgrade methods
#[export_name = "canister_init"]
fn main() {
    over_init(
        |CandidOne(LedgerCanisterInitPayload {
             minting_account,
             initial_values,
             archive_canister,
             max_message_size_bytes,
         })| {
            init(
                minting_account,
                initial_values,
                archive_canister,
                max_message_size_bytes,
            )
        },
    )
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    over_init(|_: BytesS| {
        let bytes = stable::get();
        *STATE.write().unwrap() = State::decode(&bytes).expect("Decoding stable memory failed");
    })
}

#[export_name = "canister_pre_upgrade"]
fn pre_upgrade() {
    setup::START.call_once(|| {
        printer::hook();
    });

    let bytes = &STATE
        .read()
        // This should never happen, but it's better to be safe than sorry
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .encode();
    stable::set(&bytes);
}

async fn archive_blocks(age: std::time::Duration) {
    match *ARCHIVE_CANISTER.read().unwrap() {
        None => print("[ledger] archive canister not set. skipping archive_blocks()"),
        Some(archive_canister) => {
            let num_blocks_before = STATE.read().unwrap().blocks.inner.len();
            let mut blocks_to_archive: VecDeque<RawBlock> = split_off_older_than(age)
                .iter()
                .map(|block| block.encode())
                .collect();
            let num_blocks_after = STATE.read().unwrap().blocks.inner.len();
            print(format!(
                "[ledger] archive_blocks(): blocks before split: {}, blocks to archive: {}, blocks after split: {}",
                num_blocks_before,
                blocks_to_archive.len(),
                num_blocks_after,
            ));

            while !blocks_to_archive.is_empty() {
                let chunk = get_chain_prefix(
                    &mut blocks_to_archive,
                    *MAX_MESSAGE_SIZE_BYTES.read().unwrap(),
                );
                assert!(!chunk.is_empty());

                print(format!(
                    "[ledger] archiving a chunk of blocks of size {} on canister {}",
                    chunk.len(),
                    archive_canister.clone()
                ));

                let () = dfn_core::api::call(
                    archive_canister,
                    "archive_blocks",
                    dfn_candid::candid_one,
                    chunk,
                )
                .await
                .unwrap();
            }
        }
    }
}

fn get_blocks(offset: usize, length: usize) -> Vec<RawBlock> {
    let blocks = &STATE.read().unwrap().blocks.inner;
    let start = std::cmp::min(offset, blocks.len());
    let end = std::cmp::min(start + length, blocks.len());
    let blocks: Vec<RawBlock> = blocks[start..end]
        .iter()
        .map(|block| block.encode())
        .collect();
    print(format!(
        "[ledger] get_blocks(offset={}, length={}): returning {} blocks",
        offset,
        length,
        blocks.len()
    ));
    blocks
}

/// Canister endpoints
#[export_name = "canister_update send"]
fn send_() {
    over(
        candid_one,
        |SendArgs {
             memo,
             amount,
             fee,
             from_subaccount,
             to,
             to_subaccount,
             block_height,
         }| {
            send(
                memo,
                amount,
                fee,
                from_subaccount,
                to,
                to_subaccount,
                block_height,
            )
        },
    );
}

#[export_name = "canister_update notify"]
fn notify_() {
    // we use over_init because it doesn't reply automatically so we can do explicit
    // replys in the callback
    over_init(
        |CandidOne(NotifyCanisterArgs {
             block_height,
             max_fee,
             from_subaccount,
             to_canister,
             to_subaccount,
         })| {
            notify(
                block_height,
                max_fee,
                from_subaccount,
                to_canister,
                to_subaccount,
            )
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
    over(
        candid_one,
        |AccountBalanceArgs {
             account,
             sub_account,
         }| account_balance(account, sub_account),
    )
}

#[export_name = "canister_query total_supply"]
fn total_supply_() {
    over(candid_one, |_: TotalSupplyArgs| total_supply())
}

#[export_name = "canister_update archive_blocks"]
fn archive_blocks_() {
    dfn_core::over_async(candid_one, archive_blocks);
}

#[export_name = "canister_query get_blocks"]
fn get_blocks_() {
    over(candid, |(offset, len)| get_blocks(offset, len));
}
