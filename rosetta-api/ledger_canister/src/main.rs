use dfn_candid::{candid_one, CandidOne};
use dfn_core::{
    api::{self, arg_data, call_with_callbacks},
    api::{caller, data_certificate, set_certified_data},
    over, over_init, printer, setup, stable, BytesS,
};
use dfn_protobuf::{protobuf, ProtoBuf};
use ic_types::CanisterId;
use ledger_canister::*;
use on_wire::{FromWire, IntoWire, NewType};
use std::time::Duration;

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
    minting_account: AccountIdentifier,
    initial_values: HashMap<AccountIdentifier, ICPTs>,
    max_message_size_bytes: Option<usize>,
    transaction_window: Option<Duration>,
    archive_options: Option<ArchiveOptions>,
) {
    print(format!(
        "[ledger] init(): minting account is {}",
        minting_account
    ));
    LEDGER.write().unwrap().from_init(
        initial_values,
        minting_account,
        dfn_core::api::now().into(),
        transaction_window,
    );
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
    set_certified_data(
        &LEDGER
            .read()
            .unwrap()
            .blockchain
            .last_hash
            .map(|h| h.into_bytes())
            .unwrap_or([0u8; 32]),
    );

    if let Some(archive_options) = archive_options {
        LEDGER.write().unwrap().blockchain.archive = Some(archive::Archive::new(archive_options))
    }
}

fn add_payment(
    memo: Memo,
    transfer: Transfer,
    created_at_time: Option<TimeStamp>,
) -> (BlockHeight, HashOf<EncodedBlock>) {
    let (height, hash) = ledger_canister::add_payment(memo, transfer, created_at_time);
    set_certified_data(&hash.into_bytes());
    (height, hash)
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
async fn send(
    memo: Memo,
    amount: ICPTs,
    fee: ICPTs,
    from_subaccount: Option<Subaccount>,
    to: AccountIdentifier,
    created_at_time: Option<TimeStamp>,
) -> BlockHeight {
    let from = AccountIdentifier::new(caller(), from_subaccount);

    let minting_acc = LEDGER
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
    let (height, _) = add_payment(memo, transfer, created_at_time);
    // Don't put anything that could ever trap after this call or people using this
    // endpoint. If something did panic the payment would appear to fail, but would
    // actually succeed on chain.
    archive_blocks(2000, 1000).await;
    height
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
    from_subaccount: Option<Subaccount>,
    to_canister: CanisterId,
    to_subaccount: Option<Subaccount>,
    notify_using_protobuf: bool,
) {
    let caller_principal = caller();

    let expected_from = AccountIdentifier::new(caller_principal, from_subaccount);

    let expected_to = AccountIdentifier::new(to_canister.get(), to_subaccount);

    let raw_block = LEDGER
        .read()
        .unwrap()
        .blockchain
        .get(block_height)
        .unwrap_or_else(|| panic!("Failed to find a block at height {}", block_height))
        .clone();

    let block = raw_block.decode().unwrap();

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

    let bytes = if notify_using_protobuf {
        ProtoBuf(transaction_notification_args)
            .into_bytes()
            .expect("transaction notification serialization failed")
    } else {
        candid::encode_one(transaction_notification_args)
            .expect("transaction notification serialization failed")
    };

    // propagate the response from 'to_canister' on success
    let on_reply = if notify_using_protobuf {
        || {
            let reply: TransactionNotificationResult =
                ProtoBuf::from_bytes(arg_data()).unwrap().into_inner();
            reply.check_size().unwrap();
            api::reply(&ProtoBuf(reply).into_bytes().unwrap());
        }
    } else {
        || {
            let reply: TransactionNotificationResult =
                CandidOne::from_bytes(arg_data()).unwrap().into_inner();
            reply.check_size().unwrap();
            api::reply(&CandidOne(reply).into_bytes().unwrap());
        }
    };
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
    add_payment(Memo(block_height), transfer, None);

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
/// together with certification
fn tip_of_chain() -> TipOfChainRes {
    let last_block_idx = &LEDGER
        .read()
        .unwrap()
        .blockchain
        .chain_length()
        .checked_sub(1)
        .unwrap();
    let certification = data_certificate();
    TipOfChainRes {
        certification,
        tip_index: *last_block_idx,
    }
}

// This is going away and being replaced by getblocks
fn block(block_index: BlockHeight) -> Option<Result<EncodedBlock, CanisterId>> {
    let state = LEDGER.read().unwrap();
    if block_index < state.blockchain.num_archived_blocks() {
        // The block we are looking for better be in the archive because it has
        // a height smaller than the number of blocks we've archived so far
        let result = state
            .find_block_in_archive(block_index)
            .expect("block not found in the archive");
        Some(Err(result))
    // Or the block may be in the ledger, or the block may not exist
    } else {
        print(format!(
            "[ledger] Checking the ledger for block [{}]",
            block_index
        ));
        match state.blockchain.get(block_index).cloned() {
            // Block in the ledger
            Some(block) => Some(Ok(block)),
            // Not in the ledger and not in the archive. Thus, does not exist
            None => None,
        }
    }
}

/// Get an account balance.
/// If the account does not exist it will return 0 ICPTs
fn account_balance(account: AccountIdentifier) -> ICPTs {
    LEDGER.read().unwrap().balances.account_balance(&account)
}

/// The total number of ICPTs not inside the minting canister
fn total_supply() -> ICPTs {
    LEDGER.read().unwrap().balances.total_supply()
}

/// Start and upgrade methods
#[export_name = "canister_init"]
fn main() {
    over_init(
        |CandidOne(LedgerCanisterInitPayload {
             minting_account,
             initial_values,
             max_message_size_bytes,
             transaction_window,
             archive_options,
         })| {
            init(
                minting_account,
                initial_values,
                max_message_size_bytes,
                transaction_window,
                archive_options,
            )
        },
    )
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    over_init(|_: BytesS| {
        let bytes = stable::get();
        *LEDGER.write().unwrap() = Ledger::decode(&bytes).expect("Decoding stable memory failed");
        set_certified_data(
            &LEDGER
                .read()
                .unwrap()
                .blockchain
                .last_hash
                .map(|h| h.into_bytes())
                .unwrap_or([0u8; 32]),
        );
    })
}

#[export_name = "canister_pre_upgrade"]
fn pre_upgrade() {
    setup::START.call_once(|| {
        printer::hook();
    });

    let bytes = &LEDGER
        .read()
        // This should never happen, but it's better to be safe than sorry
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .encode();
    stable::set(&bytes);
}

/// Upon reaching a `trigger_threshold` we will archive `num_blocks`. For
/// instance, archive_blocks(2000, 1000) will trigger when there are 2000 blocks
/// in the ledger and it will archive 1000 oldest bocks, leaving 1000 blocks in
/// the ledger itself.
async fn archive_blocks(trigger_threshold: usize, num_blocks: usize) {
    let mut state = LEDGER.write().unwrap();
    if state.blockchain.archive.is_none() {
        print("[ledger] archive not enabled. skipping archive_blocks()");
        return;
    }

    let num_blocks_before = state.blockchain.num_unarchived_blocks();

    if (num_blocks_before as usize) < trigger_threshold {
        return;
    }

    let mut blocks_to_archive: VecDeque<EncodedBlock> =
        state.split_off_blocks_to_archive(num_blocks);

    let num_blocks_after = state.blockchain.num_unarchived_blocks();
    print(format!(
        "[ledger] archive_blocks(): trigger_threshold: {}, num_blocks: {}, blocks before split: {}, blocks to archive: {}, blocks after split: {}",
        trigger_threshold,
        num_blocks,
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
            "[ledger] archiving a chunk of blocks of size {}",
            chunk.len(),
        ));

        state
            .blockchain
            .archive
            .as_mut()
            .unwrap()
            .archive_blocks(VecDeque::from(chunk))
            .await
    }
}

/// Canister endpoints
#[export_name = "canister_update send_pb"]
fn send_() {
    dfn_core::over_async(
        protobuf,
        |SendArgs {
             memo,
             amount,
             fee,
             from_subaccount,
             to,
             created_at_time,
         }| { send(memo, amount, fee, from_subaccount, to, created_at_time) },
    );
}

/// Do not use call this from code, this is only here so dfx has something to
/// call when making a payment. This will be changed in ways that are not
/// backwards compatible with previous interfaces.
///
/// I STRONGLY recommend that you use "send_pb" instead.
#[export_name = "canister_update send_dfx"]
fn send_dfx_() {
    dfn_core::over_async(
        candid_one,
        |SendArgs {
             memo,
             amount,
             fee,
             from_subaccount,
             to,
             created_at_time,
         }| { send(memo, amount, fee, from_subaccount, to, created_at_time) },
    );
}

#[export_name = "canister_update notify_pb"]
fn notify_() {
    // we use over_init because it doesn't reply automatically so we can do explicit
    // replys in the callback
    over_init(
        |ProtoBuf(NotifyCanisterArgs {
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
                true,
            )
        },
    );
}

/// See caveats of use on send_dfx
#[export_name = "canister_update notify_dfx"]
fn notify_dfx_() {
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
                false,
            )
        },
    );
}

#[export_name = "canister_query block_pb"]
fn block_() {
    dfn_core::over(protobuf, |BlockArg(height)| BlockRes(block(height)));
}

#[export_name = "canister_query tip_of_chain_pb"]
fn tip_of_chain_() {
    over(protobuf, |protobuf::TipOfChainRequest {}| tip_of_chain());
}

#[export_name = "canister_query get_archive_index_pb"]
fn get_archive_index_() {
    over(protobuf, |()| {
        let state = LEDGER.read().unwrap();
        let entries = match &state.blockchain.archive {
            None => vec![],
            Some(archive) => archive
                .index()
                .into_iter()
                .map(
                    |((height_from, height_to), canister_id)| protobuf::ArchiveIndexEntry {
                        height_from,
                        height_to,
                        canister_id: Some(canister_id.get()),
                    },
                )
                .collect(),
        };
        protobuf::ArchiveIndexResponse { entries }
    });
}

#[export_name = "canister_query account_balance_pb"]
fn account_balance_() {
    over(protobuf, |AccountBalanceArgs { account }| {
        account_balance(account)
    })
}

/// See caveats of use on send_dfx
#[export_name = "canister_query account_balance_dfx"]
fn account_balance_dfx_() {
    over(candid_one, |AccountBalanceArgs { account }| {
        account_balance(account)
    })
}

#[export_name = "canister_query total_supply_pb"]
fn total_supply_() {
    over(protobuf, |_: TotalSupplyArgs| total_supply())
}

#[export_name = "canister_update archive_blocks"]
fn archive_blocks_() {
    dfn_core::over_async(dfn_candid::candid, |(threshold, num_blocks)| {
        archive_blocks(threshold, num_blocks)
    });
}

/// Get multiple blocks by *offset into the container* (not BlockHeight) and
/// length. Note that this simply iterates the blocks available in the Ledger
/// without taking into account the archive. For example, if the ledger contains
/// blocks with heights [100, 199] then iter_blocks(0, 1) will return the block
/// with height 100.
#[export_name = "canister_query iter_blocks_pb"]
fn iter_blocks_() {
    over(protobuf, |IterBlocksArgs { start, length }| {
        let blocks = &LEDGER.read().unwrap().blockchain.blocks;
        ledger_canister::iter_blocks(&blocks, start, length)
    });
}

/// Get multiple blocks by BlockHeight and length. If the query is outside the
/// range stored in the Node the result is an error.
#[export_name = "canister_query get_blocks_pb"]
fn get_blocks_() {
    over(protobuf, |GetBlocksArgs { start, length }| {
        let blockchain: &Blockchain = &LEDGER.read().unwrap().blockchain;
        let start_offset = blockchain.num_archived_blocks();
        ledger_canister::get_blocks(&blockchain.blocks, start_offset, start, length)
    });
}

#[export_name = "canister_query get_nodes"]
fn get_nodes_() {
    dfn_core::over(dfn_candid::candid, |()| -> Vec<CanisterId> {
        LEDGER
            .read()
            .unwrap()
            .blockchain
            .archive
            .as_ref()
            .map(|archive| archive.nodes().to_vec())
            .unwrap_or_default()
    });
}
