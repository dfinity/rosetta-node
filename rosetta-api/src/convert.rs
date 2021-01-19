use crate::models;
use crate::models::{
    AccountIdentifier, Amount, ApiError, BlockIdentifier, Currency, Operation, Timestamp,
    TransactionIdentifier,
};
use crate::sync::HashedBlock;
use core::fmt::Display;
use dfn_candid::Candid;
use ic_types::messages::{HttpRequestEnvelope, HttpSubmitContent};
use ic_types::PrincipalId;
use ledger_canister::{
    BlockHeight, HashOf, ICPTs, SubmitArgs, Transaction, Transfer, DECIMAL_PLACES,
};
use on_wire::{FromWire, IntoWire};
use serde_json::map::Map;
use serde_json::{from_value, Value};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

/// This module converts from ledger_canister data structures to Rosetta data
/// structures

pub fn timestamp(timestamp: SystemTime) -> Result<Timestamp, ApiError> {
    timestamp
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_millis())
        .ok()
        .and_then(|x| i64::try_from(x).ok())
        .map(Timestamp::from)
        .ok_or(ApiError::InternalError(false, None))
}

// Since our blockchain doesn't have smart contracts all operations are always a
// single value
const STATUS: &str = "COMPLETED";
const TRANSACTION: &str = "TRANSACTION";
const MINT: &str = "MINT";
const BURN: &str = "BURN";

pub fn transaction(
    transaction: &Transfer,
    transaction_identifier: TransactionIdentifier,
) -> Result<models::Transaction, ApiError> {
    let operations = operations(transaction, true)?;
    Ok(models::Transaction::new(transaction_identifier, operations))
}

// This currently only takes a transation
pub fn operations(transaction: &Transfer, completed: bool) -> Result<Vec<Operation>, ApiError> {
    // The spec just says if there aren't smart contracts all statuses should
    // be the same
    let status = if completed {
        Some(STATUS.to_string())
    } else {
        None
    };

    let ops = match transaction {
        Transfer::Send { from, to, amount } => {
            let from_account = Some(account_identifier(from));
            let to_account = Some(account_identifier(to));
            let amount = i128::try_from(amount.get_doms())
                .map_err(|_| ApiError::InternalError(true, None))?;
            let db = Operation::new(
                0,
                TRANSACTION.to_string(),
                status.clone(),
                from_account,
                Some(signed_amount(-amount)),
            );
            let mut cr = Operation::new(
                1,
                TRANSACTION.to_string(),
                status,
                to_account,
                Some(signed_amount(amount)),
            );
            cr.related_operations = Some(vec![db.operation_identifier.clone()]);
            vec![db, cr]
        }
        // TODO include the destination in the metadata
        Transfer::Mint { to, amount, .. } => {
            let account = Some(account_identifier(to));
            let amount = Some(amount_(*amount)?);
            let op = Operation::new(0, MINT.to_string(), status, account, amount);
            vec![op]
        }
        Transfer::Burn { from, amount, .. } => {
            let amount = i128::try_from(amount.get_doms())
                .map_err(|_| ApiError::InternalError(true, None))?;
            let account = Some(account_identifier(from));
            let amount = Some(signed_amount(-amount));
            let op = Operation::new(0, BURN.to_string(), status, account, amount);
            vec![op]
        }
    };
    Ok(ops)
}

pub fn from_operations(ops: Vec<Operation>) -> Result<Vec<Transfer>, ApiError> {
    fn min_identifier_index(op: &Operation) -> i64 {
        let op_index = op.operation_identifier.index;
        let mut related_indicies: Vec<i64> = match &op.related_operations {
            Some(ops) => ops.iter().map(|id| id.index).collect(),
            None => Vec::new(),
        };
        related_indicies.push(op_index);
        *related_indicies
            .iter()
            .min()
            .expect("This is impossible because there is at least 1 element")
    }

    // Group related operations
    let mut related: HashMap<i64, Vec<Operation>> = HashMap::new();
    for o in ops.into_iter() {
        let min = min_identifier_index(&o);
        let entry = related.entry(min).or_insert_with(Vec::new);
        entry.push(o);
    }

    // Check that all values have the same _type and return it
    fn read_transaction(op: &Operation) -> Result<(i128, PrincipalId), String> {
        // let id = op.operation_identifier.clone();

        // Check the operation looks like part of a transaction
        let (amount, account_id) = match op {
            Operation {
                operation_identifier: _,
                related_operations: _,
                _type,
                account: Some(account),
                amount: Some(amount),
                coin_change: None,
                metadata: _,
                ..
            } => match &_type[..] {
                TRANSACTION => Ok((amount, account)),
                other => Err(format!(
                    "Fields _type and status Expected {:?}, but found {:?}",
                    (TRANSACTION, STATUS),
                    other
                )),
            },
            Operation { account: None, .. } | Operation { amount: None, .. } => {
                Err("Fields account and amount must both be populated".to_string())
            }
            Operation {
                coin_change: Some(_),
                ..
            } => Err("Coin changes are not permitted".to_string()),
        }?;

        let principal = principal_id(&account_id)?;
        let amount = from_amount(amount)?;
        Ok((amount, principal))
    }

    fn to_transaction(mut ops: Vec<Operation>) -> Result<Transfer, ApiError> {
        ops.sort_by_key(|v| v.operation_identifier.index);

        let handle_error = move |id| {
            move |e| {
                let msg = format!("In operation '{:?}': {}", id, e);
                ApiError::InvalidTransaction(false, into_error(msg))
            }
        };

        match &ops[..] {
            [op1, op2] => {
                let (db_amount, from) =
                    read_transaction(op1).map_err(handle_error(&op1.operation_identifier))?;
                let (cr_amount, to) =
                    read_transaction(op2).map_err(handle_error(&op2.operation_identifier))?;

                let error = move |msg| {
                    let msg = format!("Bad transaction in {:?} and {:?}: {}", op1, op2, msg);
                    let err = ApiError::InvalidTransaction(false, into_error(msg));
                    Err(err)
                };

                if db_amount != -cr_amount {
                    return error("Credit account + Debit amount must net to zero");
                }

                let amount = if cr_amount > 0 {
                    ICPTs::from_doms(cr_amount as u64)
                } else {
                    return error("Debit amount must be greater than zero");
                };

                if from == to {
                    return error("Transactions can't start and finish in the same place");
                }

                Ok(Transfer::Send { from, to, amount })
            }
            // TODO support Burn here
            wrong => Err(ApiError::InvalidTransaction(
                false,
                into_error(format!(
                    "Operations do not combine to make a recognizable transaction: {:?}",
                    wrong
                )),
            )),
        }
    }

    related
        .into_iter()
        .map(|(_k, v)| to_transaction(v))
        .collect()
}

pub fn amount_(amount: ICPTs) -> Result<Amount, ApiError> {
    let amount = amount.get_doms();
    Ok(Amount {
        value: format!("{}", amount),
        currency: icp(),
        metadata: None,
    })
}

pub fn signed_amount(amount: i128) -> Amount {
    Amount {
        value: format!("{}", amount),
        currency: icp(),
        metadata: None,
    }
}

pub fn from_amount(amount: &Amount) -> Result<i128, String> {
    match amount {
        Amount {
            value,
            currency,
            metadata: None,
        } if currency == &icp() => value.parse().map_err(|e| {
            format!(
                "Parsing amount failed, value field should be a number but was: {}",
                e
            )
        }),
        wrong => Err(format!("This value is not icp {:?}", wrong)),
    }
}
pub fn ledgeramount_from_amount(amount: &Amount) -> Result<ICPTs, String> {
    let inner = from_amount(amount)?;
    Ok(ICPTs::from_doms(inner as u64))
}

pub fn icp() -> Currency {
    Currency::new("ICP".to_string(), DECIMAL_PLACES)
}

pub fn block_id(block: &HashedBlock) -> Result<BlockIdentifier, ApiError> {
    let idx = i64::try_from(block.index).map_err(internal_error)?;
    Ok(BlockIdentifier::new(idx, from_hash(&block.hash)))
}

pub fn transaction_identifier(hash: &HashOf<Transaction>) -> TransactionIdentifier {
    TransactionIdentifier::new(format!("{}", hash))
}

pub fn account_identifier(uid: &PrincipalId) -> AccountIdentifier {
    AccountIdentifier::new(hex::encode(&uid.into_vec()))
}

pub fn principal_id(aid: &AccountIdentifier) -> Result<PrincipalId, String> {
    // TODO validate
    match hex::decode(aid.address.clone()) {
        Ok(vec) => Ok(PrincipalId::try_from(&vec).map_err(|e| e.to_string())?),
        Err(e) => Err(format!(
            "Account Identifer {} is not hex encoded: {}",
            aid.address, e
        )),
    }
}

const LAST_HEIGHT: &str = "last_height";

// Last hash is an option because there may be no blocks on the system
pub fn from_metadata(mut ob: models::Object) -> Result<BlockHeight, ApiError> {
    let v = ob
        .remove(LAST_HEIGHT)
        .ok_or(ApiError::InternalError(false, None))?;
    from_value(v).map_err(|_| ApiError::InternalError(false, None))
}

pub fn into_metadata(h: BlockHeight) -> models::Object {
    let mut m = Map::new();
    m.insert(LAST_HEIGHT.to_string(), Value::from(h));
    m
}

// This converts an error message to something that ApiError can consume
// This returns an option because it's what the error type expects, but it will
// always return Some
pub fn into_error(error_msg: String) -> Option<models::Object> {
    let mut m = Map::new();
    m.insert("error_message".to_string(), Value::from(error_msg));
    Some(m)
}

pub fn from_public_key(pk: models::PublicKey) -> Result<Vec<u8>, ApiError> {
    from_hex(pk.hex_bytes)
}

pub fn from_hex(hex: String) -> Result<Vec<u8>, ApiError> {
    hex::decode(hex).map_err(|e| {
        ApiError::InvalidRequest(false, into_error(format!("Hex could not be decoded {}", e)))
    })
}

pub fn to_hex(v: &[u8]) -> String {
    hex::encode(v)
}

pub fn transaction_id(
    signed_transaction: HttpRequestEnvelope<HttpSubmitContent>,
) -> Result<TransactionIdentifier, ApiError> {
    let update = match signed_transaction.content {
        HttpSubmitContent::Call { update } => update,
    };
    let from = PrincipalId::try_from(update.sender.0).map_err(|e| internal_error(e.to_string()))?;
    let (memo, amount, to, bh) = from_arg(update.arg.0)?;
    let created_at = bh.ok_or_else(|| internal_error(
        "A transaction ID cannot be generated from a constructed transaction without an explicit block height"
    ))?;

    let hash = Transaction::new(from, to, amount, memo, created_at).hash();

    Ok(transaction_identifier(&hash))
}

pub fn internal_error<D: Display>(msg: D) -> ApiError {
    ApiError::InternalError(false, into_error(format!("{}", msg)))
}

pub fn invalid_block_id<D: Display>(msg: D) -> ApiError {
    ApiError::InvalidBlockId(false, into_error(format!("{}", msg)))
}

pub fn account_from_public_key(pk: models::PublicKey) -> Result<AccountIdentifier, ApiError> {
    let pid = PrincipalId::new_self_authenticating(&from_hex(pk.hex_bytes)?);
    Ok(account_identifier(&pid))
}

// This is so I can keep track of where this conversion is done
pub fn from_arg(encoded: Vec<u8>) -> Result<SubmitArgs, ApiError> {
    Candid::from_bytes(encoded)
        .map_err(internal_error)
        .map(|Candid(c)| c)
}

pub fn to_arg(args: SubmitArgs) -> Vec<u8> {
    Candid(args).into_bytes().expect("Serialization failed")
}

pub fn from_hash<T>(hash: &HashOf<T>) -> String {
    format!("{}", *hash)
}

pub fn to_hash<T>(s: &str) -> Result<HashOf<T>, ApiError> {
    s.parse().map_err(|_| ApiError::InternalError(false, None))
}
