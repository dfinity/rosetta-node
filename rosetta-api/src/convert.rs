use crate::ledger_canister::{Hash, Transaction, UserID};
use crate::ledger_client::BlockInfo;
use crate::models;
use crate::models::{
    AccountBalanceResponse, AccountIdentifier, Amount, ApiError, BlockIdentifier, Currency,
    Operation, Timestamp, TransactionIdentifier,
};
use core::fmt::Display;

use ic_types::messages::{HttpRequestEnvelope, HttpSubmitContent};
use ic_types::PrincipalId;
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
    transaction: &Transaction,
    transaction_identifier: TransactionIdentifier,
) -> Result<models::Transaction, ApiError> {
    let operations = operations(transaction)?;
    Ok(models::Transaction::new(transaction_identifier, operations))
}

// This currently only takes a transation
pub fn operations(transaction: &Transaction) -> Result<Vec<Operation>, ApiError> {
    // The spec just says if there aren't smart contracts all statuses should
    // be the same
    let status = STATUS.to_string();

    let ops = match transaction {
        Transaction::Send { from, to, amount } => {
            let from_account = Some(account_identifier(from));
            let to_account = Some(account_identifier(to));
            let amount = i64::try_from(*amount).map_err(|_| ApiError::InternalError(true, None))?;
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
        Transaction::Mint { to, amount, .. } => {
            let account = Some(account_identifier(to));
            let amount = Some(amount_(*amount)?);
            let op = Operation::new(0, MINT.to_string(), status, account, amount);
            vec![op]
        }
        Transaction::Burn { from, amount, .. } => {
            let amount = i64::try_from(*amount).map_err(|_| ApiError::InternalError(true, None))?;
            let account = Some(account_identifier(from));
            let amount = Some(signed_amount(-amount));
            let op = Operation::new(0, BURN.to_string(), status, account, amount);
            vec![op]
        }
    };
    Ok(ops)
}

pub fn from_operations(ops: Vec<Operation>) -> Result<Vec<Transaction>, ApiError> {
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
    fn read_transaction(op: &Operation) -> Result<(i64, UserID), String> {
        // let id = op.operation_identifier.clone();

        // Check the operation looks like part of a transaction
        let (amount, account) = match op {
            Operation {
                operation_identifier: _,
                related_operations: _,
                _type,
                status,
                account: Some(account),
                amount: Some(amount),
                coin_change: None,
                metadata: _,
            } => match (&_type[..], &status[..]) {
                (TRANSACTION, STATUS) => Ok((amount, account)),
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

        let account = user_id(&account)?;
        let amount = from_amount(amount)?;
        Ok((amount, account))
    }

    fn to_transaction(mut ops: Vec<Operation>) -> Result<Transaction, ApiError> {
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

                let amount = if db_amount > 0 {
                    db_amount as u64
                } else {
                    return error("Debit amount must be greater than zero");
                };

                if from == to {
                    return error("Transactions can't start and finish in the same place");
                }

                Ok(Transaction::Send { from, to, amount })
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

const DECIMAL_PLACES: u32 = 8;

/// How many times can ICPs be divided
// const ICP_SUBDIVIDABLE_BY: i64 = 100_000_000;

pub fn amount_(amount: u64) -> Result<Amount, ApiError> {
    let amount = i64::try_from(amount).map_err(|_| ApiError::InternalError(true, None))?;
    Ok(Amount {
        value: format!("{}", amount),
        currency: icp(),
        metadata: None,
    })
}

pub fn signed_amount(amount: i64) -> Amount {
    Amount {
        value: format!("{}", amount),
        currency: icp(),
        metadata: None,
    }
}

pub fn from_amount(amount: &Amount) -> Result<i64, String> {
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

pub fn icp() -> Currency {
    Currency::new("ICP".to_string(), DECIMAL_PLACES)
}

pub fn block_id(block: &BlockInfo) -> Result<BlockIdentifier, ApiError> {
    let idx = i64::try_from(block.index).map_err(|_| ApiError::InternalError(true, None))?;
    Ok(BlockIdentifier::new(idx, from_hash(&block.hash)))
}

pub fn transaction_identifier(hash: &Hash) -> TransactionIdentifier {
    TransactionIdentifier::new(hex::encode(hash.to_be_bytes()))
}

pub fn account_identifier(uid: &UserID) -> AccountIdentifier {
    AccountIdentifier::new(hex::encode(&uid.0))
}

pub fn user_id(aid: &AccountIdentifier) -> Result<UserID, String> {
    // TODO validate
    match hex::decode(aid.address.clone()) {
        Ok(vec) => Ok(UserID(vec)),
        Err(e) => Err(format!(
            "Account Identifer {} is not hex encoded: {}",
            aid.address, e
        )),
    }
}

pub fn account_balance(amount: u64, block: &BlockInfo) -> Result<AccountBalanceResponse, ApiError> {
    Ok(AccountBalanceResponse::new(
        block_id(block)?,
        vec![amount_(amount)?],
    ))
}

const LAST_HASH: &str = "last_hash";

// Last hash is an option because there may be no blocks on the system
pub fn from_metadata(mut ob: models::Object) -> Result<Option<Hash>, ApiError> {
    let v = ob
        .remove(LAST_HASH)
        .ok_or(ApiError::InternalError(false, None))?;
    from_value(v).map_err(|_| ApiError::InternalError(false, None))
}

pub fn into_metadata(hash: Option<Hash>) -> models::Object {
    let mut m = Map::new();
    if let Some(h) = hash {
        m.insert(LAST_HASH.to_string(), Value::from(h));
    }
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

pub fn transaction_id(signed_transaction: &str) -> Result<TransactionIdentifier, ApiError> {
    let envelope: HttpRequestEnvelope<HttpSubmitContent> =
        serde_json::from_str(signed_transaction).map_err(internal_error)?;

    let arg = match envelope.content {
        HttpSubmitContent::Call { update } => update.arg,
    };
    let (transaction_id, _, _): (Hash, UserID, u64) = from_arg(&arg.0)?;

    Ok(transaction_identifier(&transaction_id))
}

pub fn internal_error<D: Display>(msg: D) -> ApiError {
    ApiError::InternalError(false, into_error(format!("{}", msg)))
}

pub fn account_from_public_key(pk: models::PublicKey) -> Result<AccountIdentifier, ApiError> {
    let pid = PrincipalId::new_self_authenticating(&from_hex(pk.hex_bytes)?);
    Ok(account_identifier(&UserID(pid.to_vec())))
}

// This is so I can keep track of where this conversion is done
pub fn from_arg(encoded: &[u8]) -> Result<(Hash, UserID, u64), ApiError> {
    serde_json::from_slice(encoded).map_err(internal_error)
}

pub fn to_arg(arg: &(Hash, UserID, u64)) -> Vec<u8> {
    serde_json::to_vec(arg).expect("Serialization failed")
}

pub fn from_hash(hash: &Hash) -> String {
    format!("{}", *hash)
}

pub fn to_hash(s: &str) -> Result<Hash, ApiError> {
    s.parse().map_err(|_| ApiError::InternalError(false, None))
}
