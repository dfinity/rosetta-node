use crate::models;
use crate::models::{
    AccountIdentifier, Amount, ApiError, BlockIdentifier, Currency, Operation, Timestamp,
    TransactionIdentifier,
};
use crate::store::HashedBlock;
use core::fmt::Display;
use dfn_candid::CandidOne;
use ic_types::messages::{HttpRequestEnvelope, HttpSubmitContent};
use ic_types::PrincipalId;
use ledger_canister::{
    BlockHeight, HashOf, ICPTs, SendArgs, Serializable, Transaction, Transfer, DECIMAL_PLACES,
    TRANSACTION_FEE,
};
use on_wire::{FromWire, IntoWire};
use serde_json::map::Map;
use serde_json::{from_value, Value};
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
const FEE: &str = "FEE";

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
        Transfer::Send {
            from,
            to,
            amount,
            fee,
        } => {
            let from_account = Some(account_identifier(from));
            let to_account = Some(account_identifier(to));
            let amount = i128::try_from(amount.get_doms())
                .map_err(|_| ApiError::InternalError(true, None))?;
            let db = Operation::new(
                0,
                TRANSACTION.to_string(),
                status.clone(),
                from_account.clone(),
                Some(signed_amount(-amount)),
            );
            let mut cr = Operation::new(
                1,
                TRANSACTION.to_string(),
                status.clone(),
                to_account,
                Some(signed_amount(amount)),
            );
            cr.related_operations = Some(vec![db.operation_identifier.clone()]);
            let mut fee = Operation::new(
                2,
                FEE.to_string(),
                status,
                from_account,
                Some(signed_amount(-(fee.get_doms() as i128))),
            );
            fee.related_operations = Some(vec![db.operation_identifier.clone()]);
            vec![db, cr, fee]
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
    let trans_err = |msg| {
        let msg = format!("Bad transaction in {:?}: {}", &ops, msg);
        let err = ApiError::InvalidTransaction(false, into_error(msg));
        Err(err)
    };

    let op_error = |op: &Operation, e| {
        let msg = format!("In operation '{:?}': {}", op, e);
        ApiError::InvalidTransaction(false, into_error(msg))
    };

    if ops.len() != 3 {
        return trans_err(
            "Operations do not combine to make a recognizable transaction".to_string(),
        );
    }

    let mut cr = None;
    let mut db = None;
    let mut fee = None;

    for o in &ops {
        if o.amount.is_none() || o.account.is_none() {
            return Err(op_error(&o, "Account and amount must be populated".into()));
        }
        if o.coin_change.is_some() {
            return Err(op_error(&o, "Coin changes are not permitted".into()));
        }
        let amount = from_amount(o.amount.as_ref().unwrap()).map_err(|e| op_error(&o, e))?;
        let account = principal_id(o.account.as_ref().unwrap()).map_err(|e| op_error(&o, e))?;

        match o._type.as_str() {
            TRANSACTION => {
                if amount < 0 || cr.is_some() && amount == 0 {
                    let icpts = ICPTs::from_doms((-amount) as u64);
                    db = Some((icpts, account));
                } else {
                    let icpts = ICPTs::from_doms(amount as u64);
                    cr = Some((icpts, account));
                }
            }
            FEE => {
                if -amount != TRANSACTION_FEE.get_doms() as i128 {
                    let msg = format!("Fee should be equal: {}", TRANSACTION_FEE.get_doms());
                    return Err(op_error(&o, msg));
                }
                let icpts = ICPTs::from_doms((-amount) as u64);
                fee = Some((icpts, account));
            }
            _ => {
                let msg = format!("Unsupported operation type: {}", o._type);
                return Err(op_error(&o, msg));
            }
        }
    }

    if cr.is_none() || db.is_none() || fee.is_none() {
        return trans_err(
            "Operations do not combine to make a recognizable transaction".to_string(),
        );
    }
    let (cr_amount, to) = cr.unwrap();
    let (db_amount, from) = db.unwrap();
    let (fee_amount, fee_acc) = fee.unwrap();

    if fee_acc != from {
        let msg = format!("Fee should be taken from {}", from);
        return trans_err(msg);
    }
    if cr_amount != db_amount {
        return trans_err("Debit_amount should be equal -credit_amount".to_string());
    }

    Ok(vec![Transfer::Send {
        from,
        to,
        amount: cr_amount,
        fee: fee_amount,
    }])
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
        } if currency == &icp() => {
            let val: i128 = value
                .parse()
                .map_err(|e| format!("Parsing amount failed: {}", e))?;
            let _ =
                u64::try_from(val.abs()).map_err(|_| "Amount does not fit in u64".to_string())?;
            Ok(val)
        }
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

pub fn from_public_key(pk: &models::PublicKey) -> Result<Vec<u8>, ApiError> {
    from_hex(&pk.hex_bytes)
}

pub fn from_hex(hex: &str) -> Result<Vec<u8>, ApiError> {
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
    let SendArgs {
        memo,
        amount,
        fee,
        from_subaccount,
        to,
        to_subaccount,
        block_height,
    } = from_arg(update.arg.0)?;
    let created_at = block_height.ok_or_else(|| internal_error(
        "A transaction ID cannot be generated from a constructed transaction without an explicit block height"
    ))?;

    let from =
        ledger_canister::account_identifier(from, from_subaccount).map_err(internal_error)?;
    let to = ledger_canister::account_identifier(to, to_subaccount).map_err(internal_error)?;

    let hash = Transaction::new(from, to, amount, fee, memo, created_at).hash();

    Ok(transaction_identifier(&hash))
}

pub fn internal_error<D: Display>(msg: D) -> ApiError {
    ApiError::InternalError(false, into_error(format!("{}", msg)))
}

pub fn ic_error(http_status: u16, msg: String) -> ApiError {
    let mut m = Map::new();
    m.insert("error_message".to_string(), Value::from(msg));
    m.insert("ic_http_status".to_string(), Value::from(http_status));
    ApiError::ICError(false, Some(m))
}

pub fn invalid_block_id<D: Display>(msg: D) -> ApiError {
    ApiError::InvalidBlockId(false, into_error(format!("{}", msg)))
}

pub fn account_from_public_key(pk: models::PublicKey) -> Result<AccountIdentifier, ApiError> {
    let pid = PrincipalId::new_self_authenticating(&from_hex(&pk.hex_bytes)?);
    Ok(account_identifier(&pid))
}

// This is so I can keep track of where this conversion is done
pub fn from_arg(encoded: Vec<u8>) -> Result<SendArgs, ApiError> {
    CandidOne::from_bytes(encoded)
        .map_err(internal_error)
        .map(|CandidOne(c)| c)
}

pub fn to_arg(args: SendArgs) -> Vec<u8> {
    CandidOne(args).into_bytes().expect("Serialization failed")
}

pub fn from_hash<T>(hash: &HashOf<T>) -> String {
    format!("{}", *hash)
}

pub fn to_hash<T>(s: &str) -> Result<HashOf<T>, ApiError> {
    s.parse().map_err(|_| ApiError::InternalError(false, None))
}
