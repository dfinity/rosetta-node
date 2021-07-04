use crate::models;
use crate::models::{
    AccountIdentifier, Amount, ApiError, BlockIdentifier, Currency, Operation, Timestamp,
    TransactionIdentifier,
};
use crate::store::HashedBlock;
use core::fmt::Display;
use dfn_protobuf::ProtoBuf;
use ic_crypto_tree_hash::Path;
use ic_types::messages::{
    HttpCanisterUpdate, HttpReadState, HttpRequestEnvelope, HttpSubmitContent,
};
use ic_types::{CanisterId, PrincipalId};
use ledger_canister::{
    BlockHeight, HashOf, ICPTs, SendArgs, Transaction, Transfer, DECIMAL_PLACES, TRANSACTION_FEE,
};
use on_wire::{FromWire, IntoWire};
use serde_json::map::Map;
use serde_json::{from_value, Number, Value};
use std::convert::TryFrom;
use std::str::FromStr;
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

pub fn transaction(hb: &HashedBlock) -> Result<models::Transaction, ApiError> {
    let block = hb
        .block
        .decode()
        .map_err(|err| internal_error(format!("Cannot decode block: {}", err)))?;
    let transaction = block.transaction;
    let transaction_identifier = transaction_identifier(&transaction.hash());
    let transfer = transaction.transfer;
    let operations = operations(&transfer, true)?;
    let mut t = models::Transaction::new(transaction_identifier, operations);
    let mut metadata = Map::new();
    metadata.insert(
        "memo".to_string(),
        Value::Number(Number::from(transaction.memo.0)),
    );
    metadata.insert(
        "block_height".to_string(),
        Value::Number(Number::from(hb.index)),
    );
    metadata.insert(
        "timestamp".to_string(),
        Value::Number(Number::from(block.timestamp.as_nanos_since_unix_epoch())),
    );
    t.metadata = Some(metadata);
    Ok(t)
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
            let from_account = Some(to_model_account_identifier(from));
            let to_account = Some(to_model_account_identifier(to));
            let amount = i128::try_from(amount.get_e8s())
                .map_err(|_| ApiError::InternalError(true, None))?;
            let db = Operation::new(
                0,
                TRANSACTION.to_string(),
                status.clone(),
                from_account.clone(),
                Some(signed_amount(-amount)),
            );
            let cr = Operation::new(
                1,
                TRANSACTION.to_string(),
                status.clone(),
                to_account,
                Some(signed_amount(amount)),
            );
            let fee = Operation::new(
                2,
                FEE.to_string(),
                status,
                from_account,
                Some(signed_amount(-(fee.get_e8s() as i128))),
            );
            vec![db, cr, fee]
        }
        // TODO include the destination in the metadata
        Transfer::Mint { to, amount, .. } => {
            let account = Some(to_model_account_identifier(to));
            let amount = Some(amount_(*amount)?);
            let op = Operation::new(0, MINT.to_string(), status, account, amount);
            vec![op]
        }
        Transfer::Burn { from, amount, .. } => {
            let amount = i128::try_from(amount.get_e8s())
                .map_err(|_| ApiError::InternalError(true, None))?;
            let account = Some(to_model_account_identifier(from));
            let amount = Some(signed_amount(-amount));
            let op = Operation::new(0, BURN.to_string(), status, account, amount);
            vec![op]
        }
    };
    Ok(ops)
}

/// Helper for `from_operations` that creates `Transfer`s from related
/// debit/credit/fee operations.
struct State {
    preprocessing: bool,
    transfers: Vec<Transfer>,
    cr: Option<(ICPTs, ledger_canister::AccountIdentifier)>,
    db: Option<(ICPTs, ledger_canister::AccountIdentifier)>,
    fee: Option<(ICPTs, ledger_canister::AccountIdentifier)>,
}

impl State {
    /// Create a `Transfer` from the credit/debit/fee operations seen
    /// previously.
    fn flush(&mut self) -> Result<(), ApiError> {
        let trans_err = |msg| {
            let msg = format!("Bad transaction: {}", msg);
            let err = ApiError::InvalidTransaction(false, into_error(msg));
            Err(err)
        };

        if self.cr.is_none() && self.db.is_none() && self.fee.is_none() {
            return Ok(());
        }

        // If you're preprocessing just continue with the default fee
        if self.preprocessing && self.fee.is_none() && self.db.is_some() {
            self.fee = Some((TRANSACTION_FEE, self.db.unwrap().1))
        }

        if self.cr.is_none() || self.db.is_none() || self.fee.is_none() {
            return trans_err(
                "Operations do not combine to make a recognizable transaction".to_string(),
            );
        }
        let (cr_amount, mut to) = self.cr.take().unwrap();
        let (db_amount, mut from) = self.db.take().unwrap();
        let (fee_amount, fee_acc) = self.fee.take().unwrap();

        if fee_acc != from {
            if cr_amount == ICPTs::ZERO && fee_acc == to {
                std::mem::swap(&mut from, &mut to);
            } else {
                let msg = format!("Fee should be taken from {}", from);
                return trans_err(msg);
            }
        }
        if cr_amount != db_amount {
            return trans_err("Debit_amount should be equal -credit_amount".to_string());
        }

        self.transfers.push(Transfer::Send {
            from,
            to,
            amount: cr_amount,
            fee: fee_amount,
        });

        Ok(())
    }

    fn transaction(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        amount: i128,
    ) -> Result<(), ApiError> {
        if amount > 0 || self.db.is_some() && amount == 0 {
            if self.cr.is_some() {
                self.flush()?;
            }
            self.cr = Some((ICPTs::from_e8s(amount as u64), account));
        } else {
            if self.db.is_some() {
                self.flush()?;
            }
            self.db = Some((ICPTs::from_e8s((-amount) as u64), account));
        }
        Ok(())
    }

    fn fee(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        amount: ICPTs,
    ) -> Result<(), ApiError> {
        if self.fee.is_some() {
            self.flush()?;
        }
        self.fee = Some((amount, account));
        Ok(())
    }
}

pub fn from_operations(ops: &[Operation], preprocessing: bool) -> Result<Vec<Transfer>, ApiError> {
    let op_error = |op: &Operation, e| {
        let msg = format!("In operation '{:?}': {}", op, e);
        ApiError::InvalidTransaction(false, into_error(msg))
    };

    let mut state = State {
        preprocessing,
        transfers: vec![],
        cr: None,
        db: None,
        fee: None,
    };

    for o in ops {
        if o.amount.is_none() || o.account.is_none() {
            return Err(op_error(&o, "Account and amount must be populated".into()));
        }
        if o.coin_change.is_some() {
            return Err(op_error(&o, "Coin changes are not permitted".into()));
        }
        let amount = from_amount(o.amount.as_ref().unwrap()).map_err(|e| op_error(&o, e))?;
        let account = from_model_account_identifier(o.account.as_ref().unwrap())
            .map_err(|e| op_error(&o, e))?;

        match o._type.as_str() {
            TRANSACTION => {
                state.transaction(account, amount)?;
            }
            FEE => {
                if -amount != TRANSACTION_FEE.get_e8s() as i128 {
                    let msg = format!("Fee should be equal: {}", TRANSACTION_FEE.get_e8s());
                    return Err(op_error(&o, msg));
                }
                state.fee(account, ICPTs::from_e8s((-amount) as u64))?;
            }
            _ => {
                let msg = format!("Unsupported operation type: {}", o._type);
                return Err(op_error(&o, msg));
            }
        }
    }

    state.flush()?;

    if state.transfers.is_empty() {
        return Err(ApiError::InvalidTransaction(
            false,
            into_error("Operations don't contain any transfer.".to_owned()),
        ));
    }

    Ok(state.transfers)
}

pub fn amount_(amount: ICPTs) -> Result<Amount, ApiError> {
    let amount = amount.get_e8s();
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
    Ok(ICPTs::from_e8s(inner as u64))
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

pub fn from_model_transaction_identifier(
    tid: &TransactionIdentifier,
) -> Result<HashOf<Transaction>, String> {
    HashOf::from_str(&tid.hash)
}

pub fn to_model_account_identifier(aid: &ledger_canister::AccountIdentifier) -> AccountIdentifier {
    AccountIdentifier::new(aid.to_hex())
}

pub fn from_model_account_identifier(
    aid: &AccountIdentifier,
) -> Result<ledger_canister::AccountIdentifier, String> {
    ledger_canister::AccountIdentifier::from_hex(&aid.address).map_err(|e| e)
}

const LAST_HEIGHT: &str = "last_height";

// Last hash is an option because there may be no blocks on the system
pub fn from_metadata(mut ob: models::Object) -> Result<BlockHeight, ApiError> {
    let v = ob
        .remove(LAST_HEIGHT)
        .ok_or(ApiError::InternalError(false, None))?;
    from_value(v).map_err(|_| ApiError::InternalError(false, None))
}

// This converts an error message to something that ApiError can consume
// This returns an option because it's what the error type expects, but it will
// always return Some
pub fn into_error(error_msg: impl Into<String>) -> Option<models::Object> {
    let mut m = Map::new();
    m.insert("error_message".into(), Value::from(error_msg.into()));
    Some(m)
}

pub fn from_public_key(pk: &models::PublicKey) -> Result<Vec<u8>, ApiError> {
    from_hex(&pk.hex_bytes)
}

pub fn from_hex(hex: &str) -> Result<Vec<u8>, ApiError> {
    hex::decode(hex).map_err(|e| invalid_request(format!("Hex could not be decoded {}", e)))
}

pub fn to_hex(v: &[u8]) -> String {
    hex::encode(v)
}

pub fn transaction_id(
    signed_transaction: &HttpRequestEnvelope<HttpSubmitContent>,
) -> Result<TransactionIdentifier, ApiError> {
    let HttpSubmitContent::Call { update } = &signed_transaction.content;
    let from = PrincipalId::try_from(update.sender.clone().0)
        .map_err(|e| internal_error(e.to_string()))?;
    let SendArgs {
        memo,
        amount,
        fee,
        from_subaccount,
        to,
        created_at_time,
    } = from_arg(update.arg.clone().0)?;
    let created_at_time = created_at_time.ok_or_else(|| internal_error(
        "A transaction ID cannot be generated from a constructed transaction without an explicit 'created_at_time'"
    ))?;

    let from = ledger_canister::AccountIdentifier::new(from, from_subaccount);

    let hash = Transaction::new(from, to, amount, fee, memo, created_at_time).hash();

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

pub fn invalid_request<D: Display>(msg: D) -> ApiError {
    ApiError::InvalidRequest(false, into_error(format!("{}", msg)))
}

pub fn invalid_block_id<D: Display>(msg: D) -> ApiError {
    ApiError::InvalidBlockId(false, into_error(format!("{}", msg)))
}

pub fn invalid_account_id<D: Display>(msg: D) -> ApiError {
    ApiError::InvalidAccountId(false, into_error(format!("{}", msg)))
}

pub fn account_from_public_key(pk: &models::PublicKey) -> Result<AccountIdentifier, ApiError> {
    let pid = principal_id_from_public_key(pk)?;
    Ok(to_model_account_identifier(&pid.into()))
}

pub fn neuron_account_from_public_key(
    governance_canister_id: &CanisterId,
    pk: &models::PublicKey,
) -> Result<AccountIdentifier, ApiError> {
    let controller = principal_id_from_public_key(pk)?;

    // We only allow 1 neuron account per public key, so the nonce is fixed to
    // be 0.
    const NONCE: u64 = 0;

    let sub_account_bytes = {
        let mut state = ic_crypto_sha256::Sha256::new();
        state.write(&[0x0c]);
        state.write(b"neuron-stake");
        state.write(&controller.as_slice());
        state.write(&NONCE.to_be_bytes());
        state.finish()
    };

    Ok(AccountIdentifier {
        address: governance_canister_id.to_string(),
        sub_account: Some(models::SubAccountIdentifier::new(hex::encode(
            &sub_account_bytes,
        ))),
        metadata: None,
    })
}

pub fn principal_id_from_public_key(pk: &models::PublicKey) -> Result<PrincipalId, ApiError> {
    if pk.curve_type != models::CurveType::Edwards25519 {
        return Err(ApiError::InvalidPublicKey(
            false,
            into_error("Only EDWARDS25519 curve type is supported".to_string()),
        ));
    }
    let pid = PrincipalId::new_self_authenticating(&ic_canister_client::ed25519_public_key_to_der(
        from_hex(&pk.hex_bytes)?,
    ));
    Ok(pid)
}

// This is so I can keep track of where this conversion is done
pub fn from_arg(encoded: Vec<u8>) -> Result<SendArgs, ApiError> {
    ProtoBuf::from_bytes(encoded)
        .map_err(internal_error)
        .map(|ProtoBuf(c)| c)
}

pub fn to_arg(args: SendArgs) -> Vec<u8> {
    ProtoBuf(args).into_bytes().expect("Serialization failed")
}

pub fn from_hash<T>(hash: &HashOf<T>) -> String {
    format!("{}", *hash)
}

pub fn to_hash<T>(s: &str) -> Result<HashOf<T>, ApiError> {
    s.parse().map_err(|_| ApiError::InternalError(false, None))
}

pub fn make_read_state_from_update(update: &HttpCanisterUpdate) -> HttpReadState {
    let path = Path::new(vec!["request_status".into(), update.id().into()]);

    HttpReadState {
        sender: update.sender.clone(),
        paths: vec![path],
        nonce: None,
        ingress_expiry: update.ingress_expiry,
    }
}
