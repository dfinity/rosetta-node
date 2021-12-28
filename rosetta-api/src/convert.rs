use crate::convert;
use crate::errors::ApiError;
use crate::models;
use crate::models::{
    AccountIdentifier, Amount, BlockIdentifier, Currency, Operation, OperationIdentifier, Timestamp,
};
use crate::request_types::{
    AddHotKey, Disburse, DisburseMetadata, KeyMetadata, NeuronIdentifierMetadata,
    PublicKeyOrPrincipal, Request, SetDissolveTimestamp, SetDissolveTimestampMetadata, Spawn,
    SpawnMetadata, Stake, StartDissolve, StopDissolve, ADD_HOT_KEY, BURN, DISBURSE, FEE, MINT,
    SET_DISSOLVE_TIMESTAMP, SPAWN, STAKE, START_DISSOLVE, STATUS_COMPLETED, STOP_DISSOLVE,
    TRANSACTION,
};
use crate::store::HashedBlock;
use crate::time::Seconds;
use crate::transaction_id::TransactionIdentifier;
use dfn_protobuf::ProtoBuf;
use ic_crypto_tree_hash::Path;
use ic_types::messages::{HttpCanisterUpdate, HttpReadState};
use ic_types::{CanisterId, PrincipalId};
use ledger_canister::{
    BlockHeight, HashOf, Operation as LedgerOperation, SendArgs, Subaccount, Tokens,
    DECIMAL_PLACES, TRANSACTION_FEE,
};
use on_wire::{FromWire, IntoWire};
use serde_json::map::Map;
use serde_json::{from_value, Number, Value};
use std::convert::TryFrom;
use std::convert::TryInto;
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
        .ok_or_else(|| {
            ApiError::internal_error(format!(
                "Could not create Timestamp from SystemTime: {:?}",
                timestamp
            ))
        })
}

pub fn transaction(hb: &HashedBlock, token_name: &str) -> Result<models::Transaction, ApiError> {
    let block = hb
        .block
        .decode()
        .map_err(|err| ApiError::internal_error(format!("Cannot decode block: {}", err)))?;
    let transaction = block.transaction;
    let transaction_identifier = TransactionIdentifier::from(&transaction);
    let operation = transaction.operation;
    let operations = {
        let mut ops = Request::requests_to_operations(&[Request::Transfer(operation)], token_name)?;
        for op in ops.iter_mut() {
            op.status = Some(STATUS_COMPLETED.to_string());
        }
        ops
    };
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

/// Translates a sequence of internal requests into an array of Rosetta API
/// operations.
pub fn requests_to_operations(
    requests: &[Request],
    token_name: &str,
) -> Result<Vec<Operation>, ApiError> {
    let mut ops = vec![];
    let mut idx = 0;
    let mut allocate_op_id = || {
        let n = idx;
        idx += 1;
        OperationIdentifier::new(n)
    };

    for request in requests {
        match request {
            Request::Transfer(LedgerOperation::Transfer {
                from,
                to,
                amount,
                fee,
            }) => {
                let from_account = Some(to_model_account_identifier(from));
                let amount = i128::from(amount.get_e8s());

                ops.push(Operation {
                    operation_identifier: allocate_op_id(),
                    _type: TRANSACTION.to_string(),
                    status: None,
                    account: from_account.clone(),
                    amount: Some(signed_amount(-amount, token_name)),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
                ops.push(Operation {
                    operation_identifier: allocate_op_id(),
                    _type: TRANSACTION.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(to)),
                    amount: Some(signed_amount(amount, token_name)),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
                ops.push(Operation {
                    operation_identifier: allocate_op_id(),
                    _type: FEE.to_string(),
                    status: None,
                    account: from_account,
                    amount: Some(signed_amount(-(fee.get_e8s() as i128), token_name)),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
            }
            Request::Transfer(LedgerOperation::Mint { to, amount, .. }) => {
                ops.push(Operation {
                    operation_identifier: allocate_op_id(),
                    _type: MINT.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(to)),
                    amount: Some(amount_(*amount, token_name)?),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
            }
            Request::Transfer(LedgerOperation::Burn { from, amount, .. }) => {
                ops.push(Operation {
                    operation_identifier: allocate_op_id(),
                    _type: BURN.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(from)),
                    amount: Some(signed_amount(-i128::from(amount.get_e8s()), token_name)),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
            }
            Request::Stake(Stake {
                account,
                neuron_index,
            }) => {
                ops.push(Operation {
                    operation_identifier: allocate_op_id(),
                    _type: STAKE.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(account)),
                    amount: None,
                    related_operations: None,
                    coin_change: None,
                    metadata: Some(
                        NeuronIdentifierMetadata {
                            neuron_index: *neuron_index,
                        }
                        .into(),
                    ),
                });
            }
            Request::SetDissolveTimestamp(SetDissolveTimestamp {
                account,
                neuron_index,
                timestamp,
            }) => {
                ops.push(Operation {
                    operation_identifier: allocate_op_id(),
                    _type: SET_DISSOLVE_TIMESTAMP.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(account)),
                    amount: None,
                    related_operations: None,
                    coin_change: None,
                    metadata: Some(
                        SetDissolveTimestampMetadata {
                            neuron_index: *neuron_index,
                            timestamp: *timestamp,
                        }
                        .into(),
                    ),
                });
            }
            Request::StartDissolve(StartDissolve {
                account,
                neuron_index,
            }) => {
                ops.push(Operation {
                    operation_identifier: allocate_op_id(),
                    _type: START_DISSOLVE.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(account)),
                    amount: None,
                    related_operations: None,
                    coin_change: None,
                    metadata: Some(
                        NeuronIdentifierMetadata {
                            neuron_index: *neuron_index,
                        }
                        .into(),
                    ),
                });
            }
            Request::StopDissolve(StopDissolve {
                account,
                neuron_index,
            }) => {
                ops.push(Operation {
                    operation_identifier: allocate_op_id(),
                    _type: STOP_DISSOLVE.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(account)),
                    amount: None,
                    related_operations: None,
                    coin_change: None,
                    metadata: Some(
                        NeuronIdentifierMetadata {
                            neuron_index: *neuron_index,
                        }
                        .into(),
                    ),
                });
            }
            Request::Disburse(Disburse {
                account,
                amount,
                recipient,
                neuron_index,
            }) => {
                ops.push(Operation {
                    operation_identifier: allocate_op_id(),
                    _type: DISBURSE.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(account)),
                    amount: amount.map(|a| amount_(a, token_name).expect("amount_ never fails")),
                    related_operations: None,
                    coin_change: None,
                    metadata: Some(
                        DisburseMetadata {
                            recipient: *recipient,
                            neuron_index: *neuron_index,
                        }
                        .into(),
                    ),
                });
            }
            Request::AddHotKey(AddHotKey {
                account,
                neuron_index,
                key,
            }) => {
                ops.push(Operation {
                    operation_identifier: allocate_op_id(),
                    _type: ADD_HOT_KEY.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(account)),
                    amount: None,
                    related_operations: None,
                    coin_change: None,
                    metadata: Some(
                        KeyMetadata {
                            key: key.clone(),
                            neuron_index: *neuron_index,
                        }
                        .into(),
                    ),
                });
            }
            Request::Spawn(Spawn {
                account,
                spawned_neuron_index,
                controller,
                neuron_index,
            }) => {
                ops.push(Operation {
                    operation_identifier: allocate_op_id(),
                    _type: SPAWN.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(account)),
                    amount: None,
                    related_operations: None,
                    coin_change: None,
                    metadata: Some(
                        SpawnMetadata {
                            neuron_index: *neuron_index,
                            controller: *controller,
                            spawned_neuron_index: *spawned_neuron_index,
                        }
                        .into(),
                    ),
                });
            }
        }
    }
    Ok(ops)
}

/// Helper for `from_operations` that creates `Transfer`s from related
/// debit/credit/fee operations.
struct State {
    preprocessing: bool,
    actions: Vec<Request>,
    cr: Option<(Tokens, ledger_canister::AccountIdentifier)>,
    db: Option<(Tokens, ledger_canister::AccountIdentifier)>,
    fee: Option<(Tokens, ledger_canister::AccountIdentifier)>,
}

impl State {
    /// Create a `Transfer` from the credit/debit/fee operations seen
    /// previously.
    fn flush(&mut self) -> Result<(), ApiError> {
        let trans_err = |msg| {
            let msg = format!("Bad transaction: {}", msg);
            let err = ApiError::InvalidTransaction(false, msg.into());
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
            if cr_amount == Tokens::ZERO && fee_acc == to {
                std::mem::swap(&mut from, &mut to);
            } else {
                let msg = format!("Fee should be taken from {}", from);
                return trans_err(msg);
            }
        }
        if cr_amount != db_amount {
            return trans_err("Debit_amount should be equal -credit_amount".to_string());
        }

        self.actions
            .push(Request::Transfer(LedgerOperation::Transfer {
                from,
                to,
                amount: cr_amount,
                fee: fee_amount,
            }));

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
            self.cr = Some((Tokens::from_e8s(amount as u64), account));
        } else {
            if self.db.is_some() {
                self.flush()?;
            }
            self.db = Some((Tokens::from_e8s((-amount) as u64), account));
        }
        Ok(())
    }

    fn fee(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        amount: Tokens,
    ) -> Result<(), ApiError> {
        if self.fee.is_some() {
            self.flush()?;
        }
        self.fee = Some((amount, account));
        Ok(())
    }

    fn stake(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
    ) -> Result<(), ApiError> {
        self.flush()?;
        self.actions.push(Request::Stake(Stake {
            account,
            neuron_index,
        }));
        Ok(())
    }

    fn set_dissolve_timestamp(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
        timestamp: Seconds,
    ) -> Result<(), ApiError> {
        self.flush()?;
        self.actions
            .push(Request::SetDissolveTimestamp(SetDissolveTimestamp {
                account,
                neuron_index,
                timestamp,
            }));
        Ok(())
    }

    fn start_dissolve(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
    ) -> Result<(), ApiError> {
        self.flush()?;

        self.actions.push(Request::StartDissolve(StartDissolve {
            account,
            neuron_index,
        }));

        Ok(())
    }

    fn stop_dissolve(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
    ) -> Result<(), ApiError> {
        self.flush()?;

        self.actions.push(Request::StopDissolve(StopDissolve {
            account,
            neuron_index,
        }));

        Ok(())
    }
    fn add_hot_key(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
        key: PublicKeyOrPrincipal,
    ) -> Result<(), ApiError> {
        self.flush()?;

        self.actions.push(Request::AddHotKey(AddHotKey {
            account,
            neuron_index,
            key,
        }));

        Ok(())
    }

    fn disburse(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
        amount: Option<Tokens>,
        recipient: Option<ledger_canister::AccountIdentifier>,
    ) -> Result<(), ApiError> {
        self.flush()?;

        self.actions.push(Request::Disburse(Disburse {
            account,
            amount,
            recipient,
            neuron_index,
        }));

        Ok(())
    }

    fn spawn(
        &mut self,
        account: ledger_canister::AccountIdentifier,
        neuron_index: u64,
        spawned_neuron_index: u64,
        controller: Option<PrincipalId>,
    ) -> Result<(), ApiError> {
        self.flush()?;

        self.actions.push(Request::Spawn(Spawn {
            account,
            spawned_neuron_index,
            controller,
            neuron_index,
        }));

        Ok(())
    }
}

pub fn from_operations(
    ops: &[Operation],
    preprocessing: bool,
    token_name: &str,
) -> Result<Vec<Request>, ApiError> {
    let op_error = |op: &Operation, e| {
        let msg = format!("In operation '{:?}': {}", op, e);
        ApiError::InvalidTransaction(false, msg.into())
    };

    let mut state = State {
        preprocessing,
        actions: vec![],
        cr: None,
        db: None,
        fee: None,
    };

    for o in ops {
        if o.account.is_none() {
            return Err(op_error(o, "Account must be populated".into()));
        }
        if o.coin_change.is_some() {
            return Err(op_error(o, "Coin changes are not permitted".into()));
        }
        let account = from_model_account_identifier(o.account.as_ref().unwrap())
            .map_err(|e| op_error(o, e))?;

        let validate_neuron_management_op = || {
            if o.amount.is_some() && o._type != DISBURSE {
                Err(op_error(
                    o,
                    format!(
                        "neuron management {} operation cannot have an amount",
                        o._type
                    ),
                ))
            } else if o.coin_change.is_some() {
                Err(op_error(
                    o,
                    format!(
                        "neuron management {} operation cannot have a coin change",
                        o._type
                    ),
                ))
            } else {
                Ok(())
            }
        };

        match o._type.as_str() {
            TRANSACTION => {
                let amount = o
                    .amount
                    .as_ref()
                    .ok_or_else(|| op_error(o, "Amount must be populated".into()))?;
                let amount = from_amount(amount, token_name).map_err(|e| op_error(o, e))?;
                state.transaction(account, amount)?;
            }
            FEE => {
                let amount = o
                    .amount
                    .as_ref()
                    .ok_or_else(|| op_error(o, "Amount must be populated".into()))?;
                let amount = from_amount(amount, token_name).map_err(|e| op_error(o, e))?;
                if -amount != TRANSACTION_FEE.get_e8s() as i128 {
                    let msg = format!("Fee should be equal: {}", TRANSACTION_FEE.get_e8s());
                    return Err(op_error(o, msg));
                }
                state.fee(account, Tokens::from_e8s((-amount) as u64))?;
            }
            STAKE => {
                validate_neuron_management_op()?;
                let NeuronIdentifierMetadata { neuron_index } = o.metadata.clone().try_into()?;
                state.stake(account, neuron_index)?;
            }
            SET_DISSOLVE_TIMESTAMP => {
                validate_neuron_management_op()?;
                let SetDissolveTimestampMetadata {
                    neuron_index,
                    timestamp,
                } = o.metadata.clone().try_into()?;

                state.set_dissolve_timestamp(account, neuron_index, timestamp)?;
            }
            START_DISSOLVE => {
                validate_neuron_management_op()?;
                let NeuronIdentifierMetadata { neuron_index } = o.metadata.clone().try_into()?;
                state.start_dissolve(account, neuron_index)?;
            }
            STOP_DISSOLVE => {
                validate_neuron_management_op()?;
                let NeuronIdentifierMetadata { neuron_index } = o.metadata.clone().try_into()?;
                state.stop_dissolve(account, neuron_index)?;
            }
            ADD_HOT_KEY => {
                let KeyMetadata { key, neuron_index } = o.metadata.clone().try_into()?;
                validate_neuron_management_op()?;
                state.add_hot_key(account, neuron_index, key)?;
            }
            DISBURSE => {
                let DisburseMetadata {
                    neuron_index,
                    recipient,
                } = o.metadata.clone().try_into()?;
                validate_neuron_management_op()?;
                let amount = if let Some(ref amount) = o.amount {
                    Some(
                        convert::ledgeramount_from_amount(amount, token_name).map_err(|e| {
                            ApiError::internal_error(format!("Could not convert Amount {:?}", e))
                        })?,
                    )
                } else {
                    None
                };
                state.disburse(account, neuron_index, amount, recipient)?;
            }
            SPAWN => {
                let SpawnMetadata {
                    neuron_index,
                    controller,
                    spawned_neuron_index,
                } = o.metadata.clone().try_into()?;
                validate_neuron_management_op()?;
                state.spawn(account, neuron_index, spawned_neuron_index, controller)?;
            }
            _ => {
                let msg = format!("Unsupported operation type: {}", o._type);
                return Err(op_error(o, msg));
            }
        }
    }

    state.flush()?;

    if state.actions.is_empty() {
        return Err(ApiError::InvalidTransaction(
            false,
            "Operations don't contain any actions.".into(),
        ));
    }

    Ok(state.actions)
}

pub fn amount_(amount: Tokens, token_name: &str) -> Result<Amount, ApiError> {
    let amount = amount.get_e8s();
    Ok(Amount {
        value: format!("{}", amount),
        currency: Currency::new(token_name.into(), DECIMAL_PLACES),
        metadata: None,
    })
}

pub fn signed_amount(amount: i128, token_name: &str) -> Amount {
    Amount {
        value: format!("{}", amount),
        currency: Currency::new(token_name.into(), DECIMAL_PLACES),
        metadata: None,
    }
}

pub fn from_amount(amount: &Amount, token_name: &str) -> Result<i128, String> {
    let cur = Currency::new(token_name.into(), DECIMAL_PLACES);
    match amount {
        Amount {
            value,
            currency,
            metadata: None,
        } if currency == &cur => {
            let val: i128 = value
                .parse()
                .map_err(|e| format!("Parsing amount failed: {}", e))?;
            let _ =
                u64::try_from(val.abs()).map_err(|_| "Amount does not fit in u64".to_string())?;
            Ok(val)
        }
        wrong => Err(format!("This value is not {} {:?}", token_name, wrong)),
    }
}

pub fn ledgeramount_from_amount(amount: &Amount, token_name: &str) -> Result<Tokens, String> {
    let inner = from_amount(amount, token_name)?;
    Ok(Tokens::from_e8s(inner as u64))
}

pub fn block_id(block: &HashedBlock) -> Result<BlockIdentifier, ApiError> {
    let idx = i64::try_from(block.index).map_err(|_| {
        ApiError::internal_error("block index is too large to be converted from a u64 to an i64")
    })?;
    Ok(BlockIdentifier::new(idx, from_hash(&block.hash)))
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
        .ok_or_else(|| ApiError::internal_error("No value `LAST_HEIGHT` in object"))?;
    from_value(v).map_err(|e| ApiError::internal_error(e.to_string()))
}

pub fn from_public_key(pk: &models::PublicKey) -> Result<Vec<u8>, ApiError> {
    from_hex(&pk.hex_bytes)
}

pub fn from_hex(hex: &str) -> Result<Vec<u8>, ApiError> {
    hex::decode(hex)
        .map_err(|e| ApiError::invalid_request(format!("Hex could not be decoded {}", e)))
}

pub fn to_hex(v: &[u8]) -> String {
    hex::encode(v)
}

pub fn account_from_public_key(pk: &models::PublicKey) -> Result<AccountIdentifier, ApiError> {
    let pid = principal_id_from_public_key(pk)?;
    Ok(to_model_account_identifier(&pid.into()))
}

/// `neuron_index` must also be the `nonce` of neuron management commands.
// TODO(ROSETTA1-178) this method doesn't work for Spawned neurons.
pub fn neuron_subaccount_bytes_from_public_key(
    pk: &models::PublicKey,
    neuron_index: u64,
) -> Result<[u8; 32], ApiError> {
    let controller = principal_id_from_public_key(pk)?;

    // FIXME: cut&paste from compute_neuron_staking_subaccount() in
    // rs/nns/governance/src/governance.rs.
    let mut state = ic_crypto_sha::Sha256::new();
    state.write(&[0x0c]);
    state.write(b"neuron-stake");
    state.write(controller.as_slice());
    state.write(&neuron_index.to_be_bytes());
    Ok(state.finish())
}

/// `neuron_index` must also be the `nonce` of neuron management commands.
pub fn neuron_account_from_public_key(
    governance_canister_id: &CanisterId,
    pk: &models::PublicKey,
    neuron_index: u64,
) -> Result<AccountIdentifier, ApiError> {
    let subaccount_bytes = neuron_subaccount_bytes_from_public_key(pk, neuron_index)?;
    Ok(to_model_account_identifier(
        &ledger_canister::AccountIdentifier::new(
            governance_canister_id.get(),
            Some(Subaccount(subaccount_bytes)),
        ),
    ))
}

pub fn principal_id_from_public_key(pk: &models::PublicKey) -> Result<PrincipalId, ApiError> {
    if pk.curve_type != models::CurveType::Edwards25519 {
        return Err(ApiError::InvalidPublicKey(
            false,
            "Only EDWARDS25519 curve type is supported".into(),
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
        .map_err(ApiError::internal_error)
        .map(|ProtoBuf(c)| c)
}

pub fn to_arg(args: SendArgs) -> Vec<u8> {
    ProtoBuf(args).into_bytes().expect("Serialization failed")
}

pub fn from_hash<T>(hash: &HashOf<T>) -> String {
    format!("{}", *hash)
}

pub fn to_hash<T>(s: &str) -> Result<HashOf<T>, ApiError> {
    s.parse().map_err(ApiError::internal_error)
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

#[cfg(test)]
mod tests;
