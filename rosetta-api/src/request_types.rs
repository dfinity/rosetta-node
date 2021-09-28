use crate::{
    convert::{
        self, amount_, principal_id_from_public_key, signed_amount, to_model_account_identifier,
    },
    errors::ApiError,
    models::{self, EnvelopePair, Object, Operation, OperationIdentifier},
    time::Seconds,
    transaction_id::TransactionIdentifier,
};
use dfn_candid::CandidOne;
use ic_nns_governance::pb::v1::manage_neuron::{self, configure, Command, Configure};
use ic_types::PrincipalId;
use ledger_canister::{AccountIdentifier, BlockHeight, ICPTs, Transfer};
use on_wire::FromWire;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::convert::TryFrom;

// Since our blockchain doesn't have smart contracts all operations are always a
// single value
pub const STATUS_COMPLETED: &str = "COMPLETED";

/// The operation associated with `Request::Transfer`.
pub const TRANSACTION: &str = "TRANSACTION";
pub const MINT: &str = "MINT";
pub const BURN: &str = "BURN";
pub const FEE: &str = "FEE";
pub const STAKE: &str = "STAKE";
pub const START_DISSOLVE: &str = "START_DISSOLVE";
pub const STOP_DISSOLVE: &str = "STOP_DISSOLVE";
pub const SET_DISSOLVE_TIMESTAMP: &str = "SET_DISSOLVE_TIMESTAMP";
pub const DISSOLVE_TIME_UTC_SECONDS: &str = "dissolve_time_utc_seconds";
pub const ADD_HOT_KEY: &str = "ADD_HOT_KEY";

/// `RequestType` contains all supported values of `Operation.type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum RequestType {
    // Aliases for backwards compatibility
    #[serde(rename = "TRANSACTION")]
    #[serde(alias = "Send")]
    Send,
    #[serde(rename = "STAKE")]
    #[serde(alias = "Stake")]
    Stake,
    #[serde(rename = "SET_DISSOLVE_TIMESTAMP")]
    #[serde(alias = "SetDissolveTimestamp")]
    SetDissolveTimestamp,
    #[serde(rename = "START_DISSOLVE")]
    #[serde(alias = "StartDissolve")]
    StartDissolve,
    #[serde(rename = "STOP_DISSOLVE")]
    #[serde(alias = "StopDissolve")]
    StopDissolve,
    #[serde(rename = "ADD_HOT_KEY")]
    #[serde(alias = "AddHotKey")]
    AddHotKey,
}

impl RequestType {
    pub const fn into_str(self) -> &'static str {
        match self {
            RequestType::Send => TRANSACTION,
            RequestType::Stake => STAKE,
            RequestType::SetDissolveTimestamp => SET_DISSOLVE_TIMESTAMP,
            RequestType::StartDissolve => START_DISSOLVE,
            RequestType::StopDissolve => STOP_DISSOLVE,
            RequestType::AddHotKey => ADD_HOT_KEY,
        }
    }

    pub fn from_type_str(s: &str) -> Option<RequestType> {
        match s {
            TRANSACTION => Some(RequestType::Send),
            STAKE => Some(RequestType::Stake),
            SET_DISSOLVE_TIMESTAMP => Some(RequestType::SetDissolveTimestamp),
            START_DISSOLVE => Some(RequestType::StartDissolve),
            STOP_DISSOLVE => Some(RequestType::StopDissolve),
            ADD_HOT_KEY => Some(RequestType::AddHotKey),
            _ => None,
        }
    }

    pub const fn is_transfer(&self) -> bool {
        matches!(self, RequestType::Send)
    }

    pub const fn is_neuron_management(&self) -> bool {
        matches!(
            self,
            RequestType::Stake
                | RequestType::SetDissolveTimestamp
                | RequestType::StartDissolve
                | RequestType::StopDissolve
                | RequestType::AddHotKey
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TransactionResults {
    pub operations: Vec<RequestResult>,
}

impl TransactionResults {
    pub fn retriable(&self) -> bool {
        self.operations
            .iter()
            .filter_map(|r| r.status.failed())
            .all(|e| e.retriable())
    }

    pub fn last_block_index(&self) -> Option<BlockHeight> {
        self.operations.iter().rev().find_map(|r| r.block_index)
    }

    pub fn last_transaction_id(&self) -> Option<&TransactionIdentifier> {
        self.operations
            .iter()
            .rev()
            .find_map(|r| r.transaction_identifier.as_ref())
    }

    /// Get the last failed Request error.
    /// There should only be one, since `construction_submit` stops
    /// when it encountered an error.
    pub fn error(&self) -> Option<&ApiError> {
        self.operations.iter().rev().find_map(|r| r.status.failed())
    }
}

impl From<TransactionResults> for Object {
    fn from(d: TransactionResults) -> Self {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => o,
            _ => Object::default(),
        }
    }
}

impl From<&TransactionResults> for Object {
    fn from(d: &TransactionResults) -> Self {
        match serde_json::to_value(d) {
            Ok(Value::Object(o)) => o,
            _ => Object::default(),
        }
    }
}

impl TryFrom<Object> for TransactionResults {
    type Error = ApiError;
    fn try_from(o: Object) -> Result<Self, ApiError> {
        serde_json::from_value(serde_json::Value::Object(o)).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse RequestsResults from Object: {}",
                e
            ))
        })
    }
}

impl From<Vec<RequestResult>> for TransactionResults {
    fn from(operations: Vec<RequestResult>) -> Self {
        Self { operations }
    }
}

impl From<TransactionResults> for Vec<RequestResult> {
    fn from(r: TransactionResults) -> Self {
        r.operations
    }
}

impl From<TransactionResults> for ApiError {
    fn from(e: TransactionResults) -> Self {
        ApiError::OperationsErrors(e)
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct RequestResult {
    #[serde(rename = "type")]
    #[serde(flatten)]
    pub _type: Request,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub block_index: Option<BlockHeight>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub transaction_identifier: Option<TransactionIdentifier>,
    #[serde(flatten)]
    pub status: Status,
}

#[test]
fn request_result_serialization_test() {
    let account = AccountIdentifier::from(ic_types::PrincipalId::default());

    let neuron_identifier = 0;

    let rr = RequestResult {
        _type: Request::Stake(Stake {
            account,
            neuron_identifier,
        }),
        block_index: None,
        transaction_identifier: None,
        status: Status::Failed(ApiError::internal_error("foo")),
    };

    let se = serde_json::to_string(&rr).unwrap();
    let de: RequestResult = serde_json::from_str(&se).unwrap();
    let s = serde_json::from_str(
        r#"{
        "type":"STAKE",
        "account":"2d0e897f7e862d2b57d9bc9ea5c65f9a24ac6c074575f47898314b8d6cb0929d",
        "status":"FAILED",
        "response":{
            "code":700,
            "message":"Internal server error",
            "retriable":false,
            "details":{"error_message":"foo"}
        }
    }"#,
    )
    .unwrap();

    assert_eq!(rr, de);
    assert_eq!(rr, s);

    let rr = RequestResult {
        _type: Request::Stake(Stake {
            account,
            neuron_identifier,
        }),
        block_index: None,
        transaction_identifier: None,
        status: Status::Completed,
    };

    let se = serde_json::to_string(&rr).unwrap();
    let de: RequestResult = serde_json::from_str(&se).unwrap();
    let s = serde_json::from_str(
        r#"{
        "type":"STAKE",
        "account":"2d0e897f7e862d2b57d9bc9ea5c65f9a24ac6c074575f47898314b8d6cb0929d",
        "status":"COMPLETED"
    }"#,
    )
    .unwrap();

    assert_eq!(rr, de);
    assert_eq!(rr, s);
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(tag = "status", content = "response")]
pub enum Status {
    Completed,
    // TODO detect already applied.
    AlreadyApplied,
    Failed(ApiError),
    NotAttempted,
}

impl Status {
    pub fn failed(&self) -> Option<&ApiError> {
        match self {
            Status::Failed(e) => Some(e),
            _ => None,
        }
    }
}

/// A `Request` is the deserialized representation of an `Operation`,
/// sans the `operation_identifier`, and `FEE` Operations.
/// Multiple `Request`s can be converted to `Operation`s via the
/// `TransactionBuilder`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Request {
    /// Contains `Send`, `Mint`, and `Burn` operations.
    /// Attempting to serialize or deserialize any Mint, or Burn will error.
    #[serde(rename = "TRANSACTION")]
    #[serde(with = "send")]
    Transfer(Transfer),
    #[serde(rename = "STAKE")]
    Stake(Stake),
    #[serde(rename = "SET_DISSOLVE_TIMESTAMP")]
    SetDissolveTimestamp(SetDissolveTimestamp),
    #[serde(rename = "START_DISSOLVE")]
    StartDissolve(StartDissolve),
    #[serde(rename = "STOP_DISSOLVE")]
    StopDissolve(StopDissolve),
    #[serde(rename = "ADD_HOT_KEY")]
    AddHotKey(AddHotKey),
}

impl Request {
    pub fn request_type(&self) -> Result<RequestType, ApiError> {
        match self {
            Request::Stake(_) => Ok(RequestType::Stake),
            Request::SetDissolveTimestamp(_) => Ok(RequestType::SetDissolveTimestamp),
            Request::StartDissolve(_) => Ok(RequestType::StartDissolve),
            Request::StopDissolve(_) => Ok(RequestType::StopDissolve),
            Request::Transfer(Transfer::Send { .. }) => Ok(RequestType::Send),
            Request::Transfer(Transfer::Burn { .. }) => Err(ApiError::invalid_request(
                "Burn operations are not supported through rosetta",
            )),
            Request::Transfer(Transfer::Mint { .. }) => Err(ApiError::invalid_request(
                "Mint operations are not supported through rosetta",
            )),
            Request::AddHotKey(AddHotKey { .. }) => Ok(RequestType::AddHotKey),
        }
    }

    /// Builds a Transaction from a sequence of `Request`s.
    /// This is a thin wrapper over the `TransactionBuilder`.
    ///
    /// TODO We should capture the concept of a Transaction in a type.
    pub fn requests_to_operations(requests: &[Request]) -> Result<Vec<Operation>, ApiError> {
        let mut builder = TransactionBuilder::default();
        for request in requests {
            match request {
                Request::Transfer(o) => builder.transfer(o)?,
                Request::Stake(o) => builder.stake(o),
                Request::SetDissolveTimestamp(o) => builder.set_dissolve_timestamp(o),
                Request::StartDissolve(o) => builder.start_dissolve(o),
                Request::StopDissolve(o) => builder.stop_dissolve(o),
                Request::AddHotKey(o) => builder.add_hot_key(o),
            };
        }
        Ok(builder.build())
    }

    pub fn is_transfer(&self) -> bool {
        matches!(self, Request::Transfer(_))
    }

    pub fn is_neuron_management(&self) -> bool {
        matches!(
            self,
            Request::Stake(_)
                | Request::SetDissolveTimestamp(_)
                | Request::StartDissolve(_)
                | Request::StopDissolve(_)
                | Request::AddHotKey(_)
        )
    }
}

/// Sort of the inverse of `construction_payloads`.
impl TryFrom<&models::Request> for Request {
    type Error = ApiError;

    fn try_from(req: &models::Request) -> Result<Self, Self::Error> {
        let (request_type, calls) = req;
        let payload: &models::EnvelopePair = calls
            .first()
            .ok_or_else(|| ApiError::invalid_request("No request payload provided."))?;

        let pid =
            PrincipalId::try_from(payload.update_content().sender.clone().0).map_err(|e| {
                ApiError::internal_error(format!(
                    "Could not parse envelope sender's public key: {}",
                    e
                ))
            })?;

        let account = AccountIdentifier::from(pid);

        let manage_neuron = || {
            {
                CandidOne::<ic_nns_governance::pb::v1::ManageNeuron>::from_bytes(
                    payload.update_content().arg.0.clone(),
                )
                .map_err(|e| {
                    ApiError::invalid_request(format!("Could not parse manage_neuron: {}", e))
                })
            }
            .map(|m| m.0.command)
        };

        let neuron_identifier = |payload: &EnvelopePair| {
            payload
                .update_content()
                .nonce
                .clone()
                .and_then(|b| CandidOne::<u64>::from_bytes(b.0).map(|c| c.0).ok())
                .unwrap_or_default()
        };

        match request_type {
            RequestType::Send => {
                let ledger_canister::SendArgs {
                    to, amount, fee, ..
                } = convert::from_arg(payload.update_content().arg.0.clone())?;
                Ok(Request::Transfer(Transfer::Send {
                    from: account,
                    to,
                    amount,
                    fee,
                }))
            }
            RequestType::Stake => Ok(Request::Stake(Stake {
                account,
                neuron_identifier: neuron_identifier(payload),
            })),
            RequestType::SetDissolveTimestamp => {
                let command = manage_neuron()?;
                if let Some(Command::Configure(Configure {
                    operation:
                        Some(configure::Operation::SetDissolveTimestamp(
                            manage_neuron::SetDissolveTimestamp {
                                dissolve_timestamp_seconds,
                                ..
                            },
                        )),
                })) = command
                {
                    Ok(Request::SetDissolveTimestamp(SetDissolveTimestamp {
                        account,
                        neuron_identifier: neuron_identifier(payload),
                        timestamp: Seconds(dissolve_timestamp_seconds),
                    }))
                } else {
                    Err(ApiError::invalid_request(
                        "Request is missing set dissolve timestamp operation.",
                    ))
                }
            }
            RequestType::StartDissolve => Ok(Request::StartDissolve(StartDissolve {
                account,
                neuron_identifier: neuron_identifier(payload),
            })),
            RequestType::StopDissolve => Ok(Request::StopDissolve(StopDissolve {
                account,
                neuron_identifier: neuron_identifier(payload),
            })),
            RequestType::AddHotKey => {
                if let Some(Command::Configure(Configure {
                    operation:
                        Some(configure::Operation::AddHotKey(manage_neuron::AddHotKey {
                            new_hot_key: Some(pid),
                            ..
                        })),
                })) = manage_neuron()?
                {
                    Ok(Request::AddHotKey(AddHotKey {
                        account,
                        neuron_identifier: neuron_identifier(payload),
                        key: PublicKeyOrPrincipal::Principal(pid),
                    }))
                } else {
                    Err(ApiError::invalid_request("Request is missing set hotkey."))
                }
            }
        }
    }
}

/// A helper for serializing `RequestResults`
mod send {
    use super::*;

    pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Transfer, D::Error> {
        Send::deserialize(d)
            .map(Transfer::from)
            .map_err(D::Error::from)
    }

    pub fn serialize<S: Serializer>(t: &Transfer, s: S) -> Result<S::Ok, S::Error> {
        Send::try_from(t)
            .map_err(serde::ser::Error::custom)
            .and_then(|t| t.serialize(s))
    }

    #[derive(Copy, Clone, Deserialize, Serialize)]
    struct Send {
        from: AccountIdentifier,
        to: AccountIdentifier,
        amount: ICPTs,
        fee: ICPTs,
    }

    impl TryFrom<&Transfer> for Send {
        type Error = String;

        fn try_from(transfer: &Transfer) -> Result<Self, String> {
            match *transfer {
                Transfer::Send {
                    from,
                    to,
                    amount,
                    fee,
                } => Ok(Send {
                    from,
                    to,
                    amount,
                    fee,
                }),
                Transfer::Burn { .. } => {
                    Err("Burn operations are not supported through rosetta".to_owned())
                }
                Transfer::Mint { .. } => {
                    Err("Mint operations are not supported through rosetta".to_owned())
                }
            }
        }
    }

    impl From<Send> for Transfer {
        fn from(s: Send) -> Self {
            let Send {
                from,
                to,
                amount,
                fee,
            } = s;
            Transfer::Send {
                from,
                to,
                amount,
                fee,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SetDissolveTimestamp {
    pub account: ledger_canister::AccountIdentifier,
    #[serde(default)]
    pub neuron_identifier: u64,
    /// The number of seconds since Unix epoch.
    pub timestamp: Seconds,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StartDissolve {
    pub account: ledger_canister::AccountIdentifier,
    pub neuron_identifier: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StopDissolve {
    pub account: ledger_canister::AccountIdentifier,
    #[serde(default)]
    pub neuron_identifier: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Stake {
    pub account: ledger_canister::AccountIdentifier,
    #[serde(default)]
    pub neuron_identifier: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AddHotKey {
    pub account: ledger_canister::AccountIdentifier,
    #[serde(default)]
    pub neuron_identifier: u64,
    pub key: PublicKeyOrPrincipal,
}

#[derive(Debug, Clone, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicKeyOrPrincipal {
    PublicKey(models::PublicKey),
    Principal(PrincipalId),
}

impl TryFrom<&PublicKeyOrPrincipal> for PrincipalId {
    type Error = ApiError;
    fn try_from(p: &PublicKeyOrPrincipal) -> Result<PrincipalId, ApiError> {
        match p {
            PublicKeyOrPrincipal::PublicKey(pk) => principal_id_from_public_key(pk),
            PublicKeyOrPrincipal::Principal(pid) => Ok(*pid),
        }
    }
}

/// Comparisons are done on the normalized representation PrincipalId.
/// This is needed for testing.
impl PartialEq for PublicKeyOrPrincipal {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PublicKeyOrPrincipal::PublicKey(pk0), PublicKeyOrPrincipal::PublicKey(pk1)) => {
                pk0 == pk1
            }
            _ => PrincipalId::try_from(self) == PrincipalId::try_from(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SetDissolveTimestampMetadata {
    #[serde(default)]
    pub neuron_identifier: u64,
    #[serde(rename = "dissolve_time_utc_seconds")]
    /// The number of seconds since Unix epoch.
    pub timestamp: Seconds,
}

impl From<SetDissolveTimestampMetadata> for Object {
    fn from(m: SetDissolveTimestampMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

impl TryFrom<Option<Object>> for SetDissolveTimestampMetadata {
    type Error = ApiError;

    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Set Dissolve Timestamp operation must have a 'dissolve_time_utc_seconds' metadata field.
                 The timestamp is a number of seconds since the Unix epoch.
                 This is represented as an unsigned 64 bit integer and encoded as a JSON string.

                 A Set Dissolve Timestamp operation may have a 'neuron_identifier' metadata field.
                 The 'neuron_identifier` field differentiates between neurons controlled by the user.

                 Parse Error: {}",
                e
            ))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Deserialize, Serialize)]
pub struct NeuronIdentifierMetadata {
    #[serde(default)]
    pub neuron_identifier: u64,
}

impl TryFrom<Option<Object>> for NeuronIdentifierMetadata {
    type Error = ApiError;

    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `neuron_identifier` from metadata JSON object: {}",
                e
            ))
        })
    }
}

impl From<NeuronIdentifierMetadata> for Object {
    fn from(m: NeuronIdentifierMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct KeyMetadata {
    #[serde(flatten)]
    pub key: PublicKeyOrPrincipal,
    #[serde(default)]
    pub neuron_identifier: u64,
}

impl TryFrom<Option<Object>> for KeyMetadata {
    type Error = ApiError;

    fn try_from(o: Option<Object>) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::Value::Object(o.unwrap_or_default())).map_err(|e| {
            ApiError::internal_error(format!(
                "Could not parse a `neuron_identifier` from metadata JSON object: {}",
                e
            ))
        })
    }
}

impl From<KeyMetadata> for Object {
    fn from(m: KeyMetadata) -> Self {
        match serde_json::to_value(m) {
            Ok(Value::Object(o)) => o,
            _ => unreachable!(),
        }
    }
}

/// Transaction is a bit of a misnomer, since operations can succeed or fail
/// independently from a Transaction.
pub struct TransactionBuilder {
    /// The next `OperationIdentifier` `index`.
    /// TODO Why is `OperationIdentifier.index` a signed integer?
    op_index: i64,
    ops: Vec<Operation>,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self {
            op_index: 0,
            ops: Vec::default(),
        }
    }
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> Vec<Operation> {
        self.ops
    }

    pub fn allocate_op_id(&mut self) -> OperationIdentifier {
        let id = OperationIdentifier::new(self.op_index);
        self.op_index += 1;
        id
    }

    /// Add a `Request::Transfer` to the Transaction.
    /// This handles `Send`, `Mint`, and `Burn`.
    pub fn transfer(&mut self, transfer: &Transfer) -> Result<(), ApiError> {
        match transfer {
            Transfer::Burn { from, amount } => {
                let operation_identifier = self.allocate_op_id();
                self.ops.push(Operation {
                    operation_identifier,
                    _type: BURN.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(from)),
                    amount: Some(signed_amount(-i128::from(amount.get_e8s()))),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
            }
            Transfer::Mint { to, amount } => {
                let operation_identifier = self.allocate_op_id();
                self.ops.push(Operation {
                    operation_identifier,
                    _type: MINT.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(&to)),
                    amount: Some(amount_(*amount)?),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
            }
            Transfer::Send {
                from,
                to,
                amount,
                fee,
            } => {
                let from_account = Some(to_model_account_identifier(&from));
                let amount = i128::from(amount.get_e8s());

                let operation_identifier = self.allocate_op_id();
                self.ops.push(Operation {
                    operation_identifier,
                    _type: TRANSACTION.to_string(),
                    status: None,
                    account: from_account.clone(),
                    amount: Some(signed_amount(-amount)),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
                let operation_identifier = self.allocate_op_id();
                self.ops.push(Operation {
                    operation_identifier,
                    _type: TRANSACTION.to_string(),
                    status: None,
                    account: Some(to_model_account_identifier(&to)),
                    amount: Some(signed_amount(amount)),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
                let operation_identifier = self.allocate_op_id();
                self.ops.push(Operation {
                    operation_identifier,
                    _type: FEE.to_string(),
                    status: None,
                    account: from_account,
                    amount: Some(signed_amount(-(fee.get_e8s() as i128))),
                    related_operations: None,
                    coin_change: None,
                    metadata: None,
                });
            }
        };
        Ok(())
    }

    pub fn stake(&mut self, stake: &Stake) {
        let Stake {
            account,
            neuron_identifier,
        } = stake;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: STAKE.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                NeuronIdentifierMetadata {
                    neuron_identifier: *neuron_identifier,
                }
                .into(),
            ),
        });
    }

    pub fn set_dissolve_timestamp(&mut self, set_dissolve: &SetDissolveTimestamp) {
        let SetDissolveTimestamp {
            account,
            neuron_identifier,
            timestamp,
        } = set_dissolve;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: SET_DISSOLVE_TIMESTAMP.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                SetDissolveTimestampMetadata {
                    neuron_identifier: *neuron_identifier,
                    timestamp: *timestamp,
                }
                .into(),
            ),
        });
    }

    pub fn start_dissolve(&mut self, start_dissolve: &StartDissolve) {
        let StartDissolve {
            account,
            neuron_identifier,
        } = start_dissolve;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: START_DISSOLVE.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                NeuronIdentifierMetadata {
                    neuron_identifier: *neuron_identifier,
                }
                .into(),
            ),
        });
    }

    pub fn stop_dissolve(&mut self, stop_dissolve: &StopDissolve) {
        let StopDissolve {
            account,
            neuron_identifier,
        } = stop_dissolve;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: STOP_DISSOLVE.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                NeuronIdentifierMetadata {
                    neuron_identifier: *neuron_identifier,
                }
                .into(),
            ),
        });
    }

    pub fn add_hot_key(&mut self, key: &AddHotKey) {
        let AddHotKey {
            account,
            neuron_identifier,
            key,
        } = key;
        let operation_identifier = self.allocate_op_id();
        self.ops.push(Operation {
            operation_identifier,
            _type: ADD_HOT_KEY.to_string(),
            status: None,
            account: Some(to_model_account_identifier(account)),
            amount: None,
            related_operations: None,
            coin_change: None,
            metadata: Some(
                KeyMetadata {
                    key: key.clone(),
                    neuron_identifier: *neuron_identifier,
                }
                .into(),
            ),
        });
    }
}
