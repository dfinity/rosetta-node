//! Canonical types for encoding canonical state tree leaves.
//!
//! These structs mirror the ones defined in the `ic-types` crate, with the
//! intent of providing a stable, efficient representation when serialized as
//! CBOR. `From` and `TryFrom` implementations allow converting back and forth
//! between these canonical types and the `ic-types` ones.
//!
//! Enums are encoded as structs with optional fields that are not encoded when
//! `None`. C-like enums are represented as the corresponding unsigned value.
//! Newtypes, such as various IDs are replaced by the wrapped type.
//! `CanisterIds` are represented as byte vectors.

use ic_protobuf::proxy::ProxyDecodeError;
use serde::{Deserialize, Serialize};
use std::convert::{From, Into, TryFrom, TryInto};

type Bytes = Vec<u8>;

/// Canonical representation of `ic_types::xnet::StreamHeader`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamHeader {
    pub begin: u64,
    pub end: u64,
    pub signals_end: u64,
}

/// Canonical representation of `ic_types::messages::RequestOrResponse`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestOrResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Request>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Response>,
}

/// Canonical representation of `ic_types::messages::Request`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(with = "serde_bytes")]
    pub receiver: Bytes,
    #[serde(with = "serde_bytes")]
    pub sender: Bytes,
    pub sender_reply_callback: u64,
    pub payment: Funds,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    pub method_payload: Bytes,
}

/// Canonical representation of `ic_types::messages::Response`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    #[serde(with = "serde_bytes")]
    pub originator: Bytes,
    #[serde(with = "serde_bytes")]
    pub respondent: Bytes,
    pub originator_reply_callback: u64,
    pub refund: Funds,
    pub response_payload: Payload,
}

/// Canonical representation of `ic_types::funds::Cycles`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cycles {
    pub raw: u64,
}

/// Canonical representation of `ic_types::funds::Funds`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Funds {
    pub cycles: Cycles,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub icp: u64,
}

pub fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// Canonical representation of `ic_types::messages::Payload`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    #[serde(with = "serde_bytes", skip_serializing_if = "Option::is_none", default)]
    pub data: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject: Option<RejectContext>,
}

/// Canonical representation of `ic_types::messages::RejectContext`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectContext {
    pub code: u8,
    pub message: String,
}

/// Canonical representation of state metadata leaf.
#[derive(Debug, Serialize)]
pub struct SystemMetadata {
    /// The counter used to allocate canister ids.
    pub id_counter: u64,
    /// Hash bytes of the previous (partial) canonical state.
    pub prev_state_hash: Option<Vec<u8>>,
}

impl From<&ic_types::xnet::StreamHeader> for StreamHeader {
    fn from(header: &ic_types::xnet::StreamHeader) -> Self {
        Self {
            begin: header.begin.get(),
            end: header.end.get(),
            signals_end: header.signals_end.get(),
        }
    }
}

impl From<StreamHeader> for ic_types::xnet::StreamHeader {
    fn from(header: StreamHeader) -> Self {
        Self {
            begin: header.begin.into(),
            end: header.end.into(),
            signals_end: header.signals_end.into(),
        }
    }
}

impl From<&ic_types::messages::RequestOrResponse> for RequestOrResponse {
    fn from(message: &ic_types::messages::RequestOrResponse) -> Self {
        use ic_types::messages::RequestOrResponse::*;
        match message {
            Request(request) => Self {
                request: Some(request.into()),
                response: None,
            },
            Response(response) => Self {
                request: None,
                response: Some(response.into()),
            },
        }
    }
}

impl TryFrom<RequestOrResponse> for ic_types::messages::RequestOrResponse {
    type Error = ProxyDecodeError;

    fn try_from(message: RequestOrResponse) -> Result<Self, Self::Error> {
        match message {
            RequestOrResponse {
                request: Some(request),
                response: None,
            } => Ok(Self::Request(request.try_into()?)),
            RequestOrResponse {
                request: None,
                response: Some(response),
            } => Ok(Self::Response(response.try_into()?)),
            other => Err(ProxyDecodeError::Other(format!(
                "RequestOrResponse: expected exactly one of `request` or `response` to be `Some(_)`, got `{:?}`",
                other
            )))
        }
    }
}

impl From<&ic_types::messages::Request> for Request {
    fn from(request: &ic_types::messages::Request) -> Self {
        Self {
            receiver: request.receiver.get().to_vec(),
            sender: request.sender.get().to_vec(),
            sender_reply_callback: request.sender_reply_callback.get(),
            payment: (&request.payment).into(),
            method_name: request.method_name.clone(),
            method_payload: request.method_payload.clone(),
        }
    }
}

impl TryFrom<Request> for ic_types::messages::Request {
    type Error = ProxyDecodeError;

    fn try_from(request: Request) -> Result<Self, Self::Error> {
        Ok(Self {
            receiver: ic_types::CanisterId::new(request.receiver.as_slice().try_into()?)?,
            sender: ic_types::CanisterId::new(request.sender.as_slice().try_into()?)?,
            sender_reply_callback: request.sender_reply_callback.into(),
            payment: request.payment.try_into()?,
            method_name: request.method_name,
            method_payload: request.method_payload,
        })
    }
}

impl From<&ic_types::messages::Response> for Response {
    fn from(response: &ic_types::messages::Response) -> Self {
        Self {
            originator: response.originator.get().to_vec(),
            respondent: response.respondent.get().to_vec(),
            originator_reply_callback: response.originator_reply_callback.get(),
            refund: (&response.refund).into(),
            response_payload: (&response.response_payload).into(),
        }
    }
}

impl TryFrom<Response> for ic_types::messages::Response {
    type Error = ProxyDecodeError;

    fn try_from(response: Response) -> Result<Self, Self::Error> {
        Ok(Self {
            originator: ic_types::CanisterId::new(response.originator.as_slice().try_into()?)?,
            respondent: ic_types::CanisterId::new(response.respondent.as_slice().try_into()?)?,
            originator_reply_callback: response.originator_reply_callback.into(),
            refund: response.refund.try_into()?,
            response_payload: response.response_payload.try_into()?,
        })
    }
}

impl From<&ic_types::funds::Cycles> for Cycles {
    fn from(cycles: &ic_types::funds::Cycles) -> Self {
        Self {
            raw: (*cycles).into(),
        }
    }
}

impl TryFrom<Cycles> for ic_types::funds::Cycles {
    type Error = ProxyDecodeError;

    fn try_from(cycles: Cycles) -> Result<Self, Self::Error> {
        Ok(Self::from(cycles.raw))
    }
}

impl From<&ic_types::funds::Funds> for Funds {
    fn from(funds: &ic_types::funds::Funds) -> Self {
        Self {
            cycles: (&funds.cycles()).into(),
            icp: funds.icp().balance(),
        }
    }
}

impl TryFrom<Funds> for ic_types::funds::Funds {
    type Error = ProxyDecodeError;

    fn try_from(funds: Funds) -> Result<Self, Self::Error> {
        Ok(Self::new(
            funds.cycles.try_into()?,
            ic_types::funds::icp::Tap::mint(funds.icp),
        ))
    }
}

impl From<&ic_types::messages::Payload> for Payload {
    fn from(payload: &ic_types::messages::Payload) -> Self {
        use ic_types::messages::Payload::*;
        match payload {
            Data(data) => Self {
                data: Some(data.clone()),
                reject: None,
            },
            Reject(reject) => Self {
                data: None,
                reject: Some(reject.into()),
            },
        }
    }
}

impl TryFrom<Payload> for ic_types::messages::Payload {
    type Error = ProxyDecodeError;

    fn try_from(payload: Payload) -> Result<Self, Self::Error> {
        match payload {
            Payload {
                data: Some(data),
                reject: None,
            } => Ok(Self::Data(data)),
            Payload {
                data: None,
                reject: Some(reject),
            } => Ok(Self::Reject(reject.try_into()?)),
            other => Err(ProxyDecodeError::Other(format!(
                "Payload: expected exactly one of `data` or `reject` to be `Some(_)`, got `{:?}`",
                other
            ))),
        }
    }
}

impl From<&ic_types::messages::RejectContext> for RejectContext {
    fn from(context: &ic_types::messages::RejectContext) -> Self {
        Self {
            code: context.code as u8,
            message: context.message.clone(),
        }
    }
}

impl TryFrom<RejectContext> for ic_types::messages::RejectContext {
    type Error = ProxyDecodeError;

    fn try_from(context: RejectContext) -> Result<Self, Self::Error> {
        Ok(Self {
            code: (context.code as u64).try_into()?,
            message: context.message,
        })
    }
}

impl From<&ic_replicated_state::metadata_state::SystemMetadata> for SystemMetadata {
    fn from(metadata: &ic_replicated_state::metadata_state::SystemMetadata) -> Self {
        Self {
            id_counter: metadata.generated_id_counter,
            prev_state_hash: metadata
                .prev_state_hash
                .as_ref()
                .map(|h| h.get_ref().0.clone()),
        }
    }
}
