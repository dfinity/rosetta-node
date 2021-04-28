use crate::{ingress::WasmResult, CanisterId, Funds, NumBytes};
use ic_error_types::{RejectCode, UserError};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::queues::v1 as pb_queues,
    types::v1 as pb_types,
};
use phantom_newtype::Id;
use serde::{Deserialize, Serialize};
use std::convert::{From, TryFrom, TryInto};

pub struct CallbackIdTag;
/// A value used as an opaque nonce to couple outgoing calls with their
/// callbacks.
pub type CallbackId = Id<CallbackIdTag, u64>;

pub enum CallContextIdTag {}
/// Identifies an incoming call.
pub type CallContextId = Id<CallContextIdTag, u64>;

/// Canister-to-canister request message.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Request {
    pub receiver: CanisterId,
    pub sender: CanisterId,
    pub sender_reply_callback: CallbackId,
    pub payment: Funds,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    pub method_payload: Vec<u8>,
}

impl Request {
    /// Returns the sender of this `Request`.
    pub fn sender(&self) -> CanisterId {
        self.sender
    }

    /// Takes the payment out of this `Request`.
    pub fn take_funds(&mut self) -> Funds {
        self.payment.take()
    }

    /// Returns this `Request`s payload.
    pub fn method_payload(&self) -> &[u8] {
        &self.method_payload
    }

    /// Returns the size of the user-controlled part of this `Request`,
    /// in bytes.
    pub fn payload_size_bytes(&self) -> NumBytes {
        let bytes = self.method_name.len() + self.method_payload.len();
        NumBytes::from(bytes as u64)
    }
}

/// The context attached when an inter-canister message is rejected.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RejectContext {
    pub code: RejectCode,
    pub message: String,
}

impl RejectContext {
    pub fn new(code: RejectCode, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> RejectCode {
        self.code
    }

    pub fn message(&self) -> String {
        self.message.clone()
    }

    /// Returns the size of this `RejectContext` in bytes.
    pub fn size_of(&self) -> NumBytes {
        let size = std::mem::size_of::<RejectCode>() + self.message.len();
        NumBytes::from(size as u64)
    }
}

impl From<UserError> for RejectContext {
    fn from(err: UserError) -> Self {
        Self {
            code: RejectCode::from(err.code()),
            message: err.description().to_string(),
        }
    }
}

/// A union of all possible message payloads.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Payload {
    /// Opaque payload data of the current message.
    Data(Vec<u8>),
    /// Reject information of the current message (which can only be a
    /// response).
    Reject(RejectContext),
}

impl Payload {
    /// Returns the size of this `Payload` in bytes.
    pub fn size_of(&self) -> NumBytes {
        match self {
            Payload::Data(data) => NumBytes::from(data.len() as u64),
            Payload::Reject(context) => context.size_of(),
        }
    }
}

impl From<Result<Option<WasmResult>, UserError>> for Payload {
    fn from(result: Result<Option<WasmResult>, UserError>) -> Self {
        match result {
            Ok(wasm_result) => match wasm_result {
                None => Payload::Reject(RejectContext {
                    code: RejectCode::CanisterError,
                    message: "No response".to_string(),
                }),
                Some(WasmResult::Reply(payload)) => Payload::Data(payload),
                Some(WasmResult::Reject(reject_msg)) => Payload::Reject(RejectContext {
                    code: RejectCode::CanisterReject,
                    message: reject_msg,
                }),
            },
            Err(user_error) => Payload::Reject(RejectContext {
                code: user_error.reject_code(),
                message: user_error.to_string(),
            }),
        }
    }
}

/// Canister-to-canister response message.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Response {
    pub originator: CanisterId,
    pub respondent: CanisterId,
    pub originator_reply_callback: CallbackId,
    pub refund: Funds,
    pub response_payload: Payload,
}

/// Canister-to-canister message.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RequestOrResponse {
    Request(Request),
    Response(Response),
}

impl RequestOrResponse {
    pub fn receiver(&self) -> CanisterId {
        match self {
            RequestOrResponse::Request(req) => req.receiver,
            RequestOrResponse::Response(resp) => resp.originator,
        }
    }

    pub fn sender(&self) -> CanisterId {
        match self {
            RequestOrResponse::Request(req) => req.sender,
            RequestOrResponse::Response(resp) => resp.respondent,
        }
    }
}

impl From<Request> for RequestOrResponse {
    fn from(req: Request) -> Self {
        RequestOrResponse::Request(req)
    }
}

impl From<Response> for RequestOrResponse {
    fn from(resp: Response) -> Self {
        RequestOrResponse::Response(resp)
    }
}

impl From<&Request> for pb_queues::Request {
    fn from(req: &Request) -> Self {
        Self {
            receiver: Some(pb_types::CanisterId::from(req.receiver)),
            sender: Some(pb_types::CanisterId::from(req.sender)),
            sender_reply_callback: req.sender_reply_callback.get(),
            payment: Some((&req.payment).into()),
            method_name: req.method_name.clone(),
            method_payload: req.method_payload.clone(),
        }
    }
}

impl TryFrom<pb_queues::Request> for Request {
    type Error = ProxyDecodeError;

    fn try_from(req: pb_queues::Request) -> Result<Self, Self::Error> {
        Ok(Self {
            receiver: try_from_option_field(req.receiver, "Request::receiver")?,
            sender: try_from_option_field(req.sender, "Request::sender")?,
            sender_reply_callback: req.sender_reply_callback.into(),
            payment: try_from_option_field(req.payment, "Request::payment")?,
            method_name: req.method_name,
            method_payload: req.method_payload,
        })
    }
}

impl From<&RejectContext> for pb_queues::RejectContext {
    fn from(rc: &RejectContext) -> Self {
        Self {
            reject_code: rc.code as u64,
            reject_message: rc.message(),
        }
    }
}

impl TryFrom<pb_queues::RejectContext> for RejectContext {
    type Error = ProxyDecodeError;

    fn try_from(rc: pb_queues::RejectContext) -> Result<Self, Self::Error> {
        Ok(RejectContext {
            code: rc.reject_code.try_into()?,
            message: rc.reject_message,
        })
    }
}

impl From<&Response> for pb_queues::Response {
    fn from(rep: &Response) -> Self {
        let p = match &rep.response_payload {
            Payload::Data(d) => pb_queues::response::ResponsePayload::Data(d.clone()),
            Payload::Reject(r) => pb_queues::response::ResponsePayload::Reject(r.into()),
        };
        Self {
            originator: Some(pb_types::CanisterId::from(rep.originator)),
            respondent: Some(pb_types::CanisterId::from(rep.respondent)),
            originator_reply_callback: rep.originator_reply_callback.get(),
            refund: Some((&rep.refund).into()),
            response_payload: Some(p),
        }
    }
}

impl TryFrom<pb_queues::Response> for Response {
    type Error = ProxyDecodeError;

    fn try_from(rep: pb_queues::Response) -> Result<Self, Self::Error> {
        let response_payload = match rep
            .response_payload
            .ok_or(ProxyDecodeError::MissingField("Response::response_payload"))?
        {
            pb_queues::response::ResponsePayload::Data(d) => Payload::Data(d),
            pb_queues::response::ResponsePayload::Reject(r) => Payload::Reject(r.try_into()?),
        };
        Ok(Self {
            originator: try_from_option_field(rep.originator, "Response::originator")?,
            respondent: try_from_option_field(rep.respondent, "Response::respondent")?,
            originator_reply_callback: rep.originator_reply_callback.into(),
            refund: try_from_option_field(rep.refund, "Response::refund")?,
            response_payload,
        })
    }
}

impl From<&RequestOrResponse> for pb_queues::RequestOrResponse {
    fn from(rr: &RequestOrResponse) -> Self {
        match rr {
            RequestOrResponse::Request(req) => pb_queues::RequestOrResponse {
                r: Some(pb_queues::request_or_response::R::Request(req.into())),
            },
            RequestOrResponse::Response(rep) => pb_queues::RequestOrResponse {
                r: Some(pb_queues::request_or_response::R::Response(rep.into())),
            },
        }
    }
}

impl TryFrom<pb_queues::RequestOrResponse> for RequestOrResponse {
    type Error = ProxyDecodeError;

    fn try_from(rr: pb_queues::RequestOrResponse) -> Result<Self, Self::Error> {
        match rr
            .r
            .ok_or(ProxyDecodeError::MissingField("RequestOrResponse::r"))?
        {
            pb_queues::request_or_response::R::Request(r) => {
                Ok(RequestOrResponse::Request(r.try_into()?))
            }
            pb_queues::request_or_response::R::Response(r) => {
                Ok(RequestOrResponse::Response(r.try_into()?))
            }
        }
    }
}
