use ic_types::{
    messages::{CallbackId, Ingress, Request, Response, StopCanisterContext},
    CanisterId, Funds, PrincipalId,
};
use std::convert::TryFrom;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CanisterInputMessage {
    Response(Response),
    Request(Request),
    Ingress(Ingress),
}

impl CanisterInputMessage {
    pub fn receiver(&self) -> &CanisterId {
        match self {
            CanisterInputMessage::Request(msg) => &msg.receiver,
            CanisterInputMessage::Ingress(msg) => &msg.receiver,
            CanisterInputMessage::Response(msg) => &msg.respondent,
        }
    }

    pub fn method_name(&self) -> Option<String> {
        match self {
            CanisterInputMessage::Request(Request { method_name, .. })
            | CanisterInputMessage::Ingress(Ingress { method_name, .. }) => {
                Some(method_name.clone())
            }
            CanisterInputMessage::Response(_) => None,
        }
    }

    pub fn callback(&self) -> Option<CallbackId> {
        match self {
            CanisterInputMessage::Request(msg) => Some(msg.sender_reply_callback),
            CanisterInputMessage::Response(msg) => Some(msg.originator_reply_callback),
            CanisterInputMessage::Ingress(_) => None,
        }
    }
}

/// A wrapper around a canister request and an ingress message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RequestOrIngress {
    Request(Request),
    Ingress(Ingress),
}

impl RequestOrIngress {
    pub fn sender(&self) -> &PrincipalId {
        match self {
            RequestOrIngress::Request(msg) => &msg.sender.as_ref(),
            RequestOrIngress::Ingress(msg) => &msg.source.as_ref(),
        }
    }

    pub fn receiver(&self) -> &CanisterId {
        match self {
            RequestOrIngress::Request(msg) => &msg.receiver,
            RequestOrIngress::Ingress(msg) => &msg.receiver,
        }
    }

    pub fn method_payload(&self) -> &[u8] {
        match self {
            RequestOrIngress::Request(msg) => msg.method_payload.as_slice(),
            RequestOrIngress::Ingress(msg) => msg.method_payload.as_slice(),
        }
    }

    pub fn method_name(&self) -> &str {
        match self {
            RequestOrIngress::Request(Request { method_name, .. })
            | RequestOrIngress::Ingress(Ingress { method_name, .. }) => method_name.as_str(),
        }
    }

    /// Extracts the funds received with this message.
    pub fn take_funds(&mut self) -> Funds {
        match self {
            RequestOrIngress::Request(Request { payment, .. }) => payment.take(),
            RequestOrIngress::Ingress(Ingress { .. }) => Funds::zero(),
        }
    }
}

impl From<RequestOrIngress> for StopCanisterContext {
    fn from(msg: RequestOrIngress) -> Self {
        assert_eq!(msg.method_name(), "stop_canister", "Converting a RequestOrIngress into StopCanisterContext should only happen with stop_canister requests.");
        match msg {
            RequestOrIngress::Request(mut req) => StopCanisterContext::Canister {
                sender: req.sender,
                reply_callback: req.sender_reply_callback,
                funds: req.payment.take(),
            },
            RequestOrIngress::Ingress(ingress) => StopCanisterContext::Ingress {
                sender: ingress.source,
                message_id: ingress.message_id,
            },
        }
    }
}

impl TryFrom<CanisterInputMessage> for RequestOrIngress {
    type Error = ();

    fn try_from(msg: CanisterInputMessage) -> Result<Self, Self::Error> {
        match msg {
            CanisterInputMessage::Request(msg) => Ok(RequestOrIngress::Request(msg)),
            CanisterInputMessage::Ingress(msg) => Ok(RequestOrIngress::Ingress(msg)),
            CanisterInputMessage::Response(_) => Err(()),
        }
    }
}
