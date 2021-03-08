//! This module contains various definitions related to Ingress messages

use super::{HttpHandlerError, MessageId, RawHttpRequestVal, UserSignature};
use crate::{
    crypto::Signed,
    messages::message_id::hash_of_map,
    messages::{Authentication, HttpCanisterUpdate, HttpRequest, HttpRequestContent},
    CanisterId, CountBytes, PrincipalId, Time, UserId,
};
use ic_protobuf::{
    log::ingress_message_log_entry::v1::IngressMessageLogEntry,
    proxy::{try_from_option_field, ProxyDecodeError},
    state::ingress::v1 as pb_ingress,
    types::v1 as pb_types,
};
use maplit::btreemap;
use serde::{Deserialize, Serialize};
use std::{
    convert::{From, TryFrom, TryInto},
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SignedIngressContent {
    sender: UserId,
    canister_id: CanisterId,
    method_name: String,
    arg: Vec<u8>,
    ingress_expiry: u64,
    nonce: Option<Vec<u8>>,
}

impl SignedIngressContent {
    fn id(&self) -> MessageId {
        use RawHttpRequestVal::*;
        let mut map = btreemap! {
            "request_type".to_string() => String("call".to_string()),
            "canister_id".to_string() => Bytes(self.canister_id.get().to_vec()),
            "method_name".to_string() => String(self.method_name.clone()),
            "arg".to_string() => Bytes(self.arg.clone()),
            "ingress_expiry".to_string() => U64(self.ingress_expiry),
            "sender".to_string() => Bytes(self.sender.get().to_vec()),
        };
        if let Some(nonce) = &self.nonce {
            map.insert("nonce".to_string(), Bytes(nonce.clone()));
        }
        MessageId::from(hash_of_map(&map))
    }
}

impl CountBytes for SignedIngressContent {
    fn count_bytes(&self) -> usize {
        self.sender.get().as_slice().len()
            + self.canister_id.get().as_slice().len()
            + self.method_name.len()
            + self.arg.len()
            + self.nonce.as_ref().map(|n| n.len()).unwrap_or(0)
    }
}

impl HttpRequestContent for SignedIngressContent {
    fn sender(&self) -> UserId {
        self.sender
    }

    fn ingress_expiry(&self) -> u64 {
        self.ingress_expiry
    }

    fn nonce(&self) -> Option<Vec<u8>> {
        self.nonce.clone()
    }
}

impl SignedIngressContent {
    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }
}

impl TryFrom<HttpCanisterUpdate> for SignedIngressContent {
    type Error = HttpHandlerError;

    fn try_from(update: HttpCanisterUpdate) -> Result<Self, Self::Error> {
        Ok(Self {
            sender: UserId::from(PrincipalId::try_from(update.sender.0).map_err(|err| {
                HttpHandlerError::InvalidPrincipalId(format!(
                    "Converting sender to PrincipalId failed with {}",
                    err
                ))
            })?),
            canister_id: CanisterId::try_from(update.canister_id.0).map_err(|err| {
                HttpHandlerError::InvalidPrincipalId(format!(
                    "Converting canister_id to PrincipalId failed with {:?}",
                    err
                ))
            })?,
            method_name: update.method_name,
            arg: update.arg.0,
            ingress_expiry: update.ingress_expiry,
            nonce: update.nonce.map(|n| n.0),
        })
    }
}

/// Describes the signed ingress message that was received from the end user.
/// The only way to construct this is
/// `TryFrom<HttpRequestEnvelope<HttpSubmitContent>>` which should guarantee
/// that all the necessary fields are accounted for and all the necessary checks
/// have been performed.
pub type SignedIngress = Signed<SignedIngressContent, Option<UserSignature>>;

impl From<&SignedIngress> for pb_types::SignedIngress {
    fn from(signed_ingress: &SignedIngress) -> Self {
        Self {
            signature: bincode::serialize(&signed_ingress.signature).unwrap(),
            sender: Some(crate::user_id_into_protobuf(signed_ingress.sender())),
            canister_id: Some(pb_types::CanisterId::from(signed_ingress.canister_id())),
            method_name: signed_ingress.method_name(),
            arg: signed_ingress.method_arg().to_vec(),
            ingress_expiry: signed_ingress.content.ingress_expiry,
            nonce: signed_ingress
                .content
                .nonce
                .clone()
                .map(|bytes| pb_types::Nonce { raw_bytes: bytes }),
        }
    }
}

impl From<&SignedIngress> for IngressMessageLogEntry {
    fn from(ingress: &SignedIngress) -> Self {
        Self {
            canister_id: Some(ingress.canister_id().to_string()),
            compute_allocation: None,
            desired_id: None,
            expiry_time: Some(ingress.expiry_time().as_nanos_since_unix_epoch()),
            memory_allocation: None,
            message_id: Some(format!("{}", ingress.id())),
            method_name: Some(ingress.method_name()),
            mode: None,
            reason: None,
            request_type: Some(String::from("call")),
            sender: Some(ingress.sender().to_string()),
            size: None,
            batch_time: None,
            batch_time_plus_ttl: None,
        }
    }
}

impl SignedIngress {
    pub fn id(&self) -> MessageId {
        self.content.id()
    }

    pub fn sender(&self) -> UserId {
        self.content.sender
    }

    pub fn canister_id(&self) -> CanisterId {
        self.content.canister_id
    }

    pub fn method_name(&self) -> String {
        self.content.method_name.clone()
    }

    pub fn method_arg(&self) -> &[u8] {
        &self.content.arg
    }

    pub fn log_entry(&self) -> IngressMessageLogEntry {
        self.into()
    }

    pub fn expiry_time(&self) -> Time {
        crate::time::UNIX_EPOCH + Duration::from_nanos(self.content.ingress_expiry)
    }
}

impl From<HttpRequest<SignedIngressContent>> for SignedIngress {
    fn from(request: HttpRequest<SignedIngressContent>) -> Self {
        Self {
            signature: match request.authentication().clone() {
                Authentication::Anonymous => None,
                Authentication::Authenticated(signature) => Some(signature),
            },
            content: request.content().clone(),
        }
    }
}

/// A message sent from an end user to a canister.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Eq, Hash)]
pub struct Ingress {
    pub source: UserId,
    pub receiver: CanisterId,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    pub method_payload: Vec<u8>,
    pub message_id: MessageId,
    pub expiry_time: Time,
}

// This conversion should be error free as long as we performed all the
// validation checks when we computed the SignedIngress.
impl From<SignedIngress> for Ingress {
    fn from(signed_ingress: SignedIngress) -> Self {
        Self {
            source: signed_ingress.sender(),
            receiver: signed_ingress.canister_id(),
            method_name: signed_ingress.method_name(),
            method_payload: signed_ingress.method_arg().to_vec(),
            message_id: signed_ingress.id(),
            expiry_time: signed_ingress.expiry_time(),
        }
    }
}

impl From<&Ingress> for pb_ingress::Ingress {
    fn from(item: &Ingress) -> Self {
        Self {
            source: Some(crate::user_id_into_protobuf(item.source)),
            receiver: Some(pb_types::CanisterId::from(item.receiver)),
            method_name: item.method_name.clone(),
            method_payload: item.method_payload.clone(),
            message_id: item.message_id.as_bytes().to_vec(),
            expiry_time_nanos: item.expiry_time.as_nanos_since_unix_epoch(),
        }
    }
}

impl TryFrom<pb_ingress::Ingress> for Ingress {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_ingress::Ingress) -> Result<Self, Self::Error> {
        Ok(Self {
            source: crate::user_id_try_from_protobuf(try_from_option_field(
                item.source,
                "Ingress::source",
            )?)?,
            receiver: try_from_option_field(item.receiver, "Ingress::receiver")?,
            method_name: item.method_name,
            method_payload: item.method_payload,
            message_id: item.message_id.as_slice().try_into()?,
            expiry_time: Time::from_nanos_since_unix_epoch(item.expiry_time_nanos),
        })
    }
}
