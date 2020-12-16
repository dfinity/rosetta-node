//! This module contains various definitions related to Ingress messages

use super::{
    HttpHandlerError, HttpRequestEnvelope, HttpSubmitContent, MessageId, RawHttpRequest,
    RawHttpRequestVal, UserSignature,
};
use crate::{crypto::Signed, CanisterId, CountBytes, PrincipalId, Time, UserId};
use ic_protobuf::{
    log::ingress_message_log_entry::v1::IngressMessageLogEntry,
    proxy::{try_from_option_field, ProxyDecodeError},
    state::ingress::v1 as pb_ingress,
    types::v1 as pb_types,
};
use serde::{Deserialize, Serialize};
use std::{
    convert::{From, TryFrom, TryInto},
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SignedIngressContent(RawHttpRequest);

impl SignedIngressContent {
    pub(crate) fn new(raw_http_request: RawHttpRequest) -> Self {
        Self(raw_http_request)
    }
}

impl CountBytes for SignedIngressContent {
    fn count_bytes(&self) -> usize {
        self.0.count_bytes()
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
        let raw_http_request = &signed_ingress.content.0;
        Self {
            signature: bincode::serialize(&signed_ingress.signature).unwrap(),
            content: raw_http_request
                .0
                .iter()
                .map(|(key, v)| pb_types::HttpRequestKv {
                    key: key.to_string(),
                    value: Some(pb_types::HttpRequestVal::from(v)),
                })
                .collect(),
        }
    }
}

impl From<&SignedIngress> for IngressMessageLogEntry {
    fn from(ingress: &SignedIngress) -> Self {
        fn get_id(key: &str, raw: &RawHttpRequest) -> Option<String> {
            match &raw.0.get(key) {
                Some(RawHttpRequestVal::Bytes(bytes)) => {
                    Some(format!("{}", PrincipalId::try_from(&bytes[..]).ok()?))
                }
                _ => None,
            }
        }

        fn get_u64(key: &str, raw: &RawHttpRequest) -> Option<u64> {
            match &raw.0.get(key) {
                Some(RawHttpRequestVal::U64(u)) => Some(*u),
                _ => None,
            }
        }

        fn get_string(key: &str, raw: &RawHttpRequest) -> Option<String> {
            match &raw.0.get(key) {
                Some(RawHttpRequestVal::String(s)) => Some(s.clone()),
                _ => None,
            }
        }

        let raw_http_request = &ingress.content.0;
        Self {
            canister_id: get_id("canister_id", raw_http_request),
            compute_allocation: get_u64("compute_allocation", raw_http_request),
            desired_id: get_id("desired_id", raw_http_request),
            expiry_time: get_u64("ingress_expiry", raw_http_request),
            memory_allocation: get_u64("memory_allocation", raw_http_request),
            message_id: Some(format!("{}", MessageId::from(raw_http_request))),
            method_name: get_string("method_name", raw_http_request),
            mode: get_string("mode", raw_http_request),
            reason: None,
            request_type: get_string("request_type", raw_http_request),
            sender: get_id("sender", raw_http_request),
            size: None,
            batch_time: None,
            batch_time_plus_ttl: None,
        }
    }
}

impl SignedIngress {
    pub fn content(&self) -> &RawHttpRequest {
        &self.content.0
    }

    pub fn sender(&self) -> UserId {
        let raw_http_request = &self.content.0;
        match raw_http_request.0.get("sender") {
            Some(bytes) => match bytes {
                RawHttpRequestVal::Bytes(raw) => {
                    UserId::from(PrincipalId::try_from(&raw[..]).expect("failed to decode user id"))
                }
                val => unreachable!("Expected `sender` to be a blob, got {:?}", val),
            },
            None => UserId::from(PrincipalId::new_anonymous()),
        }
    }

    pub fn canister_id(&self) -> CanisterId {
        let raw_http_request = &self.content.0;
        match raw_http_request.0.get("canister_id") {
            Some(bytes) => match bytes {
                RawHttpRequestVal::Bytes(raw) => CanisterId::new(
                    PrincipalId::try_from(&raw[..]).expect("failed to decode canister id"),
                )
                .unwrap(),
                val => unreachable!("Expected `canister_id` to be a blob, got {:?}", val),
            },
            None => unreachable!("No canister id defined: invalid request value."),
        }
    }

    pub fn method_name(&self) -> Result<String, ()> {
        let raw_http_request = &self.content.0;
        match raw_http_request.0.get("method_name") {
            Some(bytes) => match bytes {
                RawHttpRequestVal::String(name) => Ok(name.to_owned()),
                _ => Err(()),
            },
            None => Err(()),
        }
    }

    pub fn method_arg(&self) -> Result<Vec<u8>, ()> {
        let raw_http_request = &self.content.0;
        match raw_http_request.0.get("arg") {
            Some(bytes) => match bytes {
                RawHttpRequestVal::Bytes(raw) => Ok(raw.to_vec()),
                _ => Err(()),
            },
            None => Err(()),
        }
    }

    pub fn log_entry(&self) -> IngressMessageLogEntry {
        self.into()
    }

    pub fn expiry_time(&self) -> Time {
        let raw_http_request = &self.content.0;
        let value = raw_http_request
            .0
            .get("ingress_expiry")
            .expect("Expected SignedIngress to carry a `ingress_expiry` field");
        match value {
            RawHttpRequestVal::U64(raw) => crate::time::UNIX_EPOCH + Duration::from_nanos(*raw),
            val => unreachable!("Expected `ingress_expiry` to be a u64, got {:?}", val),
        }
    }
}

impl TryFrom<(HttpRequestEnvelope<HttpSubmitContent>, Time)> for SignedIngress {
    type Error = HttpHandlerError;

    fn try_from(
        input: (HttpRequestEnvelope<HttpSubmitContent>, Time),
    ) -> Result<Self, Self::Error> {
        let (request, current_time) = input;
        match request.content {
            HttpSubmitContent::Call { update } => {
                let raw_http_request = RawHttpRequest::try_from((update, current_time))?;
                match (
                    request.sender_pubkey,
                    request.sender_sig,
                    request.sender_delegation,
                ) {
                    (None, None, None) => Ok(SignedIngress {
                        content: SignedIngressContent::new(raw_http_request),
                        signature: None,
                    }),
                    (Some(pubkey), Some(signature), delegation) => {
                        let signature = UserSignature {
                            signature: signature.0,
                            signer_pubkey: pubkey.0,
                            sender_delegation: delegation,
                        };
                        Ok(SignedIngress {
                            content: SignedIngressContent::new(raw_http_request),
                            signature: Some(signature),
                        })
                    }
                    rest => Err(HttpHandlerError::MissingPubkeyOrSignature(format!(
                        "Invalid combination of pubkey and signature {:?}",
                        rest,
                    ))),
                }
            }
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
impl From<(SignedIngress, MessageId)> for Ingress {
    fn from(input: (SignedIngress, MessageId)) -> Self {
        let (signed_ingress, message_id) = input;
        let mut raw_http_request = signed_ingress.content.0;
        let request_type = raw_http_request.take_string("request_type");

        match request_type.as_str() {
            "call" => Self {
                source: raw_http_request.take_sender(),
                receiver: CanisterId::new(
                    PrincipalId::try_from(&raw_http_request.take_bytes("canister_id")[..])
                        .expect("failed to parse canister id"),
                )
                .unwrap(),
                method_name: raw_http_request.take_string("method_name"),
                method_payload: raw_http_request.take_bytes("arg"),
                message_id,
                expiry_time: crate::time::UNIX_EPOCH
                    + Duration::from_nanos(raw_http_request.take_u64("ingress_expiry")),
            },
            _ => unreachable!("Expected request type to be `call`, got {}", request_type),
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
