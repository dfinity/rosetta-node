mod blob;
mod http;
mod ingress_messages;
mod inter_canister;
mod message_id;
mod query;
mod read_state;
mod request_status;
mod webauthn;

use crate::{
    crypto::{BasicSig, BasicSigOf},
    ingress::MAX_INGRESS_TTL,
    user_id_into_protobuf, user_id_try_from_protobuf, CanisterId, CanisterIdError, CountBytes,
    Funds, NumBytes, PrincipalId, Time, UserId,
};
pub use blob::Blob;
pub use http::{
    Certificate, CertificateDelegation, Delegation, HttpCanisterUpdate, HttpQueryResponse,
    HttpQueryResponseReply, HttpReadContent, HttpReadState, HttpReadStateResponse, HttpReply,
    HttpRequestEnvelope, HttpRequestStatus, HttpRequestStatusResponse, HttpResponseStatus,
    HttpStatusResponse, HttpSubmitContent, HttpUserQuery, RawHttpRequest, RawHttpRequestVal,
    SignedDelegation,
};
pub use ic_base_types::CanisterInstallMode;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::state::canister_state_bits::v1 as pb;
use ic_protobuf::types::v1 as pb_types;
pub use ingress_messages::{Ingress, SignedIngress};
pub use inter_canister::{
    CallContextId, CallbackId, Payload, RejectContext, Request, RequestOrResponse, Response,
};
pub use message_id::{MessageId, MessageIdError, EXPECTED_MESSAGE_ID_LENGTH};
pub use query::{SignedUserQuery, UserQuery};
pub use read_state::{ReadState, SignedReadState};
pub use request_status::{RequestStatus, SignedRequestStatus};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, error::Error, fmt};
pub use webauthn::{WebAuthnEnvelope, WebAuthnSignature};

/// This sets the upper bound on how big a single inter-canister request or
/// response can be.  We know that allowing messages larger than around 2MB has
/// various security and performance impacts on the network.  More specifically,
/// large messages can allow dishonest block makers to always manage to get
/// their blocks notarized; and when the consensus protocol is configured for
/// smaller messages, a large message in the network can cause the finalization
/// rate to drop.
pub const MAX_INTER_CANISTER_PAYLOAD_IN_BYTES: NumBytes = NumBytes::new(3 * 1024 * 1024); // 3 MiB

/// The maximum size of an inter-canister request or response that the IC can
/// support.
///
/// This should be strictly larger than MAX_INTER_CANISTER_PAYLOAD_IN_BYTES to
/// account for the additional metadata in the `Request`s and `Response`s.  At
/// the time of writing, these data structures contain some variable length
/// fields (e.g. sender: CanisterId), so it is not possible to statically
/// compute an upper bound on their sizes.  Hopefully the additional space we
/// have allocated here is sufficient.
pub const MAX_INTER_CANISTER_MESSAGE_IN_BYTES: NumBytes = NumBytes::new(2 * 1024 * 1024); // 2 MiB

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserSignature {
    /// The actual signature.  End users should sign the MessageId computed from
    /// the message that they are signing.
    pub signature: UserSignatureOnly,
    /// The user's public key whose corresponding private key should have been
    /// used to sign the MessageId.
    pub signer_pubkey: Vec<u8>,

    pub sender_delegation: Option<Vec<SignedDelegation>>,
}

/// Represents the signature that an end user places on messages that they sign
/// along with the metadata needed to verify the signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UserSignatureOnly {
    Plain(BasicSigOf<MessageId>),
    WebAuthn(WebAuthnSignature),
}

impl From<Vec<u8>> for UserSignatureOnly {
    fn from(raw_bytes: Vec<u8>) -> Self {
        // Does the signature parse as WebAuthnSignature? Else, use it as BasicSig.
        match WebAuthnSignature::try_from(&raw_bytes[..]) {
            Ok(sig) => UserSignatureOnly::WebAuthn(sig),
            Err(_e) => UserSignatureOnly::Plain(BasicSigOf::from(BasicSig(raw_bytes))),
        }
    }
}

impl CountBytes for UserSignature {
    fn count_bytes(&self) -> usize {
        self.signature.count_bytes() + self.signer_pubkey.len()
    }
}

impl CountBytes for UserSignatureOnly {
    fn count_bytes(&self) -> usize {
        match &self {
            UserSignatureOnly::Plain(sig) => sig.count_bytes(),
            UserSignatureOnly::WebAuthn(sig) => sig.count_bytes(),
        }
    }
}

impl CountBytes for Option<UserSignature> {
    fn count_bytes(&self) -> usize {
        match self {
            Some(signature) => signature.count_bytes(),
            None => 0,
        }
    }
}

/// Stores info needed for processing and tracking requests to
/// stop canisters.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum StopCanisterContext {
    Ingress {
        sender: UserId,
        message_id: MessageId,
    },
    Canister {
        sender: CanisterId,
        reply_callback: CallbackId,
        /// The funds that the request to stop the canister contained.  Stored
        /// here so that they can be returned to the caller in the eventual
        /// reply.
        funds: Funds,
    },
}

impl StopCanisterContext {
    pub fn sender(&self) -> &PrincipalId {
        match self {
            StopCanisterContext::Ingress { sender, .. } => sender.get_ref(),
            StopCanisterContext::Canister { sender, .. } => sender.get_ref(),
        }
    }

    pub fn take_funds(&mut self) -> Funds {
        match self {
            StopCanisterContext::Ingress { .. } => Funds::zero(),
            StopCanisterContext::Canister { funds, .. } => funds.take(),
        }
    }
}

impl From<&StopCanisterContext> for pb::StopCanisterContext {
    fn from(item: &StopCanisterContext) -> Self {
        match item {
            StopCanisterContext::Ingress { sender, message_id } => Self {
                context: Some(pb::stop_canister_context::Context::Ingress(
                    pb::stop_canister_context::Ingress {
                        sender: Some(user_id_into_protobuf(*sender)),
                        message_id: message_id.as_bytes().to_vec(),
                    },
                )),
            },
            StopCanisterContext::Canister {
                sender,
                reply_callback,
                funds,
            } => Self {
                context: Some(pb::stop_canister_context::Context::Canister(
                    pb::stop_canister_context::Canister {
                        sender: Some(pb_types::CanisterId::from(*sender)),
                        reply_callback: reply_callback.get(),
                        funds: Some(funds.into()),
                    },
                )),
            },
        }
    }
}

impl TryFrom<pb::StopCanisterContext> for StopCanisterContext {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::StopCanisterContext) -> Result<Self, Self::Error> {
        let stop_canister_context =
            match try_from_option_field(value.context, "StopCanisterContext::context")? {
                pb::stop_canister_context::Context::Ingress(
                    pb::stop_canister_context::Ingress { sender, message_id },
                ) => StopCanisterContext::Ingress {
                    sender: user_id_try_from_protobuf(try_from_option_field(
                        sender,
                        "StopCanisterContext::Ingress::sender",
                    )?)?,
                    message_id: MessageId::try_from(message_id.as_slice())?,
                },
                pb::stop_canister_context::Context::Canister(
                    pb::stop_canister_context::Canister {
                        sender,
                        reply_callback,
                        funds,
                    },
                ) => StopCanisterContext::Canister {
                    sender: try_from_option_field(sender, "StopCanisterContext::Canister::sender")?,
                    reply_callback: CallbackId::from(reply_callback),
                    funds: try_from_option_field(funds, "StopCanisterContext::Canister::funds")?,
                },
            };
        Ok(stop_canister_context)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum HttpHandlerError {
    InvalidMessageId(String),
    InvalidIngressExpiry(String),
    InvalidPrincipalId(String),
    MissingPubkeyOrSignature(String),
}

impl fmt::Display for HttpHandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpHandlerError::InvalidMessageId(msg) => write!(f, "invalid message ID: {}", msg),
            HttpHandlerError::InvalidIngressExpiry(msg) => {
                write!(f, "invalid ingress expiry time: {}", msg)
            }
            HttpHandlerError::InvalidPrincipalId(msg) => write!(f, "invalid princial id: {}", msg),
            HttpHandlerError::MissingPubkeyOrSignature(msg) => {
                write!(f, "missing pubkey or signature: {}", msg)
            }
        }
    }
}

impl Error for HttpHandlerError {}

impl From<CanisterIdError> for HttpHandlerError {
    fn from(err: CanisterIdError) -> Self {
        Self::InvalidPrincipalId(format!("Converting to canister id failed with {}", err))
    }
}

#[derive(Debug, PartialEq)]
pub enum SignedReadRequest {
    Query(SignedUserQuery),
    RequestStatus(SignedRequestStatus),
    ReadState(SignedReadState),
}

impl SignedReadRequest {
    pub fn signature(&self) -> Option<&UserSignature> {
        match self {
            Self::Query(query) => query.signature.as_ref(),
            Self::RequestStatus(request_status) => request_status.signature.as_ref(),
            Self::ReadState(read_state) => read_state.signature.as_ref(),
        }
    }

    pub fn message_id(&self) -> MessageId {
        match self {
            Self::Query(query) => MessageId::from(&query.content),
            Self::RequestStatus(request_status) => MessageId::from(&request_status.content),
            Self::ReadState(read_state) => MessageId::from(&read_state.content),
        }
    }
}

impl TryFrom<(HttpRequestEnvelope<HttpReadContent>, Time)> for SignedReadRequest {
    type Error = HttpHandlerError;

    fn try_from(input: (HttpRequestEnvelope<HttpReadContent>, Time)) -> Result<Self, Self::Error> {
        let (request, current_time) = input;
        match request.content {
            HttpReadContent::Query { query } => {
                let content = RawHttpRequest::try_from((query, current_time))?;
                match (
                    request.sender_pubkey,
                    request.sender_sig,
                    request.sender_delegation,
                ) {
                    (Some(pubkey), Some(signature), delegation) => {
                        let signature = UserSignature {
                            signature: UserSignatureOnly::from(signature.0),
                            signer_pubkey: pubkey.0,
                            sender_delegation: delegation,
                        };
                        Ok(Self::Query(SignedUserQuery {
                            content,
                            signature: Some(signature),
                        }))
                    }
                    (None, None, None) => Ok(Self::Query(SignedUserQuery {
                        content,
                        signature: None,
                    })),
                    rest => Err(Self::Error::MissingPubkeyOrSignature(format!(
                        "Got {:?}",
                        rest
                    ))),
                }
            }

            HttpReadContent::RequestStatus { request_status } => {
                let content = RawHttpRequest::try_from((request_status, current_time))?;
                match (
                    request.sender_pubkey,
                    request.sender_sig,
                    request.sender_delegation,
                ) {
                    (Some(pubkey), Some(signature), delegation) => {
                        let signature = UserSignature {
                            signature: UserSignatureOnly::from(signature.0),
                            signer_pubkey: pubkey.0,
                            sender_delegation: delegation,
                        };
                        Ok(Self::RequestStatus(SignedRequestStatus {
                            content,
                            signature: Some(signature),
                        }))
                    }
                    (None, None, None) => Ok(Self::RequestStatus(SignedRequestStatus {
                        content,
                        signature: None,
                    })),
                    rest => Err(Self::Error::MissingPubkeyOrSignature(format!(
                        "Got {:?}",
                        rest
                    ))),
                }
            }

            HttpReadContent::ReadState { read_state } => {
                let content = RawHttpRequest::try_from((read_state, current_time))?;
                match (
                    request.sender_pubkey,
                    request.sender_sig,
                    request.sender_delegation,
                ) {
                    (Some(pubkey), Some(signature), delegation) => {
                        let signature = UserSignature {
                            signature: UserSignatureOnly::from(signature.0),
                            signer_pubkey: pubkey.0,
                            sender_delegation: delegation,
                        };
                        Ok(SignedReadRequest::ReadState(SignedReadState {
                            content,
                            signature: Some(signature),
                        }))
                    }
                    (None, None, None) => Ok(Self::ReadState(SignedReadState {
                        content,
                        signature: None,
                    })),
                    rest => Err(Self::Error::MissingPubkeyOrSignature(format!(
                        "Got {:?}",
                        rest
                    ))),
                }
            }
        }
    }
}

/// Check if ingress_expiry has not expired with respect to the given time,
/// i.e., it is greater than or equal to current_time.
pub fn validate_ingress_expiry(
    ingress_expiry: u64,
    current_time: Time,
) -> Result<(), HttpHandlerError> {
    let min_allowed_expiry = current_time.as_nanos_since_unix_epoch();
    if ingress_expiry < min_allowed_expiry {
        let msg = format!(
            "Specified ingress_expiry {}ns is less than allowed expiry time {}ns",
            ingress_expiry, min_allowed_expiry,
        );
        return Err(HttpHandlerError::InvalidIngressExpiry(msg));
    }
    Ok(())
}

/// Check if ingress_expiry is within a proper range with respect to the given
/// time, i.e., it is not expired yet and is not too far in the future.
pub fn validate_ingress_expiry_range(
    ingress_expiry: u64,
    current_time: Time,
) -> Result<(), HttpHandlerError> {
    let min_allowed_expiry = current_time.as_nanos_since_unix_epoch();
    let range = min_allowed_expiry..=(min_allowed_expiry + MAX_INGRESS_TTL.as_nanos() as u64);
    if !range.contains(&ingress_expiry) {
        let msg = format!(
            "Specified ingress_expiry {}ns is not in the expected time range [{} .. {}]",
            ingress_expiry,
            range.start(),
            range.end()
        );
        return Err(HttpHandlerError::InvalidIngressExpiry(msg));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::current_time_and_expiry_time;
    use assert_matches::assert_matches;
    use maplit::btreemap;
    use proptest::prelude::*;
    use serde_cbor::Value;
    use std::{convert::TryFrom, io::Cursor};

    fn debug_blob(v: Vec<u8>) -> String {
        format!("{:?}", Blob(v))
    }

    #[test]
    fn test_debug_blob() {
        assert_eq!(debug_blob(vec![]), "Blob{empty}");
        assert_eq!(debug_blob(vec![0]), "Blob{00}");
        assert_eq!(debug_blob(vec![255, 0]), "Blob{ff00}");
        assert_eq!(debug_blob(vec![1, 2, 3]), "Blob{010203}");
        assert_eq!(debug_blob(vec![0, 1, 15, 255]), "Blob{4 bytes;00010fff}");
        let long_vec: Vec<u8> = (0 as u8..100 as u8).collect();
        let long_debug = debug_blob(long_vec);
        assert_eq!(
            long_debug.len(),
            "Blob{100 bytes;}".len() + 100 /*bytes*/ * 2 /* char per byte */
        );
        assert!(
            long_debug.starts_with("Blob{100 bytes;"),
            "long_debug: {}",
            long_debug
        );
        assert!(long_debug.ends_with("63}"), "long_debug: {}", long_debug); // 99 = 16*6 + 3
    }

    fn format_blob(v: Vec<u8>) -> String {
        format!("{}", Blob(v))
    }

    #[test]
    fn test_format_blob() {
        assert_eq!(format_blob(vec![]), "Blob{empty}");
        assert_eq!(format_blob(vec![0]), "Blob{00}");
        assert_eq!(format_blob(vec![255, 0]), "Blob{ff00}");
        assert_eq!(format_blob(vec![1, 2, 3]), "Blob{010203}");
        assert_eq!(format_blob(vec![0, 1, 15, 255]), "Blob{4 bytes;00010fff}");
        let long_vec: Vec<u8> = (0 as u8..100 as u8).collect();
        let long_str = format_blob(long_vec);
        assert_eq!(
            long_str.len(),
            "Blob{100 bytes;…}".len() + 40 /*max num bytes to format */ * 2 /* char per byte */
        );
        assert!(
            long_str.starts_with("Blob{100 bytes;"),
            "long_str: {}",
            long_str
        );
        // The last printed byte is 39, which is 16*2 + 7
        assert!(long_str.ends_with("27…}"), "long_str: {}", long_str);
    }

    /// Makes sure that `val` deserializes to `obj`
    /// Used when testing _incoming_ messages from the HTTP Handler's point of
    /// view
    fn assert_cbor_de_equal<T>(obj: &T, val: Value)
    where
        for<'de> T: serde::Deserialize<'de> + std::fmt::Debug + std::cmp::Eq,
    {
        let obj2 = serde_cbor::value::from_value(val).expect("Could not read CBOR value");
        assert_eq!(*obj, obj2);
    }

    fn text(text: &'static str) -> Value {
        Value::Text(text.to_string())
    }

    fn bytes(bs: &[u8]) -> Value {
        Value::Bytes(bs.to_vec())
    }

    fn integer(val: u64) -> Value {
        Value::Integer(val as i128)
    }

    proptest! {
        #[test]
        // The conversion from Submit to SignedIngress is not total so we proptest
        // the hell out of it to make sure no enum constructors are added which are
        // not handled by the conversion.
        fn request_id_conversion_does_not_panic(
            submit: HttpRequestEnvelope::<HttpSubmitContent>,
            current_time: Time)
        {
            let _ = SignedIngress::try_from((submit, current_time));
        }
    }

    #[test]
    fn decoding_submit_call() {
        let (_, expiry_time) = current_time_and_expiry_time();
        assert_cbor_de_equal(
            &HttpRequestEnvelope::<HttpSubmitContent> {
                content: HttpSubmitContent::Call {
                    update: HttpCanisterUpdate {
                        canister_id: Blob(vec![42; 8]),
                        method_name: "some_method".to_string(),
                        arg: Blob(b"".to_vec()),
                        sender: Blob(vec![0x04]),
                        nonce: None,
                        ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
                    },
                },
                sender_pubkey: Some(Blob(vec![])),
                sender_sig: Some(Blob(vec![])),
                sender_delegation: None,
            },
            Value::Map(btreemap! {
                text("content") => Value::Map(btreemap! {
                    text("request_type") => text("call"),
                    text("canister_id") => bytes(&[42; 8][..]),
                    text("method_name") => text("some_method"),
                    text("arg") => bytes(b""),
                    text("sender") => bytes(&[0x04][..]),
                    text("ingress_expiry") => integer(expiry_time.as_nanos_since_unix_epoch()),
                }),
                text("sender_pubkey") => bytes(b""),
                text("sender_sig") => bytes(b""),
            }),
        );
    }

    #[test]
    fn decoding_submit_call_arg() {
        let (_, expiry_time) = current_time_and_expiry_time();
        assert_cbor_de_equal(
            &HttpRequestEnvelope::<HttpSubmitContent> {
                content: HttpSubmitContent::Call {
                    update: HttpCanisterUpdate {
                        canister_id: Blob(vec![42; 8]),
                        method_name: "some_method".to_string(),
                        arg: Blob(b"some_arg".to_vec()),
                        sender: Blob(vec![0x04]),
                        nonce: None,
                        ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
                    },
                },
                sender_pubkey: Some(Blob(vec![])),
                sender_sig: Some(Blob(vec![])),
                sender_delegation: None,
            },
            Value::Map(btreemap! {
                text("content") => Value::Map(btreemap! {
                    text("request_type") => text("call"),
                    text("canister_id") => bytes(&[42; 8][..]),
                    text("method_name") => text("some_method"),
                    text("arg") => bytes(b"some_arg"),
                    text("sender") => bytes(&[0x04][..]),
                    text("ingress_expiry") => integer(expiry_time.as_nanos_since_unix_epoch()),
                }),
                text("sender_pubkey") => bytes(b""),
                text("sender_sig") => bytes(b""),
            }),
        );
    }

    #[test]
    fn decoding_submit_call_with_nonce() {
        let (_, expiry_time) = current_time_and_expiry_time();
        assert_cbor_de_equal(
            &HttpRequestEnvelope::<HttpSubmitContent> {
                content: HttpSubmitContent::Call {
                    update: HttpCanisterUpdate {
                        canister_id: Blob(vec![42; 8]),
                        method_name: "some_method".to_string(),
                        arg: Blob(b"some_arg".to_vec()),
                        sender: Blob(vec![0x04]),
                        nonce: Some(Blob(vec![1, 2, 3, 4, 5])),
                        ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
                    },
                },
                sender_pubkey: Some(Blob(vec![])),
                sender_sig: Some(Blob(vec![])),
                sender_delegation: None,
            },
            Value::Map(btreemap! {
                text("content") => Value::Map(btreemap! {
                    text("request_type") => text("call"),
                    text("canister_id") => bytes(&[42; 8][..]),
                    text("method_name") => text("some_method"),
                    text("arg") => bytes(b"some_arg"),
                    text("sender") => bytes(&[0x04][..]),
                    text("ingress_expiry") => integer(expiry_time.as_nanos_since_unix_epoch()),
                    text("nonce") => bytes(&[1, 2, 3, 4, 5][..]),
                }),
                text("sender_pubkey") => bytes(b""),
                text("sender_sig") => bytes(b""),
            }),
        );
    }

    #[test]
    fn serialize_via_bincode() {
        let (current_time, expiry_time) = current_time_and_expiry_time();
        let update = HttpRequestEnvelope::<HttpSubmitContent> {
            content: HttpSubmitContent::Call {
                update: HttpCanisterUpdate {
                    canister_id: Blob(vec![42; 8]),
                    method_name: "some_method".to_string(),
                    arg: Blob(b"".to_vec()),
                    sender: Blob(vec![0x04]),
                    nonce: None,
                    ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
                },
            },
            sender_pubkey: Some(Blob(vec![2; 32])),
            sender_sig: Some(Blob(vec![1; 32])),
            sender_delegation: None,
        };
        let signed_ingress = SignedIngress::try_from((update, current_time)).unwrap();
        let bytes = bincode::serialize(&signed_ingress).unwrap();
        let signed_ingress1 = bincode::deserialize::<SignedIngress>(&bytes);
        assert!(signed_ingress1.is_ok());
    }

    #[test]
    fn serialize_via_bincode_without_signature() {
        let (current_time, expiry_time) = current_time_and_expiry_time();
        let update = HttpRequestEnvelope::<HttpSubmitContent> {
            content: HttpSubmitContent::Call {
                update: HttpCanisterUpdate {
                    canister_id: Blob(vec![42; 8]),
                    method_name: "some_method".to_string(),
                    arg: Blob(b"".to_vec()),
                    sender: Blob(vec![0x04]),
                    nonce: None,
                    ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
                },
            },
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        };
        let signed_ingress = SignedIngress::try_from((update, current_time)).unwrap();
        let bytes = bincode::serialize(&signed_ingress).unwrap();
        let mut buffer = Cursor::new(&bytes);
        let signed_ingress1: SignedIngress = bincode::deserialize_from(&mut buffer).unwrap();
        assert_eq!(signed_ingress, signed_ingress1);
    }

    #[test]
    fn too_big_message_id() {
        let (current_time, expiry_time) = current_time_and_expiry_time();
        let read_request = HttpRequestEnvelope::<HttpReadContent> {
            content: HttpReadContent::RequestStatus {
                request_status: HttpRequestStatus {
                    request_id: Blob(vec![1; 33]),
                    nonce: None,
                    ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
                },
            },
            sender_pubkey: Some(Blob(vec![])),
            sender_sig: Some(Blob(vec![])),
            sender_delegation: None,
        };
        let err = SignedReadRequest::try_from((read_request, current_time)).unwrap_err();
        assert_matches!(err, HttpHandlerError::InvalidMessageId(_));
    }

    #[test]
    fn too_small_message_id() {
        let (current_time, expiry_time) = current_time_and_expiry_time();
        let read_request = HttpRequestEnvelope::<HttpReadContent> {
            content: HttpReadContent::RequestStatus {
                request_status: HttpRequestStatus {
                    request_id: Blob(vec![1; 31]),
                    nonce: None,
                    ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
                },
            },
            sender_pubkey: Some(Blob(vec![])),
            sender_sig: Some(Blob(vec![])),
            sender_delegation: None,
        };
        let err = SignedReadRequest::try_from((read_request, current_time)).unwrap_err();
        assert_matches!(err, HttpHandlerError::InvalidMessageId(_));
    }

    #[test]
    fn exact_message_id() {
        let (current_time, expiry_time) = current_time_and_expiry_time();
        let read_request = HttpRequestEnvelope::<HttpReadContent> {
            content: HttpReadContent::RequestStatus {
                request_status: HttpRequestStatus {
                    request_id: Blob(vec![1; 32]),
                    nonce: None,
                    ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
                },
            },
            sender_pubkey: Some(Blob(vec![])),
            sender_sig: Some(Blob(vec![])),
            sender_delegation: None,
        };
        SignedReadRequest::try_from((read_request, current_time)).unwrap();
    }
}
