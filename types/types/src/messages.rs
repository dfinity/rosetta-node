mod blob;
mod http;
mod ingress_messages;
mod inter_canister;
mod message_id;
mod query;
mod read_state;
mod webauthn;

use crate::{
    user_id_into_protobuf, user_id_try_from_protobuf, CountBytes, Funds, NumBytes, UserId,
};
pub use blob::Blob;
pub use http::{
    validate_ingress_expiry, Authentication, Certificate, CertificateDelegation, Delegation,
    HttpCanisterUpdate, HttpQueryResponse, HttpQueryResponseReply, HttpReadContent, HttpReadState,
    HttpReadStateResponse, HttpReply, HttpRequest, HttpRequestContent, HttpRequestEnvelope,
    HttpResponseStatus, HttpStatusResponse, HttpSubmitContent, HttpUserQuery, RawHttpRequest,
    RawHttpRequestVal, ReadContent, SignedDelegation,
};
pub use ic_base_types::CanisterInstallMode;
use ic_base_types::{CanisterId, CanisterIdError, PrincipalId};
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::state::canister_state_bits::v1 as pb;
use ic_protobuf::types::v1 as pb_types;
pub use ingress_messages::{Ingress, SignedIngress};
pub use inter_canister::{
    CallContextId, CallbackId, Payload, RejectContext, Request, RequestOrResponse, Response,
};
pub use message_id::{MessageId, MessageIdError, EXPECTED_MESSAGE_ID_LENGTH};
pub use query::UserQuery;
pub use read_state::ReadState;
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
pub const MAX_INTER_CANISTER_PAYLOAD_IN_BYTES: NumBytes = NumBytes::new(2 * 1024 * 1024); // 2 MiB

/// The maximum size of an inter-canister request or response that the IC can
/// support.
///
/// This should be strictly larger than MAX_INTER_CANISTER_PAYLOAD_IN_BYTES to
/// account for the additional metadata in the `Request`s and `Response`s.  At
/// the time of writing, these data structures contain some variable length
/// fields (e.g. sender: CanisterId), so it is not possible to statically
/// compute an upper bound on their sizes.  Hopefully the additional space we
/// have allocated here is sufficient.
pub const MAX_XNET_PAYLOAD_IN_BYTES: NumBytes = NumBytes::new(2202009); // 2.1 MiB

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserSignature {
    /// The actual signature.  End users should sign the MessageId computed from
    /// the message that they are signing.
    pub signature: Vec<u8>,
    /// The user's public key whose corresponding private key should have been
    /// used to sign the MessageId.
    pub signer_pubkey: Vec<u8>,

    pub sender_delegation: Option<Vec<SignedDelegation>>,
}

impl CountBytes for UserSignature {
    fn count_bytes(&self) -> usize {
        self.signature.len() + self.signer_pubkey.len()
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
            HttpHandlerError::InvalidIngressExpiry(msg) => write!(f, "{}", msg),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{time::current_time_and_expiry_time, Time};
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
}
