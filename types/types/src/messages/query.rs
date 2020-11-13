use super::{HttpCanisterQuery, HttpHandlerError, RawHttpRequest, UserSignature};
use crate::{crypto::Signed, CanisterId, PrincipalId, UserId};
use std::convert::TryFrom;

/// Describes the signed query that was received from the end user.  The only
/// way to construct this is `TryFrom<HttpRequestEnvelope<HttpReadContent>> for
/// SignedUserQueryOrRequestStatus` which should guarantee that all the
/// necessary fields are accounted for and all the necessary checks have been
/// performed.
pub type SignedUserQuery = Signed<RawHttpRequest, Option<UserSignature>>;

/// Represents a Query that is sent by an end user to a canister.
#[derive(Clone, PartialEq, Debug)]
pub struct UserQuery {
    pub source: UserId,
    pub receiver: CanisterId,
    pub method_name: String,
    pub method_payload: Vec<u8>,
}

// This conversion should be error free as long as we performed all the
// validation checks when we computed the SignedUserQuery.
impl From<SignedUserQuery> for UserQuery {
    fn from(input: SignedUserQuery) -> Self {
        let mut raw_http_request = input.content;
        Self {
            source: raw_http_request.take_sender(),
            receiver: CanisterId::try_from(
                PrincipalId::try_from(&raw_http_request.take_bytes("canister_id")[..])
                    .expect("failed to parse canister id"),
            )
            .unwrap(),
            method_name: raw_http_request.take_string("method_name"),
            method_payload: raw_http_request.take_bytes("arg"),
        }
    }
}

/// Represents a query that is sent by one canister to another.
///
/// TODO(akhi): these types of queries are currently not signed.  We need a
/// design on how canisters can safely sign queries.
pub struct QueryRequest {
    pub sender: CanisterId,
    pub receiver: CanisterId,
    pub method_name: String,
    pub method_payload: Vec<u8>,
}

impl TryFrom<HttpCanisterQuery> for QueryRequest {
    type Error = HttpHandlerError;

    fn try_from(input: HttpCanisterQuery) -> Result<Self, Self::Error> {
        let sender = input.sender.0;
        let receiver = input.receiver.0;
        Ok(Self {
            sender: CanisterId::new(PrincipalId::try_from(&sender[..]).map_err(|err| {
                HttpHandlerError::InvalidPrincipalId(format!(
                    "converting {:?} to PrincipalId failed with {}",
                    sender, err
                ))
            })?)?,
            receiver: CanisterId::new(PrincipalId::try_from(&receiver[..]).map_err(|err| {
                HttpHandlerError::InvalidPrincipalId(format!(
                    "converting {:?} to PrincipalId failed with {}",
                    receiver, err
                ))
            })?)?,
            method_name: input.method_name,
            method_payload: input.method_payload.0,
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::{Blob, HttpUserQuery};
    use maplit::btreemap;
    use serde::Deserialize;
    use serde_cbor::Value;

    fn bytes(bytes: &[u8]) -> Value {
        Value::Bytes(bytes.to_vec())
    }

    fn text(text: &'static str) -> Value {
        Value::Text(text.to_string())
    }

    fn number(value: u64) -> Value {
        Value::Integer(value.into())
    }

    /// Makes sure that `val` deserializes to `obj`
    /// Used when testing _incoming_ messages from the HTTP Handler's point of
    /// view
    fn assert_cbor_de_equal<T>(obj: &T, val: Value)
    where
        for<'de> T: Deserialize<'de> + std::fmt::Debug + std::cmp::Eq,
    {
        let obj2 = serde_cbor::value::from_value(val).expect("Could not read CBOR value");
        assert_eq!(*obj, obj2);
    }

    #[test]
    fn decoding_read_query() {
        assert_cbor_de_equal(
            &HttpUserQuery {
                arg: Blob(vec![]),
                canister_id: Blob(vec![42; 8]),
                method_name: "some_method_name".to_string(),
                sender: Blob(vec![0x04]),
                nonce: None,
                ingress_expiry: 0,
            },
            Value::Map(btreemap! {
                text("arg") => bytes(&[][..]),
                text("canister_id") => bytes(&[42; 8][..]),
                text("method_name") => text("some_method_name"),
                text("sender") => bytes(&[0x04][..]),
                text("ingress_expiry") => number(0),
            }),
        );
    }

    #[test]
    fn decoding_read_query_arg() {
        assert_cbor_de_equal(
            &HttpUserQuery {
                arg: Blob(b"Hello, World!".to_vec()),
                canister_id: Blob(vec![42; 8]),
                method_name: "some_method_name".to_string(),
                sender: Blob(vec![0; 33]),
                nonce: None,
                ingress_expiry: 0,
            },
            Value::Map(btreemap! {
                text("arg") => bytes(b"Hello, World!"),
                text("canister_id") => bytes(&[42; 8][..]),
                text("method_name") => text("some_method_name"),
                text("sender") => bytes(&[0; 33]),
                text("ingress_expiry") => number(0),
            }),
        );
    }
}
