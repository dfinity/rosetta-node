use super::{MessageId, RawHttpRequest, UserSignature};
use crate::crypto::Signed;
use std::convert::TryFrom;

#[derive(Debug, PartialEq, Eq)]
/// A deserialized type used by end users to query the status of an Ingress
/// message.
pub struct RequestStatus(pub MessageId);

/// Describes the signed request status that was received from the end user.
/// The only way to construct this is
/// `TryFrom<HttpRequestEnvelope<HttpReadContent>> for
/// SignedUserQueryOrRequestStatus` which should guarantee that all the
/// necessary fields are accounted for and all the necessary checks have been
/// performed.
pub type SignedRequestStatus = Signed<RawHttpRequest, Option<UserSignature>>;

// This conversion should be error free as long as we performed all the
// validation checks when we computed the SignedRequestStatus.
impl From<SignedRequestStatus> for RequestStatus {
    fn from(input: SignedRequestStatus) -> Self {
        let mut raw_http_request = input.content;
        Self(MessageId::try_from(raw_http_request.take_bytes("request_id").as_slice()).unwrap())
    }
}
