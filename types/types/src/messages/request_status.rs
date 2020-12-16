use super::{MessageId, RawHttpRequest, UserSignature};
use crate::crypto::Signed;
use std::convert::TryFrom;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedRequestStatusContent(RawHttpRequest);

impl SignedRequestStatusContent {
    pub(crate) fn new(raw_http_request: RawHttpRequest) -> Self {
        Self(raw_http_request)
    }
}

#[derive(Debug, PartialEq, Eq)]
/// A deserialized type used by end users to query the status of an Ingress
/// message.
pub struct RequestStatus(pub MessageId);

impl SignedRequestStatus {
    pub fn content(&self) -> &RawHttpRequest {
        &self.content.0
    }
}

/// Describes the signed request status that was received from the end user.
/// The only way to construct this is
/// `TryFrom<HttpRequestEnvelope<HttpReadContent>> for
/// SignedUserQueryOrRequestStatus` which should guarantee that all the
/// necessary fields are accounted for and all the necessary checks have been
/// performed.
pub type SignedRequestStatus = Signed<SignedRequestStatusContent, Option<UserSignature>>;

// This conversion should be error free as long as we performed all the
// validation checks when we computed the SignedRequestStatus.
impl From<SignedRequestStatus> for RequestStatus {
    fn from(input: SignedRequestStatus) -> Self {
        let mut raw_http_request = input.content.0;
        Self(MessageId::try_from(raw_http_request.take_bytes("request_id").as_slice()).unwrap())
    }
}
