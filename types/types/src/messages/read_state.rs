use super::{RawHttpRequest, RawHttpRequestVal, UserSignature};
use crate::{crypto::Signed, UserId};
use ic_crypto_tree_hash::{Label, Path};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedReadStateContent(RawHttpRequest);

impl SignedReadStateContent {
    pub(crate) fn new(raw_http_request: RawHttpRequest) -> Self {
        Self(raw_http_request)
    }
}

pub type SignedReadState = Signed<SignedReadStateContent, Option<UserSignature>>;

impl SignedReadState {
    pub fn content(&self) -> &RawHttpRequest {
        &self.content.0
    }
}

pub struct ReadState {
    pub source: UserId,
    pub paths: Vec<Path>,
}

// This conversion should be error free as long as we performed all the
// validation checks when we computed the SignedReadState.
impl From<SignedReadState> for ReadState {
    fn from(input: SignedReadState) -> Self {
        let mut raw_http_request = input.content.0;
        let paths = match raw_http_request.0.remove("paths").unwrap() {
            RawHttpRequestVal::Array(array) => array,
            val => unreachable!("Expected paths to be a array, got {:?}", val),
        };
        let paths = paths
            .into_iter()
            .map(|inner_paths| {
                let inner_paths = match inner_paths {
                    RawHttpRequestVal::Array(array) => array,
                    val => unreachable!("Expected array, got {:?}", val),
                };
                inner_paths
                    .into_iter()
                    .map(|segment| {
                        Label::from(match segment {
                            RawHttpRequestVal::Bytes(bytes) => bytes,
                            val => unreachable!("Expected bytes, got {:?}", val),
                        })
                    })
                    .collect()
            })
            .collect();

        Self {
            source: raw_http_request.take_sender(),
            paths,
        }
    }
}
