use super::{Blob, RawHttpRequest, RawHttpRequestVal, UserSignature};
use crate::{crypto::Signed, UserId};

pub type ReadStatePath = Vec<Blob>;

pub type SignedReadState = Signed<RawHttpRequest, Option<UserSignature>>;

pub struct ReadState {
    pub source: UserId,
    pub paths: Vec<ReadStatePath>,
}

// This conversion should be error free as long as we performed all the
// validation checks when we computed the SignedReadState.
impl From<SignedReadState> for ReadState {
    fn from(input: SignedReadState) -> Self {
        let mut raw_http_request = input.content;
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
                    .map(|path| {
                        Blob(match path {
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
