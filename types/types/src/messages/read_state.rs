use crate::{
    messages::{HttpHandlerError, HttpReadState},
    PrincipalId, UserId,
};
use ic_crypto_tree_hash::Path;
use std::convert::TryFrom;

#[derive(Clone, Debug, PartialEq)]
pub struct ReadState {
    pub source: UserId,
    pub paths: Vec<Path>,
    pub ingress_expiry: u64,
    pub nonce: Option<Vec<u8>>,
}

impl TryFrom<HttpReadState> for ReadState {
    type Error = HttpHandlerError;

    fn try_from(read_state: HttpReadState) -> Result<Self, Self::Error> {
        Ok(Self {
            source: UserId::from(PrincipalId::try_from(read_state.sender.0).map_err(|err| {
                HttpHandlerError::InvalidPrincipalId(format!(
                    "Converting sender to PrincipalId failed with {}",
                    err
                ))
            })?),
            paths: read_state.paths,
            ingress_expiry: read_state.ingress_expiry,
            nonce: read_state.nonce.map(|n| n.0),
        })
    }
}
