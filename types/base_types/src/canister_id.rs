use super::{PrincipalId, PrincipalIdBlobParseError, SubnetId};
use candid::CandidType;
use ic_protobuf::types::v1 as pb;
use serde::de::Error;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, CandidType, Serialize)]
pub struct CanisterId(PrincipalId);

#[derive(Debug)]
pub enum CanisterIdError {
    InvalidPrincipalId(String),
}

impl fmt::Display for CanisterIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrincipalId(string) => write!(f, "Got an invalid principal id {}", string),
        }
    }
}

impl std::error::Error for CanisterIdError {}

impl CanisterId {
    /// Returns the id of the management canister
    pub const fn ic_00() -> Self {
        Self(PrincipalId::new(0, [0; PrincipalId::MAX_LENGTH_IN_BYTES]))
    }

    pub fn get_ref(&self) -> &PrincipalId {
        &self.0
    }

    pub fn get(self) -> PrincipalId {
        self.0
    }

    pub const fn new(principal_id: PrincipalId) -> Result<Self, CanisterIdError> {
        // TODO(akhi): enable this check when canister ids must be just u64.
        // const LENGTH: usize = std::mem::size_of::<u64>();
        // assert_eq!(principal_id.as_slice().len(), LENGTH);
        Ok(Self(principal_id))
    }

    pub const fn from_u64(val: u64) -> Self {
        // It is important to use big endian here to ensure that the generated
        // `PrincipalId`s still maintain ordering.
        let mut data = [0 as u8; PrincipalId::MAX_LENGTH_IN_BYTES];

        // Specify explicitly the length, so as to assert at compile time that a u64
        // takes exactly 8 bytes
        let val: [u8; 8] = val.to_be_bytes();

        // for-loops in const fn are not supported
        data[0] = val[0];
        data[1] = val[1];
        data[2] = val[2];
        data[3] = val[3];
        data[4] = val[4];
        data[5] = val[5];
        data[6] = val[6];
        data[7] = val[7];

        // Even though not defined in public spec, add another 0x1 to the array
        // to create a sub category that could be used in future.
        data[8] = 0x01;

        let blob_length : usize = 8 /* the u64 */ + 1 /* the last 0x01 */;

        Self(PrincipalId::new_opaque_from_array(data, blob_length))
    }
}

impl AsRef<PrincipalId> for CanisterId {
    fn as_ref(&self) -> &PrincipalId {
        &self.0
    }
}

impl fmt::Display for CanisterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<PrincipalId> for CanisterId {
    type Error = CanisterIdError;

    fn try_from(principal_id: PrincipalId) -> Result<Self, Self::Error> {
        Self::new(principal_id)
    }
}

#[derive(Debug)]
pub enum CanisterIdBlobParseError {
    PrincipalIdBlobParseError(PrincipalIdBlobParseError),
    CanisterIdError(CanisterIdError),
}

impl TryFrom<&[u8]> for CanisterId {
    type Error = CanisterIdBlobParseError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(
            PrincipalId::try_from(bytes)
                .map_err(CanisterIdBlobParseError::PrincipalIdBlobParseError)?,
        )
        .map_err(CanisterIdBlobParseError::CanisterIdError)
    }
}

impl TryFrom<&Vec<u8>> for CanisterId {
    type Error = CanisterIdBlobParseError;
    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<Vec<u8>> for CanisterId {
    type Error = CanisterIdBlobParseError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(
            PrincipalId::try_from(bytes)
                .map_err(CanisterIdBlobParseError::PrincipalIdBlobParseError)?,
        )
        .map_err(CanisterIdBlobParseError::CanisterIdError)
    }
}

// TODO(akhi): This exists as temporary scaffolding as there are various places
// in the code currently, where we encode subnet ids as canister ids.
impl From<SubnetId> for CanisterId {
    fn from(subnet_id: SubnetId) -> Self {
        CanisterId::new(subnet_id.get()).unwrap()
    }
}

impl From<CanisterId> for PrincipalId {
    fn from(canister_id: CanisterId) -> Self {
        canister_id.0
    }
}

impl From<CanisterId> for pb::CanisterId {
    fn from(id: CanisterId) -> Self {
        Self {
            principal_id: Some(pb::PrincipalId::from(id.0)),
        }
    }
}

impl TryFrom<pb::CanisterId> for CanisterId {
    type Error = PrincipalIdBlobParseError;

    fn try_from(id: pb::CanisterId) -> Result<Self, Self::Error> {
        // All fields in Protobuf definition are required hence they are encoded in
        // `Option`.  We simply treat them as required here though.
        let principal_id = PrincipalId::try_from(id.principal_id.unwrap())?;
        Ok(CanisterId(principal_id))
    }
}

impl From<u64> for CanisterId {
    fn from(val: u64) -> Self {
        Self::from_u64(val)
    }
}

impl<'de> Deserialize<'de> for CanisterId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        // Not all principals are valid inside a CanisterId.
        // Therefore, deserialization must explicitly
        // transform the PrincipalId into a CanisterId.
        // A derived implementation of Deserialize would open
        // the door to invariant violation.
        let res = CanisterId::try_from(PrincipalId::deserialize(deserializer)?);
        let id = res.map_err(D::Error::custom)?;
        Ok(id)
    }
}
