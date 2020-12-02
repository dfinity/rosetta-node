use crate::{
    consensus::{
        Committee, HasCommittee, HasHeight, HasVersion, ThresholdSignature, ThresholdSignatureShare,
    },
    crypto::{CryptoHash, CryptoHashOf, Signed, SignedBytesWithoutDomainSeparator},
    replica_version::{ReplicaVersion, ReplicaVersionParseError},
    CryptoHashOfPartialState, Height,
};
use ic_protobuf::messaging::xnet::v1 as pb;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// Contains a partial signature or combined muti-signature of a state hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum CertificationMessage {
    Certification(Certification),
    CertificationShare(CertificationShare),
}

impl HasHeight for CertificationMessage {
    fn height(&self) -> Height {
        match self {
            CertificationMessage::Certification(c) => c.height,
            CertificationMessage::CertificationShare(c) => c.height,
        }
    }
}

impl TryFrom<CertificationMessage> for Certification {
    type Error = CertificationMessage;
    fn try_from(msg: CertificationMessage) -> Result<Self, Self::Error> {
        match msg {
            CertificationMessage::Certification(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl TryFrom<CertificationMessage> for CertificationShare {
    type Error = CertificationMessage;
    fn try_from(msg: CertificationMessage) -> Result<Self, Self::Error> {
        match msg {
            CertificationMessage::CertificationShare(x) => Ok(x),
            _ => Err(msg),
        }
    }
}

impl From<Certification> for CertificationMessage {
    fn from(msg: Certification) -> Self {
        CertificationMessage::Certification(msg)
    }
}

impl From<CertificationShare> for CertificationMessage {
    fn from(msg: CertificationShare) -> Self {
        CertificationMessage::CertificationShare(msg)
    }
}

/// Message hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum CertificationMessageHash {
    Certification(CryptoHashOf<Certification>),
    CertificationShare(CryptoHashOf<CertificationShare>),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CertificationContent {
    version: ReplicaVersion,
    pub hash: CryptoHashOfPartialState,
}

impl CertificationContent {
    pub fn new(hash: CryptoHashOfPartialState) -> Self {
        CertificationContent {
            version: ReplicaVersion::default(),
            hash,
        }
    }
}

impl TryFrom<pb::CertificationContent> for CertificationContent {
    type Error = ReplicaVersionParseError;

    fn try_from(value: pb::CertificationContent) -> Result<Self, Self::Error> {
        let version = ReplicaVersion::try_from(value.version)?;
        Ok(CertificationContent {
            version,
            hash: CryptoHashOfPartialState::new(CryptoHash(value.hash)),
        })
    }
}

impl SignedBytesWithoutDomainSeparator for CertificationContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        self.hash.get_ref().0.clone()
    }
}

// Returning a constant role is needed to work with the existing membership, to
// select correct threshold value.
impl HasCommittee for Certification {
    fn committee() -> Committee {
        Committee::HighThreshold
    }
}

impl HasVersion for CertificationContent {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

impl HasVersion for Certification {
    fn version(&self) -> &ReplicaVersion {
        self.signed.version()
    }
}

impl HasVersion for CertificationShare {
    fn version(&self) -> &ReplicaVersion {
        self.signed.version()
    }
}

impl HasVersion for CertificationMessage {
    fn version(&self) -> &ReplicaVersion {
        match self {
            CertificationMessage::Certification(x) => x.version(),
            CertificationMessage::CertificationShare(x) => x.version(),
        }
    }
}

impl AsRef<CertificationContent> for CertificationMessage {
    fn as_ref(&self) -> &CertificationContent {
        match self {
            CertificationMessage::Certification(sig) => &sig.signed.content,
            CertificationMessage::CertificationShare(sig) => &sig.signed.content,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Certification {
    pub height: Height,
    pub signed: Signed<CertificationContent, ThresholdSignature<CertificationContent>>,
}

impl HasHeight for Certification {
    fn height(&self) -> Height {
        self.height
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificationShare {
    pub height: Height,
    pub signed: Signed<CertificationContent, ThresholdSignatureShare<CertificationContent>>,
}

impl HasHeight for CertificationShare {
    fn height(&self) -> Height {
        self.height
    }
}
