pub use crate::crypto::threshold_sig::ni_dkg::config::receivers::NiDkgReceivers;
use crate::crypto::threshold_sig::ni_dkg::config::NiDkgThreshold;
use crate::crypto::threshold_sig::ThresholdSigPublicKey;
use crate::NumberOfNodes;
use crate::{
    Height, IDkgId, NodeId, PrincipalId, PrincipalIdBlobParseError, RegistryVersion, SubnetId,
};
use core::fmt;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{CspNiDkgDealing, CspNiDkgTranscript};
use ic_protobuf::types::v1 as pb;
use ic_protobuf::types::v1::NiDkgId as NiDkgIdProto;
use phantom_newtype::Id;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::convert::TryFrom;
use strum_macros::EnumIter;

pub mod config;
pub mod errors;
pub mod id;

pub use id::NiDkgId;

#[cfg(test)]
mod tests;

/// Allows to distinguish between parallel protocol executions.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, EnumIter,
)]
pub enum NiDkgTag {
    LowThreshold = 1,
    HighThreshold = 2,
}

impl From<&NiDkgTag> for pb::NiDkgTag {
    fn from(tag: &NiDkgTag) -> Self {
        match tag {
            NiDkgTag::LowThreshold => pb::NiDkgTag::LowThreshold,
            NiDkgTag::HighThreshold => pb::NiDkgTag::HighThreshold,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NiDkgTargetSubnet {
    Local,
    // We cannot use `SubnetId` as type contained in the _remote_ variant because
    // the exact subnet ID is derived from the subnet's public key, which is only known
    // _after_ the DKG protocol was successfully run. Said differently, at the time the
    // containing `NiDkgId` is created, the exact `SubnetId` of the target subnet is
    // not (and cannot be) known yet.
    Remote(NiDkgTargetId),
}

pub const NI_DKG_TARGET_ID_SIZE: usize = 32;
pub struct NiDkgTargetIdTag;
pub type NiDkgTargetId = Id<NiDkgTargetIdTag, [u8; NI_DKG_TARGET_ID_SIZE]>;

impl fmt::Debug for NiDkgTargetSubnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => write!(f, "Local"),
            Self::Remote(target_id) => write!(f, "Remote(0x{})", hex::encode(target_id.get())),
        }
    }
}

impl fmt::Display for NiDkgTargetSubnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<i32> for NiDkgTag {
    type Error = ();

    fn try_from(ni_dkg_tag: i32) -> Result<Self, Self::Error> {
        match ni_dkg_tag {
            1 => Ok(NiDkgTag::LowThreshold),
            2 => Ok(NiDkgTag::HighThreshold),
            _ => Err(()),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DkgId {
    IDkgId(IDkgId),
    NiDkgId(NiDkgId),
}

impl fmt::Display for DkgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}

/// Contribution to distributed key generation.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct NiDkgDealing {
    pub internal_dealing: CspNiDkgDealing,
}

impl fmt::Display for NiDkgDealing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl NiDkgDealing {
    pub fn dummy_dealing_for_tests(seed: u8) -> NiDkgDealing {
        NiDkgDealing {
            internal_dealing: CspNiDkgDealing::placeholder_to_delete(seed),
        }
    }
}

impl From<CspNiDkgDealing> for NiDkgDealing {
    fn from(csp_dealing: CspNiDkgDealing) -> Self {
        NiDkgDealing {
            internal_dealing: csp_dealing,
        }
    }
}

impl From<NiDkgDealing> for CspNiDkgDealing {
    fn from(dealing: NiDkgDealing) -> Self {
        dealing.internal_dealing
    }
}

/// Summarizes a distributed key generation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NiDkgTranscript {
    pub dkg_id: NiDkgId,
    pub threshold: NiDkgThreshold,
    pub committee: NiDkgReceivers,
    pub registry_version: RegistryVersion,
    pub internal_csp_transcript: CspNiDkgTranscript,
}

impl From<&NiDkgTranscript> for pb::NiDkgTranscript {
    fn from(transcript: &NiDkgTranscript) -> Self {
        Self {
            dkg_id: Some(pb::NiDkgId::from(transcript.dkg_id)),
            threshold: transcript.threshold.get().get(),
            committee: transcript
                .committee
                .get()
                .iter()
                .cloned()
                .map(crate::node_id_into_protobuf)
                .collect(),
            registry_version: transcript.registry_version.get(),
            internal_csp_transcript: bincode::serialize(&transcript.internal_csp_transcript)
                .unwrap(),
        }
    }
}

impl TryFrom<&pb::NiDkgTranscript> for NiDkgTranscript {
    type Error = String;
    fn try_from(summary: &pb::NiDkgTranscript) -> Result<Self, Self::Error> {
        Ok(Self {
            dkg_id: NiDkgId::from_option_protobuf(summary.dkg_id.clone(), "NiDkgTranscript")?,
            threshold: NiDkgThreshold::new(NumberOfNodes::from(summary.threshold))
                .map_err(|e| format!("threshold error {:?}", e))?,
            committee: NiDkgReceivers::new(
                summary
                    .committee
                    .iter()
                    .cloned()
                    .map(crate::node_id_try_from_protobuf)
                    .collect::<Result<BTreeSet<_>, _>>()
                    .map_err(|err| {
                        format!("Problem loading committee in NiDkgTranscript: {:?}", err)
                    })?,
            )
            .map_err(|e| format!("{:?}", e))?,
            registry_version: RegistryVersion::from(summary.registry_version),
            internal_csp_transcript: bincode::deserialize(&summary.internal_csp_transcript)
                .map_err(|e| format!("{:?}", e))?,
        })
    }
}

impl fmt::Display for NiDkgTranscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl From<&NiDkgTranscript> for CspNiDkgTranscript {
    fn from(transcript: &NiDkgTranscript) -> Self {
        transcript.internal_csp_transcript.clone()
    }
}

impl NiDkgTranscript {
    #[allow(clippy::new_without_default)]
    pub fn dummy_transcript_for_tests_with_params(
        committee: Vec<NodeId>,
        dkg_tag: NiDkgTag,
        threshold: u32,
    ) -> Self {
        Self {
            dkg_id: NiDkgId {
                start_block_height: Height::from(0),
                dealer_subnet: SubnetId::from(PrincipalId::new_subnet_test_id(0)),
                dkg_tag,
                target_subnet: NiDkgTargetSubnet::Local,
            },
            threshold: NiDkgThreshold::new(crate::NumberOfNodes::new(threshold))
                .expect("Couldn't create a non-interactive DKG threshold."),
            committee: NiDkgReceivers::new(committee.into_iter().collect())
                .expect("Couldn't create non-interactive DKG committee"),
            registry_version: RegistryVersion::from(0),
            internal_csp_transcript: CspNiDkgTranscript::placeholder_to_delete(),
        }
    }
    pub fn dummy_transcript_for_tests() -> Self {
        NiDkgTranscript::dummy_transcript_for_tests_with_params(
            vec![NodeId::from(PrincipalId::new_node_test_id(0))],
            NiDkgTag::LowThreshold,
            1,
        )
    }
}

impl NiDkgTranscript {
    /// Computes the threshold-committee public key from the transcript.
    pub fn public_key(&self) -> ThresholdSigPublicKey {
        ThresholdSigPublicKey::from(self)
    }
}
