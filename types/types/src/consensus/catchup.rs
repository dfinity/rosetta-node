use crate::{
    consensus::{
        Block, Committee, HasCommittee, HasHeight, HasVersion, RandomBeacon, ThresholdSignature,
        ThresholdSignatureShare,
    },
    crypto::threshold_sig::ni_dkg::NiDkgId,
    crypto::*,
    CryptoHashOfState, Height, RegistryVersion, ReplicaVersion,
};
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::cmp::{Ordering, PartialOrd};
use std::convert::TryFrom;

/// CatchUpContent contains all necessary data to bootstrap a subnet's
/// participant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct CatchUpContent {
    /// A finalized Block that contains DKG summary. We call its height the
    /// catchup height.
    pub block: Block,
    /// The RandomBeacon that is used at the catchup height.
    pub random_beacon: RandomBeacon,
    /// Hash of the subnet execution state that has been fully computed at the
    /// catchup height.
    pub state_hash: CryptoHashOfState,
    /// Hash of Block. Only used to implement PartialOrd/Ord.
    pub block_hash: CryptoHashOf<Block>,
    /// Hash of RandomBeacon. Only used to implement PartialOrd/Ord.
    pub random_beacon_hash: CryptoHashOf<RandomBeacon>,
}

impl CatchUpContent {
    /// Return the registry version as recorded in the DKG summary of
    /// the block contained in the CatchUpContent.
    pub fn registry_version(&self) -> RegistryVersion {
        self.block.dkg_payload.summary().registry_version
    }
}

impl From<&CatchUpContent> for pb::CatchUpContent {
    fn from(content: &CatchUpContent) -> Self {
        Self {
            block: Some(pb::Block::from(&content.block)),
            random_beacon: Some(pb::RandomBeacon::from(&content.random_beacon)),
            state_hash: content.state_hash.clone().get().0,
            block_hash: content.block_hash.clone().get().0,
            random_beacon_hash: content.random_beacon_hash.clone().get().0,
        }
    }
}

pub fn catch_up_content_from_protobuf<
    F: FnOnce(&crate::batch::BatchPayload) -> CryptoHashOf<crate::batch::BatchPayload>
        + Send
        + 'static,
>(
    hash_func: F,
    content: pb::CatchUpContent,
) -> Result<CatchUpContent, String> {
    Ok(CatchUpContent {
        block: super::block_from_protobuf(
            hash_func,
            content
                .block
                .ok_or_else(|| String::from("Error: CUP missing block"))?,
        )?,
        random_beacon: RandomBeacon::try_from(
            content
                .random_beacon
                .ok_or_else(|| String::from("Error: CUP missing block"))?,
        )?,
        state_hash: CryptoHashOf::from(CryptoHash(content.state_hash)),
        block_hash: CryptoHashOf::from(CryptoHash(content.block_hash)),
        random_beacon_hash: CryptoHashOf::from(CryptoHash(content.random_beacon_hash)),
    })
}

impl SignedBytesWithoutDomainSeparator for CatchUpContent {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

impl HasVersion for CatchUpContent {
    fn version(&self) -> &ReplicaVersion {
        self.block.version()
    }
}

/// To avoid imposing PartiaOrd trait on Block type, we implement a custom
/// PartialOrd trait instance for CatchUpContent.
impl PartialOrd for CatchUpContent {
    fn partial_cmp(&self, other: &CatchUpContent) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// To avoid imposing Ord trait on Block type, we implement a custom
/// Ord trait instance for CatchUpContent.
///
/// TODO(CON-318): Remove the Ord trait requirement for share aggregation.
impl Ord for CatchUpContent {
    fn cmp(&self, other: &CatchUpContent) -> Ordering {
        match self.height().cmp(&other.height()) {
            Ordering::Equal => {
                (&self.block_hash, &self.state_hash, &self.random_beacon_hash).cmp(&(
                    &other.block_hash,
                    &other.state_hash,
                    &other.random_beacon_hash,
                ))
            }
            result => result,
        }
    }
}

impl HasHeight for CatchUpContent {
    fn height(&self) -> Height {
        self.block.height()
    }
}

impl HasCommittee for CatchUpContent {
    fn committee() -> Committee {
        Committee::HighThreshold
    }
}

/// CatchUpPackage is signed by a threshold public key. Its CatchUpContent is
/// only trusted if the threshold public key is trusted.
///
/// TODO(CON-306): At the moment the signature used here is ThresholdSignature,
/// which has dkgId as the signer. This should be revisited once we have a
/// clearer picture of what the key should be, where it is stored, etc.
pub type CatchUpPackage = Signed<CatchUpContent, ThresholdSignature<CatchUpContent>>;

impl From<&CatchUpPackage> for pb::CatchUpPackage {
    fn from(cup: &CatchUpPackage) -> Self {
        Self {
            signer: Some(pb::NiDkgId::from(cup.signature.signer)),
            signature: cup.signature.signature.clone().get().0,
            content: Some(pb::CatchUpContent::from(&cup.content)),
        }
    }
}

pub fn catch_up_package_from_protobuf<
    F: FnOnce(&crate::batch::BatchPayload) -> CryptoHashOf<crate::batch::BatchPayload>
        + Send
        + 'static,
>(
    hash_func: F,
    cup: pb::CatchUpPackage,
) -> Result<CatchUpPackage, String> {
    Ok(CatchUpPackage {
        content: catch_up_content_from_protobuf(
            hash_func,
            cup.content.ok_or("Error: cup content missing")?,
        )?,
        signature: ThresholdSignature {
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(cup.signature)),
            signer: NiDkgId::try_from(
                cup.signer
                    .ok_or_else(|| String::from("Error: CUP signer not present"))?,
            )
            .map_err(|e| format!("Unable to decode CUP signer {:?}", e))?,
        },
    })
}

/// CatchUpPackageShare is signed by individual members in a threshold
/// committee.
pub type CatchUpPackageShare = Signed<CatchUpContent, ThresholdSignatureShare<CatchUpContent>>;

/// The parameters used to request `CatchUpPackage` (by nodemanager).
///
/// We make use of the `Ord` trait to determine if one `CatchUpPackage` is newer
/// than the other:
///
/// ```ignore
/// C1 > C2 iff
///   C1.height > C2.height ||
///   C1.height == C2.height && C1.registry_version > C2.registry_version
/// ```
#[derive(Serialize, Deserialize, Ord, PartialEq, Eq, Clone, Copy, Debug)]
pub struct CatchUpPackageParam {
    height: Height,
    registry_version: RegistryVersion,
}

/// The PartialOrd instance is explicitly given below to avoid relying on
/// the ordering of the struct fields.
impl PartialOrd for CatchUpPackageParam {
    fn partial_cmp(&self, other: &CatchUpPackageParam) -> Option<Ordering> {
        match self.height.cmp(&other.height) {
            Ordering::Greater => Some(Ordering::Greater),
            _ => self.registry_version.partial_cmp(&other.registry_version),
        }
    }
}

impl From<&CatchUpPackage> for CatchUpPackageParam {
    fn from(catch_up_package: &CatchUpPackage) -> Self {
        Self {
            height: catch_up_package.height(),
            registry_version: catch_up_package.content.registry_version(),
        }
    }
}

#[test]
fn test_catch_up_package_param_partial_ord() {
    let c1 = CatchUpPackageParam {
        height: Height::from(1),
        registry_version: RegistryVersion::from(1),
    };
    let c2 = CatchUpPackageParam {
        height: Height::from(2),
        registry_version: RegistryVersion::from(1),
    };
    let c3 = CatchUpPackageParam {
        height: Height::from(2),
        registry_version: RegistryVersion::from(2),
    };
    // c2 > c1
    assert_eq!(c2.cmp(&c1), Ordering::Greater);
    // c3 > c1
    assert_eq!(c3.cmp(&c1), Ordering::Greater);
    // c3 > c2. This can happen when we want to recover a stuck subnet
    // with a new CatchUpPackage.
    assert_eq!(c3.cmp(&c2), Ordering::Greater);
    // c3 == c3
    assert_eq!(c3.cmp(&c3), Ordering::Equal);
}
