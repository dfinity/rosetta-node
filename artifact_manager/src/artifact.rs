use ic_consensus_message::ConsensusMessageHashable;
use ic_types::{
    artifact::*, consensus::certification::CertificationMessageHash, crypto::CryptoHashOf,
    messages::SignedRequestBytes, CountBytes,
};
use serde::{Deserialize, Serialize};

/// The `ArtifactKind` of consensus messages.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ConsensusArtifact;

impl ArtifactKind for ConsensusArtifact {
    const TAG: ArtifactTag = ArtifactTag::ConsensusArtifact;
    type Id = ConsensusMessageId;
    type Message = ConsensusMessage;
    type SerializeAs = ConsensusMessage;
    type Attribute = ConsensusMessageAttribute;
    type Filter = ConsensusMessageFilter;

    fn to_advert(msg: &ConsensusMessage) -> Advert<ConsensusArtifact> {
        let bindata = bincode::serialize(msg).unwrap();
        let attribute = ConsensusMessageAttribute::from(msg);
        let size = bindata.len();
        Advert {
            id: msg.get_id(),
            attribute,
            size,
            integrity_hash: ic_crypto::crypto_hash(msg).get(),
        }
    }
}

/// The `ArtifactKind` of ingress message.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IngressArtifact;

impl ArtifactKind for IngressArtifact {
    const TAG: ArtifactTag = ArtifactTag::IngressArtifact;
    type Id = IngressMessageId;
    type Message = SignedIngress;
    type SerializeAs = SignedRequestBytes;
    type Attribute = IngressMessageAttribute;
    type Filter = IngressMessageFilter;

    fn to_advert(msg: &SignedIngress) -> Advert<IngressArtifact> {
        Advert {
            id: IngressMessageId::from(msg),
            attribute: IngressMessageAttribute::new(msg),
            size: msg.count_bytes(),
            integrity_hash: ic_crypto::crypto_hash(msg.binary()).get(),
        }
    }
}

/// The `ArtifactKind` of certification messages.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CertificationArtifact;

impl ArtifactKind for CertificationArtifact {
    const TAG: ArtifactTag = ArtifactTag::CertificationArtifact;
    type Id = CertificationMessageId;
    type Message = CertificationMessage;
    type SerializeAs = CertificationMessage;
    type Attribute = CertificationMessageAttribute;
    type Filter = CertificationMessageFilter;

    fn to_advert(msg: &CertificationMessage) -> Advert<CertificationArtifact> {
        use CertificationMessage::*;
        let (attribute, id) = match msg {
            Certification(cert) => (
                CertificationMessageAttribute::Certification(cert.height),
                CertificationMessageId {
                    height: cert.height,
                    hash: CertificationMessageHash::Certification(CryptoHashOf::from(
                        ic_crypto::crypto_hash(cert).get(),
                    )),
                },
            ),
            CertificationShare(share) => (
                CertificationMessageAttribute::CertificationShare(share.height),
                CertificationMessageId {
                    height: share.height,
                    hash: CertificationMessageHash::CertificationShare(CryptoHashOf::from(
                        ic_crypto::crypto_hash(share).get(),
                    )),
                },
            ),
        };
        Advert {
            id,
            attribute,
            size: bincode::serialize(msg).unwrap().len(),
            integrity_hash: ic_crypto::crypto_hash(msg).get(),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DkgArtifact;

impl ArtifactKind for DkgArtifact {
    const TAG: ArtifactTag = ArtifactTag::DkgArtifact;
    type Id = DkgMessageId;
    type Message = DkgMessage;
    type SerializeAs = DkgMessage;
    type Attribute = DkgMessageAttribute;
    type Filter = ();

    fn to_advert(msg: &DkgMessage) -> Advert<DkgArtifact> {
        let size = bincode::serialize(msg).unwrap().len();
        let attribute = DkgMessageAttribute {
            interval_start_height: msg.content.dkg_id.start_block_height,
        };
        let hash = ic_crypto::crypto_hash(msg);
        Advert {
            id: hash.clone(),
            attribute,
            size,
            integrity_hash: hash.get(),
        }
    }
}
