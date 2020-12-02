pub mod dkg;
pub mod error;
pub mod threshold_sig;

use crate::crypto::threshold_sig::ni_dkg::DkgId;
use crate::registry::RegistryClientError;
use crate::{CountBytes, NodeId, RegistryVersion, SubnetId};
use core::fmt::Formatter;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::MalformedThresholdSigPublicKeyError;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use phantom_newtype::Id;
#[cfg(all(test, not(target_arch = "wasm32")))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use strum_macros::EnumIter;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(pub [u8; 32]);
ic_crypto_internal_types::derive_serde!(KeyId, 32);

#[cfg(test)]
mod tests;

impl KeyId {
    pub fn get(&self) -> [u8; 32] {
        self.0
    }
}
impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId(0x{})", hex::encode(self.0))
    }
}
impl From<[u8; 32]> for KeyId {
    fn from(bytes: [u8; 32]) -> Self {
        KeyId(bytes)
    }
}
impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId(0x{})", hex::encode(self.0))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct CryptoHash(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl fmt::Debug for CryptoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CryptoHash(0x{})", hex::encode(self.0.clone()))
    }
}

pub type CryptoHashOf<T> = Id<T, CryptoHash>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Signed<T, S> {
    pub content: T,
    pub signature: S,
}

impl<T: CountBytes, S: CountBytes> CountBytes for Signed<T, S> {
    fn count_bytes(&self) -> usize {
        self.content.count_bytes() + self.signature.count_bytes()
    }
}

pub trait SignedBytesWithoutDomainSeparator {
    /// Returns a bytes-representation of the object for digital signatures.
    /// The returned value together with a domain-separator (that can be empty,
    /// depending on the type) are the bytes that are used for
    /// signing/verification.
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8>;
}

// WARNING: The integer values of those enums discriminant is used in serialized
// data. This means that existing discriminants should never change. Obsolete
// discriminants should be marked as being never reusable.
#[derive(
    Clone, Copy, Debug, Deserialize, EnumIter, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[cfg_attr(all(test, not(target_arch = "wasm32")), derive(Arbitrary))]
pub enum KeyPurpose {
    Placeholder = 0,
    NodeSigning = 1,
    QueryResponseSigning = 2,
    DkgDealingEncryption = 3,
    CommitteeSigning = 4,
}

#[derive(
    Clone, Copy, Debug, Deserialize, EnumIter, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize,
)]
#[cfg_attr(all(test, not(target_arch = "wasm32")), derive(Arbitrary))]
#[allow(non_camel_case_types)]
pub enum AlgorithmId {
    Placeholder = 0,
    MultiBls12_381 = 1,
    ThresBls12_381 = 2,
    SchnorrSecp256k1 = 3,
    StaticDhSecp256k1 = 4,
    HashSha256 = 5,
    Tls = 6,
    Ed25519 = 7,
    Secp256k1 = 8,
    Groth20_Bls12_381 = 9,
    NiDkg_Groth20_Bls12_381 = 10,
    EcdsaP256 = 11,
}

impl From<CspThresholdSigPublicKey> for AlgorithmId {
    fn from(public_key: CspThresholdSigPublicKey) -> Self {
        match public_key {
            CspThresholdSigPublicKey::ThresBls12_381(_) => AlgorithmId::ThresBls12_381,
        }
    }
}

impl From<i32> for AlgorithmId {
    fn from(algorithm_id: i32) -> Self {
        match algorithm_id {
            1 => AlgorithmId::MultiBls12_381,
            2 => AlgorithmId::ThresBls12_381,
            3 => AlgorithmId::SchnorrSecp256k1,
            4 => AlgorithmId::StaticDhSecp256k1,
            5 => AlgorithmId::HashSha256,
            6 => AlgorithmId::Tls,
            7 => AlgorithmId::Ed25519,
            8 => AlgorithmId::Secp256k1,
            9 => AlgorithmId::Groth20_Bls12_381,
            10 => AlgorithmId::NiDkg_Groth20_Bls12_381,
            11 => AlgorithmId::EcdsaP256,
            _ => AlgorithmId::Placeholder,
        }
    }
}
impl From<KeyPurpose> for AlgorithmId {
    fn from(key_purpose: KeyPurpose) -> Self {
        match key_purpose {
            KeyPurpose::QueryResponseSigning => AlgorithmId::Ed25519,
            KeyPurpose::NodeSigning => AlgorithmId::Ed25519,
            KeyPurpose::DkgDealingEncryption => AlgorithmId::StaticDhSecp256k1,
            KeyPurpose::CommitteeSigning => AlgorithmId::MultiBls12_381,
            KeyPurpose::Placeholder => AlgorithmId::Placeholder,
        }
    }
}

#[derive(Debug)]
pub enum PublicKey {
    UserPublicKey(UserPublicKey),
    NodePublicKey(NodePublicKey),
    IcpPublicKey(IcpPublicKey),
    CommitteeMemberPublicKey(CommitteeMemberPublicKey),
}

impl CountBytes for PublicKey {
    fn count_bytes(&self) -> usize {
        match self {
            PublicKey::UserPublicKey(key) => key.count_bytes(),
            PublicKey::NodePublicKey(key) => key.count_bytes(),
            PublicKey::IcpPublicKey(key) => key.count_bytes(),
            PublicKey::CommitteeMemberPublicKey(key) => key.count_bytes(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserPublicKey {
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    pub algorithm_id: AlgorithmId,
}

impl fmt::Display for UserPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "algorithm_id: {:?}, key: 0x{}",
            self.algorithm_id,
            hex::encode(&self.key)
        )
    }
}

impl CountBytes for UserPublicKey {
    fn count_bytes(&self) -> usize {
        self.key.len()
    }
}

#[derive(Debug)]
pub struct NodePublicKey {
    pub key: Vec<u8>,
    pub proof_of_possession: Vec<u8>,
}

impl CountBytes for NodePublicKey {
    fn count_bytes(&self) -> usize {
        self.key.len() + self.proof_of_possession.len()
    }
}

#[derive(Debug)]
pub struct IcpPublicKey {
    pub key: Vec<u8>,
}

impl CountBytes for IcpPublicKey {
    fn count_bytes(&self) -> usize {
        self.key.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitteeMemberPublicKey {
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub proof_of_possession: Vec<u8>,
}

impl CountBytes for CommitteeMemberPublicKey {
    fn count_bytes(&self) -> usize {
        self.key.len() + self.proof_of_possession.len()
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoError {
    /// The arguments are semantically incorrect.
    /// This error is not retriable.
    /// This is equivalent to HTTP 422: The request was well-formed but was
    /// unable to be followed due to semantic errors.
    InvalidArgument { message: String },
    /// Public key for given (entity, purpose) pair not found at given registry
    /// version.
    PublicKeyNotFound {
        node_id: NodeId,
        key_purpose: KeyPurpose,
        registry_version: RegistryVersion,
    },
    /// Secret key not found in SecretKeyStore.
    SecretKeyNotFound {
        algorithm: AlgorithmId,
        key_id: KeyId,
    },
    /// Secret key could not be parsed or is otherwise invalid.
    MalformedSecretKey {
        algorithm: AlgorithmId,
        internal_error: String,
    },
    /// Public key could not be parsed or is otherwise invalid.
    MalformedPublicKey {
        algorithm: AlgorithmId,
        key_bytes: Option<Vec<u8>>,
        internal_error: String,
    },
    /// Signature could not be parsed or is otherwise invalid.
    MalformedSignature {
        algorithm: AlgorithmId,
        sig_bytes: Vec<u8>,
        internal_error: String,
    },
    /// Signature could not be verified.
    SignatureVerification {
        algorithm: AlgorithmId,
        public_key_bytes: Vec<u8>,
        sig_bytes: Vec<u8>,
        internal_error: String,
    },
    /// Multi-signature: inconsistent (multiple) algorithms.
    InconsistentAlgorithms {
        algorithms: BTreeSet<AlgorithmId>,
        key_purpose: KeyPurpose,
        registry_version: RegistryVersion,
    },
    /// Algorithm not supported.
    AlgorithmNotSupported {
        algorithm: AlgorithmId,
        reason: String,
    },
    /// Error querying the registry.
    RegistryClient(RegistryClientError),
    /// Threshold signature data store did not contain the expected data (public
    /// coefficients and node indices)
    ThresholdSigDataNotFound { dkg_id: DkgId },
    /// DKG transcript for given subnet ID not found at given registry version.
    DkgTranscriptNotFound {
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    },
}

impl From<MalformedThresholdSigPublicKeyError> for CryptoError {
    fn from(error: MalformedThresholdSigPublicKeyError) -> Self {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::ThresBls12_381,
            key_bytes: error.key_bytes,
            internal_error: error.internal_error,
        }
    }
}

impl CryptoError {
    pub fn is_public_key_not_found(&self) -> bool {
        match self {
            CryptoError::PublicKeyNotFound { .. } => true,
            _ => false,
        }
    }

    pub fn is_secret_key_not_found(&self) -> bool {
        match self {
            CryptoError::SecretKeyNotFound { .. } => true,
            _ => false,
        }
    }

    pub fn is_malformed_secret_key(&self) -> bool {
        match self {
            CryptoError::MalformedSecretKey { .. } => true,
            _ => false,
        }
    }

    pub fn is_malformed_public_key(&self) -> bool {
        match self {
            CryptoError::MalformedPublicKey { .. } => true,
            _ => false,
        }
    }

    pub fn is_malformed_signature(&self) -> bool {
        match self {
            CryptoError::MalformedSignature { .. } => true,
            _ => false,
        }
    }

    pub fn is_signature_verification_error(&self) -> bool {
        match self {
            CryptoError::SignatureVerification { .. } => true,
            _ => false,
        }
    }

    pub fn is_inconsistent_algorithms(&self) -> bool {
        match self {
            CryptoError::InconsistentAlgorithms { .. } => true,
            _ => false,
        }
    }

    pub fn is_algorithm_not_supported(&self) -> bool {
        match self {
            CryptoError::AlgorithmNotSupported { .. } => true,
            _ => false,
        }
    }

    pub fn is_registry_client_error(&self) -> bool {
        match self {
            CryptoError::RegistryClient(_) => true,
            _ => false,
        }
    }

    pub fn is_threshold_sig_data_not_found(&self) -> bool {
        match self {
            CryptoError::ThresholdSigDataNotFound { .. } => true,
            _ => false,
        }
    }

    pub fn is_dkg_transcript_not_found(&self) -> bool {
        match self {
            CryptoError::DkgTranscriptNotFound { .. } => true,
            _ => false,
        }
    }
}

impl From<RegistryClientError> for CryptoError {
    fn from(registry_client_error: RegistryClientError) -> Self {
        CryptoError::RegistryClient(registry_client_error)
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoError::RegistryClient(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Debug for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidArgument { message } => {
                write!(f, "Semantic error in argument: {}", message)
            }
            CryptoError::PublicKeyNotFound {
                node_id,
                key_purpose,
                registry_version,
            } => write!(
                f,
                "Cannot find public key registry record for node with \
                 ID {:?} with purpose {:?} at registry version {:?}",
                node_id, key_purpose, registry_version
            ),

            CryptoError::SecretKeyNotFound { algorithm, key_id } => write!(
                f,
                "Cannot find {:?} secret key with ID {:?}",
                algorithm, key_id
            ),

            CryptoError::MalformedSecretKey { algorithm, .. } => {
                write!(f, "Malformed {:?} secret key", algorithm)
            }

            CryptoError::MalformedPublicKey {
                algorithm,
                key_bytes: Some(key_bytes),
                internal_error,
            } => write!(
                f,
                "Malformed {:?} public key: {}, error: {}",
                algorithm,
                hex::encode(&key_bytes),
                internal_error,
            ),
            CryptoError::MalformedPublicKey {
                algorithm,
                internal_error,
                ..
            } => write!(
                f,
                "Malformed {:?} public key: {}",
                algorithm, internal_error
            ),

            CryptoError::MalformedSignature {
                algorithm,
                sig_bytes,
                internal_error,
            } => write!(
                f,
                "Malformed {:?} signature: [{}] error: '{}'",
                algorithm,
                hex::encode(&sig_bytes),
                internal_error
            ),

            CryptoError::SignatureVerification {
                algorithm,
                public_key_bytes,
                sig_bytes,
                internal_error,
            } => write!(
                f,
                "{:?} signature could not be verified: public key {}, signature {}, error: {}",
                algorithm,
                hex::encode(&public_key_bytes),
                hex::encode(&sig_bytes),
                internal_error,
            ),

            CryptoError::InconsistentAlgorithms {
                algorithms,
                key_purpose,
                registry_version,
            } => write!(
                f,
                "Expected the given nodes' public key registry records for key purpose \
                 {:?} and registry version {:?} to all have the same algorithm but \
                 instead found the following algorithms {:?}.",
                key_purpose, registry_version, algorithms
            ),

            CryptoError::AlgorithmNotSupported { algorithm, reason } => {
                write!(f, "Algorithm {:?} not supported: {}", algorithm, reason)
            }

            CryptoError::RegistryClient(e) => write!(f, "Cannot query registry: {}", e),

            CryptoError::ThresholdSigDataNotFound { dkg_id } => write!(
                f,
                "Cannot find transcript data for DKG ID {:?} in data store",
                dkg_id
            ),
            CryptoError::DkgTranscriptNotFound {
                subnet_id,
                registry_version,
            } => write!(
                f,
                "Cannot find initial DKG transcript for subnet ID {:?} at registry version {:?}",
                subnet_id, registry_version
            ),
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub type CryptoResult<T> = std::result::Result<T, CryptoError>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ListOfLists {
    Leaf(#[serde(with = "serde_bytes")] Vec<u8>),
    Node(Vec<ListOfLists>),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BasicSig(#[serde(with = "serde_bytes")] pub Vec<u8>);
pub type BasicSigOf<T> = Id<T, BasicSig>; // Use newtype instead? E.g., `pub struct BasicSigOf<T>(Id<T, BasicSig>);`

impl CountBytes for BasicSig {
    fn count_bytes(&self) -> usize {
        self.0.len()
    }
}

impl<T: CountBytes> CountBytes for BasicSigOf<T> {
    fn count_bytes(&self) -> usize {
        self.get_ref().count_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IndividualMultiSig(#[serde(with = "serde_bytes")] pub Vec<u8>);
pub type IndividualMultiSigOf<T> = Id<T, IndividualMultiSig>; // Use newtype instead?

impl CountBytes for IndividualMultiSig {
    fn count_bytes(&self) -> usize {
        self.0.len()
    }
}

impl<T: CountBytes> CountBytes for IndividualMultiSigOf<T> {
    fn count_bytes(&self) -> usize {
        self.get_ref().count_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CombinedMultiSig(#[serde(with = "serde_bytes")] pub Vec<u8>);
pub type CombinedMultiSigOf<T> = Id<T, CombinedMultiSig>; // Use newtype instead?

impl CountBytes for CombinedMultiSig {
    fn count_bytes(&self) -> usize {
        self.0.len()
    }
}

impl<T: CountBytes> CountBytes for CombinedMultiSigOf<T> {
    fn count_bytes(&self) -> usize {
        self.get_ref().count_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdSigShare(#[serde(with = "serde_bytes")] pub Vec<u8>);
pub type ThresholdSigShareOf<T> = Id<T, ThresholdSigShare>; // Use newtype instead?

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CombinedThresholdSig(#[serde(with = "serde_bytes")] pub Vec<u8>);
pub type CombinedThresholdSigOf<T> = Id<T, CombinedThresholdSig>; // Use newtype instead?
