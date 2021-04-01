// We disable clippy warnings for the whole module because they apply to
// generated code, meaning we can't locally disable the warnings (the code is
// defined in another module). https://dfinity.atlassian.net/browse/DFN-467
#![allow(clippy::unit_arg)]

pub use conversions::CspSecretKeyConversionError;
use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types as ecdsa_secp256k1_types;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types as ecdsa_secp256r1_types;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_multi_sig_bls12381::types as multi_types;
use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1::types::{
    CLibResponseBytes, CLibTranscriptBytes, EncryptedShareBytes, EphemeralKeySetBytes,
    EphemeralPopBytes,
};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::types::CspFsEncryptionKeySet;
use ic_crypto_internal_threshold_sig_bls12381::types as threshold_types;
use ic_types::crypto::AlgorithmId;
use serde::{Deserialize, Serialize};
use strum_macros::IntoStaticStr;
use zeroize::Zeroize;

pub mod conversions;
mod external_conversion_utilities;

#[cfg(test)]
use proptest_derive::Arbitrary;
mod test_utils;
#[cfg(test)]
mod tests;

use ic_crypto_internal_tls::keygen::TlsEd25519SecretKeyDerBytes;
use std::collections::BTreeMap;
#[cfg(test)]
use test_utils::{
    arbitrary_ecdsa_secp256k1_public_key, arbitrary_ecdsa_secp256r1_public_key,
    arbitrary_ecdsa_secp256r1_signature, arbitrary_ed25519_public_key,
    arbitrary_ed25519_secret_key, arbitrary_ed25519_signature, arbitrary_ephemeral_key_set,
    arbitrary_fs_encryption_key_set, arbitrary_multi_bls12381_combined_signature,
    arbitrary_multi_bls12381_individual_signature, arbitrary_multi_bls12381_public_key,
    arbitrary_multi_bls12381_secret_key, arbitrary_secp256k1_signature,
    arbitrary_threshold_bls12381_combined_signature,
    arbitrary_threshold_bls12381_individual_signature, arbitrary_threshold_bls12381_secret_key,
    arbitrary_tls_ed25519_secret_key,
};

pub use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::CspPublicCoefficients;

#[derive(Clone, Eq, IntoStaticStr, PartialEq, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum CspSecretKey {
    #[cfg_attr(test, proptest(value(arbitrary_ed25519_secret_key)))]
    Ed25519(ed25519_types::SecretKeyBytes),
    #[cfg_attr(test, proptest(value(arbitrary_multi_bls12381_secret_key)))]
    MultiBls12_381(multi_types::SecretKeyBytes),
    #[cfg_attr(test, proptest(value(arbitrary_threshold_bls12381_secret_key)))]
    ThresBls12_381(threshold_types::SecretKeyBytes),
    #[cfg_attr(test, proptest(value(arbitrary_ephemeral_key_set)))]
    Secp256k1WithPublicKey(EphemeralKeySetBytes),
    #[cfg_attr(test, proptest(value(arbitrary_tls_ed25519_secret_key)))]
    TlsEd25519(TlsEd25519SecretKeyDerBytes),
    #[cfg_attr(test, proptest(value(arbitrary_fs_encryption_key_set)))]
    FsEncryption(CspFsEncryptionKeySet),
}

impl CspSecretKey {
    pub fn ed25519_bytes(&self) -> Option<&[u8; 32]> {
        match self {
            CspSecretKey::Ed25519(bytes) => Some(&bytes.0),
            _ => None,
        }
    }
}

#[cfg(test)]
impl std::fmt::Debug for CspSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CspSecretKey::Ed25519(sk) => write!(f, "CspSecretKey: {}", hex::encode(&sk.0[..])),
            CspSecretKey::MultiBls12_381(sk) => {
                write!(f, "CspSecretKey: {}", hex::encode(&sk.0[..]))
            }
            CspSecretKey::ThresBls12_381(sk) => {
                write!(f, "CspSecretKey: {}", hex::encode(&sk.0[..]))
            }
            CspSecretKey::Secp256k1WithPublicKey(sk) => write!(
                f,
                "CspSecretKey: secret_key: {} public_key: {} pop: {}",
                hex::encode(&sk.secret_key_bytes.0[..]),
                hex::encode(&sk.public_key_bytes.0[..]),
                hex::encode(&sk.pop_bytes.0[..])
            ),
            CspSecretKey::TlsEd25519(sk) => {
                write!(f, "CspSecretKey: {}", hex::encode(&sk.bytes[..]))
            }
            CspSecretKey::FsEncryption(sk) => {
                write!(f, "CspSecretKey: ")?;
                sk.fmt(f)
            }
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CspEncryptedSecretKey {
    ThresBls12_381(EncryptedShareBytes),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum CspPublicKey {
    #[cfg_attr(test, proptest(value(arbitrary_ecdsa_secp256r1_public_key)))]
    EcdsaP256(ecdsa_secp256r1_types::PublicKeyBytes),
    #[cfg_attr(test, proptest(value(arbitrary_ecdsa_secp256k1_public_key)))]
    EcdsaSecp256k1(ecdsa_secp256k1_types::PublicKeyBytes),
    #[cfg_attr(test, proptest(value(arbitrary_ed25519_public_key)))]
    Ed25519(ed25519_types::PublicKeyBytes),
    #[cfg_attr(test, proptest(value(arbitrary_multi_bls12381_public_key)))]
    MultiBls12_381(multi_types::PublicKeyBytes),
}

impl CspPublicKey {
    pub fn ecdsa_p256_bytes(&self) -> Option<&[u8]> {
        match self {
            CspPublicKey::EcdsaP256(bytes) => Some(&bytes.0),
            _ => None,
        }
    }

    pub fn ed25519_bytes(&self) -> Option<&[u8; 32]> {
        match self {
            CspPublicKey::Ed25519(bytes) => Some(&bytes.0),
            _ => None,
        }
    }

    pub fn multi_bls12_381_bytes(&self) -> Option<&[u8]> {
        match self {
            CspPublicKey::MultiBls12_381(bytes) => Some(&bytes.0),
            _ => None,
        }
    }

    pub fn algorithm_id(&self) -> AlgorithmId {
        match self {
            CspPublicKey::EcdsaSecp256k1(_) => AlgorithmId::EcdsaSecp256k1,
            CspPublicKey::EcdsaP256(_) => AlgorithmId::EcdsaP256,
            CspPublicKey::Ed25519(_) => AlgorithmId::Ed25519,
            CspPublicKey::MultiBls12_381(_) => AlgorithmId::MultiBls12_381,
        }
    }

    pub fn pk_bytes(&self) -> &[u8] {
        match self {
            CspPublicKey::EcdsaSecp256k1(pk_bytes) => &pk_bytes.0,
            CspPublicKey::EcdsaP256(pk_bytes) => &pk_bytes.0,
            CspPublicKey::Ed25519(pk_bytes) => &pk_bytes.0,
            CspPublicKey::MultiBls12_381(pk_bytes) => &pk_bytes.0,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CspPop {
    MultiBls12_381(multi_types::PopBytes),
    Secp256k1(EphemeralPopBytes),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum CspSignature {
    #[cfg_attr(test, proptest(value(arbitrary_ecdsa_secp256r1_signature)))]
    EcdsaP256(ecdsa_secp256r1_types::SignatureBytes),
    #[cfg_attr(test, proptest(value(arbitrary_secp256k1_signature)))]
    EcdsaSecp256k1(ecdsa_secp256k1_types::SignatureBytes),
    #[cfg_attr(test, proptest(value(arbitrary_ed25519_signature)))]
    Ed25519(ed25519_types::SignatureBytes),
    MultiBls12_381(MultiBls12_381_Signature),
    ThresBls12_381(ThresBls12_381_Signature),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Arbitrary))]
#[allow(non_camel_case_types)]
pub enum MultiBls12_381_Signature {
    #[cfg_attr(test, proptest(value(arbitrary_multi_bls12381_individual_signature)))]
    Individual(multi_types::IndividualSignatureBytes),
    #[cfg_attr(test, proptest(value(arbitrary_multi_bls12381_combined_signature)))]
    Combined(multi_types::CombinedSignatureBytes),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum ThresBls12_381_Signature {
    #[cfg_attr(
        test,
        proptest(value(arbitrary_threshold_bls12381_individual_signature))
    )]
    Individual(threshold_types::IndividualSignatureBytes),
    #[cfg_attr(test, proptest(value(arbitrary_threshold_bls12381_combined_signature)))]
    Combined(threshold_types::CombinedSignatureBytes),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CspDealing {
    pub common_data: CspPublicCoefficients,
    pub receiver_data: Vec<Option<CspEncryptedSecretKey>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CspResponse {
    Secp256k1(CLibResponseBytes),
}

impl CspResponse {
    pub fn new_without_complaints() -> CspResponse {
        CspResponse::Secp256k1(CLibResponseBytes {
            complaints: BTreeMap::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CspDkgTranscript {
    Secp256k1(CLibTranscriptBytes),
}

impl CspSignature {
    pub fn ecdsa_p256_bytes(&self) -> Option<&[u8]> {
        match self {
            CspSignature::EcdsaP256(bytes) => Some(&bytes.0),
            _ => None,
        }
    }

    pub fn ed25519_bytes(&self) -> Option<&[u8; 64]> {
        match self {
            CspSignature::Ed25519(bytes) => Some(&bytes.0),
            _ => None,
        }
    }

    pub fn algorithm(&self) -> AlgorithmId {
        match self {
            CspSignature::EcdsaP256(_) => AlgorithmId::EcdsaP256,
            CspSignature::EcdsaSecp256k1(_) => AlgorithmId::EcdsaSecp256k1,
            CspSignature::Ed25519(_) => AlgorithmId::Ed25519,
            CspSignature::MultiBls12_381(_) => AlgorithmId::MultiBls12_381,
            CspSignature::ThresBls12_381(_) => AlgorithmId::ThresBls12_381,
        }
    }
}

pub struct SigConverter {
    target_algorithm: AlgorithmId,
}