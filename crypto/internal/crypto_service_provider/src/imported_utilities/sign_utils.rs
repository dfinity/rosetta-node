use crate::crypto_lib::basic_sig::ecdsa;
use crate::types::CspSignature;
use ic_crypto_internal_basic_sig_der_utils as der_utils;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_threshold_sig_bls12381 as bls12_381;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes as BlsPublicKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_interfaces::crypto::Signable;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::{
    AlgorithmId, BasicSig, CombinedThresholdSig, CombinedThresholdSigOf, CryptoError, CryptoResult,
    UserPublicKey,
};
use ic_types::{NumberOfNodes, Randomness};
use std::convert::{TryFrom, TryInto};

#[cfg(test)]
mod tests;

/// Indicates the content type of serialised key bytes passed for parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyBytesContentType {
    Ed25519PublicKeyDer,
    EcdsaP256PublicKeyDer,
    EcdsaP256PublicKeyDerWrappedCose,
}

/// Parses the given `bytes` as a DER- or COSE-encoded public key, and returns,
/// if the parsing is successful, the key as `UserPublicKey`-struct and an enum
/// that indicates the content type of the passed `bytes`.
/// If parsing fails, returns an error.
pub fn user_public_key_from_bytes(
    bytes: &[u8],
) -> CryptoResult<(UserPublicKey, KeyBytesContentType)> {
    // Try DER-encoded Ed255519 public key.
    if let Ok(ed25519_pk) = ed25519::api::public_key_from_der(bytes) {
        return Ok((
            UserPublicKey {
                key: ed25519_pk.0.to_vec(),
                algorithm_id: AlgorithmId::Ed25519,
            },
            KeyBytesContentType::Ed25519PublicKeyDer,
        ));
    }
    // Try DER-encoded ECDSA-P256 public key.
    if let Ok(ecdsa_pk) = ecdsa::api::public_key_from_der(bytes) {
        return Ok((
            UserPublicKey {
                key: ecdsa_pk.0,
                algorithm_id: AlgorithmId::EcdsaP256,
            },
            KeyBytesContentType::EcdsaP256PublicKeyDer,
        ));
    }

    // Try DER-wrapped COSE ECDSA-P256 public key.
    if let Ok(pk_cose) = der_utils::public_key_bytes_from_der_wrapping(bytes) {
        if let Ok(ecdsa_pk) = ecdsa::api::public_key_from_cose(&pk_cose) {
            return Ok((
                UserPublicKey {
                    key: ecdsa_pk.0,
                    algorithm_id: AlgorithmId::EcdsaP256,
                },
                KeyBytesContentType::EcdsaP256PublicKeyDerWrappedCose,
            ));
        }
    }

    Err(CryptoError::AlgorithmNotSupported {
        algorithm: AlgorithmId::Placeholder,
        reason: "Unsupported public key".to_string(),
    })
}

#[allow(unused)]
pub fn ecdsa_p256_signature_from_der_bytes(bytes: &[u8]) -> CryptoResult<BasicSig> {
    let ecdsa_sig = ecdsa::api::signature_from_der(bytes)?;
    Ok(BasicSig(ecdsa_sig.0.to_vec()))
}

pub fn threshold_sig_public_key_to_der(pk: ThresholdSigPublicKey) -> CryptoResult<Vec<u8>> {
    // TODO(CRP-641): add a check that the key is indeed a BLS key.
    let pk = BlsPublicKeyBytes(pk.into_bytes());
    bls12_381::api::public_key_to_der(pk)
}

pub fn threshold_sig_public_key_from_der(bytes: &[u8]) -> CryptoResult<ThresholdSigPublicKey> {
    let pk = bls12_381::api::public_key_from_der(bytes)?;
    Ok(pk.into())
}

pub fn ed25519_public_key_to_der(raw_key: Vec<u8>) -> CryptoResult<Vec<u8>> {
    let key: [u8; 32] = raw_key.as_slice().try_into().map_err(|_| {
        let key_length = raw_key.len();
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: Some(raw_key),
            internal_error: format!(
                "Incorrect length. Expected 32 bytes but found {} bytes",
                key_length
            ),
        }
    })?;

    Ok(ed25519::public_key_to_der(ed25519::types::PublicKeyBytes(
        key,
    )))
}

// TODO(CRP-622): remove this helper once crypto has NNS-verfification built in.
#[allow(dead_code)]
pub fn verify_combined_threshold_sig<T: Signable>(
    msg: &T,
    sig: &CombinedThresholdSigOf<T>,
    pk: &ThresholdSigPublicKey,
) -> CryptoResult<()> {
    let bls_pk = BlsPublicKeyBytes(pk.into_bytes());
    let csp_sig = CspSignature::try_from(sig)?;
    if csp_sig.algorithm() != AlgorithmId::ThresBls12_381 {
        return Err(CryptoError::MalformedSignature {
            algorithm: AlgorithmId::ThresBls12_381,
            sig_bytes: vec![],
            internal_error: "Not a ThresBls12_381-signature".to_string(),
        });
    }
    let bls_sig = bls12_381::types::CombinedSignatureBytes::try_from(csp_sig)?;
    bls12_381::api::verify_combined_signature(&msg.as_signed_bytes(), bls_sig, bls_pk)
}

// TODO(CRP-622): consider turning it into a test_util once crypto has
// NNS-verfification built in.
#[allow(dead_code)]
pub fn combined_threshold_signature_and_public_key<T: Signable>(
    seed: Randomness,
    message: &T,
) -> (CombinedThresholdSigOf<T>, ThresholdSigPublicKey) {
    let group_size = 1;
    let threshold = NumberOfNodes::new(1);
    let (signature, public_key) = bls12_381::api::combined_signature_and_public_key(
        seed,
        group_size,
        threshold,
        &message.as_signed_bytes(),
    );
    (
        CombinedThresholdSigOf::from(CombinedThresholdSig(signature.0.to_vec())),
        ThresholdSigPublicKey::from(CspThresholdSigPublicKey::from(public_key)),
    )
}
