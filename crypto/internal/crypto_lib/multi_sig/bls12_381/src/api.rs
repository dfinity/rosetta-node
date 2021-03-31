//! External API for the multisignature library
use super::crypto;
use super::types::{
    CombinedSignatureBytes, IndividualSignature, IndividualSignatureBytes, Pop, PopBytes,
    PublicKey, PublicKeyBytes, SecretKeyBytes,
};
use ic_types::crypto::{AlgorithmId, CryptoError};
use rand::{CryptoRng, Rng};
use std::convert::TryFrom;
use std::convert::TryInto;

#[cfg(test)]
mod tests;

pub fn keypair_from_rng<R: Rng + CryptoRng>(rng: &mut R) -> (SecretKeyBytes, PublicKeyBytes) {
    let (secret_key, public_key) = crypto::keypair_from_rng(rng);
    (secret_key.into(), public_key.into())
}

/// Sign with multi-signatures
/// Note: This hashes the message to be signed.  If we pre-hash, the hashing
/// can be skipped. https://docs.rs/threshold_crypto/0.3.2/threshold_crypto/struct.SecretKey.html#method.sign
pub fn sign(
    message: &[u8],
    secret_key: SecretKeyBytes,
) -> Result<IndividualSignatureBytes, CryptoError> {
    Ok(crypto::sign_message(message, secret_key.into()).into())
}

pub fn create_pop(
    public_key_bytes: PublicKeyBytes,
    secret_key_bytes: SecretKeyBytes,
) -> Result<PopBytes, CryptoError> {
    let public_key = public_key_bytes.try_into()?;
    Ok(crypto::create_pop(public_key, secret_key_bytes.into()).into())
}

/// Verifies a public key's proof of possession (PoP).
///
/// As part of the PoP verification, it is also verified that the
/// public key is a point on the curve and in the right subgroup.
pub fn verify_pop(
    pop_bytes: PopBytes,
    public_key_bytes: PublicKeyBytes,
) -> Result<(), CryptoError> {
    let pop = Pop::try_from(pop_bytes)?;
    let public_key = PublicKey::try_from(public_key_bytes)?;
    if crypto::verify_pop(pop, public_key) {
        Ok(())
    } else {
        Err(CryptoError::PopVerification {
            algorithm: AlgorithmId::MultiBls12_381,
            public_key_bytes: public_key_bytes.0.to_vec(),
            pop_bytes: pop_bytes.0.to_vec(),
            internal_error: "PoP verification failed".to_string(),
        })
    }
}

pub fn combine(
    signatures: &[IndividualSignatureBytes],
) -> Result<CombinedSignatureBytes, CryptoError> {
    let signatures: Result<Vec<IndividualSignature>, CryptoError> = signatures
        .iter()
        .cloned()
        .map(|signature_bytes| signature_bytes.try_into())
        .collect();
    let signature = crypto::combine_signatures(&signatures?);
    Ok(signature.into())
}

pub fn verify_individual(
    message: &[u8],
    signature_bytes: IndividualSignatureBytes,
    public_key_bytes: PublicKeyBytes,
) -> Result<(), CryptoError> {
    let signature = signature_bytes.try_into()?;
    let public_key = public_key_bytes.try_into()?;
    if crypto::verify_individual_message_signature(message, signature, public_key) {
        Ok(())
    } else {
        Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::MultiBls12_381,
            public_key_bytes: public_key_bytes.0.to_vec(),
            sig_bytes: signature_bytes.0.to_vec(),
            internal_error: "Verification of individual contribution to multisignature failed"
                .to_string(),
        })
    }
}

pub fn verify_combined(
    message: &[u8],
    signature: CombinedSignatureBytes,
    public_keys: &[PublicKeyBytes],
) -> Result<(), CryptoError> {
    let public_keys: Result<Vec<PublicKey>, CryptoError> =
        public_keys.iter().cloned().map(|x| x.try_into()).collect();
    if crypto::verify_combined_message_signature(message, signature.try_into()?, &public_keys?[..])
    {
        Ok(())
    } else {
        Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::MultiBls12_381,
            public_key_bytes: Vec::new(),
            sig_bytes: signature.0.to_vec(),
            internal_error: "Verification of multisignature failed".to_string(),
        })
    }
}
