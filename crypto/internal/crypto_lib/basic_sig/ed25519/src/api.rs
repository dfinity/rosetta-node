//! Ed25519 signature methods
use super::types;
use ic_crypto_internal_basic_sig_der_utils as der_utils;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use rand::{CryptoRng, Rng};
use simple_asn1::{BigUint, OID};
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

pub fn keypair_from_rng<R: Rng + CryptoRng>(
    csprng: &mut R,
) -> (types::SecretKeyBytes, types::PublicKeyBytes) {
    let keypair = ed25519_dalek::Keypair::generate(csprng);
    let sk = types::SecretKeyBytes(keypair.secret.to_bytes());
    let pk = types::PublicKeyBytes(keypair.public.to_bytes());
    (sk, pk)
}

// Tries to parse `pk_der` as a DER-encoded Ed25519 public key
// (see https://tools.ietf.org/html/rfc8410 for the spec).
pub fn public_key_from_der(pk_der: &[u8]) -> CryptoResult<types::PublicKeyBytes> {
    let (oid, pk_bytes) = der_utils::oid_and_public_key_bytes_from_der(pk_der).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: Some(pk_der.to_vec()),
            internal_error: e.internal_error,
        }
    })?;
    ensure_correct_oid(oid, pk_der)?;
    types::PublicKeyBytes::try_from(&pk_bytes)
}

/// Encodes the provided key into a DER-encoded Ed25519 key.
/// See https://tools.ietf.org/html/rfc8410
pub fn public_key_to_der(key: types::PublicKeyBytes) -> Vec<u8> {
    // Prefixing the following bytes to the key is sufficient to DER-encode it.
    let mut der_pk = vec![
        48, 42, // A sequence of 42 bytes follows.
        48, 5, // An element of 5 bytes follows.
        6, 3, 43, 101, 112, // The OID
        3, 33, // A bitstring of 33 bytes follows.
        0,  // The bitstring (32 bytes) is divisible by 8
    ];
    der_pk.extend_from_slice(&key.0);
    der_pk
}

// TODO (DFN-845): Consider storing pubkey in key store to improve performance
pub fn sign(msg: &[u8], sk: &types::SecretKeyBytes) -> CryptoResult<types::SignatureBytes> {
    use ed25519_dalek::{Keypair, PublicKey, SecretKey};

    let secret = SecretKey::from_bytes(&sk.0).map_err(|e| CryptoError::MalformedSecretKey {
        algorithm: AlgorithmId::Ed25519,
        internal_error: e.to_string(),
    })?;
    let public = PublicKey::from(&secret);

    Ok(types::SignatureBytes(
        Keypair { secret, public }.sign(msg).to_bytes(),
    ))
}

pub fn verify(
    sig: &types::SignatureBytes,
    msg: &[u8],
    pk: &types::PublicKeyBytes,
) -> CryptoResult<()> {
    use ed25519_dalek::{PublicKey, Signature};

    let pk = PublicKey::from_bytes(&pk.0).map_err(|e| CryptoError::MalformedPublicKey {
        algorithm: AlgorithmId::Ed25519,
        key_bytes: Some(pk.0.to_vec()),
        internal_error: e.to_string(),
    })?;
    let sig = Signature::from_bytes(&sig.0).map_err(|e| CryptoError::MalformedSignature {
        algorithm: AlgorithmId::Ed25519,
        sig_bytes: sig.0.to_vec(),
        internal_error: e.to_string(),
    })?;

    pk.verify(msg, &sig)
        .map_err(|e| CryptoError::SignatureVerification {
            algorithm: AlgorithmId::Ed25519,
            public_key_bytes: pk.as_bytes().to_vec(),
            sig_bytes: sig.to_bytes().to_vec(),
            internal_error: e.to_string(),
        })
}

fn ensure_correct_oid(oid: simple_asn1::OID, pk_der: &[u8]) -> CryptoResult<()> {
    // OID for Ed25519 is 1.3.101.112, see https://tools.ietf.org/html/rfc8410
    if oid != simple_asn1::oid!(1, 3, 101, 112) {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: Some(Vec::from(pk_der)),
            internal_error: format!("Wrong OID: {:?}", oid),
        });
    }
    Ok(())
}
