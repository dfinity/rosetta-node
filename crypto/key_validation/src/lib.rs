use crate::proto_conversions::fs_ni_dkg::fs_ni_dkg_pubkey_from_proto;
use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_internal_basic_sig_ed25519::types::PublicKeyBytes as BasicSigEd25519PublicKeyBytes;
use ic_crypto_internal_multi_sig_bls12381::types::PopBytes as MultiSigBls12381PopBytes;
use ic_crypto_internal_multi_sig_bls12381::types::PublicKeyBytes as MultiSigBls12381PublicKeyBytes;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use std::convert::TryFrom;
use std::fmt;
use tls_cert_validation::validate_tls_certificate;

#[cfg(test)]
mod tests;

mod proto_conversions;
mod tls_cert_validation;

#[derive(Clone, Debug, PartialEq)]
pub struct ValidNodePublicKeys {
    node_id: NodeId,
    node_signing_pubkey: PublicKey,
    committee_signing_pubkey: PublicKey,
    dkg_dealing_encryption_pubkey: PublicKey,
    tls_certificate: X509PublicKeyCert,
}

impl ValidNodePublicKeys {
    // TODO (CRP-657): check version?
    /// Determines if the given node public key material is valid.
    ///
    /// Returns `ValidNodePublicKeys` iff the `keys` are valid and iff they
    /// are valid for `node_id`. After successful validation, callers should
    /// only work with `ValidNodePublicKeys` in their API and not with
    /// the possibly invalid `NodePublicKeys` so as to avoid confusion about
    /// whether key material is validated or not.
    pub fn try_from(keys: &NodePublicKeys, node_id: NodeId) -> Result<Self, KeyValidationError> {
        validate_node_signing_key(&keys.node_signing_pk, node_id)?;
        validate_committee_signing_key(&keys.committee_signing_pk)?;
        validate_dkg_dealing_encryption_key(&keys.dkg_dealing_encryption_pk)?;
        validate_tls_certificate(&keys.tls_certificate, node_id)?;

        Ok(ValidNodePublicKeys {
            node_id,
            node_signing_pubkey: keys.node_signing_pk.as_ref().unwrap().clone(),
            committee_signing_pubkey: keys.committee_signing_pk.as_ref().unwrap().clone(),
            dkg_dealing_encryption_pubkey: keys.dkg_dealing_encryption_pk.as_ref().unwrap().clone(),
            tls_certificate: keys.tls_certificate.as_ref().unwrap().clone(),
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn node_signing_key(&self) -> &PublicKey {
        &self.node_signing_pubkey
    }

    pub fn committee_signing_key(&self) -> &PublicKey {
        &self.committee_signing_pubkey
    }

    pub fn dkg_dealing_encryption_key(&self) -> &PublicKey {
        &self.dkg_dealing_encryption_pubkey
    }

    pub fn tls_certificate(&self) -> &X509PublicKeyCert {
        &self.tls_certificate
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyValidationError {
    pub error: String,
}

impl fmt::Display for KeyValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Validates a node's signing key.
///
/// This includes verifying that
/// * the key is present and well-formed
/// * the node ID derived from the key matches the `node_id`
/// * the public key is valid, which includes checking that the key is a point
///   on the curve and in the right subgroup
fn validate_node_signing_key(
    node_signing_key: &Option<PublicKey>,
    node_id: NodeId,
) -> Result<(), KeyValidationError> {
    let pubkey_proto = node_signing_key
        .as_ref()
        .ok_or_else(|| invalid_node_signing_key_error("key is missing"))?;

    let pubkey_bytes = BasicSigEd25519PublicKeyBytes::try_from(pubkey_proto)
        .map_err(|e| invalid_node_signing_key_error(format!("{}", e)))?;

    if node_id != derive_node_id(pubkey_bytes) {
        return Err(invalid_node_signing_key_error(format!(
            "key not valid for node ID {}",
            node_id
        )));
    }
    if !ic_crypto_internal_basic_sig_ed25519::verify_public_key(&pubkey_bytes) {
        return Err(invalid_node_signing_key_error("verification failed"));
    }
    Ok(())
}

/// Validates a node's committee signing key.
///
/// This includes
/// * verifying that the key is present and well-formed
/// * verifying the public key's proof of possession (PoP) is valid
/// * verifying that the public key is a point on the curve and in the right
///   subgroup
fn validate_committee_signing_key(
    committee_signing_key: &Option<PublicKey>,
) -> Result<(), KeyValidationError> {
    let pubkey_proto = committee_signing_key
        .as_ref()
        .ok_or_else(|| invalid_committee_signing_key_error("key is missing"))?;

    let pubkey_bytes = MultiSigBls12381PublicKeyBytes::try_from(pubkey_proto)
        .map_err(|e| invalid_committee_signing_key_error(format!("{}", e)))?;
    let pop_bytes = MultiSigBls12381PopBytes::try_from(pubkey_proto)
        .map_err(|e| invalid_committee_signing_key_error(format!("{}", e)))?;

    // Note that `verify_pop` also ensures that the public key is a point on the
    // curve and in the right subgroup.
    ic_crypto_internal_multi_sig_bls12381::verify_pop(pop_bytes, pubkey_bytes)
        .map_err(|e| invalid_committee_signing_key_error(format!("{}", e)))
}

/// Validates a node's DKG dealing encryption key
///
/// This includes
/// * verifying that the key is present and well-formed
/// * verifying the public key's proof of knowledge (PoK) is valid
/// * verifying that the public key is a point on the curve and in the right
///   subgroup
fn validate_dkg_dealing_encryption_key(
    dkg_dealing_encryption_key: &Option<PublicKey>,
) -> Result<(), KeyValidationError> {
    let pubkey_proto = dkg_dealing_encryption_key
        .as_ref()
        .ok_or_else(|| invalid_dkg_dealing_enc_pubkey_error("key is missing"))?;

    // Note: `fs_ni_dkg_pubkey_from_proto` also ensures that the
    // public key is a point on the curve and in the right subgroup.
    let fs_ni_dkg_pubkey = fs_ni_dkg_pubkey_from_proto(pubkey_proto)
        .map_err(|e| invalid_dkg_dealing_enc_pubkey_error(format!("{}", e)))?;
    if !fs_ni_dkg_pubkey.verify() {
        return Err(invalid_dkg_dealing_enc_pubkey_error("verification failed"));
    }
    Ok(())
}

fn derive_node_id(pk_bytes: BasicSigEd25519PublicKeyBytes) -> NodeId {
    let pubkey_der = ic_crypto_internal_basic_sig_ed25519::public_key_to_der(pk_bytes);
    NodeId::from(PrincipalId::new_self_authenticating(&pubkey_der))
}

fn invalid_node_signing_key_error<S: Into<String>>(internal_error: S) -> KeyValidationError {
    KeyValidationError {
        error: format!("invalid node signing key: {}", internal_error.into()),
    }
}

fn invalid_committee_signing_key_error<S: Into<String>>(internal_error: S) -> KeyValidationError {
    KeyValidationError {
        error: format!("invalid committee signing key: {}", internal_error.into()),
    }
}

fn invalid_dkg_dealing_enc_pubkey_error<S: Into<String>>(internal_error: S) -> KeyValidationError {
    KeyValidationError {
        error: format!(
            "invalid DKG dealing encryption key: {}",
            internal_error.into()
        ),
    }
}
