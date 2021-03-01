//! Distributed non-interactive key generation

use super::encryption::{encrypt_and_prove, verify_zk_proofs};
use crate::api::ni_dkg_errors::{
    dealing::InvalidDealingError, CspDkgCreateReshareDealingError, CspDkgVerifyDealingError,
    InvalidArgumentError, MalformedSecretKeyError, MisnumberedReceiverError, SizeError,
};
use crate::{
    api::individual_public_key,
    crypto::{keygen, keygen_with_secret},
};
use ic_crypto_internal_bls12381_common::fr_to_bytes;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use pairing::bls12_381::FrRepr;
use std::collections::BTreeMap;
use std::convert::TryFrom;

// "Old style" CSP types, used for the threshold keys:
use crate::types::{SecretKey as ThresholdSecretKey, SecretKeyBytes as ThresholdSecretKeyBytes};

// "New style" internal types, used for the NiDKG:
use super::ALGORITHM_ID;
use ic_crypto_internal_types::curves::bls12_381::Fr as FrBytes;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    Dealing, FsEncryptionPlaintext, FsEncryptionPublicKey, PublicCoefficientsBytes,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;

/// Creates a new dealing: Generates threshold keys.
///
/// Note: This is a functional but insecure placeholder;  it does not encrypt
/// shares, or rather it applies a trivial encryption with no security
/// whatsoever.
pub fn create_dealing(
    keygen_seed: Randomness,
    encryption_seed: Randomness,
    threshold: NumberOfNodes,
    receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
    epoch: Epoch,
    resharing_secret: Option<ThresholdSecretKeyBytes>,
) -> Result<Dealing, CspDkgCreateReshareDealingError> {
    // Check parameters
    {
        let number_of_receivers = number_of_receivers(receiver_keys)
            .map_err(CspDkgCreateReshareDealingError::SizeError)?;
        verify_threshold(threshold, number_of_receivers)
            .map_err(CspDkgCreateReshareDealingError::InvalidThresholdError)?;
        verify_receiver_indices(receiver_keys, number_of_receivers)?;
    }

    let (public_coefficients, threshold_secret_key_shares) = {
        let selected_nodes: Vec<bool> = {
            let max_node_index = receiver_keys.keys().max();
            let mut selected =
                vec![false; max_node_index.map(|index| *index as usize + 1).unwrap_or(0)];
            for index in receiver_keys.keys() {
                selected[*index as usize] = true;
            }
            selected
        };
        if let Some(resharing_secret) = resharing_secret {
            let resharing_secret: ThresholdSecretKey =
                ThresholdSecretKey::try_from(&resharing_secret).map_err(|_| {
                    CspDkgCreateReshareDealingError::MalformedReshareSecretKeyError(
                        MalformedSecretKeyError {
                            algorithm: ALGORITHM_ID,
                            internal_error: "Malformed reshared secret key".to_string(),
                        },
                    )
                })?;

            keygen_with_secret(
                keygen_seed,
                threshold,
                &selected_nodes[..],
                &resharing_secret,
            )
            .map_err(CspDkgCreateReshareDealingError::InvalidThresholdError)
        } else {
            keygen(keygen_seed, threshold, &selected_nodes[..])
                .map_err(CspDkgCreateReshareDealingError::InvalidThresholdError)
        }
    }?;

    let public_coefficients = PublicCoefficientsBytes::from(&public_coefficients); // Internal to CSP type conversion

    let (ciphertexts, zk_proof_decryptability, zk_proof_correct_sharing) = {
        let key_message_pairs: Vec<(FsEncryptionPublicKey, FsEncryptionPlaintext)> = (0..)
            .zip(&threshold_secret_key_shares)
            .map(|(index, share)| {
                let share = share
                    .clone()
                    .expect("The keys should be contiguous but we have a missing entry.");
                let share = FrRepr::from(share);
                let share = FrBytes(fr_to_bytes(&share));
                let share = FsEncryptionPlaintext::from(&share);
                (
                    *receiver_keys
                        .get(&index)
                        .expect("There should be a public key for each share"),
                    share,
                )
            })
            .collect();
        encrypt_and_prove(
            encryption_seed,
            &key_message_pairs,
            epoch,
            &public_coefficients,
        )
    }?;

    let dealing = Dealing {
        public_coefficients,
        ciphertexts,
        zk_proof_decryptability,
        zk_proof_correct_sharing,
    };
    Ok(dealing)
}

pub fn verify_dealing(
    _dkg_id: NiDkgId,
    threshold: NumberOfNodes,
    _epoch: Epoch,
    receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
    dealing: &Dealing,
) -> Result<(), CspDkgVerifyDealingError> {
    let number_of_receivers =
        number_of_receivers(receiver_keys).map_err(CspDkgVerifyDealingError::SizeError)?;
    verify_threshold(threshold, number_of_receivers)
        .map_err(CspDkgVerifyDealingError::InvalidThresholdError)?;
    verify_receiver_indices(receiver_keys, number_of_receivers)?;
    verify_all_shares_are_present_and_well_formatted(dealing, number_of_receivers)
        .map_err(CspDkgVerifyDealingError::InvalidDealingError)?;
    verify_public_coefficients_match_threshold(dealing, threshold)
        .map_err(CspDkgVerifyDealingError::InvalidDealingError)?;
    verify_zk_proofs(
        receiver_keys,
        &dealing.public_coefficients,
        &dealing.ciphertexts,
        &dealing.zk_proof_decryptability,
        &dealing.zk_proof_correct_sharing,
    )?;
    Ok(())
}

pub fn verify_resharing_dealing(
    dkg_id: NiDkgId,
    threshold: NumberOfNodes,
    epoch: Epoch,
    receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
    dealing: &Dealing,
    resharing_public_coefficients: &PublicCoefficientsBytes,
    resharing_index: NodeIndex,
) -> Result<(), CspDkgVerifyDealingError> {
    verify_dealing(dkg_id, threshold, epoch, receiver_keys, dealing)?;

    // Check the constant term in the public coefficient corresponds to the
    // individual public key of the dealer in the resharing instance
    let dealt_public_key = dealing
        .public_coefficients
        .coefficients
        .get(0)
        .expect("verify_dealing guarantees that public_coefficients.len() == threshold > 0");
    let reshared_public_key = individual_public_key(resharing_public_coefficients, resharing_index)
        .map_err(|error| {
            let error = InvalidArgumentError {
                message: format!("{}", error),
            };
            CspDkgVerifyDealingError::InvalidDealingError(error)
        })?;
    if *dealt_public_key != reshared_public_key {
        let error = InvalidDealingError::ReshareMismatch {
            old: reshared_public_key,
            new: *dealt_public_key,
        };
        let error = InvalidArgumentError::from(error);
        return Err(CspDkgVerifyDealingError::InvalidDealingError(error));
    }

    Ok(())
}

/// Tries to get the number of receivers as NumberOfNodes
pub fn number_of_receivers(
    receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
) -> Result<NumberOfNodes, SizeError> {
    let size = NodeIndex::try_from(receiver_keys.len()).map_err(|_| SizeError {
        message: format!(
            "Unsupported number of receivers:\n  Num receivers: {}\n  Max: {}",
            receiver_keys.len(),
            NodeIndex::max_value()
        ),
    })?;
    Ok(NumberOfNodes::from(size))
}

/// Verifies that the threshold is at least 1 but not greater than the number of
/// receivers
pub fn verify_threshold(
    threshold: NumberOfNodes,
    number_of_receivers: NumberOfNodes,
) -> Result<(), InvalidArgumentError> {
    let min_threshold = NumberOfNodes::from(1);
    if threshold < min_threshold {
        return Err(InvalidArgumentError {
            message: format!(
                "Threshold to small:\n  Threshold: {}\n  minimum: {}",
                threshold, min_threshold
            ),
        });
    }

    if threshold > number_of_receivers {
        return Err(InvalidArgumentError {
            message: format!(
                "Threshold to large:\n  Threshold: {}\n  Number of receivers: {}",
                threshold, number_of_receivers
            ),
        });
    }
    Ok(())
}

/// Verifies that dealing.public_coefficients.len() == threshold.
pub fn verify_public_coefficients_match_threshold(
    dealing: &Dealing,
    threshold: NumberOfNodes,
) -> Result<(), InvalidArgumentError> {
    let public_coefficients_len =
        NodeIndex::try_from(dealing.public_coefficients.coefficients.len());
    if public_coefficients_len == Ok(threshold.get()) {
        Ok(())
    } else {
        let err = InvalidDealingError::ThresholdMismatch {
            threshold,
            public_coefficients_len: dealing.public_coefficients.coefficients.len(),
        };
        Err(InvalidArgumentError::from(err))
    }
}

/// Verifies that receivers are indexed correctly
///
/// # Errors
/// This returns an error if:
/// * The receiver indices are not 0..num_receivers-1 inclusive.
pub fn verify_receiver_indices(
    receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
    number_of_receivers: NumberOfNodes,
) -> Result<(), MisnumberedReceiverError> {
    // Verify that the receivers are indexed correctly:
    for receiver_index in receiver_keys.keys().copied() {
        if receiver_index >= number_of_receivers.get() {
            let error = MisnumberedReceiverError {
                receiver_index,
                number_of_receivers,
            };
            return Err(error);
        }
    }
    Ok(())
}

/// Verifies that shares are well formed and have the correct indices.
///
/// # Errors
/// This returns an error if:
/// * The share indices are not 0..num_receivers-1 inclusive.
/// * Any shares are malformed.
pub fn verify_all_shares_are_present_and_well_formatted(
    dealing: &Dealing,
    number_of_receivers: NumberOfNodes,
) -> Result<(), InvalidArgumentError> {
    // Check that all required indices are present:
    let num_encrypted_chunks = NodeIndex::try_from(dealing.ciphertexts.ciphertext_chunks.len());
    if num_encrypted_chunks != Ok(number_of_receivers.get()) {
        return Err(InvalidArgumentError {
            message: format!(
                "Incorrect number of shares.\n  Expected: {}\n  Got: {}",
                number_of_receivers.get(),
                dealing.ciphertexts.ciphertext_chunks.len()
            ),
        });
    }
    Ok(())
}
