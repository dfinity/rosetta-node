//! Non-Interactive Distributed Key Generation
//!
//! The code in this file mediates between the external API, the CSP state
//! including the secret key store and random number generator, and the
//! stateless crypto lib.

use crate::api::{NiDkgCspClient, NodePublicKeyData};
use crate::keygen::forward_secure_key_id;
use crate::secret_key_store::{SecretKeyStore, SecretKeyStoreError};
use crate::types::conversions::key_id_from_csp_pub_coeffs;
use crate::types::{CspPublicCoefficients, CspSecretKey};
use crate::Csp;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381 as clib;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::{
    secret_key_from_miracl, trusted_secret_key_into_miracl,
};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::types::CspFsEncryptionKeySet;
use ic_crypto_internal_threshold_sig_bls12381::types as threshold_types;
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::scope::{ConstScope, Scope};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_logger::debug;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::{NodeId, NodeIndex, NumberOfNodes, Randomness};
use rand::{CryptoRng, Rng};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
mod tests;

pub const NIDKG_THRESHOLD_SCOPE: Scope = Scope::Const(ConstScope::NiDkgThresholdKeys);
pub const NIDKG_FS_SCOPE: Scope = Scope::Const(ConstScope::NiDkgFsEncryptionKeys);

/// Non-interactive distributed key generation client
///
/// Please see the trait definition for full documentation.
impl<R: Rng + CryptoRng, S: SecretKeyStore> NiDkgCspClient for Csp<R, S> {
    /// Creates a key pair for encrypting threshold key shares in transmission
    /// from dealers to receivers.
    fn create_forward_secure_key_pair(
        &mut self,
        algorithm_id: AlgorithmId,
        node_id: NodeId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), ni_dkg_errors::CspDkgCreateFsKeyError>
    {
        debug!(self.logger; crypto.method_name => "create_forward_secure_key_pair");

        // Get state
        let seed = Randomness::from(self.rng_write_lock().gen::<[u8; 32]>());
        // Specialise
        let result = match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                // Call lib:
                let key_set = clib::create_forward_secure_key_pair(seed, node_id.get().as_slice());

                // Generalise over fs key variants:
                let public_key = CspFsEncryptionPublicKey::Groth20_Bls12_381(key_set.public_key);
                let pop = CspFsEncryptionPop::Groth20WithPop_Bls12_381(key_set.pop);
                let key_set = CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(key_set);
                Ok((public_key, pop, key_set))
            }
            other => Err(ni_dkg_errors::CspDkgCreateFsKeyError::UnsupportedAlgorithmId(other)),
        };
        let (public_key, pop, key_set) = result?;

        // Update state:
        let key_id = forward_secure_key_id(&public_key);
        if let Err(err) = self.sks_write_lock().insert(
            key_id,
            CspSecretKey::FsEncryption(key_set),
            Some(NIDKG_FS_SCOPE),
        ) {
            match err {
              SecretKeyStoreError::DuplicateKeyId(_key_id) =>
                panic!(
                    "Could not insert key as the KeyId is already in use.  This suggests an insecure RNG."
                ),
            };
        };

        // FIN:
        Ok((public_key, pop))
    }

    /// Verifies that a forward secure public key and PoP are valid.
    fn verify_forward_secure_key(
        &self,
        algorithm_id: AlgorithmId,
        public_key: CspFsEncryptionPublicKey,
        pop: CspFsEncryptionPop,
        node_id: NodeId,
    ) -> Result<(), ni_dkg_errors::CspDkgVerifyFsKeyError> {
        static_api::verify_forward_secure_key(algorithm_id, public_key, pop, node_id)
    }

    /// Erases forward secure secret keys before a given epoch
    fn update_forward_secure_epoch(
        &self,
        algorithm_id: AlgorithmId,
        epoch: Epoch,
    ) -> Result<(), ni_dkg_errors::CspDkgUpdateFsEpochError> {
        debug!(self.logger; crypto.method_name => "update_forward_secure_epoch", crypto.dkg_epoch => epoch.get());

        let key_id = self.dkg_dealing_encryption_key_id();

        let updated_key_set = match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                // Retrieve key from key store
                let key_set = self.sks_read_lock().get(&key_id).ok_or_else(|| {
                    ni_dkg_errors::CspDkgUpdateFsEpochError::FsKeyNotInSecretKeyStoreError(
                        ni_dkg_errors::KeyNotFoundError {
                            internal_error: "Cannot update forward secure key if it is missing"
                                .to_string(),
                            key_id,
                        },
                    )
                })?;

                // Specialise to Groth20
                let key_set = specialise::fs_key_set(key_set)
                    .expect("Not a forward secure secret key; it should be impossible to retrieve a key of the wrong type.");
                let mut key_set = specialise::groth20::fs_key_set(key_set)
                    .expect("If key generation is correct, it should be impossible to retrieve a key of the wrong type.");

                // Update secret key to new epoch (deserialize key first)
                let mut secret_key = trusted_secret_key_into_miracl(&key_set.secret_key);
                let seed = Randomness::from(self.rng_write_lock().gen::<[u8; 32]>());
                clib::update_key_inplace_to_epoch(&mut secret_key, epoch, seed);

                // Replace secret key in key set (serialize key first)
                key_set.secret_key = secret_key_from_miracl(&secret_key);

                // Generalise:
                Ok(CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(key_set))
            }
            other => Err(ni_dkg_errors::CspDkgUpdateFsEpochError::UnsupportedAlgorithmId(other)),
        };

        // Save state
        if let Err(err) = self.sks_write_lock().insert_or_replace(
            key_id,
            CspSecretKey::FsEncryption(updated_key_set?),
            Some(NIDKG_FS_SCOPE),
        ) {
            match err {
                SecretKeyStoreError::DuplicateKeyId(_key_id) => unreachable!(),
            };
        };

        // FIN
        Ok(())
    }

    /// Creates a CSP dealing
    fn create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        _dkg_id: NiDkgId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
    ) -> Result<CspNiDkgDealing, ni_dkg_errors::CspDkgCreateDealingError> {
        debug!(self.logger; crypto.method_name => "create_dealing", crypto.dkg_epoch => epoch.get());
        // Specialisation to this scheme:
        match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                let receiver_keys = specialise::groth20::receiver_keys(&receiver_keys).map_err(
                    |(receiver_index, error)| {
                        ni_dkg_errors::CspDkgCreateDealingError::MalformedFsPublicKeyError {
                            receiver_index,
                            error,
                        }
                    },
                )?;
                // Stateless call to crypto lib
                // Acquire an rng lock and generate randomness before invoking create_dealing
                // because:
                // * acquiring two locks inline in the create_dealing call would lead to a
                //   deadlock.
                // * we should not hold the write lock for the whole duration of create_dealing.
                let (keygen_seed, encryption_seed) = {
                    let mut rng = self.rng_write_lock();
                    (rng.gen::<[u8; 32]>(), rng.gen::<[u8; 32]>())
                };
                let dealing = clib::create_dealing(
                    Randomness::from(keygen_seed),
                    Randomness::from(encryption_seed),
                    threshold,
                    &receiver_keys,
                    epoch,
                    dealer_index,
                    None,
                )?;
                // Response
                Ok(CspNiDkgDealing::Groth20_Bls12_381(dealing))
            }
            other => Err(ni_dkg_errors::CspDkgCreateDealingError::UnsupportedAlgorithmId(other)),
        }
    }

    /// Creates a CSP dealing by resharing a previous secret key
    fn create_resharing_dealing(
        &self,
        algorithm_id: AlgorithmId,
        dkg_id: NiDkgId,
        dealer_resharing_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<CspNiDkgDealing, ni_dkg_errors::CspDkgCreateReshareDealingError> {
        debug!(self.logger; crypto.method_name => "create_resharing_dealing", crypto.dkg_epoch => epoch.get());
        // Get state
        // Fetch secret key corresponding to the resharing_public_coefficients from the
        // Secret Key Store.
        let resharing_secret_key = {
            let key_id = key_id_from_csp_pub_coeffs(&resharing_public_coefficients);
            let secret_key: Option<CspSecretKey> = self.sks_read_lock().get(&key_id);
            secret_key.ok_or_else(|| {
                ni_dkg_errors::CspDkgCreateReshareDealingError::ReshareKeyNotInSecretKeyStoreError(
                    ni_dkg_errors::KeyNotFoundError {
                        internal_error: format!(
                            "Cannot find threshold key to be reshared:\n  Dkg: {}\n  Epoch:  {}",
                            dkg_id, epoch
                        ),
                        key_id,
                    },
                )
            })
        }?;
        // Specialisation to this scheme:
        match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                let resharing_secret_key = specialise::groth20::threshold_secret_key(
                    resharing_secret_key,
                )
                .map_err(
                    ni_dkg_errors::CspDkgCreateReshareDealingError::MalformedReshareSecretKeyError,
                )?;
                let receiver_keys = specialise::groth20::receiver_keys(&receiver_keys).map_err(
                    |(receiver_index, error)| {
                        ni_dkg_errors::CspDkgCreateReshareDealingError::MalformedFsPublicKeyError {
                            receiver_index,
                            error,
                        }
                    },
                )?;
                // Stateless call to crypto lib
                // Acquire an rng lock and generate randomness before invoking create_dealing
                // because:
                // * acquiring two locks inline in the create_dealing call would lead to a
                //   deadlock.
                // * we should not hold the write lock for the whole duration of create_dealing.
                let (keygen_seed, encryption_seed) = {
                    let mut rng = self.rng_write_lock();
                    (rng.gen::<[u8; 32]>(), rng.gen::<[u8; 32]>())
                };
                let dealing = clib::create_dealing(
                    Randomness::from(keygen_seed),
                    Randomness::from(encryption_seed),
                    threshold,
                    &receiver_keys,
                    epoch,
                    dealer_resharing_index,
                    Some(resharing_secret_key),
                )?;
                // Response
                Ok(CspNiDkgDealing::Groth20_Bls12_381(dealing))
            }
            other => {
                Err(ni_dkg_errors::CspDkgCreateReshareDealingError::UnsupportedAlgorithmId(other))
            }
        }
    }

    /// Verify a CSP dealing
    fn verify_dealing(
        &self,
        algorithm_id: AlgorithmId,
        dkg_id: NiDkgId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        dealing: CspNiDkgDealing,
    ) -> Result<(), ni_dkg_errors::CspDkgVerifyDealingError> {
        static_api::verify_dealing(
            algorithm_id,
            dkg_id,
            dealer_index,
            threshold,
            epoch,
            receiver_keys,
            dealing,
        )
    }

    /// Verify a resharing dealing
    fn verify_resharing_dealing(
        &self,
        algorithm_id: AlgorithmId,
        dkg_id: NiDkgId,
        dealer_resharing_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        dealing: CspNiDkgDealing,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<(), ni_dkg_errors::CspDkgVerifyReshareDealingError> {
        static_api::verify_resharing_dealing(
            algorithm_id,
            dkg_id,
            dealer_resharing_index,
            threshold,
            epoch,
            receiver_keys,
            dealing,
            resharing_public_coefficients,
        )
    }

    /// Create a CSP transcript from CSP dealings
    fn create_transcript(
        &self,
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        number_of_receivers: NumberOfNodes,
        csp_dealings: BTreeMap<NodeIndex, CspNiDkgDealing>,
    ) -> Result<CspNiDkgTranscript, ni_dkg_errors::CspDkgCreateTranscriptError> {
        static_api::create_transcript(algorithm_id, threshold, number_of_receivers, csp_dealings)
    }

    ///Create a CSP transcript from CSP resharing dealings
    fn create_resharing_transcript(
        &self,
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        number_of_receivers: NumberOfNodes,
        csp_dealings: BTreeMap<NodeIndex, CspNiDkgDealing>,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<CspNiDkgTranscript, ni_dkg_errors::CspDkgCreateReshareTranscriptError> {
        static_api::create_resharing_transcript(
            algorithm_id,
            threshold,
            number_of_receivers,
            csp_dealings,
            resharing_public_coefficients,
        )
    }

    /// Derives the threshold signing key share and loads it into the Secret Key
    /// Store
    fn load_threshold_signing_key(
        &self,
        algorithm_id: AlgorithmId,
        _dkg_id: NiDkgId,
        epoch: Epoch,
        csp_transcript: CspNiDkgTranscript,
        receiver_index: NodeIndex,
    ) -> Result<(), ni_dkg_errors::CspDkgLoadPrivateKeyError> {
        debug!(self.logger; crypto.method_name => "load_threshold_signing_key", crypto.dkg_epoch => epoch.get());
        match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                let threshold_key_id =
                    key_id_from_csp_pub_coeffs(&CspPublicCoefficients::from(&csp_transcript));

                // Convert types
                let transcript = specialise::groth20::transcript(csp_transcript)
                    .map_err(ni_dkg_errors::CspDkgLoadPrivateKeyError::MalformedTranscriptError)?;

                // Check if threshold key has been computed already
                let threshold_secret_key: Option<CspSecretKey> =
                    self.sks_read_lock().get(&threshold_key_id);
                if let Some(secret_key) = threshold_secret_key {
                    // this adds a sanity check to ensure the key is well formed:
                    return specialise::groth20::threshold_secret_key(secret_key)
                        .map(|_| ())
                        .map_err(
                            ni_dkg_errors::CspDkgLoadPrivateKeyError::MalformedSecretKeyError,
                        );
                }

                // Compute the key
                let fs_decryption_key = {
                    let key_id = self.dkg_dealing_encryption_key_id();
                    let key_set = self.sks_read_lock().get(&key_id).ok_or_else(||
                      ni_dkg_errors::CspDkgLoadPrivateKeyError::KeyNotFoundError( // TODO (CRP-820): This name is inconsistent with the other error enums, where this is now called FsKeyNotInSecretKeyStoreError or some such paragraph-of-a-name.
                        ni_dkg_errors::KeyNotFoundError {
                          internal_error: "Cannot decrypt shares if the forward secure key encryption key is missing".to_string(),
                          key_id,
                        },
                      )
                    )?;

                    let raw_fs_key_set =
                        specialise::groth20::fs_key_set(
                            specialise::fs_key_set(key_set).expect("Not a forward secure secret key; it should be impossible to retrieve a key of the wrong type.")
                        ).expect("If key generation is correct, it should be impossible to retrieve a key of the wrong type.");

                    trusted_secret_key_into_miracl(&raw_fs_key_set.secret_key)
                };

                let csp_secret_key = clib::compute_threshold_signing_key(
                    &transcript,
                    receiver_index,
                    &fs_decryption_key,
                    epoch,
                )
                .map(CspSecretKey::ThresBls12_381)?;

                match self.sks_write_lock().insert(
                    threshold_key_id,
                    csp_secret_key,
                    Some(NIDKG_THRESHOLD_SCOPE),
                ) {
                    Ok(()) => Ok(()),
                    Err(SecretKeyStoreError::DuplicateKeyId(_key_id)) => Ok(()),
                }
            }
            other => Err(ni_dkg_errors::CspDkgLoadPrivateKeyError::UnsupportedAlgorithmId(other)),
        }
    }

    fn retain_threshold_keys_if_present(&self, active_keys: BTreeSet<CspPublicCoefficients>) {
        debug!(self.logger; crypto.method_name => "retain_threshold_keys_if_present");
        let active_key_ids: BTreeSet<KeyId> =
            active_keys.iter().map(key_id_from_csp_pub_coeffs).collect();
        self.sks_write_lock().retain(
            |key_id, _| active_key_ids.contains(key_id),
            NIDKG_THRESHOLD_SCOPE,
        )
    }
}

pub mod static_api {
    //! Some methods are non-static purely due to the way the mock framework is
    //! used by callers.  The following are the true, static versions of those
    //! API methods.
    use super::*;

    /// Verifies that a forward secure public key and PoP are valid.
    pub fn verify_forward_secure_key(
        algorithm_id: AlgorithmId,
        public_key: CspFsEncryptionPublicKey,
        pop: CspFsEncryptionPop,
        node_id: NodeId,
    ) -> Result<(), ni_dkg_errors::CspDkgVerifyFsKeyError> {
        // Specialisation to this scheme:
        match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                // Specialise:
                let public_key = specialise::groth20::fs_public_key(public_key)
                    .map_err(ni_dkg_errors::CspDkgVerifyFsKeyError::MalformedPublicKeyError)?;
                let fs_pop = specialise::groth20::fs_pop(pop)
                    .map_err(ni_dkg_errors::CspDkgVerifyFsKeyError::MalformedPopError)?;

                // Call lib:
                clib::verify_forward_secure_key(&public_key, &fs_pop, node_id.get().as_slice())
                    .map_err(ni_dkg_errors::CspDkgVerifyFsKeyError::InvalidPop)
            }
            other => Err(ni_dkg_errors::CspDkgVerifyFsKeyError::UnsupportedAlgorithmId(other)),
        }
    }

    /// Verifies a CSP dealing
    pub fn verify_dealing(
        algorithm_id: AlgorithmId,
        dkg_id: NiDkgId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        dealing: CspNiDkgDealing,
    ) -> Result<(), ni_dkg_errors::CspDkgVerifyDealingError> {
        match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                // Specialisation to this scheme:
                let dealing = specialise::groth20::dealing(dealing)
                    .map_err(ni_dkg_errors::CspDkgVerifyDealingError::MalformedDealingError)?;
                let receiver_keys = specialise::groth20::receiver_keys(&receiver_keys).map_err(
                    |(receiver_index, error)| {
                        ni_dkg_errors::CspDkgVerifyDealingError::MalformedFsPublicKeyError {
                            receiver_index,
                            error,
                        }
                    },
                )?;
                // Call the specialised library method:
                clib::verify_dealing(
                    dkg_id,
                    dealer_index,
                    threshold,
                    epoch,
                    &receiver_keys,
                    &dealing,
                )
            }
            other => Err(ni_dkg_errors::CspDkgVerifyDealingError::UnsupportedAlgorithmId(other)),
        }
    }

    /// Verifies a CSP resharing
    #[allow(clippy::too_many_arguments)]
    pub fn verify_resharing_dealing(
        algorithm_id: AlgorithmId,
        dkg_id: NiDkgId,
        dealer_resharing_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        dealing: CspNiDkgDealing,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<(), ni_dkg_errors::CspDkgVerifyReshareDealingError> {
        match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                // Specialisation to this scheme:
                let dealing = specialise::groth20::dealing(dealing).map_err(
                    ni_dkg_errors::CspDkgVerifyReshareDealingError::MalformedDealingError,
                )?;
                let receiver_keys = specialise::groth20::receiver_keys(&receiver_keys).map_err(
                    |(receiver_index, error)| {
                        ni_dkg_errors::CspDkgVerifyDealingError::MalformedFsPublicKeyError {
                            receiver_index,
                            error,
                        }
                    },
                )?;
                let resharing_public_coefficients =
                    specialise::groth20::public_coefficients(resharing_public_coefficients)
                        .map_err(
                            ni_dkg_errors::CspDkgVerifyReshareDealingError::MalformedResharePublicCoefficientsError,
                        )?;
                // Call the specialised library method:
                clib::verify_resharing_dealing(
                    dkg_id,
                    dealer_resharing_index,
                    threshold,
                    epoch,
                    &receiver_keys,
                    &dealing,
                    &resharing_public_coefficients,
                )
                .map_err(ni_dkg_errors::CspDkgVerifyReshareDealingError::from)
            }
            other => {
                Err(ni_dkg_errors::CspDkgVerifyReshareDealingError::UnsupportedAlgorithmId(other))
            }
        }
    }

    /// Create a CSP transcript from CSP dealings
    pub fn create_transcript(
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        number_of_receivers: NumberOfNodes,
        csp_dealings: BTreeMap<NodeIndex, CspNiDkgDealing>,
    ) -> Result<CspNiDkgTranscript, ni_dkg_errors::CspDkgCreateTranscriptError> {
        match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                // Specialise:
                let csp_dealings = specialise::groth20::dealings(csp_dealings).map_err(
                    |(dealer_index, error)| {
                        ni_dkg_errors::CspDkgCreateTranscriptError::InvalidDealingError {
                            dealer_index,
                            error,
                        }
                    },
                )?;
                // Call the specialised library method:
                let transcript =
                    clib::create_transcript(threshold, number_of_receivers, &csp_dealings)?;
                // Generalise:
                let transcript = CspNiDkgTranscript::Groth20_Bls12_381(transcript);
                Ok(transcript)
            }
            other => Err(ni_dkg_errors::CspDkgCreateTranscriptError::UnsupportedAlgorithmId(other)),
        }
    }

    /// Create a CSP transcript from CSP dealings
    pub fn create_resharing_transcript(
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        number_of_receivers: NumberOfNodes,
        csp_dealings: BTreeMap<NodeIndex, CspNiDkgDealing>,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<CspNiDkgTranscript, ni_dkg_errors::CspDkgCreateReshareTranscriptError> {
        match algorithm_id {
            AlgorithmId::NiDkg_Groth20_Bls12_381 => {
                // Specialise:
                let csp_dealings = specialise::groth20::dealings(csp_dealings).map_err(
                    |(dealer_index, error)| {
                        ni_dkg_errors::CspDkgCreateReshareTranscriptError::InvalidDealingError {
                            dealer_index,
                            error,
                        }
                    },
                )?;
                let resharing_public_coefficients = specialise::groth20::public_coefficients(
            resharing_public_coefficients,
        )
        .map_err(ni_dkg_errors::CspDkgCreateReshareTranscriptError::MalformedResharePublicCoefficientsError)?;
                // Static call:
                let transcript = clib::create_resharing_transcript(
                    threshold,
                    number_of_receivers,
                    &csp_dealings,
                    &resharing_public_coefficients,
                )?;
                // Generalise
                let transcript = CspNiDkgTranscript::Groth20_Bls12_381(transcript);
                Ok(transcript)
            }
            other => Err(
                ni_dkg_errors::CspDkgCreateReshareTranscriptError::UnsupportedAlgorithmId(other),
            ),
        }
    }
}

pub mod specialise {
    //! The API methods sometimes take multiple arguments, but those
    //! arguments must be of compatible types.
    //!
    //! Potential strategies for dealing with the potential error of
    //! incompatible types:
    //! * Give the caller the problem of using the correct types:
    //!   * Tag types with the scheme they are to be used with.  E.g.
    //!     FsEncryptionPublicKey<Groth20>.
    //!     * Con: It prevents one type from being used in multiple schemes.
    //!       Perhaps the caller could do type conversion and we would have
    //!       alist of legal conversions.
    //!   * Make every method take a single argument; an enum of structs, each
    //!     struct corresponding to a scheme.
    //!   * Con: If the caller is to be responsible for ensuring that types are
    //!     correct, the caller needs to be aware of the difference between
    //!     different schemes, however it is an explicit design goal that the
    //!     IDKM and above should be unaware of algorithm changes.  It seems
    //!     that the caller cannot be made responsible for providing the correct
    //!     type variants.
    //! * Deal with the type conversion ourselves:
    //!   * Pro: Simplifies life for the caller
    //!   * Con: Makes no real attempt to design errors out of existence, if
    //!     that is possible in this case.
    //!
    //! We choose to deal with the type conversion internally.  These
    //! are the type conversions, or to be more specific,
    //! type specialisations:
    use super::*;
    use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381 as g20_internal_types;

    /// An error during specialisation
    #[derive(Debug)]
    pub struct SpecialisationError {
        unexpected_type_name: &'static str,
    }

    /// Converts a secret key into a forward secure secret key set.
    ///
    /// # Errors
    /// This returns an error if the secret key is not forward secure.
    pub fn fs_key_set(
        secret_key: CspSecretKey,
    ) -> Result<CspFsEncryptionKeySet, ni_dkg_errors::MalformedSecretKeyError> {
        if let CspSecretKey::FsEncryption(key_set) = secret_key {
            Ok(key_set)
        } else {
            let unexpected_type_name: &'static str = secret_key.into();
            Err(ni_dkg_errors::MalformedSecretKeyError {
                algorithm: AlgorithmId::Placeholder, // There is no on expected algorithm ID.
                internal_error: format!("Unexpected variant: {}", unexpected_type_name),
            })
        }
    }

    pub mod groth20 {
        //! Type specialisations for the NiDkg_Groth20 scheme.
        use super::*;
        use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;

        const ALGORITHM_ID: AlgorithmId = AlgorithmId::NiDkg_Groth20_Bls12_381;

        /// Converts a threshold secret key to the variant used by
        /// NiDkg_Groth20.
        ///
        /// # Errors
        /// This returns an error if the type variant is not that used
        /// in NiDkg_Groth20.
        pub fn threshold_secret_key(
            secret_key: CspSecretKey,
        ) -> Result<threshold_types::SecretKeyBytes, ni_dkg_errors::MalformedSecretKeyError>
        {
            if let CspSecretKey::ThresBls12_381(secret_key) = secret_key {
                Ok(secret_key)
            } else {
                let unexpected_type_name: &'static str = secret_key.into();
                Err(ni_dkg_errors::MalformedSecretKeyError {
                    algorithm: ALGORITHM_ID,
                    internal_error: format!("Unexpected key type: {}", unexpected_type_name),
                })
            }
        }

        /// Note: We use the CSP equivalent of the
        /// g20_internal_types::PublicCoefficientsBytes.
        pub fn public_coefficients(
            public_coefficients: CspPublicCoefficients,
        ) -> Result<PublicCoefficientsBytes, ni_dkg_errors::MalformedPublicKeyError> {
            let CspPublicCoefficients::Bls12_381(public_coefficients) = public_coefficients;
            Ok(public_coefficients)
        }

        /// Converts a forward secure public key to the variant used by
        /// NiDkg_Groth20.
        ///
        /// # Errors
        /// This returns an error if the type variant is not that used
        /// in NiDkg_Groth20.
        #[allow(irrefutable_let_patterns)] // There is currently only one version of DKG.
        pub fn fs_public_key(
            fs_public_key: CspFsEncryptionPublicKey,
        ) -> Result<g20_internal_types::FsEncryptionPublicKey, ni_dkg_errors::MalformedPublicKeyError>
        {
            if let CspFsEncryptionPublicKey::Groth20_Bls12_381(fs_public_key) = fs_public_key {
                Ok(fs_public_key)
            } else {
                let unexpected_type_name: &'static str = fs_public_key.into();
                Err(ni_dkg_errors::MalformedPublicKeyError {
                    algorithm: ALGORITHM_ID,
                    key_bytes: None,
                    internal_error: format!("Unexpected key type: {}", unexpected_type_name),
                })
            }
        }

        /// Converts a proof of possession for a forward secure key to the
        /// variant used by NiDkg_Groth20.
        ///
        /// # Errors
        /// This returns an error if the type variant is not that used
        /// in NiDkg_Groth20.
        #[allow(irrefutable_let_patterns)] // There is currently only one version of NiDKG.
        pub fn fs_pop(
            pop: CspFsEncryptionPop,
        ) -> Result<g20_internal_types::FsEncryptionPop, ni_dkg_errors::MalformedPopError> {
            if let CspFsEncryptionPop::Groth20WithPop_Bls12_381(fs_pop) = pop {
                Ok(fs_pop)
            } else {
                let unexpected_type_name: &'static str = pop.into();
                Err(ni_dkg_errors::MalformedPopError {
                    algorithm: ALGORITHM_ID,
                    internal_error: format!("Unexpected variant: {}", unexpected_type_name),
                    bytes: None,
                })
            }
        }

        /// Converts a secret key set to the variant used by NiDkg_Groth20.
        ///
        /// # Errors
        /// This returns an error if the type variant is not that used
        /// in NiDkg_Groth20.
        #[allow(irrefutable_let_patterns)] // There is currently only one version of NiDKG.
        pub fn fs_key_set(
            key_set: CspFsEncryptionKeySet,
        ) -> Result<clib::types::FsEncryptionKeySetWithPop, ni_dkg_errors::MalformedSecretKeyError>
        {
            if let CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(key_set) = key_set {
                Ok(key_set)
            } else {
                let unexpected_type_name: &'static str = key_set.into();
                Err(ni_dkg_errors::MalformedSecretKeyError {
                    algorithm: ALGORITHM_ID,
                    internal_error: format!("Unexpected variant: {}", unexpected_type_name),
                })
            }
        }

        /// Converts a map of generic public keys to the variant used by
        /// NiDkg_Groth20.
        ///
        /// # Errors
        /// This returns an error if at least one of the public keys is
        /// not of the type expected by NiDkg_Groth20.
        pub fn receiver_keys(
            receiver_keys: &BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        ) -> Result<
            BTreeMap<NodeIndex, g20_internal_types::FsEncryptionPublicKey>,
            (NodeIndex, ni_dkg_errors::MalformedPublicKeyError),
        > {
            receiver_keys
                .iter()
                .map(|(node_index, public_key)| {
                    fs_public_key(*public_key)
                        .map(|public_key| (*node_index, public_key))
                        .map_err(|error| (*node_index, error))
                })
                .collect()
        }

        /// Converts a generic dealing to the variant used by NiDkg_Groth20.
        #[allow(irrefutable_let_patterns)]
        pub fn dealing(
            dealing: CspNiDkgDealing,
        ) -> Result<g20_internal_types::Dealing, ni_dkg_errors::InvalidArgumentError> {
            if let CspNiDkgDealing::Groth20_Bls12_381(dealing) = dealing {
                Ok(dealing)
            } else {
                let variant_name: &'static str = dealing.into();
                Err(ni_dkg_errors::InvalidArgumentError {
                    message: format!("Unexpected dealing variant: {}", variant_name),
                })
            }
        }

        /// Converts a map of generic dealings to the variant used by
        /// NiDkg_Groth20.
        pub fn dealings(
            dealings: BTreeMap<NodeIndex, CspNiDkgDealing>,
        ) -> Result<
            BTreeMap<NodeIndex, g20_internal_types::Dealing>,
            (NodeIndex, ni_dkg_errors::InvalidArgumentError),
        > {
            dealings
                .into_iter()
                .map(|(node_index, csp_dealing)| {
                    let dealing = dealing(csp_dealing).map_err(|error| (node_index, error))?;
                    Ok((node_index, dealing))
                })
                .collect()
        }

        /// Note: We use the CSP equivalent of the
        /// g20_internal_types::PublicCoefficientsBytes.
        pub fn transcript(
            transcript: CspNiDkgTranscript,
        ) -> Result<g20_internal_types::Transcript, ni_dkg_errors::MalformedDataError> {
            let CspNiDkgTranscript::Groth20_Bls12_381(transcript) = transcript;
            Ok(transcript)
        }
    }
}
