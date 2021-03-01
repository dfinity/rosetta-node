use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgConfig;
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_dealing_error::DkgCreateDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_transcript_error::DkgCreateTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::key_removal_error::DkgKeyRemovalError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::load_transcript_error::DkgLoadTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgDealing, NiDkgTag, NiDkgTranscript};
use ic_types::NodeId;
use std::collections::BTreeMap;

/// The building blocks to perform non-interactive distributed key generation
/// (DKG).
///
/// There are two variants of DKG that are supported:
///
/// # (Non-Resharing) DKG
/// In the standard DKG, the group public key changes in every DKG epoch.
///
/// To run this variant of DKG, always use a `NiDkgConfig` that has
/// `resharing_transcript = None`.
///
/// # Resharing DKG
/// In resharing DKG, the group public key remains the same, as opposed to
/// changing in every DKG epoch.
///
/// To run non-resharing DKG, proceed as follows:
/// * In the first epoch, run (non-resharing) DKG using a `NiDkgConfig` that has
///   `resharing_transcript = None`.
/// * With the resulting `NiDkgTranscript`, re-sharing DKG can be run repeatedly
///   by using a `NiDkgConfig` that has `resharing_transcript =
///   Some(transcript)`, where transcript is the `NiDkgTranscript` from the
///   previous DKG epoch.
///
/// # Preconditions
/// * For a fixed `NiDkgId`, the `NiDkgConfig` must never change. That is, if
///   two calls to methods of `NiDkgAlgorithm` are made with `NiDkgConfig`
///   values `config1` and `config2` respectively, then if `config1.dkg_id ==
///   config2.dkg_id`, we must have `config1 == config2`.
pub trait NiDkgAlgorithm {
    /// Creates a non-interactive DKG dealing.
    ///
    /// # Errors
    /// * `DkgCreateDealingError::InvalidTranscript` if the
    ///   `resharing_transcript` in the `config` cannot be parsed.
    /// * `DkgCreateDealingError::NotADealer` if the `self.node_id` is not
    ///   contained in the `config`'s dealers.
    /// * `DkgCreateDealingError::FsEncryptionPublicKeyNotInRegistry` if a
    ///   forward secure encryption public key is not in the registry.
    /// * `DkgCreateDealingError::Registry` if the registry client returns an
    ///   error, e.g. because the `registry_version` in the `config` is not
    ///   available.
    /// * `DkgCreateDealingError::MalformedFsEncryptionPublicKey` if the
    ///   encryption public key fetched from the registry is malformed.
    /// * `DkgCreateDealingError::FsDecryptionKeyNotInSecretKeyStore` if the
    ///   forward secure decryption key is not in the secret key store.
    fn create_dealing(&self, config: &NiDkgConfig) -> Result<NiDkgDealing, DkgCreateDealingError>;

    /// Verifies a non-interactive DKG dealing.
    ///
    /// # Errors
    /// * `DkgVerifyDealingError::InvalidDealingError` if the dealing is
    ///   invalid.
    /// * `DkgVerifyDealingError::NotADealer` if the `dealer` is not contained
    ///   in the `config`'s dealers.
    /// * `DkgVerifyDealingError::FsEncryptionPublicKeyNotInRegistry` if a
    ///   forward secure encryption public key is not in the registry.
    /// * `DkgVerifyDealingError::Registry` if the registry client returns an
    ///   error, e.g. because the `registry_version` in the `config` is not
    ///   available.
    /// * `DkgVerifyDealingError::MalformedFsEncryptionPublicKey` if the
    ///   encryption public key fetched from the registry is malformed.
    /// * `DkgVerifyDealingError::MalformedResharingTranscriptInConfig` if the
    ///   `resharing_transcript` in the `config` is malformed.
    fn verify_dealing(
        &self,
        config: &NiDkgConfig,
        dealer: NodeId,
        dealing: &NiDkgDealing,
    ) -> Result<(), DkgVerifyDealingError>;

    /// Combines the dealings into a transcript.
    ///
    /// # Preconditions
    /// * For each `(dealer, dealing)` in `verified_dealings`, it holds that
    ///   `verify_dealing(config, dealer, dealing).is_ok()`
    ///
    /// # Errors
    /// * `DkgCreateTranscriptError::InsufficientDealings` if
    ///   `verified_dealings` contains an insufficient number of dealings.
    /// * `DkgCreateTranscriptError::MalformedResharingTranscriptInConfig` if
    ///   the `config` contains a malformed `resharing_transcript`.
    ///
    /// # Panics
    /// * if a dealing is invalid. This is a precondition violation, see the
    ///   precondition above. Note that this method does not perform a complete
    ///   dealing validation as performed by 'verify_dealing'.
    /// * if there are dealings in `verified_dealings` for `NodeId`s that are
    ///   not in the `config`'s dealers. As above, this is a precondition
    ///   violation since that dealing could not have been verified
    ///   successfully.
    fn create_transcript(
        &self,
        config: &NiDkgConfig,
        verified_dealings: &BTreeMap<NodeId, NiDkgDealing>,
    ) -> Result<NiDkgTranscript, DkgCreateTranscriptError>;

    /// Loads the transcript. This ensures that
    /// * the (group's) public threshold signing key is available for the
    ///   methods of the `ThresholdSigVerifier` trait, and
    /// * the individual nodes' public threshold signing keys are available for
    ///   the methods of the `ThresholdSigVerifier` trait, and
    /// * if the node is a receiver and the node's forward secure decryption key
    ///   is present in the secret key store, the node's secret threshold
    ///   signing key is available for the methods of the `ThresholdSigner`
    ///   trait for the DKG instance identified by the DKG ID contained in the
    ///   transcript.
    ///
    /// # Errors
    /// * `DkgLoadTranscriptError::FsEncryptionPublicKeyNotInRegistry` if a
    ///   forward secure encryption public key is not in the registry.
    /// * `DkgLoadTranscriptError::MalformedFsEncryptionPublicKey` if a
    ///   encryption public key fetched from the registry is malformed.
    /// * `DkgLoadTranscriptError::Registry` if the registry client returns an
    ///   error, e.g. because the registry version is not available.
    /// * `DkgLoadTranscriptError::InvalidTranscript` if the transcript could
    ///   not be parsed.
    fn load_transcript(&self, transcript: &NiDkgTranscript) -> Result<(), DkgLoadTranscriptError>;

    /// Retains only keys for the current and next transcripts.
    ///
    /// This ensures that any other keys are no longer stored in the Secret Key
    /// Store. It ensures the following:
    /// * The only threshold signing keys in the store are the ones for
    ///   `transcript.dkg_id` for any `transcript` in `current_transcripts` or
    ///   `next_transcripts`.
    /// * The decryption key of the FS encryption keys is updated to the epoch
    ///   `epoch:= min(current_transcripts.get(LowThreshold).registry_version,
    ///   current_transcripts.get(HighThreshold).registry_version)`. Decryption
    ///   can no longer be performed on earlier epochs. This means that it
    ///   should still be possible to decrypt the signing keys for the current
    ///   and next transcripts.
    ///
    /// # Errors:
    /// * `DkgKeyRemovalError::InputValidationError`: if any of the invariants
    ///   of the constructor of `CurrentAndNextTranscripts` fails.
    /// * `DkgKeyRemovalError::FsEncryptionPublicKeyNotInRegistry`,
    ///   `DkgKeyRemovalError::MalformedFsEncryptionPublicKey`, or
    ///   `DkgKeyRemovalError::Registry`: If the FS encryption public key stored
    ///   for the node in the registry at version
    ///   `version=min(current_transcripts.get(LowThreshold).registry_version,
    ///   current_transcripts.get(HighThreshold).registry_version)` cannot be
    ///   obtained or is malformed. In this case the FS decryption key is not
    ///   updated, but the removal of threshold signing keys is still ensured.
    /// * `FsKeyNotInSecretKeyStoreError::FsKeyNotInSecretKeyStoreError`: If the
    ///   forward secure key to be updated is not found in the secret key store.
    fn retain_only_active_keys_if_present(
        &self,
        current_transcripts: &BTreeMap<NiDkgTag, NiDkgTranscript>,
        next_transcripts: &BTreeMap<NiDkgTag, NiDkgTranscript>,
    ) -> Result<(), DkgKeyRemovalError>;
}
