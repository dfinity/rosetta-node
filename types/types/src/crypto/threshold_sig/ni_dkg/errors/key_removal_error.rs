use crate::crypto::error::KeyNotFoundError;
use crate::crypto::threshold_sig::ni_dkg::errors::{
    current_and_next_transcripts_validation_error::CurrentAndNextTranscriptsValidationError,
    FsEncryptionPublicKeyNotInRegistryError, MalformedFsEncryptionPublicKeyError,
};
use crate::registry::RegistryClientError;
use std::fmt;
use std::fmt::Formatter;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DkgKeyRemovalError {
    InputValidationError(CurrentAndNextTranscriptsValidationError),
    FsEncryptionPublicKeyNotInRegistry(FsEncryptionPublicKeyNotInRegistryError),
    MalformedFsEncryptionPublicKey(MalformedFsEncryptionPublicKeyError),
    Registry(RegistryClientError),
    FsKeyNotInSecretKeyStoreError(KeyNotFoundError),
}

impl fmt::Display for DkgKeyRemovalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // TODO (CRP-665): implement display and debug
        write!(f, "{:?}", &self)
    }
}
