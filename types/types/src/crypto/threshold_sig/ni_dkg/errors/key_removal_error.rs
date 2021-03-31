use crate::crypto::error::KeyNotFoundError;
use crate::crypto::threshold_sig::ni_dkg::errors::transcripts_to_retain_validation_error::TranscriptsToRetainValidationError;
use crate::crypto::threshold_sig::ni_dkg::errors::{
    FsEncryptionPublicKeyNotInRegistryError, MalformedFsEncryptionPublicKeyError,
};
use crate::registry::RegistryClientError;
use std::fmt;
use std::fmt::Formatter;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DkgKeyRemovalError {
    InputValidationError(TranscriptsToRetainValidationError),
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
