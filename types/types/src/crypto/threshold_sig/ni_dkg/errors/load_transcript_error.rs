use crate::crypto::error::InvalidArgumentError;
use crate::crypto::threshold_sig::ni_dkg::errors::FsEncryptionPublicKeyNotInRegistryError;
use crate::registry::RegistryClientError;
use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DkgLoadTranscriptError {
    FsEncryptionPublicKeyNotInRegistry(FsEncryptionPublicKeyNotInRegistryError),
    Registry(RegistryClientError),
    InvalidTranscript(InvalidArgumentError),
    // Reminder: document error definition changes on `NiDkgAlgorithm::load_transcript`.
}

impl fmt::Display for DkgLoadTranscriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = "Failed to load transcript: ";
        match self {
            DkgLoadTranscriptError::Registry(error) => write!(f, "{}{}", prefix, error),
            DkgLoadTranscriptError::FsEncryptionPublicKeyNotInRegistry(error) => {
                write!(f, "{}{}", prefix, error)
            }
            DkgLoadTranscriptError::InvalidTranscript(error) => write!(f, "{}{}", prefix, error),
        }
    }
}
