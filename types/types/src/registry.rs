// We disable the clippy warning for the whole module because they apply to
// generated code, meaning we can't locally disable the warnings (the code is
// defined in another module). https://dfinity.atlassian.net/browse/DFN-467
#![allow(clippy::redundant_closure)]

use crate::crypto::{AlgorithmId, KeyId, KeyPurpose};
use crate::{time, NodeId, RegistryVersion};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::result::Result;
use std::str::FromStr;
use thiserror::Error;

#[cfg(test)]
use proptest::prelude::{any, Strategy};
#[cfg(test)]
use proptest_derive::Arbitrary;

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct TimeRecord {
    #[cfg_attr(
        test,
        proptest(strategy = "any::<u64>().prop_map(|x| RegistryVersion::from(x))")
    )]
    pub version: RegistryVersion,
    #[cfg_attr(
        test,
        proptest(strategy = "any::<std::time::Duration>().prop_map(|x| time::UNIX_EPOCH + x)")
    )]
    pub time: time::Time,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
// Disabled until phantom newtype issues are fixed:
//#[cfg_attr(test, derive(Arbitrary))]
//#[proptest(filter="|x| x.valid_thru.map_or(true, |thru| x.valid_from<thru)")]
pub struct PublicKeyRegistryRecord {
    pub node_id: NodeId,
    pub key_purpose: KeyPurpose,
    pub key: Vec<u8>,
    pub key_id: KeyId,
    pub algorithm_id: AlgorithmId,
    pub version: RegistryVersion,
    //pub custodian: (NodeId, KeyPurpose),
}

// FromStr implementation for the the registry admin tool.
impl FromStr for KeyPurpose {
    type Err = String;

    fn from_str(string: &str) -> Result<Self, <Self as FromStr>::Err> {
        match string {
            "node_signing" => Ok(KeyPurpose::NodeSigning),
            "query_response_signing" => Ok(KeyPurpose::QueryResponseSigning),
            "dkg_dealing_encryption" => Ok(KeyPurpose::DkgDealingEncryption),
            "committee_signing" => Ok(KeyPurpose::CommitteeSigning),
            _ => Err(format!("Invalid key purpose: {:?}", string)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryError {
    /// Requested registry version is older than minimum known version.
    VersionTooOld {
        min: RegistryVersion,
        max: RegistryVersion,
        requested: RegistryVersion,
    },
    /// Requested registry version is newer than maximum known version.
    VersionTooNew {
        min: RegistryVersion,
        max: RegistryVersion,
        requested: RegistryVersion,
    },
    /// Duplicate registry key at given registry version.
    DuplicateKey {
        kind: String,
        key: String,
        version: RegistryVersion,
    },
    /// Indicates a configuration error. Should contain a human readable
    /// description of the cause.
    Unreadable(String),
    /// Validation error when deserializing registry. Optionally wraps a source
    /// `RegistryError` for more detail.
    ValidationError {
        message: String,
        source: Option<Box<RegistryError>>,
    },
}

impl std::error::Error for RegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RegistryError::ValidationError {
                source: Some(source),
                ..
            } => Some(source),
            _ => None,
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::VersionTooOld {
                min,
                max,
                requested,
            } => write!(
                f,
                "Requested registry version {} is too old. Known versions: [{}, {}).",
                requested, min, max
            ),

            RegistryError::VersionTooNew {
                min,
                max,
                requested,
            } => write!(
                f,
                "Requested registry version {} is too new. Known versions: [{}, {}).",
                requested, min, max
            ),

            RegistryError::DuplicateKey { kind, key, version } => write!(
                f,
                "Duplicate {} registry entry for key {:?} at version {}.",
                kind, key, version
            ),

            RegistryError::Unreadable(s) => write!(f, "Registry could not be read: {:?}", s),

            RegistryError::ValidationError {
                message,
                source: Some(source),
            } => write!(f, "Invalid registry: {}: {}", message, *source),
            RegistryError::ValidationError {
                message,
                source: None,
            } => write!(f, "Invalid registry: {}", message),
        }
    }
}

impl RegistryError {
    pub fn is_version_too_old(&self) -> bool {
        match self {
            RegistryError::VersionTooOld { .. } => true,
            _ => false,
        }
    }

    pub fn is_version_too_new(&self) -> bool {
        match self {
            RegistryError::VersionTooNew { .. } => true,
            _ => false,
        }
    }

    pub fn is_duplicate_key(&self) -> bool {
        match self {
            RegistryError::DuplicateKey { .. } => true,
            _ => false,
        }
    }

    pub fn is_validation_error(&self) -> bool {
        match self {
            RegistryError::ValidationError { .. } => true,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryDataProviderError {
    /// Timeout occurred when attempting to fetch updates from the registry
    /// canister.
    Timeout,
    /// Error when using registry transfer
    Transfer {
        source: ic_registry_transport::Error,
    },
}

impl std::error::Error for RegistryDataProviderError {}

impl fmt::Display for RegistryDataProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryDataProviderError::Timeout => write!(f, "Registry transport client timed out."),
            RegistryDataProviderError::Transfer { source } => write!(
                f,
                "Registry transport client failed to fetch registry update from registry canister: {}", source
            ),
        }
    }
}

#[derive(Error, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryClientError {
    #[error("the requested version is not available locally: {version:}")]
    VersionNotAvailable { version: RegistryVersion },

    #[error("failed to query data provider: {source:}")]
    DataProviderQueryFailed {
        #[from]
        source: RegistryDataProviderError,
    },

    #[error("failed to acquire poll lock: {error:}")]
    PollLockFailed {
        // Ideally this would be a TryLockError, but that takes a type parameter
        // which 'infects' this enum, and everything that uses it.
        error: String,
    },
}
