use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
};

use anyhow::Result;
use gflags_derive::GFlags;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub(crate) mod local_store;
pub(crate) mod nns;

#[derive(Error, Debug)]
pub(crate) enum ConfigError {
    #[error(transparent)]
    NnsConfigurationFailed {
        #[from]
        source: nns::ConfigError,
    },

    #[error(transparent)]
    ConfigFileFailed {
        #[from]
        source: ConfigFileError,
    },

    #[error("either --nns_urls or --local_store_path is required")]
    ConfigMissing,
}

/// External configuration -- from a config file and/or flags.
#[derive(Clone, Debug, Default, Deserialize, Serialize, GFlags)]
#[serde(default)]
#[gflags(prefix = "_")]
pub(crate) struct Config {
    /// Path to configuration file to load
    #[gflags(placeholder = "PATH")]
    config_file: String,

    /// The registry nns_url configuration
    #[gflags(skip)]
    pub(crate) nns: nns::Config,

    /// The registry local store configuration
    #[gflags(skip)]
    pub(crate) local_store: local_store::Config,

    /// Registry version (default is to use the latest)
    #[gflags(type = "u64", placeholder = "RegistryVersion")]
    pub registry_version: Option<u64>,
}

impl Config {
    pub fn new() -> Result<Self, ConfigError> {
        let mut config = if CONFIG_FILE.is_present() {
            read_config_from_file(CONFIG_FILE.flag)?
        } else {
            Config::default()
        };

        if REGISTRY_VERSION.is_present() {
            config.registry_version = Some(REGISTRY_VERSION.flag);
        }

        config.nns = nns::from_flags(config.nns)?;
        config.local_store = local_store::from_flags();

        if config.nns.urls.is_empty() && config.local_store.path.as_os_str().is_empty() {
            return Err(ConfigError::ConfigMissing);
        }

        Ok(config)
    }
}

#[derive(Error, Debug)]
pub(crate) enum ConfigFileError {
    #[error("loading configuration failed: {source}")]
    IoError {
        #[from]
        source: io::Error,
    },

    #[error("parsing configuration failed: {source}")]
    SerdeJsonError {
        #[from]
        source: serde_json::error::Error,
    },
}

fn read_config_from_file<P: AsRef<Path>>(path: P) -> Result<Config, ConfigFileError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let c = serde_json::from_reader(reader)?;

    Ok(c)
}
