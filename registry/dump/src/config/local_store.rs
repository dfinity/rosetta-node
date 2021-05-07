//! Configuration data to connect to the registry

use gflags_derive::GFlags;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// External mechanism for configuring registry client
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, GFlags)]
#[gflags(prefix = "local_store_")]
#[serde(default)]
pub struct Config {
    /// Path to registry local store
    #[gflags(type = "&str", placeholder = "PATH")]
    pub path: PathBuf,
}

pub(crate) fn from_flags() -> Config {
    if LOCAL_STORE_PATH.is_present() {
        let path: &std::path::Path = LOCAL_STORE_PATH.flag.as_ref();
        Config { path: path.into() }
    } else {
        Config::default()
    }
}
