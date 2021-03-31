#![allow(clippy::redundant_closure)]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(test)]
use proptest::prelude::{any, Strategy};
#[cfg(test)]
use proptest_derive::Arbitrary;

// This path is not used in practice. The code should panic if it is.
pub const FIREWALL_FILE_DEFAULT_PATH: &str = "/This/must/not/be/a/real/path";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(Arbitrary))]
pub struct DataCenter {
    pub dcop_principal_id: Vec<u8>,
    pub ipv6_prefixes: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(Arbitrary))]
pub struct Config {
    /// Path to use for storing state on the file system
    #[cfg_attr(
        test,
        proptest(strategy = "any::<String>().prop_map(|x| PathBuf::from(x))")
    )]
    pub config_file: PathBuf,
    pub ipv4_config: String,
    pub ipv6_config: String,
    pub dcs_var_name: String,
    pub data_centers: Vec<DataCenter>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_file: PathBuf::from(FIREWALL_FILE_DEFAULT_PATH),
            ipv4_config: "".to_string(),
            ipv6_config: "".to_string(),
            dcs_var_name: "".to_string(),
            data_centers: vec![],
        }
    }
}
