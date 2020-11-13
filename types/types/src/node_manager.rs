// We disable the clippy warning for the whole module because they apply to
// generated code, meaning we can't locally disable the warnings (the code is
// defined in another module). https://dfinity.atlassian.net/browse/DFN-467
#![allow(clippy::redundant_closure)]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(test)]
use proptest::prelude::{any, Strategy};
#[cfg(test)]
use proptest_derive::Arbitrary;

type ServiceName = String;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, Serialize)]
#[cfg_attr(test, derive(Arbitrary))]
struct ServiceManagerConfig {
    configurations: Vec<ServiceConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, Serialize)]
#[cfg_attr(test, derive(Arbitrary))]
struct ServiceConfig {
    name: ServiceName,
    #[cfg_attr(
        test,
        proptest(strategy = "any::<String>().prop_map(|x| PathBuf::from(x))")
    )]
    executable: PathBuf,
    #[cfg_attr(
        test,
        proptest(strategy = "any::<String>().prop_map(|x| PathBuf::from(x))")
    )]
    working_directory: PathBuf,
    args: Vec<String>,
    envs: Vec<(String, String)>,
    dependencies: Option<Vec<ServiceName>>,
    /* Note: More fields may be added here when the requirements have stabilised but we should
     * keep them to an absolute minimum.
     * Example: Some designs use running a setup process and then exiting rather than
     * daemonising. Example: Processing users will be needed to satisfy security
     * requirements around private key storage. */
}

impl Default for ServiceManagerConfig {
    fn default() -> Self {
        let configurations = vec![
            ServiceConfig {
                name: ServiceName::from("mainnet"),
                executable: PathBuf::from("/replica/current/bin/replica"),
                working_directory: PathBuf::from("/var/lib/replica/snapshots/current"),
                args: Vec::new(),
                envs: Vec::new(),
                dependencies: None,
            },
            ServiceConfig {
                name: ServiceName::from("log_uploader"),
                executable: PathBuf::from("/replica/current/bin/log_uploader"),
                working_directory: PathBuf::from("/tmp"),
                args: Vec::new(),
                envs: Vec::new(),
                dependencies: None,
            },
            ServiceConfig {
                name: ServiceName::from("monitoring_uploader"),
                executable: PathBuf::from("/replica/current/bin/monitoring_uploader"),
                working_directory: PathBuf::from("/tmp"),
                args: Vec::new(),
                envs: Vec::new(),
                dependencies: None,
            },
        ];
        Self { configurations }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn serde_test(config: ServiceConfig) {
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: ServiceConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(config, deserialized);
    }

    proptest! {
        #[test]
        fn arbitrary_config_serializes_and_deserializes(config: ServiceConfig) {
            serde_test(config);
        }
    }
}
