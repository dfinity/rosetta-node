//! Dump (parts of) the registry
//!
//! Usage:
//!
//! ic-registry-dump --nns_urls URLS
//!
//! Where URLS is a comma-separated list of one or more URLs for replicas
//! hosting registry canisters on an IC you care about.
//!
//! Sample output:
//!
//! ```json
//! {
//! "registry_version": 7,
//!   "subnet_ids": [
//!     "ak2jc-de3ae-aaaaa-aaaap-yai",
//!     "fscpm-uiaaa-aaaaa-aaaap-yai",
//!     "yndj2-3ybaa-aaaaa-aaaap-yai",
//!     "fbysm-3acaa-aaaaa-aaaap-yai"
//!   ],
//!   "nodes": [
//!     {
//!       "node_id": "aaphl-wdrbs-s7xir-bavlf-ylz3e-5dfx5-nevqr-akyqe-y2dnz-ctw6w-sqe",
//!       "subnet_id": "ak2jc-de3ae-aaaaa-aaaap-yai",
//!       "transport_info": {
//!         "node_operator_id": [],
//!         "xnet": {
//!           "ip_addr": "10.12.32.7",
//!           "port": 2497
//!         },
//!         "http": {
//!           "ip_addr": "10.12.32.7",
//!           "port": 8080
//!         },
//!         "p2p_flow_endpoints": [
//!           {
//!             "flow_tag": 1234,
//!             "endpoint": {
//!               "ip_addr": "10.12.32.7",
//!               "port": 4100
//!             }
//!           }
//!         ],
//!         "prometheus_metrics_http": {
//!           "ip_addr": "0.0.0.0",
//!           "port": 0
//!         }
//!       }
//!     },
//! ...
//! ```

use std::{collections::HashSet, iter::FromIterator, sync::Arc};

use anyhow::{Context, Result};
use config::Config;
use ic_registry_client::{
    client::{
        create_data_provider, DataProviderConfig, RegistryClient, RegistryClientError,
        RegistryClientImpl, RegistryVersion,
    },
    helper::node::{NodeId, NodeRegistry, SubnetId},
    helper::{
        node::NodeRecord,
        subnet::{SubnetListRegistry, SubnetRegistry},
    },
};
use ic_registry_subnet_type::SubnetType;
use serde::Serialize;
use std::convert::TryFrom;
use thiserror::Error;

mod config;

/// Output structure, serialized to JSON for display
#[derive(Clone, Debug, Default, Serialize)]
struct Output {
    registry_version: RegistryVersion,
    nns_subnet_id: String,
    subnet_ids: Vec<String>,
    nodes: Vec<Node>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct Node {
    id: String,
    subnet_id: String,
    transport_info: NodeRecord,
}

fn get_nns_subnet_id(
    registry: Arc<dyn RegistryClient>,
    subnet_ids: &[SubnetId],
    registry_version: RegistryVersion,
) -> SubnetId {
    for subnet_id in subnet_ids {
        if get_subnet_type(&registry, *subnet_id, registry_version) == SubnetType::System {
            return *subnet_id;
        }
    }
    unreachable!("Could not find the NNS subnet id.");
}

fn get_subnet_type(
    registry: &Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
) -> SubnetType {
    loop {
        match registry.get_subnet_record(subnet_id, registry_version) {
            Ok(subnet_record) => {
                break match subnet_record {
                    Some(record) => SubnetType::try_from(record.subnet_type)
                        .expect("Could not parse SubnetType"),
                    // This can only happen if the registry is corrupted, so better to crash.
                    None => panic!(),
                };
            }
            Err(err) => panic!("{:?}", err),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: HashSet<&'static str> = HashSet::from_iter(gflags::parse().iter().cloned());
    if args.contains("help") {
        gflags::print_help_and_exit(0);
    }

    let config = Config::new().context("failed to process configuration")?;

    let provider_config = if !config.nns.urls.is_empty() {
        DataProviderConfig::RegistryCanisterUrl(config.nns.urls)
    } else {
        DataProviderConfig::LocalStore(config.local_store.path)
    };
    let data_provider = create_data_provider(&provider_config, /* nns_public_key= */ None);
    let registry_client = Arc::new(RegistryClientImpl::new(data_provider, None));
    if let Err(e) = registry_client.fetch_and_start_polling() {
        panic!("fetch_and_start_polling failed: {}", e);
    };

    let registry_version = config
        .registry_version
        .map(RegistryVersion::from)
        .unwrap_or_else(|| registry_client.get_latest_version());

    let mut out = Output {
        registry_version,
        ..Default::default()
    };

    let subnet_ids = registry_client
        .get_subnet_ids(registry_version)
        .map_err(|source| RegistryInvariantError::GetSubnetsFailed {
            source,
            registry_version,
        })?
        .unwrap_or_default();

    out.subnet_ids = subnet_ids.iter().map(|id| id.get().to_string()).collect();
    out.nns_subnet_id = get_nns_subnet_id(registry_client.clone(), &subnet_ids, registry_version)
        .get()
        .to_string();

    for subnet_id in subnet_ids {
        let node_ids = registry_client
            .get_node_ids_on_subnet(subnet_id, registry_version)
            .map_err(|source| RegistryInvariantError::GetNodeIdsFailed {
                source,
                subnet_id,
                registry_version,
            })?
            .unwrap_or_default();

        for node_id in node_ids {
            let transport_info = registry_client
                .get_transport_info(node_id, registry_version)
                .map_err(|source| RegistryInvariantError::GetTransportInfoFailed {
                    node_id,
                    registry_version,
                    source,
                })?
                .ok_or(RegistryInvariantError::NodeHasNoTransportInfo {
                    node_id,
                    registry_version,
                })?;

            let node_record = Node {
                id: node_id.get().to_string(),
                subnet_id: subnet_id.get().to_string(),
                transport_info,
            };

            out.nodes.push(node_record);
        }
    }

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

#[derive(Error, Debug)]
pub(crate) enum RegistryInvariantError {
    #[error("failed to fetch subnet list from registry {registry_version}: {source}")]
    GetSubnetsFailed {
        source: RegistryClientError,
        registry_version: RegistryVersion,
    },

    #[error("failed to fetch node ID list for subnet {subnet_id} from registry {registry_version}: {source}")]
    GetNodeIdsFailed {
        subnet_id: SubnetId,
        source: RegistryClientError,
        registry_version: RegistryVersion,
    },

    #[error("failed to get transport info for node {node_id} from registry {registry_version}: {source}")]
    GetTransportInfoFailed {
        node_id: NodeId,
        registry_version: RegistryVersion,
        source: RegistryClientError,
    },

    #[error("node {node_id} has no transport info at registry {registry_version}")]
    NodeHasNoTransportInfo {
        node_id: NodeId,
        registry_version: RegistryVersion,
    },
}
