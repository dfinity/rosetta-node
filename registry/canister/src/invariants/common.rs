use prost::Message;
use std::{
    collections::BTreeMap,
    convert::TryFrom,
    error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_nns_common::registry::decode_or_panic;
use ic_protobuf::registry::{node::v1::NodeRecord, subnet::v1::SubnetListRecord};
use ic_registry_keys::{get_node_record_node_id, make_subnet_list_record_key};

/// A representation of the data held by the registry.
/// It is kept in-memory only, for global consistency checks before mutations
/// are finalized.
pub(crate) type RegistrySnapshot = BTreeMap<Vec<u8>, Vec<u8>>;

#[derive(Debug)]
pub(crate) struct InvariantCheckError {
    pub msg: String,
    pub source: Option<Box<dyn error::Error + 'static>>,
}

impl Display for InvariantCheckError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "InvariantCheckError: {:?}", self.msg)
    }
}

// TODO(NNS1-488) Improved error handling
impl error::Error for InvariantCheckError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

pub(crate) fn get_value_from_snapshot<T: Message + Default>(
    snapshot: &RegistrySnapshot,
    key: String,
) -> Option<T> {
    snapshot
        .get(key.as_bytes())
        .map(|v| decode_or_panic(v.clone()))
}

/// Returns all node records from the snapshot.
pub(crate) fn get_node_records_from_snapshot(
    snapshot: &RegistrySnapshot,
) -> BTreeMap<NodeId, NodeRecord> {
    let mut result = BTreeMap::<NodeId, NodeRecord>::new();
    for key in snapshot.keys() {
        if let Some(principal_id) =
            get_node_record_node_id(String::from_utf8(key.clone()).unwrap().as_str())
        {
            // This is indeed a node record
            let node_record = match snapshot.get(key) {
                Some(node_record_bytes) => decode_or_panic::<NodeRecord>(node_record_bytes.clone()),
                None => panic!("Cannot fetch node record for an existing key"),
            };
            let node_id = NodeId::from(principal_id);
            result.insert(node_id, node_record);
        }
    }
    result
}

pub(crate) fn get_subnet_ids_from_snapshot(snapshot: &RegistrySnapshot) -> Vec<SubnetId> {
    get_value_from_snapshot::<SubnetListRecord>(snapshot, make_subnet_list_record_key())
        .map(|r| {
            r.subnets
                .iter()
                .map(|s| SubnetId::from(PrincipalId::try_from(s.clone().as_slice()).unwrap()))
                .collect()
        })
        .unwrap_or_else(Vec::new)
}
