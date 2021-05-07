use ic_protobuf::registry::routing_table::v1::RoutingTable as PbRoutingTable;
use ic_registry_common::registry::RegistryCanister;
use ic_registry_keys::make_routing_table_record_key;
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_transport::pb::v1::{Precondition, RegistryMutation};
use ic_types::SubnetId;
use prost::Message;
use std::convert::TryFrom;

async fn get_routing_table_and_mutation_type(
    registry: &RegistryCanister,
) -> (RoutingTable, i32, u64) {
    let routing_table_record_result = registry
        .get_value(make_routing_table_record_key().as_bytes().to_vec(), None)
        .await;
    match routing_table_record_result {
        Ok((bytes, version)) => match PbRoutingTable::decode(&bytes[..]) {
            Ok(record) => (RoutingTable::try_from(record).unwrap(), 1, version),
            Err(error) => panic!("Error decoding routing table record: {:?}", error),
        },

        Err(err) => panic!(
            "Error while fetching current routing table record: {:?}",
            err
        ),
    }
}

fn into_registry_mutation(routing_table: RoutingTable, mutation_type: i32) -> RegistryMutation {
    let mut buf = vec![];
    let pb_routing_table = PbRoutingTable::from(routing_table);
    pb_routing_table.encode(&mut buf).unwrap();
    RegistryMutation {
        mutation_type,
        key: make_routing_table_record_key().as_bytes().to_vec(),
        value: buf,
    }
}

pub(crate) async fn add_subnet_to_routing_table(
    registry: &RegistryCanister,
    subnet_id: SubnetId,
) -> (RegistryMutation, Precondition) {
    let (mut routing_table, mutation_type, version) =
        get_routing_table_and_mutation_type(registry).await;

    routing_table_insert_subnet(&mut routing_table, subnet_id).unwrap();
    (
        into_registry_mutation(routing_table, mutation_type),
        Precondition {
            key: make_routing_table_record_key().as_bytes().to_vec(),
            expected_version: version,
        },
    )
}
