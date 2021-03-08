/// A record for a node operator. Each node operator is associated with a
/// unique principal id, a.k.a. NOID.
///
/// Note that while a node operator might host nodes for more than
/// one funding parter, its principal ID must be unique.
///
/// TODO: Add funding partners once we'll have them (right now dc/fp pairs
/// are the only entity that exists).
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NodeOperatorRecord {
    /// The principal id of the node operator. This principal is the entity that
    /// is able to add and remove nodes.
    ///
    /// This must be unique across NodeOperatorRecords.
    #[prost(bytes, tag="1")]
    pub node_operator_principal_id: std::vec::Vec<u8>,
    /// The remaining number of nodes that could be added by this node operator.
    /// This number should never go below 0.
    #[prost(uint64, tag="2")]
    pub node_allowance: u64,
}
