#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeTopology {
    #[prost(string, tag="1")]
    pub ip_address: std::string::String,
    #[prost(uint32, tag="2")]
    pub http_port: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetTopologyEntry {
    #[prost(message, optional, tag="1")]
    pub node_id: ::std::option::Option<super::super::super::types::v1::NodeId>,
    #[prost(message, optional, tag="2")]
    pub node_topology: ::std::option::Option<NodeTopology>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetTopology {
    #[prost(message, repeated, tag="1")]
    pub nodes: ::std::vec::Vec<SubnetTopologyEntry>,
    /// The public key of the subnet (a DER-encoded BLS key, see
    /// https://docs.dfinity.systems/public/v/master/#certification)
    #[prost(bytes, tag="2")]
    pub public_key: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetsEntry {
    #[prost(message, optional, tag="1")]
    pub subnet_id: ::std::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(message, optional, tag="2")]
    pub subnet_topology: ::std::option::Option<SubnetTopology>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NetworkTopology {
    #[prost(message, repeated, tag="1")]
    pub subnets: ::std::vec::Vec<SubnetsEntry>,
    #[prost(message, optional, tag="2")]
    pub routing_table: ::std::option::Option<super::super::super::registry::routing_table::v1::RoutingTable>,
    #[prost(message, optional, tag="3")]
    pub nns_subnet_id: ::std::option::Option<super::super::super::types::v1::SubnetId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetupInitialDkgContext {
    #[prost(message, optional, tag="1")]
    pub request: ::std::option::Option<super::super::queues::v1::Request>,
    #[prost(message, repeated, tag="2")]
    pub nodes_in_subnet: ::std::vec::Vec<super::super::super::types::v1::NodeId>,
    #[prost(message, optional, tag="3")]
    pub subnet_id: ::std::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(bytes, tag="4")]
    pub target_id: std::vec::Vec<u8>,
    #[prost(uint64, tag="5")]
    pub registry_version: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetCallContext {
    #[prost(message, optional, tag="1")]
    pub setup_initial_dkg_context: ::std::option::Option<SetupInitialDkgContext>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetCallContextTree {
    #[prost(uint64, tag="1")]
    pub callback_id: u64,
    #[prost(message, optional, tag="2")]
    pub context: ::std::option::Option<SubnetCallContext>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetCallContextManager {
    #[prost(uint64, tag="1")]
    pub next_callback_id: u64,
    #[prost(message, repeated, tag="2")]
    pub contexts: ::std::vec::Vec<SubnetCallContextTree>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SystemMetadata {
    #[prost(uint64, tag="1")]
    pub generated_id_counter: u64,
    #[prost(message, optional, tag="2")]
    pub prev_state_hash: ::std::option::Option<::std::vec::Vec<u8>>,
    #[prost(uint64, tag="3")]
    pub batch_time_nanos: u64,
    #[prost(message, optional, tag="4")]
    pub ingress_history: ::std::option::Option<super::super::ingress::v1::IngressHistoryState>,
    #[prost(message, repeated, tag="5")]
    pub streams: ::std::vec::Vec<super::super::queues::v1::StreamEntry>,
    #[prost(message, optional, tag="6")]
    pub network_topology: ::std::option::Option<NetworkTopology>,
    #[prost(message, optional, tag="7")]
    pub own_subnet_id: ::std::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(message, optional, tag="8")]
    pub subnet_call_context_manager: ::std::option::Option<SubnetCallContextManager>,
    /// Version of the StateSync protocol that should be used to compute
    /// checkpoint manifests and transmit state.
    #[prost(uint32, tag="9")]
    pub state_sync_version: u32,
    /// Version of the certification protocol that should be used to
    /// certify this state.
    #[prost(uint32, tag="10")]
    pub certification_version: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StableMemory {
    #[prost(bytes, tag="1")]
    pub memory: std::vec::Vec<u8>,
}
