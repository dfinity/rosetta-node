#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize)]
pub struct ReplicaConfig {
    #[prost(bytes, tag="1")]
    pub node_id: std::vec::Vec<u8>,
    #[prost(bytes, tag="3")]
    pub subnet_id: std::vec::Vec<u8>,
}
