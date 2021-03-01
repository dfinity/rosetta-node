#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct GossipMessage {
    #[prost(oneof="gossip_message::Body", tags="1, 2, 3, 4")]
    pub body: ::std::option::Option<gossip_message::Body>,
}
pub mod gossip_message {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub enum Body {
        #[prost(message, tag="1")]
        Advert(super::GossipAdvert),
        #[prost(message, tag="2")]
        ChunkRequest(super::GossipChunkRequest),
        #[prost(message, tag="3")]
        Chunk(super::GossipChunk),
        #[prost(message, tag="4")]
        RetransmissionRequest(super::GossipRetransmissionRequest),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct GossipAdvert {
    #[prost(bytes, tag="1")]
    pub attribute: std::vec::Vec<u8>,
    #[prost(uint64, tag="2")]
    pub size: u64,
    #[prost(bytes, tag="3")]
    pub artifact_id: std::vec::Vec<u8>,
    #[prost(bytes, tag="4")]
    pub integrity_hash: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct GossipChunkRequest {
    #[prost(bytes, tag="1")]
    pub artifact_id: std::vec::Vec<u8>,
    #[prost(uint32, tag="2")]
    pub chunk_id: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ArtifactFilter {
    #[prost(message, optional, tag="1")]
    pub consensus_filter: ::std::option::Option<ConsensusMessageFilter>,
    #[prost(message, optional, tag="2")]
    pub ingress_filter: ::std::option::Option<IngressMessageFilter>,
    #[prost(message, optional, tag="3")]
    pub certification_message_filter: ::std::option::Option<CertificationMessageFilter>,
    #[prost(message, optional, tag="4")]
    pub state_sync_filter: ::std::option::Option<StateSyncFilter>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ConsensusMessageFilter {
    #[prost(uint64, tag="1")]
    pub height: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct IngressMessageFilter {
    #[prost(uint64, tag="1")]
    pub time: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CertificationMessageFilter {
    #[prost(uint64, tag="1")]
    pub height: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct StateSyncFilter {
    #[prost(uint64, tag="1")]
    pub height: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct GossipRetransmissionRequest {
    #[prost(message, optional, tag="1")]
    pub filter: ::std::option::Option<ArtifactFilter>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct GossipChunk {
    #[prost(bytes, tag="1")]
    pub artifact_id: std::vec::Vec<u8>,
    #[prost(uint32, tag="2")]
    pub chunk_id: u32,
    #[prost(oneof="gossip_chunk::Response", tags="3, 4")]
    pub response: ::std::option::Option<gossip_chunk::Response>,
}
pub mod gossip_chunk {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub enum Response {
        #[prost(message, tag="3")]
        Chunk(super::ArtifactChunk),
        #[prost(enumeration="super::P2pError", tag="4")]
        Error(i32),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ArtifactChunk {
    #[prost(bytes, repeated, tag="1")]
    pub witnesses: ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(oneof="artifact_chunk::Data", tags="2, 3")]
    pub data: ::std::option::Option<artifact_chunk::Data>,
}
pub mod artifact_chunk {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub enum Data {
        /// TODO: convert bincoded Artifact to protobuf
        #[prost(bytes, tag="2")]
        Artifact(std::vec::Vec<u8>),
        #[prost(bytes, tag="3")]
        Chunk(std::vec::Vec<u8>),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum P2pError {
    Unspecified = 0,
    NotFound = 1,
}
