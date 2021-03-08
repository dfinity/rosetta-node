#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Eq, Hash)]
pub struct PrincipalId {
    #[prost(bytes, tag="1")]
    pub raw: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CanisterId {
    #[prost(message, optional, tag="1")]
    pub principal_id: ::std::option::Option<PrincipalId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Eq, Hash)]
pub struct SubnetId {
    #[prost(message, optional, tag="1")]
    pub principal_id: ::std::option::Option<PrincipalId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct UserId {
    #[prost(message, optional, tag="1")]
    pub principal_id: ::std::option::Option<PrincipalId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NodeId {
    #[prost(message, optional, tag="1")]
    pub principal_id: ::std::option::Option<PrincipalId>,
}
/// Non-interactive DKG ID
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Eq, Hash)]
pub struct NiDkgId {
    #[prost(uint64, tag="1")]
    pub start_block_height: u64,
    #[prost(bytes, tag="2")]
    pub dealer_subnet: std::vec::Vec<u8>,
    #[prost(enumeration="NiDkgTag", tag="4")]
    pub dkg_tag: i32,
    #[prost(message, optional, tag="5")]
    pub remote_target_id: ::std::option::Option<::std::vec::Vec<u8>>,
}
/// Non-interactive DKG tag
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum NiDkgTag {
    Unspecified = 0,
    LowThreshold = 1,
    HighThreshold = 2,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DkgMessage {
    #[prost(message, optional, tag="5")]
    pub signer: ::std::option::Option<NodeId>,
    #[prost(bytes, tag="1")]
    pub signature: std::vec::Vec<u8>,
    #[prost(string, tag="2")]
    pub replica_version: std::string::String,
    #[prost(message, optional, tag="3")]
    pub dkg_id: ::std::option::Option<NiDkgId>,
    #[prost(bytes, tag="4")]
    pub dealing: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DkgPayload {
    #[prost(oneof="dkg_payload::Val", tags="1, 2")]
    pub val: ::std::option::Option<dkg_payload::Val>,
}
pub mod dkg_payload {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub enum Val {
        #[prost(message, tag="1")]
        Summary(super::Summary),
        #[prost(message, tag="2")]
        Dealings(super::Dealings),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Dealings {
    #[prost(message, repeated, tag="1")]
    pub dealings: ::std::vec::Vec<DkgMessage>,
    #[prost(uint64, tag="2")]
    pub summary_height: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Summary {
    #[prost(uint64, tag="1")]
    pub registry_version: u64,
    #[prost(uint64, tag="2")]
    pub interval_length: u64,
    #[prost(uint64, tag="3")]
    pub next_interval_length: u64,
    #[prost(uint64, tag="4")]
    pub height: u64,
    #[prost(message, repeated, tag="5")]
    pub current_transcripts: ::std::vec::Vec<TaggedNiDkgTranscript>,
    #[prost(message, repeated, tag="6")]
    pub next_transcripts: ::std::vec::Vec<TaggedNiDkgTranscript>,
    #[prost(message, repeated, tag="7")]
    pub configs: ::std::vec::Vec<NiDkgConfig>,
    #[prost(message, repeated, tag="8")]
    pub transcripts_for_new_subnets: ::std::vec::Vec<IdedNiDkgTranscript>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TaggedNiDkgTranscript {
    #[prost(message, optional, tag="1")]
    pub transcript: ::std::option::Option<NiDkgTranscript>,
    #[prost(enumeration="NiDkgTag", tag="2")]
    pub tag: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct IdedNiDkgTranscript {
    #[prost(message, optional, tag="1")]
    pub dkg_id: ::std::option::Option<NiDkgId>,
    #[prost(message, optional, tag="2")]
    pub transcript_result: ::std::option::Option<NiDkgTranscriptResult>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NiDkgTranscriptResult {
    #[prost(oneof="ni_dkg_transcript_result::Val", tags="1, 2")]
    pub val: ::std::option::Option<ni_dkg_transcript_result::Val>,
}
pub mod ni_dkg_transcript_result {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub enum Val {
        #[prost(message, tag="1")]
        Transcript(super::NiDkgTranscript),
        #[prost(bytes, tag="2")]
        ErrorString(std::vec::Vec<u8>),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NiDkgTranscript {
    #[prost(message, optional, tag="1")]
    pub dkg_id: ::std::option::Option<NiDkgId>,
    #[prost(uint32, tag="2")]
    pub threshold: u32,
    #[prost(message, repeated, tag="3")]
    pub committee: ::std::vec::Vec<NodeId>,
    #[prost(uint64, tag="4")]
    pub registry_version: u64,
    #[prost(bytes, tag="5")]
    pub internal_csp_transcript: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NiDkgConfig {
    #[prost(message, optional, tag="1")]
    pub dkg_id: ::std::option::Option<NiDkgId>,
    #[prost(uint32, tag="2")]
    pub max_corrupt_dealers: u32,
    #[prost(message, repeated, tag="3")]
    pub dealers: ::std::vec::Vec<NodeId>,
    #[prost(uint32, tag="4")]
    pub max_corrupt_receivers: u32,
    #[prost(message, repeated, tag="5")]
    pub receivers: ::std::vec::Vec<NodeId>,
    #[prost(uint32, tag="6")]
    pub threshold: u32,
    #[prost(uint64, tag="7")]
    pub registry_version: u64,
    #[prost(message, optional, tag="8")]
    pub resharing_transcript: ::std::option::Option<NiDkgTranscript>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Nonce {
    #[prost(bytes, tag="1")]
    pub raw_bytes: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SignedIngress {
    #[prost(bytes, tag="1")]
    pub signature: std::vec::Vec<u8>,
    #[prost(message, optional, tag="3")]
    pub sender: ::std::option::Option<UserId>,
    #[prost(message, optional, tag="4")]
    pub canister_id: ::std::option::Option<CanisterId>,
    #[prost(string, tag="5")]
    pub method_name: std::string::String,
    #[prost(bytes, tag="6")]
    pub arg: std::vec::Vec<u8>,
    #[prost(uint64, tag="7")]
    pub ingress_expiry: u64,
    #[prost(message, optional, tag="8")]
    pub nonce: ::std::option::Option<Nonce>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Eq, Hash)]
pub struct CatchUpPackage {
    #[prost(bytes, tag="1")]
    pub content: std::vec::Vec<u8>,
    #[prost(bytes, tag="2")]
    pub signature: std::vec::Vec<u8>,
    #[prost(message, optional, tag="3")]
    pub signer: ::std::option::Option<NiDkgId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CatchUpContent {
    #[prost(message, optional, tag="1")]
    pub block: ::std::option::Option<Block>,
    #[prost(message, optional, tag="2")]
    pub random_beacon: ::std::option::Option<RandomBeacon>,
    #[prost(bytes, tag="3")]
    pub state_hash: std::vec::Vec<u8>,
    #[prost(bytes, tag="4")]
    pub block_hash: std::vec::Vec<u8>,
    #[prost(bytes, tag="5")]
    pub random_beacon_hash: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Block {
    #[prost(string, tag="1")]
    pub version: std::string::String,
    #[prost(bytes, tag="2")]
    pub parent: std::vec::Vec<u8>,
    #[prost(message, optional, tag="3")]
    pub dkg_payload: ::std::option::Option<DkgPayload>,
    #[prost(uint64, tag="4")]
    pub height: u64,
    #[prost(uint64, tag="5")]
    pub rank: u64,
    /// ValidationContext
    #[prost(uint64, tag="6")]
    pub time: u64,
    #[prost(uint64, tag="7")]
    pub registry_version: u64,
    #[prost(uint64, tag="8")]
    pub certified_height: u64,
    /// Payloads
    #[prost(message, optional, tag="9")]
    pub ingress_payload: ::std::option::Option<IngressPayload>,
    #[prost(message, optional, tag="10")]
    pub xnet_payload: ::std::option::Option<XNetPayload>,
    #[prost(bytes, tag="11")]
    pub payload_hash: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RandomBeacon {
    #[prost(string, tag="1")]
    pub version: std::string::String,
    #[prost(uint64, tag="2")]
    pub height: u64,
    #[prost(bytes, tag="3")]
    pub parent: std::vec::Vec<u8>,
    #[prost(bytes, tag="4")]
    pub signature: std::vec::Vec<u8>,
    #[prost(message, optional, tag="5")]
    pub signer: ::std::option::Option<NiDkgId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SubnetStreamSlice {
    #[prost(message, optional, tag="1")]
    pub subnet_id: ::std::option::Option<SubnetId>,
    #[prost(message, optional, tag="2")]
    pub stream_slice: ::std::option::Option<super::super::messaging::xnet::v1::CertifiedStreamSlice>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct XNetPayload {
    #[prost(message, repeated, tag="1")]
    pub stream_slices: ::std::vec::Vec<SubnetStreamSlice>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct IngressIdOffset {
    #[prost(uint64, tag="1")]
    pub expiry: u64,
    #[prost(bytes, tag="2")]
    pub message_id: std::vec::Vec<u8>,
    #[prost(uint64, tag="3")]
    pub offset: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct IngressPayload {
    #[prost(message, repeated, tag="1")]
    pub id_and_pos: ::std::vec::Vec<IngressIdOffset>,
    #[prost(bytes, tag="2")]
    pub buffer: std::vec::Vec<u8>,
}
