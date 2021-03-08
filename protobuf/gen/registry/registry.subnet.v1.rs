/// A subnet: A logical group of nodes that run consensus
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SubnetRecord {
    #[prost(bytes, repeated, tag="3")]
    pub membership: ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(message, optional, tag="2")]
    pub initial_dkg_transcript: ::std::option::Option<InitialDkgTranscriptRecord>,
    /// Ingress message params used by that subnet.
    ///
    /// Maximum amount of bytes per block. This is a soft cap, which means
    /// we stop adding messages once overall size grows above this limit. This
    /// allows big messages to still get into the block, because the size of
    /// a message can exceed this limit.
    #[prost(uint64, tag="4")]
    pub ingress_bytes_per_block_soft_cap: u64,
    /// Maximum amount of bytes per message. This is a hard cap, which means
    /// ingress messages greater than the limit will be dropped.
    #[prost(uint64, tag="5")]
    pub max_ingress_bytes_per_message: u64,
    /// Unit delay for blockmaker (in milliseconds).
    #[prost(uint64, tag="7")]
    pub unit_delay_millis: u64,
    /// Initial delay for notary (in milliseconds), to give time to rank-0 block
    /// propagation.
    #[prost(uint64, tag="8")]
    pub initial_notary_delay_millis: u64,
    /// ID of the Replica version to run
    #[prost(string, tag="9")]
    pub replica_version_id: std::string::String,
    /// The length of all DKG intervals. The DKG interval length is the number of rounds following the DKG summary.
    #[prost(uint64, tag="10")]
    pub dkg_interval_length: u64,
    /// Gossip Config
    #[prost(message, optional, tag="13")]
    pub gossip_config: ::std::option::Option<GossipConfig>,
    /// If set to yes, the subnet starts as a (new) NNS
    #[prost(bool, tag="14")]
    pub start_as_nns: bool,
    /// The type of subnet.
    #[prost(enumeration="SubnetType", tag="15")]
    pub subnet_type: i32,
    /// The upper bound for the number of dealings we allow in a block.
    #[prost(uint64, tag="16")]
    pub dkg_dealings_per_block: u64,
}
/// Contains the initial DKG transcripts for the subnet and materials to construct a base CUP (i.e.
/// a CUP with no dependencies on previous CUPs or blocks). Such CUP materials can be used to
/// construct the genesis CUP or a recovery CUP in the event of a subnet stall.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CatchUpPackageContents {
    /// Initial non-interactive low-threshold DKG transcript
    #[prost(message, optional, tag="1")]
    pub initial_ni_dkg_transcript_low_threshold: ::std::option::Option<InitialNiDkgTranscriptRecord>,
    /// Initial non-interactive high-threshold DKG transcript
    #[prost(message, optional, tag="2")]
    pub initial_ni_dkg_transcript_high_threshold: ::std::option::Option<InitialNiDkgTranscriptRecord>,
    /// The blockchain height that the CUP should have
    #[prost(uint64, tag="3")]
    pub height: u64,
    /// Block time for the CUP's block
    #[prost(uint64, tag="4")]
    pub time: u64,
    /// The hash of the state that the subnet should use
    #[prost(bytes, tag="5")]
    pub state_hash: std::vec::Vec<u8>,
}
/// A list of subnet ids of all subnets present in this instance of the IC.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SubnetListRecord {
    #[prost(bytes, repeated, tag="2")]
    pub subnets: ::std::vec::Vec<std::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct InitialDkgTranscriptRecord {
    /// the dkg id
    #[prost(message, optional, tag="1")]
    pub id: ::std::option::Option<DkgId>,
    /// Node Ids of the nodes that originally participated in this subnet
    #[prost(bytes, repeated, tag="4")]
    pub committee: ::std::vec::Vec<std::vec::Vec<u8>>,
    /// the transcript
    #[prost(bytes, tag="3")]
    pub transcript_bytes: std::vec::Vec<u8>,
}
/// The dkg id
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DkgId {
    #[prost(uint64, tag="1")]
    pub instance_id: u64,
    #[prost(bytes, tag="3")]
    pub subnet_id: std::vec::Vec<u8>,
}
/// Initial non-interactive DKG transcript record
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct InitialNiDkgTranscriptRecord {
    #[prost(message, optional, tag="1")]
    pub id: ::std::option::Option<super::super::super::types::v1::NiDkgId>,
    #[prost(uint32, tag="2")]
    pub threshold: u32,
    #[prost(bytes, repeated, tag="3")]
    pub committee: ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(uint64, tag="4")]
    pub registry_version: u64,
    #[prost(bytes, tag="5")]
    pub internal_csp_transcript: std::vec::Vec<u8>,
}
/// Per subnet P2P configuration
/// Note: protoc is mangling the name P2PConfig to P2pConfig
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct GossipConfig {
    /// max outstanding request per peer MIN/DEFAULT/MAX 1/20/200
    #[prost(uint32, tag="1")]
    pub max_artifact_streams_per_peer: u32,
    /// timeout for a outstanding request 3_000/15_000/180_000
    #[prost(uint32, tag="2")]
    pub max_chunk_wait_ms: u32,
    /// max duplicate requests in underutilized networks 1/28/6000
    #[prost(uint32, tag="3")]
    pub max_duplicity: u32,
    /// maximum chunk size supported on this subnet 1024/4096/131_072
    #[prost(uint32, tag="4")]
    pub max_chunk_size: u32,
    /// history size for receive check 1_000/5_000/30_000
    #[prost(uint32, tag="5")]
    pub receive_check_cache_size: u32,
    /// period for re evaluating the priority function. 1_000/3_000/30_000
    #[prost(uint32, tag="6")]
    pub pfn_evaluation_period_ms: u32,
    /// period for polling the registry for updates 1_000/3_000/30_000
    #[prost(uint32, tag="7")]
    pub registry_poll_period_ms: u32,
    /// period for sending a retransmission request    
    #[prost(uint32, tag="8")]
    pub retransmission_request_ms: u32,
}
/// Represents the type of subnet. Subnets of different type might exhibit different
/// behavior, e.g. being more restrictive in what operations are allowed or privileged
/// compared to other subnet types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum SubnetType {
    Unspecified = 0,
    /// A normal subnet where no restrictions are applied.
    Application = 1,
    /// A more privileged subnet where certain restrictions are applied,
    /// like not charging for cycles or restricting who can create and
    /// install canisters on it.
    System = 2,
}
