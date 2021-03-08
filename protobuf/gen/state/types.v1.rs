#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrincipalId {
    #[prost(bytes, tag="1")]
    pub raw: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterId {
    #[prost(message, optional, tag="1")]
    pub principal_id: ::std::option::Option<PrincipalId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetId {
    #[prost(message, optional, tag="1")]
    pub principal_id: ::std::option::Option<PrincipalId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserId {
    #[prost(message, optional, tag="1")]
    pub principal_id: ::std::option::Option<PrincipalId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeId {
    #[prost(message, optional, tag="1")]
    pub principal_id: ::std::option::Option<PrincipalId>,
}
/// Non-interactive DKG ID
#[derive(Clone, PartialEq, ::prost::Message)]
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
pub enum NiDkgTag {
    Unspecified = 0,
    LowThreshold = 1,
    HighThreshold = 2,
}
