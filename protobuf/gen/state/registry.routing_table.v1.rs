/// Represents a closed range of canister ids.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterIdRange {
    #[prost(message, optional, tag="3")]
    pub start_canister_id: ::std::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag="4")]
    pub end_canister_id: ::std::option::Option<super::super::super::types::v1::CanisterId>,
}
/// A list of closed ranges of canister Ids.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterIdRanges {
    #[prost(message, repeated, tag="1")]
    pub ranges: ::std::vec::Vec<CanisterIdRange>,
}
/// Maps a closed range of canister Ids to a subnet id.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RoutingTable {
    /// Defined as `repeated` instead of `map` in order to preserve ordering.
    #[prost(message, repeated, tag="1")]
    pub entries: ::std::vec::Vec<routing_table::Entry>,
}
pub mod routing_table {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Entry {
        #[prost(message, optional, tag="1")]
        pub range: ::std::option::Option<super::CanisterIdRange>,
        #[prost(message, optional, tag="2")]
        pub subnet_id: ::std::option::Option<super::super::super::super::types::v1::SubnetId>,
    }
}
