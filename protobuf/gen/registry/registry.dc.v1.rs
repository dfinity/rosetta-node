/// A record for a data center. Each data center is associated with a
/// unique dc operator principal id, a.k.a. DCID.
///
/// Note that while a physical data center might host nodes for more than
/// one funding parter, its dcop_principal_id must be unique.
///
/// TODO: Add funding partners once we'll have them (right now dc/fp pairs
/// are the only entity that exists).
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DcRecord {
    /// The principal id of the data-center operator that is associated with
    /// this DC. This principal is the entity that is able to add and remove
    /// nodes from a data center.
    ///
    /// This must be unique across DCRecords.
    #[prost(bytes, tag="1")]
    pub dcop_principal_id: std::vec::Vec<u8>,
    /// The remaining number of nodes that could be added to this DC.
    /// This number should never go below 0.
    #[prost(uint64, tag="2")]
    pub node_allowance: u64,
    /// List of IPv6 prefixes associated with this DC, separated by a comma
    /// These prefixes are added to firewalls to allow traffic from this DC
    #[prost(string, tag="3")]
    pub ipv6_prefixes: std::string::String,
}
/// A record for a list of data centers
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DcList {
    #[prost(bytes, repeated, tag="1")]
    pub dcop_principal_ids: ::std::vec::Vec<std::vec::Vec<u8>>,
}
