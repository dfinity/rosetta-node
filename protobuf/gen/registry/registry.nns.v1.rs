/// Information about an NNS canister.
///
/// Corresponding mutations are handled by the `root` handler:
/// See /rs/nns/handlers/root
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NnsCanisterRecord {
    #[prost(message, optional, tag="1")]
    pub id: ::std::option::Option<super::super::super::types::v1::CanisterId>,
}
/// All of the (post-genesis, or all?) NNS canisters.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NnsCanisterRecords {
    #[prost(btree_map="string, message", tag="1")]
    pub canisters: ::std::collections::BTreeMap<std::string::String, NnsCanisterRecord>,
}
