/// There used to be a canister record proto.
/// This existed when the mapping canister -> subnet was per canister.
/// This is now obsolete: the routing table supersedes it.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CanisterRecord {
}
