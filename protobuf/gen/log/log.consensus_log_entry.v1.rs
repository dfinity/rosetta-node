#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize)]
pub struct ConsensusLogEntry {
    #[prost(message, optional, tag="1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: ::std::option::Option<u64>,
    #[prost(message, optional, tag="2")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: ::std::option::Option<::std::string::String>,
}
