#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BlockLogEntry {
    #[prost(message, optional, tag="1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_size: ::std::option::Option<u64>,
    #[prost(message, optional, tag="2")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certified_height: ::std::option::Option<u64>,
    #[prost(message, optional, tag="3")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dkg_payload_type: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="4")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="5")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: ::std::option::Option<u64>,
    #[prost(message, optional, tag="6")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_hash: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="7")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: ::std::option::Option<u64>,
    #[prost(message, optional, tag="8")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_version: ::std::option::Option<u64>,
    #[prost(message, optional, tag="9")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: ::std::option::Option<u64>,
    #[prost(message, optional, tag="10")]
    pub version: ::std::option::Option<::std::string::String>,
}
