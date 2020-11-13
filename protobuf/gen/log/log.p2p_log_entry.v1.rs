#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize)]
pub struct P2pLogEntry {
    #[prost(message, optional, tag="1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="2")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: ::std::option::Option<u64>,
    #[prost(message, optional, tag="3")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest: ::std::option::Option<u64>,
    #[prost(message, optional, tag="4")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_id: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="5")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_id: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="6")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advert: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="7")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="8")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="9")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: ::std::option::Option<u64>,
    #[prost(message, optional, tag="10")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnect_elapsed: ::std::option::Option<u64>,
}
