#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize)]
pub struct IngressMessageLogEntry {
    #[prost(message, optional, tag="1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canister_id: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="2")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compute_allocation: ::std::option::Option<u64>,
    #[prost(message, optional, tag="3")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired_id: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="4")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_time: ::std::option::Option<u64>,
    #[prost(message, optional, tag="5")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_allocation: ::std::option::Option<u64>,
    #[prost(message, optional, tag="6")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="7")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_name: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="8")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: ::std::option::Option<::std::string::String>,
    /// Gives additional information about this log event
    #[prost(message, optional, tag="9")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="10")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_type: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="11")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="12")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: ::std::option::Option<u64>,
    #[prost(message, optional, tag="13")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_time: ::std::option::Option<u64>,
    #[prost(message, optional, tag="14")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_time_plus_ttl: ::std::option::Option<u64>,
}
