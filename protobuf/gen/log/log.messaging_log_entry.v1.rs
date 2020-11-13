#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize)]
pub struct MessagingLogEntry {
    #[prost(message, optional, tag="1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub round: ::std::option::Option<u64>,
    #[prost(message, optional, tag="2")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub core: ::std::option::Option<u64>,
    #[prost(message, optional, tag="3")]
    pub canister_id: ::std::option::Option<::std::string::String>,
    #[prost(message, optional, tag="4")]
    pub message_id: ::std::option::Option<::std::string::String>,
}
