#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize)]
pub struct ExecutionLogEntry {
    #[prost(message, optional, tag="1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canister_id: ::std::option::Option<::std::string::String>,
    #[prost(enumeration="execution_log_entry::MessageType", tag="2")]
    pub message_type: i32,
}
pub mod execution_log_entry {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum MessageType {
        Unspecified = 0,
        Ingress = 1,
        CanisterRequest = 2,
        CanisterResponse = 3,
    }
}
