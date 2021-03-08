#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Funds {
    #[prost(uint64, tag="1")]
    pub cycles: u64,
    #[prost(uint64, tag="2")]
    pub icp: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Stream {
    #[prost(uint64, tag="1")]
    pub messages_begin: u64,
    #[prost(message, repeated, tag="2")]
    pub messages: ::std::vec::Vec<RequestOrResponse>,
    #[prost(uint64, tag="5")]
    pub signals_end: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamEntry {
    #[prost(message, optional, tag="1")]
    pub subnet_id: ::std::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(message, optional, tag="2")]
    pub subnet_stream: ::std::option::Option<Stream>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Request {
    #[prost(message, optional, tag="1")]
    pub receiver: ::std::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag="2")]
    pub sender: ::std::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(uint64, tag="3")]
    pub sender_reply_callback: u64,
    #[prost(message, optional, tag="4")]
    pub payment: ::std::option::Option<Funds>,
    #[prost(string, tag="5")]
    pub method_name: std::string::String,
    #[prost(bytes, tag="6")]
    pub method_payload: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RejectContext {
    #[prost(uint64, tag="1")]
    pub reject_code: u64,
    #[prost(string, tag="2")]
    pub reject_message: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Response {
    #[prost(message, optional, tag="1")]
    pub originator: ::std::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag="2")]
    pub respondent: ::std::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(uint64, tag="3")]
    pub originator_reply_callback: u64,
    #[prost(message, optional, tag="4")]
    pub refund: ::std::option::Option<Funds>,
    #[prost(oneof="response::ResponsePayload", tags="5, 6")]
    pub response_payload: ::std::option::Option<response::ResponsePayload>,
}
pub mod response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ResponsePayload {
        #[prost(bytes, tag="5")]
        Data(std::vec::Vec<u8>),
        #[prost(message, tag="6")]
        Reject(super::RejectContext),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RequestOrResponse {
    #[prost(oneof="request_or_response::R", tags="1, 2")]
    pub r: ::std::option::Option<request_or_response::R>,
}
pub mod request_or_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum R {
        #[prost(message, tag="1")]
        Request(super::Request),
        #[prost(message, tag="2")]
        Response(super::Response),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InputOutputQueue {
    #[prost(message, repeated, tag="1")]
    pub queue: ::std::vec::Vec<RequestOrResponse>,
    #[prost(uint64, tag="2")]
    pub ind: u64,
    #[prost(uint64, tag="3")]
    pub capacity: u64,
    #[prost(uint64, tag="4")]
    pub num_slots_reserved: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueueEntry {
    #[prost(message, optional, tag="1")]
    pub canister_id: ::std::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag="2")]
    pub queue: ::std::option::Option<InputOutputQueue>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterQueues {
    #[prost(message, repeated, tag="2")]
    pub ingress_queue: ::std::vec::Vec<super::super::ingress::v1::Ingress>,
    #[prost(message, repeated, tag="3")]
    pub input_queues: ::std::vec::Vec<QueueEntry>,
    #[prost(message, repeated, tag="4")]
    pub input_schedule: ::std::vec::Vec<super::super::super::types::v1::CanisterId>,
    #[prost(message, repeated, tag="5")]
    pub output_queues: ::std::vec::Vec<QueueEntry>,
}
