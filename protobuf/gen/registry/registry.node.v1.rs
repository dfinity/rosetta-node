/// A connection endpoint.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ConnectionEndpoint {
    /// The IP address. Senders SHOULD use dotted-quad notation for IPv4 addresses
    /// and RFC5952 representation for IPv6 addresses (which means that IPv6
    /// addresses are *not* enclosed in `[` and `]`, as they are not written
    /// with the port in the same field).
    ///
    /// Clients MUST be prepared to accept IPv6 addresses in the forms shown in
    /// RFC4291.
    #[prost(string, tag="1")]
    pub ip_addr: std::string::String,
    #[prost(uint32, tag="2")]
    pub port: u32,
    /// Protocol that is used on this endpoint. If PROTOCOL_UNSPECIFIED then
    /// code should default to PROTOCOL_HTTP1 for backwards compatability.
    #[prost(enumeration="connection_endpoint::Protocol", tag="4")]
    pub protocol: i32,
}
pub mod connection_endpoint {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub enum Protocol {
        Unspecified = 0,
        Http1 = 1,
        Http1Tls13 = 2,
        P2p1Tls13 = 3,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct FlowEndpoint {
    /// The flow identifier (tag). This has to be unique per NodeRecord.
    #[prost(uint32, tag="1")]
    pub flow_tag: u32,
    /// The IP/port for this flow.
    #[prost(message, optional, tag="2")]
    pub endpoint: ::std::option::Option<ConnectionEndpoint>,
}
/// A node: one machine running a replica instance.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NodeRecord {
    /// The id of the dc operator that added this node.
    #[prost(bytes, tag="9")]
    pub dcop_principal_id: std::vec::Vec<u8>,
    /// The endpoint where this node receives xnet messages.
    #[prost(message, optional, tag="5")]
    pub xnet: ::std::option::Option<ConnectionEndpoint>,
    /// The endpoint where this node receives http requests.
    #[prost(message, optional, tag="6")]
    pub http: ::std::option::Option<ConnectionEndpoint>,
    /// The P2P flow end points.
    #[prost(message, repeated, tag="8")]
    pub p2p_flow_endpoints: ::std::vec::Vec<FlowEndpoint>,
    /// Endpoint where the node provides Prometheus format metrics over HTTP
    #[prost(message, optional, tag="10")]
    pub prometheus_metrics_http: ::std::option::Option<ConnectionEndpoint>,
    /// Endpoints on which the public API is served.
    #[prost(message, repeated, tag="11")]
    pub public_api: ::std::vec::Vec<ConnectionEndpoint>,
    /// Endpoints on which private APIs are served.
    #[prost(message, repeated, tag="12")]
    pub private_api: ::std::vec::Vec<ConnectionEndpoint>,
    /// Endpoints on which metrics compatible with the Prometheus export
    /// format are served.
    #[prost(message, repeated, tag="13")]
    pub prometheus_metrics: ::std::vec::Vec<ConnectionEndpoint>,
}
