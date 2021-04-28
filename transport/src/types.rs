//! Shared types internal to transport crate

use crate::metrics::{ControlPlaneMetrics, DataPlaneMetrics, SendQueueMetrics};
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces::transport::AsyncTransportEventHandler;
use ic_logger::ReplicaLogger;
use ic_types::transport::{
    FlowId, FlowTag, TransportClientType, TransportConfig, TransportPayload,
};
use ic_types::{NodeId, RegistryVersion};
use phantom_newtype::{AmountOf, Id};

use async_trait::async_trait;
use futures::future::AbortHandle;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock, Weak};
use tokio::runtime::Handle;
use tokio::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerPortTag;
pub type ServerPort = Id<ServerPortTag, u16>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueueSizeTag;
pub type QueueSize = AmountOf<QueueSizeTag, usize>;

pub const TRANSPORT_HEADER_SIZE: usize = 8;

pub const TRANSPORT_FLAGS_SENDER_ERROR: u8 = 1;
pub const TRANSPORT_FLAGS_IS_HEARTBEAT: u8 = 2;

/// A message is sent on the wire as two writes:
///
///   1. The TransportHeader
///   2. The payload (client message, which is an opaque byte array)
///
/// Note:
///
/// For message framing the transport header must serialize to the
/// same size irrespective of its contents. Fields like NodeId can
/// result violation of the same requirement as it can get serialized
/// to different lengths.
///
/// To maintain the size invariant the header is manually serialized.
/// This struct is ephemeral hence the lack of derivations or tagging.
pub(crate) struct TransportHeader {
    pub(crate) version: u8, // Currently 0
    pub(crate) flags: u8,
    pub(crate) reserved: u16, // Currently 0, serialized little endian.
    /// The length of the byte payload that follows next
    pub(crate) payload_length: u32, // Serialized little endian.
}

// Transport state.
pub(crate) struct TransportImpl {
    pub node_id: NodeId,
    pub node_ip: IpAddr,
    pub config: TransportConfig,
    pub client_map: RwLock<HashMap<TransportClientType, ClientState>>,

    // Crypto and data required for TLS handshakes
    pub allowed_clients: Arc<RwLock<BTreeSet<NodeId>>>,
    pub registry_version: Arc<RwLock<RegistryVersion>>,
    pub crypto: Arc<dyn TlsHandshake + Send + Sync>,

    pub data_plane_metrics: DataPlaneMetrics,
    pub control_plane_metrics: ControlPlaneMetrics,
    pub send_queue_metrics: SendQueueMetrics,

    pub tokio_runtime: Handle,
    pub log: ReplicaLogger,
    pub weak_self: RwLock<Weak<TransportImpl>>,
}

// Per client state.
pub(crate) struct ClientState {
    pub accept_ports: HashMap<FlowTag, ServerPort>,
    // Hooks to cancel the accept() tasks on the server side
    pub accept_cancelers: Vec<Arc<AtomicBool>>,
    pub peer_map: HashMap<NodeId, PeerState>,
    pub event_handler: Arc<dyn AsyncTransportEventHandler>,
}

// Per-peer state, specific to a client.
pub(crate) struct PeerState {
    // State of the flows with the peer
    pub flow_map: HashMap<FlowTag, FlowState>,
    // If the peer is the server, hooks to cancel the connect() tasks in progress
    pub connect_cancelers: Vec<Arc<AtomicBool>>,
}

// Per-flow state, specific to a client and peer.
pub(crate) struct FlowState {
    pub flow_id: FlowId,
    /// Flow tag as a metrics label
    pub flow_tag_label: String,
    // Flow label, used for metrics
    pub flow_label: String,
    pub connection_state: ConnectionState,
    // To stop the send/receive tasks for this flow
    pub abort_handles: Option<(AbortHandle, AbortHandle)>,
    pub send_queue: Box<dyn SendQueue + Send + Sync>,
}

// Current state of the connection for a flow with a peer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionState {
    Listening,              // We are the server, waiting for peer to connect
    Connecting(SocketAddr), // We are the client, connection in progress
    Connected(SocketAddr),  // Connection established
}

/// Per-flow: send queue
///
/// Single producer, single consumer queues for sending data over
/// sockets. There could be multiple sender threads sending into the
/// queue, but the Impl would guarantee mutually exclusive access to
/// the send queue.
#[async_trait]
pub(crate) trait SendQueue {
    /// Gets the read end to be passed to the write task.
    /// Returns None if the reader is already in use by a previously created
    /// write task.
    fn get_reader(&self) -> Box<dyn SendQueueReader + Send + Sync>;

    /// Submits a client message for sending to a peer. If the message
    /// cannot be enqueued, the message is returned back to the caller.
    fn enqueue(&self, message: TransportPayload) -> Option<TransportPayload>;

    /// Discards enqueued messages and clears the queue.
    fn clear(&self);
}

/// Per-flow: send queue read end
#[async_trait]
pub(crate) trait SendQueueReader {
    /// Called by the scheduler to get the next enqueued message, if any.
    async fn dequeue(&mut self, bytes_limit: usize, timeout: Duration) -> Vec<DequeuedMessage>;
}

/// A wrapper for messages that also encloses any related errors
pub(crate) struct DequeuedMessage {
    /// Message payload
    pub(crate) payload: TransportPayload,

    /// Errors
    pub(crate) sender_error: bool,
}
