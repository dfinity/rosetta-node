/// An asynchronous event handler for interacting with the ICP gossip
/// layer.
///
/// P2P receives events as network messages from the transport and the
/// HttpHandler (Ingress messages).
///
///```text
///                +-----------------------------+
///                |     HttpHandler(Ingress)    |
///                +-----------------------------+
///                |    IngressEventHandler{}    |
///                +------------v----------------+
///                |       P2P/Gossip            |
///                +----^----------------^-------+
///                | AsyncTranportEventHandler{} |
///                +-----------------------------+
///                |        Transport            |
///                +-----------------------------+
/// ```
///
/// Internally P2P treats event streams as flows. Each flow is
/// abstracted as a message queue implemented over an asynchronous
/// channel. The channel implements back pressure by having a bounded
/// number of buffers.  There are 5 flows: advert, request,
/// re-transmission, chunk and ingress. The first three flows are
/// received from the gossip peer network and ingress flow is received
/// from the http handler.
///
/// Flow-control/back-pressure for transport throttles/suspends the
/// in-flow of messages to match the p2p flow consumption rate.
/// Receiver side back pressure throttles/suspends draining of
/// messages from the transport socket buffers. Sender-side transport
/// queue full condition results in gossip layer dropping the messages
/// intended to be sent. On the sender side, there are no retries/wait
/// for transport queues to free up. Receiver side flow channels and
/// sender-side transport queues have sufficient backlog/buffer
/// capacity to ensure that nodes communicating as per protocol
/// specification will not experience any message drops due to
/// backpressure under favorable network conditions.
///
/// Flow control for ingress messages is based on admission control in
/// the ingress pool. The ingress pool is fixed in size. This limits
/// the user-ingress flow from vying with gossip network flow for
/// transport bandwidth.
///
/// Flow control message queues are per peer per flow. Thus each flow
/// from a peer can be independently controlled. P2P event handler
/// employs 1 synchronous thread to service each flow type across
/// peers. The flow thread round-robins all connected among-st peer
///
/// NOTE: Ingress flow is emulated as a flow originating from the node
/// itself.
///
///
///```text
/// +------+---------+                          +------+----+-------------+
/// |Arc<Mutex<<Map>>|                          | Arc<Mutex<<Map>>        |
/// +------+---------+                          +------+----+-------------+
/// |NodeId|Send     |                          |NodeId|Rcv |             |
/// +------+---------+                          +------+----+ Thread      |
/// |1     |Send     |<--Queues(Size:Backlog)-->|1     |Rcv | Process     |
/// +------+---------+                          +------+----+ Message(T)  |
/// |2     |...      |                          |2     |... |             |
/// +------+---------+                          +------+----+             |
/// |3..   |Send     |                          |3..   |Rcv |             |
/// +------+---------+                          +------+----+-------------+
///
///      PeerFlowQueueMap: A single flow being addressed by 1 thread.
/// ```
use crate::{
    gossip_protocol::{
        Gossip, GossipChunk, GossipChunkRequest, GossipMessage, GossipRetransmissionRequest,
    },
    metrics::EventHandlerMetrics,
    P2PErrorCode, P2PResult,
};
use async_trait::async_trait;
use ic_base_thread::spawn_and_wait;
use ic_interfaces::{
    artifact_manager::OnArtifactError,
    ingress_pool::IngressPoolThrottler,
    p2p::IngressEventHandler,
    transport::{AsyncTransportEventHandler, SendError},
};
use ic_logger::{info, replica_logger::ReplicaLogger, trace};
use ic_metrics::MetricsRegistry;
use ic_protobuf::p2p::v1 as pb;
use ic_protobuf::proxy::ProtoProxy;
use ic_protobuf::registry::subnet::v1::GossipConfig;
use ic_types::{
    artifact::Artifact,
    messages::SignedIngress,
    transport::{FlowId, TransportNotification, TransportPayload},
    NodeId, SubnetId,
};
use ic_types::{p2p::GossipAdvert, transport};
use std::{
    cmp::max,
    collections::BTreeMap,
    convert::TryInto,
    sync::{Arc, Mutex, RwLock},
    vec::Vec,
};

use crossbeam_channel::Receiver as CrossBeamReceiver;
use crossbeam_channel::Sender as CrossBeamSender;
use futures::future::select_all;
use futures::future::FutureExt;
use ic_types::transport::{TransportError, TransportErrorCode, TransportFlowInfo};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use tokio::{
    runtime::Handle,
    sync::mpsc::error::TrySendError,
    sync::mpsc::{channel, Receiver, Sender},
    task::JoinHandle,
    time::{self, Duration},
};

pub(crate) trait P2PEventHandlerControl: Send + Sync {
    // Start the event processing loop, dispatching events to the
    // gossip component
    fn start(&self, gossip_arc: GossipArc);

    // Add/register a peer node with the event handler. The P2P event
    // handler implementation maintains per-peer-per-flow queues to
    // process messages. Each flow type is backed by a dedicated
    // processing thread.
    //
    // Message from nodes that haven't been registered are
    // dropped. Thus, valid nodes must be added to the event handler
    // before any network processing starts.
    fn add_node(&self, node_id: NodeId);

    // Stop the event handler. No-op if event handler hasn't been
    // started.
    fn stop(&self);
}

#[derive(EnumIter, PartialOrd, Ord, Eq, PartialEq)]
enum FlowType {
    Advert, // Transport flows
    Request,
    Chunk,
    Retransmission,
    Transport,
    SendAdvert, // Artifact Manager flows
}

// Message sent to the receive threads (in process_message() loop)
enum ManagementCommands<T> {
    AddPeer(NodeId, Receiver<T>),
    Stop,
    // TODO: RemovePeer(NodeId) - when implemented
}

type RecvMap<T> = Vec<(NodeId, Receiver<T>)>; // Exclusive ownership
type SendMap<T> = Arc<RwLock<BTreeMap<NodeId, Sender<T>>>>; // Shared

// TODO: add_node(), etc happen from sync path, hence we can't use
// tokio channels here. Once all the paths are made async, this can be
// migrated to use tokio channel. That would also allow us to get rid
// of the timeout in the processing loop.
// An alternative would be to use block_on() with async channels, but that
// causes tests to panic as they are async.
type MgmtCmdSend<T> = CrossBeamSender<ManagementCommands<T>>;
type MgmtCmdReceive<T> = CrossBeamReceiver<ManagementCommands<T>>;

type GossipArc = Arc<
    dyn Gossip<
            GossipAdvert = GossipAdvert,
            GossipChunkRequest = GossipChunkRequest,
            GossipChunk = GossipChunk,
            NodeId = NodeId,
            TransportNotification = TransportNotification,
            Ingress = SignedIngress,
        > + Send
        + Sync,
>;

// Peer flow map :    |NodeId -> BoundedFlow|
// It also encapsulates the task processing the received messages.
struct PeerFlowQueueMap<T: Send + 'static> {
    // Ends need to be thread-safe to support concurrent node
    // addition and polling.
    send_map: SendMap<T>,
    mgmt_cmd_send: MgmtCmdSend<T>,
    // mutex for interior mutability
    recv_task_handle: Mutex<Option<JoinHandle<()>>>,
    mgmt_cmd_receive: Mutex<Option<MgmtCmdReceive<T>>>,
}

impl<T: Send + 'static> Default for PeerFlowQueueMap<T> {
    fn default() -> Self {
        let (mgmt_cmd_send, mgmt_cmd_receive) = crossbeam_channel::unbounded();
        Self {
            send_map: Arc::new(RwLock::new(BTreeMap::new())),
            mgmt_cmd_send,
            mgmt_cmd_receive: Mutex::new(Some(mgmt_cmd_receive)),
            recv_task_handle: Mutex::new(None),
        }
    }
}

impl<T: Send + 'static> PeerFlowQueueMap<T> {
    fn start<F>(&self, fn_consume_message: F)
    where
        F: Fn(T, NodeId) + Clone + Send + 'static,
    {
        let mgmt_cmd_receive = self.mgmt_cmd_receive.lock().unwrap().take().unwrap();
        let recv_task_handle = Handle::current().spawn_blocking(move || {
            Self::process_messages(mgmt_cmd_receive, fn_consume_message);
        });

        self.recv_task_handle
            .lock()
            .unwrap()
            .replace(recv_task_handle)
            .ok_or(0)
            .expect_err("Handler already started");
    }

    fn stop(&self) {
        self.mgmt_cmd_send
            .send(ManagementCommands::Stop)
            .expect("Failed to send ManagementCommands::Stop command");
        if let Some(handle) = self.recv_task_handle.lock().unwrap().take() {
            spawn_and_wait(handle).unwrap();
        }
    }

    // event handler loop: does a select() on receivers and
    // dispatch.
    fn process_messages<F>(mut mgmt_cmd_receive: MgmtCmdReceive<T>, fn_consume_message: F)
    where
        F: Fn(T, NodeId) + Clone + 'static,
    {
        let mut recv_map: RecvMap<T> = Vec::with_capacity(MAX_PEERS_HINT);
        while Self::process_mgmt_cmds(&mut recv_map, &mut mgmt_cmd_receive).is_ok() {
            let recv_futs = recv_map
                .iter_mut()
                .map(|(_, recv)| recv.recv().boxed())
                .collect::<Vec<_>>();
            let mut timeout = time::delay_for(Duration::from_millis(500));
            let received_item = Handle::current().block_on(async move {
                tokio::select! {
                            _ = & mut timeout => { None }
                            (item, idx, _rem) = select_all(recv_futs) => {
                Some((item,  idx))
                            }
                }
            });

            // process the ready channel up to BATCH_LIMIT
            if let Some((item, idx)) = received_item {
                if let Some(item) = item {
                    let mut batch = Vec::with_capacity(BATCH_LIMIT);
                    batch.push(item);
                    while let Ok(item) = recv_map[idx].1.try_recv() {
                        batch.push(item);
                        if batch.len() >= BATCH_LIMIT {
                            break;
                        }
                    }
                    let node_id = recv_map[idx].0;
                    for item in batch.into_iter() {
                        fn_consume_message(item, node_id);
                    }

                    // reorder recv map
                    let t = recv_map.remove(idx);
                    recv_map.push(t);
                }
            }
        }
    }

    fn process_mgmt_cmds(
        recv_map: &mut RecvMap<T>,
        mgmt_cmd_receive: &mut MgmtCmdReceive<T>,
    ) -> P2PResult<()> {
        loop {
            match mgmt_cmd_receive.try_recv() {
                Ok(cmd) => match cmd {
                    ManagementCommands::AddPeer(node_id, receiver) => {
                        recv_map.push((node_id, receiver));
                    }
                    ManagementCommands::Stop => return P2PErrorCode::ChannelShutDown.into(),
                },
                Err(crossbeam_channel::TryRecvError::Empty) => return Ok(()),
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    return P2PErrorCode::ChannelShutDown.into()
                }
            }
        }
    }

    fn add_node(&self, node_id: NodeId, buffer: usize) {
        let mut send_map = self.send_map.write().unwrap();
        if !send_map.contains_key(&node_id) {
            let (send, recv) = channel(max(1, buffer));
            send_map.insert(node_id, send);

            self.mgmt_cmd_send
                .send(ManagementCommands::AddPeer(node_id, recv))
                .expect("Failed to send ManagementCommands::AddPeer command");
        }
    }
}

#[derive(Default)]
struct PeerFlows {
    /*
     * Do not make a discriminated union. The variant size difference is
     * large.  clippy::large_enum_variant
     */
    advert: PeerFlowQueueMap<GossipAdvert>,
    request: PeerFlowQueueMap<GossipChunkRequest>,
    chunk: PeerFlowQueueMap<GossipChunk>,
    retransmission: PeerFlowQueueMap<GossipRetransmissionRequest>,
    send_advert: PeerFlowQueueMap<GossipAdvert>,
    transport: PeerFlowQueueMap<TransportNotification>,
}

impl PeerFlows {
    // start the p2p event handler loop for the individual flow types.
    pub fn start(&self, gossip: GossipArc) {
        for flow_type in FlowType::iter() {
            let c_gossip = gossip.clone();
            match flow_type {
                FlowType::Advert => {
                    self.advert.start(move |item, peer_id| {
                        c_gossip.on_advert(item, peer_id);
                    });
                }
                FlowType::Request => {
                    self.request.start(move |item, peer_id| {
                        c_gossip.on_chunk_request(item, peer_id);
                    });
                }
                FlowType::Chunk => {
                    self.chunk.start(move |item, peer_id| {
                        c_gossip.on_chunk(item, peer_id);
                    });
                }
                FlowType::Retransmission => {
                    self.retransmission.start(move |item, peer_id| {
                        c_gossip.on_retransmission_request(item, peer_id);
                    });
                }
                FlowType::Transport => {
                    self.transport.start(move |item, _peer_id| match item {
                        TransportNotification::TransportStateChange(state_change) => {
                            c_gossip.on_transport_state_change(state_change)
                        }
                        TransportNotification::TransportError(error) => {
                            c_gossip.on_transport_error(error)
                        }
                    });
                }
                FlowType::SendAdvert => {
                    self.send_advert
                        .start(move |item, _peer_id| c_gossip.broadcast_advert(item));
                }
            }
        }
    }

    fn add_node(&self, node_id: NodeId, channel_config: &ChannelConfig) {
        for flow_type in FlowType::iter() {
            let flow_type = &flow_type;
            match flow_type {
                FlowType::Advert => self.advert.add_node(node_id, channel_config.map[flow_type]),
                FlowType::Request => self
                    .request
                    .add_node(node_id, channel_config.map[flow_type]),
                FlowType::Chunk => self.chunk.add_node(node_id, channel_config.map[flow_type]),
                FlowType::Retransmission => self
                    .retransmission
                    .add_node(node_id, channel_config.map[flow_type]),
                FlowType::Transport => self
                    .transport
                    .add_node(node_id, channel_config.map[flow_type]),
                FlowType::SendAdvert => self
                    .send_advert
                    .add_node(node_id, channel_config.map[flow_type]),
            };
        }
    }

    fn stop(&self) {
        for flow_type in FlowType::iter() {
            let flow_type = &flow_type;
            match flow_type {
                FlowType::Advert => self.advert.stop(),
                FlowType::Request => self.request.stop(),
                FlowType::Chunk => self.chunk.stop(),
                FlowType::Retransmission => self.retransmission.stop(),
                FlowType::Transport => self.transport.stop(),
                FlowType::SendAdvert => self.send_advert.stop(),
            };
        }
    }
}

pub(crate) type IngressThrottle = Arc<RwLock<dyn IngressPoolThrottler + Send + Sync>>;
// Implements the async event handler traits for consumption by the
// transport, ingress, artifact manager, and node add+remove.
pub(crate) struct P2PEventHandlerImpl {
    node_id: NodeId,      // replica node id
    _subnet_id: SubnetId, // replica subnetid

    log: ReplicaLogger,
    pub metrics: EventHandlerMetrics,

    channel_config: ChannelConfig,
    peer_flows: PeerFlows, // per peer per  flow a map.
}

const MAX_PEERS_HINT: usize = 100;
const BATCH_LIMIT: usize = 100;

pub(crate) const MAX_ADVERT_BUFFER: usize = 100_000;
pub(crate) const MAX_TRANSPORT_BUFFER: usize = 1000;
pub(crate) const MAX_RETRANSMISSION_BUFFER: usize = 1000;
#[derive(Default)]
struct ChannelConfig {
    map: BTreeMap<FlowType, usize>,
}
impl From<GossipConfig> for ChannelConfig {
    fn from(gossip_config: GossipConfig) -> Self {
        let max_outstanding_buffer = gossip_config
            .max_artifact_streams_per_peer
            .try_into()
            .unwrap();
        Self {
            map: FlowType::iter()
                .map(|flow_type| match flow_type {
                    FlowType::Advert => (flow_type, MAX_ADVERT_BUFFER),
                    FlowType::Request => (flow_type, max_outstanding_buffer),
                    FlowType::Chunk => (flow_type, max_outstanding_buffer),
                    FlowType::Retransmission => (flow_type, MAX_RETRANSMISSION_BUFFER),
                    FlowType::Transport => (flow_type, MAX_TRANSPORT_BUFFER),
                    FlowType::SendAdvert => (flow_type, MAX_ADVERT_BUFFER),
                })
                .collect(),
        }
    }
}

impl P2PEventHandlerImpl {
    #[allow(dead_code, clippy::too_many_arguments)] // pending integration with P2P crate
    pub(crate) fn new(
        node_id: NodeId,
        _subnet_id: SubnetId,
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
        gossip_config: GossipConfig,
    ) -> Self {
        let handler = P2PEventHandlerImpl {
            node_id,
            _subnet_id,
            log,
            metrics: EventHandlerMetrics::new(metrics_registry),
            channel_config: ChannelConfig::from(gossip_config),
            peer_flows: Default::default(),
        };
        handler
            .peer_flows
            .add_node(node_id, &handler.channel_config);
        handler
    }
}

impl P2PEventHandlerControl for P2PEventHandlerImpl {
    fn start(&self, gossip_arc: GossipArc) {
        self.peer_flows.start(gossip_arc);
    }

    fn stop(&self) {
        self.peer_flows.stop();
    }

    // Add a node to the event handler. Message from nodes that are
    // not found in the peer flow maps are not processed
    fn add_node(&self, node_id: NodeId) {
        self.peer_flows.add_node(node_id, &self.channel_config);
    }
}

#[async_trait]
impl AsyncTransportEventHandler for P2PEventHandlerImpl {
    async fn send_message(&self, flow: FlowId, message: TransportPayload) -> Result<(), SendError> {
        let gossip_message = <pb::GossipMessage as ProtoProxy<GossipMessage>>::proxy_decode(
            &message.0,
        )
        .map_err(|e| {
            trace!(self.log, "Deserialization failed {}", e);
            SendError::DeserializationFailed
        })?;
        let start_time = std::time::Instant::now();
        let (msg_type, ret) = match gossip_message {
            GossipMessage::Advert(msg) => {
                let mut sender = {
                    let send_map = self.peer_flows.advert.send_map.read().unwrap();
                    send_map
                        .get(&flow.peer_id)
                        .ok_or(SendError::EndpointNotFound)?
                        .clone()
                };
                ("Advert", {
                    match sender.try_send(msg) {
                        Err(e) => {
                            let msg = match e {
                                TrySendError::Full(a) => a,
                                TrySendError::Closed(a) => a,
                            };
                            self.metrics.adverts_blocked.inc();
                            sender
                                .send(msg)
                                .await
                                .map_err(|_| SendError::EndpointClosed)
                        }
                        Ok(_) => Ok(()),
                    }
                })
            }
            GossipMessage::ChunkRequest(msg) => {
                let mut sender = {
                    let send_map = self.peer_flows.request.send_map.read().unwrap();
                    send_map
                        .get(&flow.peer_id)
                        .ok_or(SendError::EndpointNotFound)?
                        .clone()
                };
                ("Request", {
                    match sender.try_send(msg) {
                        Err(e) => {
                            let msg = match e {
                                TrySendError::Full(a) => a,
                                TrySendError::Closed(a) => a,
                            };
                            self.metrics.requests_blocked.inc();
                            sender
                                .send(msg)
                                .await
                                .map_err(|_| SendError::EndpointClosed)
                        }
                        Ok(_) => Ok(()),
                    }
                })
            }
            GossipMessage::Chunk(msg) => {
                let mut sender = {
                    let send_map = self.peer_flows.chunk.send_map.read().unwrap();
                    send_map
                        .get(&flow.peer_id)
                        .ok_or(SendError::EndpointNotFound)?
                        .clone()
                };
                ("Chunk", {
                    match sender.try_send(msg) {
                        Err(e) => {
                            let msg = match e {
                                TrySendError::Full(a) => a,
                                TrySendError::Closed(a) => a,
                            };
                            self.metrics.chunks_blocked.inc();
                            sender
                                .send(msg)
                                .await
                                .map_err(|_| SendError::EndpointClosed)
                        }
                        Ok(_) => Ok(()),
                    }
                })
            }
            GossipMessage::RetransmissionRequest(msg) => {
                let mut sender = {
                    let send_map = self.peer_flows.retransmission.send_map.read().unwrap();
                    send_map
                        .get(&flow.peer_id)
                        .ok_or(SendError::EndpointNotFound)?
                        .clone()
                };
                ("Retransmission", {
                    match sender.try_send(msg) {
                        Err(e) => {
                            let msg = match e {
                                TrySendError::Full(a) => a,
                                TrySendError::Closed(a) => a,
                            };
                            self.metrics.retransmissions_blocked.inc();
                            sender
                                .send(msg)
                                .await
                                .map_err(|_| SendError::EndpointClosed)
                        }
                        Ok(_) => Ok(()),
                    }
                })
            }
        };
        self.metrics
            .send_message_duration_msec
            .with_label_values(&[msg_type])
            .observe(start_time.elapsed().as_millis() as f64);
        ret
    }

    async fn state_changed(&self, state_change: transport::TransportStateChange) {
        let mut sender = {
            let send_map = self.peer_flows.transport.send_map.read().unwrap();
            send_map
                .get(&self.node_id)
                .expect("Self Node channel not setup")
                .clone()
        };
        sender
            .send(TransportNotification::TransportStateChange(state_change))
            .await
            .unwrap_or_else(|e| {
                // panic as we  will be blocking re-transmission requests at this point.
                panic!(format!("Failed to dispatch transport state change {:?}", e))
            });
    }

    async fn error(&self, flow: FlowId, error: TransportErrorCode) {
        if let TransportErrorCode::SenderErrorIndicated = error {
            let mut sender = {
                let send_map = self.peer_flows.transport.send_map.read().unwrap();
                send_map
                    .get(&self.node_id)
                    .expect("Self Node channel not setup")
                    .clone()
            };
            sender
                .send(TransportNotification::TransportError(
                    TransportError::TransportSendError(TransportFlowInfo {
                        peer_id: flow.peer_id,
                        flow_tag: flow.flow_tag,
                    }),
                ))
                .await
                .unwrap_or_else(|e| {
                    // panic as we  will be blocking re-transmission requests at this point.
                    panic!(format!("Failed to dispatch transport error {:?}", e))
                });
        }
    }
}

// Interface between the ingress handler and P2P
pub(crate) struct IngressEventHandlerImpl {
    ingress_throttle: IngressThrottle,
    c_gossip: GossipArc,
    node_id: NodeId,
}

impl IngressEventHandlerImpl {
    pub fn new(ingress_throttle: IngressThrottle, c_gossip: GossipArc, node_id: NodeId) -> Self {
        Self {
            ingress_throttle,
            c_gossip,
            node_id,
        }
    }
}

impl IngressEventHandler for IngressEventHandlerImpl {
    fn can_accept_user_request(&self) -> bool {
        !self.ingress_throttle.read().unwrap().exceeds_threshold()
    }

    fn on_ingress_message(
        &self,
        signed_ingress: SignedIngress,
    ) -> Result<(), OnArtifactError<Artifact>> {
        self.c_gossip.on_user_ingress(signed_ingress, self.node_id)
    }
}

// Interface between Artifact Manager and P2P.
pub(crate) trait AdvertSubscriber {
    fn broadcast_advert(&self, advert: GossipAdvert);
}

impl AdvertSubscriber for P2PEventHandlerImpl {
    fn broadcast_advert(&self, advert: GossipAdvert) {
        let mut sender = {
            let send_map = self.peer_flows.send_advert.send_map.read().unwrap();
            // channel for self.node_id is populated in the constructor
            send_map.get(&self.node_id).unwrap().clone()
        };
        sender
            .try_send(advert)
            .or_else::<TrySendError<GossipAdvert>, _>(|e| {
                if let TrySendError::Closed(_) = e {
                    info!(self.log, "Send advert channel closed");
                };
                Ok(())
            })
            .unwrap();
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub mod tests {
    use super::*;
    use crate::download_prioritization::test::make_gossip_advert;
    use ic_interfaces::ingress_pool::IngressPoolThrottler;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::{
        p2p::p2p_test_setup_logger,
        p2p::P2P_SUBNET_ID_DEFAULT,
        types::ids::{node_test_id, subnet_test_id},
    };
    use ic_types::transport::FlowTag;
    use ic_types::transport::TransportStateChange;
    use tokio::time::{delay_for, Duration};

    struct TestThrottle();
    impl IngressPoolThrottler for TestThrottle {
        fn exceeds_threshold(&self) -> bool {
            false
        }
    }

    type ItemCountCollector = Mutex<BTreeMap<NodeId, usize>>;
    struct TestGossip {
        node_id: NodeId,
        advert_processing_delay: Duration,
        num_adverts: ItemCountCollector,
        num_chunks: ItemCountCollector,
        num_reqs: ItemCountCollector,
        num_ingress: ItemCountCollector,
        num_changes: ItemCountCollector,
        num_advert_bcasts: ItemCountCollector,
    }

    impl TestGossip {
        fn new(advert_processing_delay: Duration, node_id: NodeId) -> Self {
            TestGossip {
                node_id,
                advert_processing_delay,
                num_adverts: Default::default(),
                num_chunks: Default::default(),
                num_reqs: Default::default(),
                num_ingress: Default::default(),
                num_changes: Default::default(),
                num_advert_bcasts: Default::default(),
            }
        }

        fn increment_or_set(map: &ItemCountCollector, peer_id: NodeId) {
            let map_i = &mut map.lock().unwrap();
            map_i.entry(peer_id).and_modify(|e| *e += 1).or_insert(1);
        }

        fn get_node_flow_count(map: &ItemCountCollector, node_id: NodeId) -> usize {
            let map_i = &mut map.lock().unwrap();
            *map_i.get(&node_id).or(Some(&0)).unwrap()
        }
    }

    impl Gossip for TestGossip {
        type GossipAdvert = GossipAdvert;
        type GossipChunkRequest = GossipChunkRequest;
        type GossipChunk = GossipChunk;
        type NodeId = NodeId;
        type TransportNotification = TransportNotification;
        type Ingress = SignedIngress;

        fn on_advert(&self, _gossip_advert: Self::GossipAdvert, peer_id: Self::NodeId) {
            std::thread::sleep(self.advert_processing_delay);
            TestGossip::increment_or_set(&self.num_adverts, peer_id);
        }

        fn on_chunk_request(&self, _gossip_request: GossipChunkRequest, peer_id: NodeId) {
            TestGossip::increment_or_set(&self.num_reqs, peer_id);
        }

        fn on_chunk(&self, _gossip_artifact: Self::GossipChunk, peer_id: Self::NodeId) {
            TestGossip::increment_or_set(&self.num_chunks, peer_id);
        }

        fn on_transport_state_change(&self, transport_state_change: TransportStateChange) {
            let peer_id = match transport_state_change {
                TransportStateChange::PeerFlowUp(x) => x,
                TransportStateChange::PeerFlowDown(x) => x,
            }
            .peer_id;
            TestGossip::increment_or_set(&self.num_changes, peer_id);
        }

        fn on_retransmission_request(
            &self,
            _gossip_request: GossipRetransmissionRequest,
            _node_id: NodeId,
        ) {
            todo!()
        }

        fn on_timer(&self, _event_handler: &Arc<dyn P2PEventHandlerControl>) {
            todo!()
        }

        fn on_user_ingress(
            &self,
            _ingress: Self::Ingress,
            peer_id: Self::NodeId,
        ) -> Result<(), OnArtifactError<Artifact>> {
            TestGossip::increment_or_set(&self.num_ingress, peer_id);
            Ok(())
        }

        fn broadcast_advert(&self, _advert: GossipAdvert) {
            TestGossip::increment_or_set(&self.num_advert_bcasts, self.node_id);
        }

        fn on_transport_error(&self, _transport_error: TransportError) {
            // Do nothing
        }
    }

    pub(crate) fn new_test_event_handler(
        advert_max_depth: usize,
        node_id: NodeId,
    ) -> P2PEventHandlerImpl {
        let mut handler = P2PEventHandlerImpl::new(
            node_id,
            subnet_test_id(P2P_SUBNET_ID_DEFAULT),
            p2p_test_setup_logger().root.clone().into(),
            &MetricsRegistry::new(),
            ic_types::p2p::build_default_gossip_config(),
        );
        handler
            .channel_config
            .map
            .insert(FlowType::Advert, advert_max_depth);
        handler
    }

    async fn send_advert(count: usize, handler: &P2PEventHandlerImpl, peer_id: NodeId) {
        for i in 0..count {
            let message = GossipMessage::Advert(make_gossip_advert(i as u64));
            let message = TransportPayload(pb::GossipMessage::proxy_encode(message).unwrap());
            let _ = handler
                .send_message(
                    FlowId {
                        client_type: transport::TransportClientType::P2P,
                        peer_id,
                        flow_tag: FlowTag::from(0),
                    },
                    message,
                )
                .await;
        }
    }

    async fn bcast_advert(count: usize, handler: &P2PEventHandlerImpl) {
        for i in 0..count {
            let message = make_gossip_advert(i as u64);
            handler.broadcast_advert(message);
        }
    }

    async fn event_handler_start_stop_int() {
        let node_test_id = node_test_id(0);
        let handler = new_test_event_handler(MAX_ADVERT_BUFFER, node_test_id);
        handler.start(Arc::new(TestGossip::new(
            Duration::from_secs(0),
            node_test_id,
        )));
        handler.stop();
    }

    async fn event_handler_advert_dispatch_int() {
        let node_test_id = node_test_id(0);
        let handler = new_test_event_handler(MAX_ADVERT_BUFFER, node_test_id);
        handler.start(Arc::new(TestGossip::new(
            Duration::from_secs(0),
            node_test_id,
        )));
        send_advert(100, &handler, node_test_id).await;
        handler.stop();
    }

    async fn event_handler_slow_consumer_int() {
        let node_id = node_test_id(0);
        let handler = new_test_event_handler(1, node_id);
        handler.start(Arc::new(TestGossip::new(Duration::from_millis(3), node_id)));
        // send adverts
        send_advert(10, &handler, node_id).await;
        handler.stop();
    }

    async fn event_handler_add_remove_nodes_int() {
        let node_id = node_test_id(0);
        let handler = Arc::new(new_test_event_handler(1, node_id));

        for node_idx in 0..64 {
            handler.add_node(node_test_id(node_idx));
        }
        handler.start(Arc::new(TestGossip::new(Duration::from_secs(0), node_id)));
        send_advert(100, &handler, node_id).await;
        handler.stop();
    }

    #[tokio::test(threaded_scheduler)]
    async fn event_handler_max_channel_capacity() {
        let node_id = node_test_id(0);
        let handler = Arc::new(new_test_event_handler(MAX_ADVERT_BUFFER, node_id));
        let node_test_id = node_test_id(0);
        let gossip_arc = Arc::new(TestGossip::new(Duration::from_secs(0), node_id));
        handler.start(gossip_arc.clone());

        send_advert(MAX_ADVERT_BUFFER, &handler, node_test_id).await;
        loop {
            let num_adverts = TestGossip::get_node_flow_count(&gossip_arc.num_adverts, node_id);
            assert!(num_adverts <= MAX_ADVERT_BUFFER);
            if num_adverts == MAX_ADVERT_BUFFER {
                break;
            }
            delay_for(Duration::from_millis(1000)).await;
        }

        bcast_advert(MAX_ADVERT_BUFFER, &handler).await;
        loop {
            let num_adverts =
                TestGossip::get_node_flow_count(&gossip_arc.num_advert_bcasts, node_id);
            assert!(num_adverts <= MAX_ADVERT_BUFFER);
            if num_adverts == MAX_ADVERT_BUFFER {
                break;
            }
            delay_for(Duration::from_millis(1000)).await;
        }
    }

    #[tokio::test(threaded_scheduler)]
    async fn event_handler_multithreaded_rt() {
        event_handler_start_stop_int().await;
        event_handler_advert_dispatch_int().await;
        event_handler_slow_consumer_int().await;
        event_handler_add_remove_nodes_int().await;
    }
}
