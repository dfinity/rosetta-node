/// Gossip protocol
///
/// This file implements the Gossip broadcast for the internet
/// computer(IC).
///
/// Spec at
///
/// rs/docs/spec/replica/protocol/p2p/gossip/index.adoc
///
/// Summary.
///
/// Gossip protocol implements artifact pools with eventual/
/// bounded delivery guarantees for its clients. Artifacts in these
/// pools are treated as binary blob structures by the P2P
/// layer. The primary data structures are
///
/// (a) peer context that tracks the per peer download activity.
///
/// (b) global list of artifacts currently under construction
/// (being downloaded).
///
/// Only under construction artifacts are owned by P2P layer, once
/// complete these objects are handed over to the artifact manager
/// that manages various application pools.
///
/// Overall protocol activity is controlled using the flow of.
/// (a) adverts,           [Serialized over the wire]
/// (b) requests, and      [Serialized over the wire]
/// (c) artifact chunks    [Serialized over the wire]
///
/// The above objects that are serialized over the wire should
/// conform to IC on-wire protocol spec.  Internally an
/// implementation may choose to have augmented structures that
/// describe implementation specific details of the above
/// on-wire concepts.
//
/// Underlying network model.
///
/// The underlying network model provided by transport is fire
/// and forget. I.e. adverts, requests, chunks, artifacts and
/// other messages exchanged over the transport have no delivery
/// guarantees.  With this transport model P2P implementation
/// has to be made idempotent, such that multiple
/// (advert,request,chunks) transmissions should not affect the
/// protocol.  In other words P2P guarantees  "at least once"
/// delivery semantics for artifacts prioritized by the client.
///
/// Artifact retention and transmission prioritization is left
/// up to client applications. I.e. applications are to retain
/// objects until they get side-band signals of objects being
/// fully/sufficiently gossiped. Ex. Consensus purges artifact
/// that are older than a certain height. State manager only retains
/// artifacts corresponding to few latest Heights.
use crate::{
    download_management::{DownloadManager, DownloadManagerImpl},
    metrics::GossipMetrics,
    P2PError, P2PErrorCode, P2PResult,
};

use ic_artifact_manager::artifact::IngressArtifact;
use ic_interfaces::artifact_manager::{ArtifactManager, OnArtifactError};
use ic_logger::{info, replica_logger::ReplicaLogger, warn};
use ic_metrics::MetricsRegistry;
use ic_protobuf::p2p::v1 as pb;
use ic_protobuf::p2p::v1::gossip_chunk::Response;
use ic_protobuf::p2p::v1::gossip_message::Body;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError, ProxyDecodeError::*};
use ic_types::{
    artifact::{Artifact, ArtifactFilter, ArtifactId, ArtifactKind},
    chunkable::{ArtifactChunk, ArtifactChunkData, ChunkId},
    messages::SignedIngress,
    p2p::GossipAdvert,
    transport::{FlowTag, TransportError, TransportNotification, TransportStateChange},
    NodeId,
};

use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

use bincode::{deserialize, serialize};

// import of malicious flags definition
use crate::{
    event_handler::P2PEventHandlerControl, use_gossip_malicious_behavior_on_chunk_request,
};
use ic_types::{malicious_flags::MaliciousFlags, SubnetId};

/// Spec description as a abstract type class.
/// ------------------------------------------------
///
/// The following trait exist to document/highlight aspect of the
/// spec.
///
/// Trait uses to associated types to keep the spec description
/// completely generic.
pub(crate) trait Gossip {
    type GossipAdvert;
    type GossipChunkRequest;
    type GossipChunk;
    type NodeId;
    type TransportNotification;
    type Ingress;

    // Handle adverts from other peers.
    fn on_advert(&self, gossip_advert: Self::GossipAdvert, peer_id: Self::NodeId);

    // Handle chunk request from other peers.
    fn on_chunk_request(&self, gossip_request: GossipChunkRequest, node_id: NodeId);

    // Adds the requested chunk to the artifact under construction and
    // presents it to the artifact manager when complete.
    fn on_chunk(&self, gossip_chunk: Self::GossipChunk, peer_id: Self::NodeId);

    // Add user ingress to the artifact manager
    fn on_user_ingress(
        &self,
        ingress: Self::Ingress,
        peer_id: Self::NodeId,
    ) -> Result<(), OnArtifactError<Artifact>>;

    // broadcast artifact manager advert stream to peers
    fn broadcast_advert(&self, advert: GossipAdvert);

    // Listens for a request from other peers.
    fn on_retransmission_request(
        &self,
        gossip_request: GossipRetransmissionRequest,
        node_id: NodeId,
    );

    // Listen to network events as the peers get
    // connected/disconnected.
    //
    // Missing disconnect events in case of dropped connections are
    // detected and handled using request timeouts.Timeouts thus form
    // the method for explicit detection of dropped connections.  P2P
    // guarantees liveness relying on a) timeouts for each request b)
    // Transport having an additional error detection mechanism (not
    // implemented yet)
    fn on_transport_state_change(&self, transport_state_change: TransportStateChange);

    fn on_transport_error(&self, transport_error: TransportError);

    // Periodic invocation of P2P on_timer guarantees  IC liveness.
    //
    // For example this function ..
    //
    // - periodically polls all artifact clients, thus allowing the
    // this IC to progress without the need for any external triggers.
    //
    // - periodically evaluates each peer for request timeouts and
    // advert download eligibility
    //
    // on_timer exists for providing Livneness guarantees, and at
    // times might do redundant work like polling peers even if there
    // is no material change in their advert queue states. On timer is
    // catch-all for a periodic and holistic refresh of IC state.
    fn on_timer(&self, event_handler: &Arc<dyn P2PEventHandlerControl>);
}

/// Request of an artifact sent to the peer
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct GossipChunkRequest {
    pub artifact_id: ArtifactId,
    pub chunk_id: ChunkId,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct GossipRetransmissionRequest {
    pub filter: ArtifactFilter,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct GossipChunk {
    pub artifact_id: ArtifactId,
    pub chunk_id: ChunkId,
    pub artifact_chunk: P2PResult<ArtifactChunk>,
}

// This is the message exchanged on the wire with the peers. This is private to
// the gossip layer. Lower layers like transport don't need to interpret the
// content.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum GossipMessage {
    Advert(GossipAdvert),
    ChunkRequest(GossipChunkRequest),
    Chunk(GossipChunk),
    RetransmissionRequest(GossipRetransmissionRequest),
}

impl Into<FlowTag> for &GossipMessage {
    fn into(self) -> FlowTag {
        FlowTag::from(0)
    }
}

pub(crate) struct GossipImpl {
    // Use component model for  internal object. Components are
    // created by passing trait object defining interfaces to other
    // components followed by configuration parameters for the component.
    _node_id: NodeId,
    _subnet_id: SubnetId,
    pub download_manager: DownloadManagerImpl,
    pub artifact_manager: Arc<dyn ArtifactManager>,
    log: ReplicaLogger,
    pub metrics: GossipMetrics,
    malicious_flags: MaliciousFlags,
}

impl GossipImpl {
    /// Create a new gossip component for the p2p functionality.
    ///
    /// The gossip component interacts the peer manager component that
    /// initiates and tracks downloads of artifacts from a peer group.
    ///
    ///  Parameters:
    /// malicious_flags To enable implementing malicious behavior for testing
    /// purposes.  download_manager      An implementation of the
    /// DownloadManager trait  log               Logger instance for the
    /// replica  metrics_registry  Registry instance for the replica
    pub fn new(
        _node_id: NodeId,
        _subnet_id: SubnetId,
        download_manager: DownloadManagerImpl,
        artifact_manager: Arc<dyn ArtifactManager>,
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        GossipImpl {
            _node_id,
            _subnet_id,
            malicious_flags,
            download_manager,
            artifact_manager,
            log,
            metrics: GossipMetrics::new(metrics_registry),
        }
    }

    // Helper functions
    fn serve_chunk(&self, gossip_request: &GossipChunkRequest) -> P2PResult<ArtifactChunk> {
        self.artifact_manager
            .get_validated_by_identifier(&gossip_request.artifact_id)
            .ok_or_else(|| {
                self.metrics.chunk_req_not_found.inc();
                P2PError {
                    p2p_error_code: P2PErrorCode::NotFound,
                }
            })?
            .get_chunk(gossip_request.chunk_id)
            .ok_or_else(|| {
                self.metrics.chunk_req_not_found.inc();
                P2PError {
                    p2p_error_code: P2PErrorCode::NotFound,
                }
            })
    }
    // This function is called when a new artifact (chunk) request is received
    //
    // XXX: Spec Code is missing specification of rogue client requesting chunks
    fn on_chunk_request(&self, gossip_request: GossipChunkRequest, node_id: NodeId) {
        let start = std::time::Instant::now();
        let artifact_chunk = self.serve_chunk(&gossip_request);
        self.metrics
            .op_duration
            .with_label_values(&["serve_chunk"])
            .observe(start.elapsed().as_millis() as f64);
        let gossip_chunk = GossipChunk {
            artifact_id: gossip_request.artifact_id.clone(),
            chunk_id: gossip_request.chunk_id,
            artifact_chunk,
        };
        use_gossip_malicious_behavior_on_chunk_request!(
            self,
            self.malicious_behavior_on_chunk_request(gossip_chunk, node_id),
            {
                self.download_manager
                    .send_chunk_to_peer(gossip_chunk, node_id);
            }
        );
    }

    fn malicious_behavior_on_chunk_request(&self, gossip_chunk: GossipChunk, node_id: NodeId) {
        if self.malicious_flags.maliciously_gossip_drop_requests {
            warn!(self.log, "Malicious behavior: dropping requests");
        } else if self.malicious_flags.maliciously_gossip_artifact_not_found {
            warn!(self.log, "Malicious behavior: artifact not found");
            let chunk_not_found = GossipChunk {
                artifact_id: gossip_chunk.artifact_id,
                chunk_id: gossip_chunk.chunk_id,
                artifact_chunk: Err(P2PError {
                    p2p_error_code: P2PErrorCode::NotFound,
                }),
            };
            self.download_manager
                .send_chunk_to_peer(chunk_not_found, node_id);
        } else if self.malicious_flags.maliciously_gossip_send_many_artifacts {
            warn!(self.log, "Malicious behavior: sending too many artifacts");
            for _n in 1..10000 {
                self.download_manager
                    .send_chunk_to_peer(gossip_chunk.clone(), node_id);
            }
        } else if self
            .malicious_flags
            .maliciously_gossip_send_invalid_artifacts
        {
            warn!(self.log, "Malicious behavior: sending invalid artifacts");
            let artifact_id = gossip_chunk.artifact_id;
            let chunk_id = gossip_chunk.chunk_id;
            let artifact_chunk_data = ArtifactChunkData::SemiStructuredChunkData([].to_vec());
            let artifact_chunk = Ok(ArtifactChunk {
                chunk_id,
                witness: Default::default(),
                artifact_chunk_data,
            });
            let invalid_chunk = GossipChunk {
                artifact_id,
                chunk_id,
                artifact_chunk,
            };
            self.download_manager
                .send_chunk_to_peer(invalid_chunk, node_id);
        } else {
            warn!(self.log, "Malicious behavior: This should never happen!");
        }
    }
}

/// Canonical Implementation for the Gossip Trait as per DFN Spec
impl Gossip for GossipImpl {
    type GossipAdvert = GossipAdvert;
    type GossipChunkRequest = GossipChunkRequest;
    type GossipChunk = GossipChunk;
    type NodeId = NodeId;
    type TransportNotification = TransportNotification;
    type Ingress = SignedIngress;

    // Spec:
    // This function is called when a new advert is received.
    //
    //  - Checks and Skip artifacts that have already been downloaded.
    //
    //  - If the artifact is not found, peer manager queues on this
    //  advert onto the peer's advert list.
    //
    //    Once queued the heavy lifting is done by download_next. This
    //    includes
    //
    //    - Prioritizing downloads as per client's priority function
    //    - Tracking Chunks, timeouts, quota and errors
    fn on_advert(&self, gossip_advert: GossipAdvert, peer_id: NodeId) {
        if self
            .artifact_manager
            .has_artifact(&gossip_advert.artifact_id)
        {
            return;
        }

        // Peer manager manages all the structures for maintaining
        // download syncrhonization logic. At this point this file
        // only is shim tying various components together
        self.download_manager.on_advert(gossip_advert, peer_id);
        // TODO: handle/count to metric
        let _ = self.download_manager.download_next(peer_id);
    }

    fn on_chunk_request(&self, chunk_request: GossipChunkRequest, node_id: NodeId) {
        self.on_chunk_request(chunk_request, node_id)
    }

    fn on_chunk(&self, gossip_chunk: GossipChunk, peer_id: NodeId) {
        self.download_manager.on_chunk(gossip_chunk, peer_id);
        // TODO: handle/count to metric
        let _ = self.download_manager.download_next(peer_id);
    }

    fn on_user_ingress(
        &self,
        ingress: Self::Ingress,
        peer_id: Self::NodeId,
    ) -> Result<(), OnArtifactError<Artifact>> {
        let advert = IngressArtifact::to_advert(&ingress);
        self.artifact_manager
            .on_artifact(
                Artifact::IngressMessage(ingress.into()),
                advert.into(),
                &peer_id,
            )
            .map_err(|e| {
                info!(self.log, "Artifact not inserted {:?}", e);
                e
            })
    }

    // Invoked when a retransmission request is received. Get adverts of all
    // validated artifacts for the requested filter and send them to the peer.
    fn on_retransmission_request(
        &self,
        gossip_retransmission_request: GossipRetransmissionRequest,
        peer_id: NodeId,
    ) {
        let _ = self
            .download_manager
            .on_retransmission_request(&gossip_retransmission_request, peer_id);
    }

    fn on_transport_state_change(&self, transport_state_change: TransportStateChange) {
        warn!(
            self.log,
            "Transport state change: {:?}", transport_state_change
        );
        match transport_state_change {
            TransportStateChange::PeerFlowDown(info) => {
                self.download_manager.peer_connection_down(info.peer_id)
            }
            TransportStateChange::PeerFlowUp(info) => {
                self.download_manager.peer_connection_up(info.peer_id)
            }
        }
    }

    fn broadcast_advert(&self, advert: GossipAdvert) {
        self.download_manager.send_advert_to_peers(advert);
    }

    fn on_transport_error(&self, _transport_error: TransportError) {
        // TODO: Uncomment when using multiple flows in Transport and when
        // having the new throttling mechanisms in download_management
        // JIRA Tickets:
        // - Multiple flows: P2P-435
        // - Error handling: P2P-261
        //
        // We can't send a retransmission request without having multiple flows
        // support as we have to be able to clear the adverts queue (and
        // only it) before responding to such a request. Otherwise,
        // we'll have to clear the entire queue to that peer. This queue
        // may contain a retransmission request. So we must send a
        // retransmission request before the adverts (that are sent as a
        // response to a retransmission request from the other side).
        // This would create an infinite loop of retransmission
        // requests. We could throttle them (as we would anyway do even
        // with multiple flows support), but then we'll end up with
        // periodic retransmission and not event-based.
        /*
        let TransportError::TransportSendError(flow) = transport_error;
        let _ = self
            .download_manager
            .send_retransmission_request(flow.peer_id);
         */
    }

    // periodic timer callback for liveness
    fn on_timer(&self, event_handler: &Arc<dyn P2PEventHandlerControl>) {
        self.download_manager.on_timer(event_handler);
    }
}

impl From<GossipMessage> for pb::GossipMessage {
    fn from(message: GossipMessage) -> Self {
        match message {
            GossipMessage::Advert(a) => Self {
                body: Some(Body::Advert(a.into())),
            },
            GossipMessage::ChunkRequest(r) => Self {
                body: Some(Body::ChunkRequest(r.into())),
            },
            GossipMessage::Chunk(c) => Self {
                body: Some(Body::Chunk(c.into())),
            },
            GossipMessage::RetransmissionRequest(r) => Self {
                body: Some(Body::RetransmissionRequest(r.into())),
            },
        }
    }
}

impl TryFrom<pb::GossipMessage> for GossipMessage {
    type Error = ProxyDecodeError;
    fn try_from(message: pb::GossipMessage) -> Result<Self, Self::Error> {
        let body = message.body.ok_or(MissingField("GossipMessage::body"))?;
        let message = match body {
            Body::Advert(a) => Self::Advert(a.try_into()?),
            Body::ChunkRequest(r) => Self::ChunkRequest(r.try_into()?),
            Body::Chunk(c) => Self::Chunk(c.try_into()?),
            Body::RetransmissionRequest(r) => Self::RetransmissionRequest(r.try_into()?),
        };
        Ok(message)
    }
}

impl From<GossipChunkRequest> for pb::GossipChunkRequest {
    fn from(gossip_chunk_request: GossipChunkRequest) -> Self {
        Self {
            artifact_id: serialize(&gossip_chunk_request.artifact_id).unwrap(),
            chunk_id: gossip_chunk_request.chunk_id.get(),
        }
    }
}

impl TryFrom<pb::GossipChunkRequest> for GossipChunkRequest {
    type Error = ProxyDecodeError;
    fn try_from(gossip_chunk_request: pb::GossipChunkRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            artifact_id: deserialize(&gossip_chunk_request.artifact_id).unwrap(),
            chunk_id: ChunkId::from(gossip_chunk_request.chunk_id),
        })
    }
}

impl From<GossipChunk> for pb::GossipChunk {
    fn from(gossip_chunk: GossipChunk) -> Self {
        let response = match gossip_chunk.artifact_chunk {
            Ok(artifact_chunk) => Some(Response::Chunk(artifact_chunk.into())),
            // Add additional cases as required.
            Err(_) => Some(Response::Error(pb::P2pError::NotFound as i32)),
        };
        Self {
            artifact_id: serialize(&gossip_chunk.artifact_id).unwrap(),
            chunk_id: gossip_chunk.chunk_id.get(),
            response,
        }
    }
}

impl TryFrom<pb::GossipChunk> for GossipChunk {
    type Error = ProxyDecodeError;
    fn try_from(gossip_chunk: pb::GossipChunk) -> Result<Self, Self::Error> {
        let response = try_from_option_field(gossip_chunk.response, "GossipChunk.response")?;
        let chunk_id = ChunkId::from(gossip_chunk.chunk_id);
        Ok(Self {
            artifact_id: deserialize(&gossip_chunk.artifact_id).unwrap(),
            chunk_id,
            artifact_chunk: match response {
                Response::Chunk(c) => Ok(add_chunk_id(c.try_into()?, chunk_id)),
                Response::Error(_e) => Err(P2PError {
                    p2p_error_code: P2PErrorCode::NotFound,
                }),
            },
        })
    }
}

fn add_chunk_id(artifact_chunk: ArtifactChunk, chunk_id: ChunkId) -> ArtifactChunk {
    ArtifactChunk {
        chunk_id,
        witness: artifact_chunk.witness,
        artifact_chunk_data: artifact_chunk.artifact_chunk_data,
    }
}

impl From<GossipRetransmissionRequest> for pb::GossipRetransmissionRequest {
    fn from(gossip_request: GossipRetransmissionRequest) -> Self {
        Self {
            filter: Some(gossip_request.filter.into()),
        }
    }
}

impl TryFrom<pb::GossipRetransmissionRequest> for GossipRetransmissionRequest {
    type Error = ProxyDecodeError;
    fn try_from(
        gossip_retransmission_request: pb::GossipRetransmissionRequest,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            filter: try_from_option_field(
                gossip_retransmission_request.filter,
                "GossipRetransmissionRequest.filter",
            )?,
        })
    }
}
