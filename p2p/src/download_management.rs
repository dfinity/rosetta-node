use ic_protobuf::p2p::v1 as pb;
use ic_protobuf::proxy::ProtoProxy;
/// Peer Management maintains datastructures on adverts and download state
/// per peer as defined in the spec
///
/// A replica connects to peers according to the latest subnet record
/// membership used by consensus and the predecessor subnet record.
/// For each such peer the peer manager manages the list
/// of adverts and in flight chunk downloads.
///
/// The following data structures represent the state of the peer manager
/// and all ongoing download activity.
///
/// ```text
///   +---------------------+
///   |Download manager     |
///   |----------- ---------|   +------------------+    +----------+     +----------+
///   |UnderconstructionList|-->|Artifact          |....|Artifact  |.....|Artifact  |
///   |                     |   |Download          |    |Download  |     |Download  |
///   |                     |   |Tracker#1         |    |Tracker#2 |     |Tracker#N |
///   |                     |   |requested_instant |    |          |     |          |
///   |                     |   +------------------+    +----------+     +----------+
///   |                     |
///   |                     |
///   |          PeerList   |-->+-------------------------------------------+---> ....
///   |                     |   |Peer#1  (PeerContext)                      |
///   |                     |   +-------------------------------------------+
///   +---------------------+   |Peer Inflight Chunk "requested" map        |
///                             +-----------------------+-------------------+
///                             |Key                    |Value              |
///                             +-----------------------+-------------------+
///                             |ArtifactID +ChunkID    |requested_instant  |
///                             +-----------------------+-------------------+
///                             |...                    |                   |
///                             +-----------------------+-------------------+
/// ```
///
/// Locking Hierarchy:
///    Peer Context lock
///    Under construction list lock
///    Prioritizer Lock (R/W)
///    Advert tracker Lock (R/W)
///
/// Note on locking: Only the download_next_compute_work() workflow
/// *requires* acquisition of multiple/all locks in the correct order.
///
///    a. Peer context lock to update the peercontext 'requested' list.
///
///    b. Under construction list lock  to add new artifacts being constructed.
///
///    c. Prioritizer lock to iterate over adverts that are eligible for
///    download
///
///    d. Advert tracker lock to mark a download attempt on a advert.
///
/// All other workflows viz. 'on_timeout' 'on_chunk' etc DO NOT
/// require locks to be acquired simultaneously. The general approach
/// is to lock and copy out the state and then immediately drop the
/// lock before proceeding to acquire the next lock. The pattern is
///
///  // copy sate and drop locks!!!
///  let state = advert_tracker.lock().unwrap().[state].clone();
///  // next lock
///  prioritizer.lock().unwrap();
///
/// Locking hierarchy is irrelevant if only 1 lock is acquired at a time.
///
/// In theory the above locking rules prevent 'Circular Waits' and thus
/// guarantee deadlock avoidance.
pub(crate) trait DownloadManager {
    // Send adverts to all peers
    fn send_advert_to_peers(&self, gossip_advert: GossipAdvert);

    // React to advert from a peer
    fn on_advert(&self, gossip_advert: GossipAdvert, peer_id: NodeId);

    // Download chunks for the next prioritized advert
    fn download_next(&self, peer_id: NodeId) -> Result<(), Box<dyn Error>>;

    // Send a chunk to a peer
    fn send_chunk_to_peer(&self, gossip_chunk: GossipChunk, peer_id: NodeId);

    // React to a chunk received from a peer
    fn on_chunk(&self, gossip_chunk: GossipChunk, peer_id: NodeId);

    // React to a connection-related event received from Transport
    fn peer_connection_down(&self, peer_id: NodeId);
    fn peer_connection_up(&self, peer_id: NodeId);

    // React to a retransmission request received. Get adverts of all
    // validated artifacts for the requested filter and send them to the peer.
    fn on_retransmission_request(
        &self,
        gossip_re_request: &GossipRetransmissionRequest,
        peer_id: NodeId,
    ) -> P2PResult<()>;

    // Send a retransmission request to a peer
    fn send_retransmission_request(&self, peer_id: NodeId);

    // The on_timer method is invoked periodically by the gossip
    // component to perform p2p book keeping tasks.
    //
    // These tasks include
    // a. calling download_next for all peers every N seconds when the
    // priority function changes,
    // b. checking for chunk download timeouts and
    // c. Polling the registry for subnet membership changes.
    fn on_timer(&self, event_handler: &Arc<dyn P2PEventHandlerControl>);
}
// End DownloadManager trait

pub(crate) trait PeerManager {
    // Return current list of peers managed by the peer manager
    fn get_current_peer_ids(&self) -> Vec<NodeId>;

    // set the list of peers
    fn set_current_peer_ids(&self, new_peers: Vec<NodeId>);

    // adds one peer to the list of current peers
    fn add_peer(
        &self,
        peer: NodeId,
        node_record: &NodeRecord,
        registry_version: RegistryVersion,
        event_handler: &Arc<dyn P2PEventHandlerControl>,
    ) -> P2PResult<()>;

    // removes a peer from the list of current peers
    fn remove_peer(&self, peer: NodeId, registry_version: RegistryVersion);
}
// End PeerManager trait

use ic_interfaces::registry::RegistryClient;
use ic_interfaces::{artifact_manager::ArtifactManager, transport::Transport};
use ic_types::{
    artifact::{Artifact, ArtifactId},
    chunkable::{ArtifactErrorCode, ChunkId},
    crypto::CryptoHash,
    p2p::GossipAdvert,
    transport::{FlowTag, TransportClientType, TransportPayload},
    NodeId, SubnetId,
};

use crate::{
    artifact_download_list::{ArtifactDownloadList, ArtifactDownloadListImpl},
    download_prioritization::{
        AdvertTracker, AdvertTrackerFinalAction, DownloadAttemptTracker, DownloadPrioritizer,
    },
    event_handler::P2PEventHandlerControl,
    event_handler::P2PEventHandlerImpl,
    gossip_protocol::{
        GossipChunk, GossipChunkRequest, GossipMessage, GossipRetransmissionRequest,
    },
    metrics::DownloadManagementMetrics,
    utils::FlowMapper,
    P2PError, P2PErrorCode, P2PResult,
};

extern crate lru;
use ic_protobuf::registry::subnet::v1::GossipConfig;
use ic_registry_client::helper::subnet::SubnetTransportRegistry;
use lru::LruCache;

use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex, RwLock},
    time::{Instant, SystemTime},
};

use ic_logger::replica_logger::ReplicaLogger;
use ic_logger::{info, trace, warn};
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_types::{transport::TransportErrorCode, RegistryVersion};
use std::collections::HashSet;
use std::ops::DerefMut;

/// For each peer a node tracks the chunks it requested from it,
/// identified by their artifact_id and chunk_id
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct GossipRequestTrackerKey {
    artifact_id: ArtifactId, // Artifact ID for the in flight chunk request
    chunk_id: ChunkId,       // Chunk ID for the in flight chunk request
}

// Per peer chunk request tracker for a chunk request sent to a peer.
// Tracking begins when a request is dispatched and concludes when
// a. MAX_CHUNK_WAIT_MS time has elapsed without a response from the peer OR
// b. the peer responds with the chunk or an error message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct GossipRequestTracker {
    requested_instant: Instant, // Instant when the request was initiated
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct PeerContext {
    peer_id: NodeId,
    requested: HashMap<GossipRequestTrackerKey, GossipRequestTracker>,
    disconnect_time: Option<SystemTime>,
    last_retransmission_request_processed_time: Instant,
}

impl From<NodeId> for PeerContext {
    fn from(peer_id: NodeId) -> Self {
        PeerContext {
            peer_id,
            requested: HashMap::new(),
            disconnect_time: None,
            last_retransmission_request_processed_time: Instant::now(),
        }
    }
}

type PeerContextDictionary = HashMap<NodeId, PeerContext>;

type ReceiveCheckCache = LruCache<CryptoHash, ()>;

pub(crate) struct PeerManagerImpl {
    node_id: NodeId,
    _subnet_id: SubnetId,
    log: ReplicaLogger,
    current_peers: Arc<Mutex<PeerContextDictionary>>,
    transport: Arc<dyn Transport>,
    transport_client_type: TransportClientType,
}

pub(crate) struct DownloadManagerImpl {
    node_id: NodeId,
    subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    artifact_manager: Arc<dyn ArtifactManager>,
    prioritizer: Arc<dyn DownloadPrioritizer>,
    peer_manager: Arc<dyn PeerManager + Send + Sync>,
    // This is correct, current_peers is shared at the moment between the download manager
    // and the peer manager. Keeping it in just one would require too big of an overhaul.
    current_peers: Arc<Mutex<PeerContextDictionary>>,
    // Transport provides a thin layer hiding its actor nature. This
    // should be substituted with the actor address.
    transport: Arc<dyn Transport>,
    flow_mapper: Arc<FlowMapper>,
    transport_client_type: TransportClientType,
    artifacts_under_construction: RwLock<ArtifactDownloadListImpl>,
    log: ReplicaLogger,
    metrics: DownloadManagementMetrics,
    gossip_config: GossipConfig,
    receive_check_caches: RwLock<HashMap<NodeId, ReceiveCheckCache>>,
    pfn_invocation_instant: Mutex<Instant>,
    registry_refresh_instant: Mutex<Instant>,
    retransmission_request_instant: Mutex<Instant>,
}

impl DownloadManager for DownloadManagerImpl {
    fn send_advert_to_peers(&self, gossip_advert: GossipAdvert) {
        let current_peers = self.peer_manager.get_current_peer_ids();
        self.send_advert_to_peer_list(gossip_advert, current_peers);
    }

    fn on_advert(&self, gossip_advert: GossipAdvert, peer_id: NodeId) {
        // Precondition ensured by gossip_protocol.on_advert():
        // Corresponding artifact is not in the artifact pool

        // Check if we've seen this artifact before
        if self
            .receive_check_caches
            .read()
            .unwrap()
            .values()
            .any(|cache| cache.contains(&gossip_advert.integrity_hash))
        {
            // Ignore advert
            return;
        }

        let mut current_peers = self.current_peers.lock().unwrap();
        if let Some(_peer_context) = current_peers.get_mut(&peer_id) {
            let _ = self.prioritizer.add_advert(gossip_advert, peer_id);
        } else {
            warn!(every_n_seconds => 30, self.log, "Dropping advert from unknown node {:?}", peer_id);
        }
        self.metrics.adverts_received.inc();
    }

    /// The download_next(i) subroutine looks at the Adverts Queue for
    /// peer i and finds the highest-priority advert that is not
    /// already being downloaded from other peers more times in
    /// parallel than the maximum duplicity, and for which there is
    /// room to store the corresponding artifact in the un-validated
    /// artifact pool of peer i.  If such an advert is found, the node
    /// adds a tracker for the advert to the Requested
    /// Queue of peer i, and sends a chunk requests for the corresponding
    /// artifact.

    /// The node also sets a download timeout for this chunk request
    /// with a duration that is appropriate size of the chunk. Every x
    /// seconds, the node iterates over the requested chunks and
    /// checks timed out requests. The timed out requests are removed
    /// from the Requested Queue of peer and a history of such
    /// timeouts is retained (TODO), Future calls download_next(i)
    /// take into account the download timeout history to de-prioritize
    /// the time request from being fetched again from same peer that
    /// time outs in the past.

    /// This is a security feature, because in case no duplicity is
    /// allowed, a bad peer could otherwise maintain a “monopoly” on
    /// providing the node with a particular artifact and prevent the
    /// node from ever receiving

    // Start downloading a chunk of the highest-priority artifact in
    // the requests queue, if bandwidth allows.
    fn download_next(&self, peer_id: NodeId) -> Result<(), Box<dyn Error>> {
        self.metrics.download_next_calls.inc();
        let start_time = Instant::now();
        let gossip_requests = self.download_next_compute_work(peer_id)?;
        self.metrics
            .download_next_time
            .set(start_time.elapsed().as_micros() as i64);
        self.send_chunk_requests(gossip_requests, peer_id);
        Ok(())
    }

    // This function is called when a new chunk is received
    fn on_chunk(&self, gossip_chunk: GossipChunk, peer_id: NodeId) {
        trace!(
            self.log,
            "Node-{:?} received chunk from Node-{:?} ->{:?}",
            self.node_id,
            peer_id,
            gossip_chunk
        );

        // Remove the chunk request tracker
        let mut current_peers = self.current_peers.lock().unwrap();
        if let Some(peer_context) = current_peers.get_mut(&peer_id) {
            if let Some(tracker) = peer_context.requested.remove(&GossipRequestTrackerKey {
                artifact_id: gossip_chunk.artifact_id.clone(),
                chunk_id: gossip_chunk.chunk_id,
            }) {
                // TODO: move this to artifact.rs
                let artifact_type = match &gossip_chunk.artifact_id {
                    ArtifactId::ConsensusMessage(_) => "consensus",
                    ArtifactId::IngressMessage(_) => "ingress",
                    ArtifactId::CertificationMessage(_) => "certification",
                    ArtifactId::DkgMessage(_) => "dkg",
                    ArtifactId::FileTreeSync(_) => "file_tree_sync",
                    ArtifactId::StateSync(_) => "state_sync",
                };
                self.metrics
                    .chunk_delivery_time
                    .with_label_values(&[artifact_type])
                    .observe(tracker.requested_instant.elapsed().as_millis() as f64);
            } else {
                trace!(
                    self.log,
                    "unsolicited or timed out artifact {:?} chunk {:?} from peer {:?}",
                    gossip_chunk.artifact_id,
                    gossip_chunk.chunk_id,
                    peer_id.get()
                );
                self.metrics.chunks_unsolicited_or_timedout.inc();
            }
        }

        // Check if the request has been served; If an error is
        // returned it means that artifact "chunk" cannot be served by
        // this peer.  We mark this chunk download as failed but
        // continue to track this advert under the peer for other
        // chunks (as this might be useful for statesync)
        // This situation is possible if one of the replicas
        // misses a part of the artifact due to corruption or progress
        // (If the peer has a higher executed height now, it might
        // have changed its state and thus may only be able to serve
        // some but not all chunks of the artifact the node is
        // interested in).
        // Allowing the rest of the artifact to be downloaded and
        // skipping only the affected chunk increase overall
        // resilience.
        if let Err(error) = gossip_chunk.artifact_chunk {
            self.metrics.chunks_not_served_from_peer.inc();
            trace!(
                self.log,
                "Chunk download failed for artifact{:?} chunk {:?} from peer {:?}",
                gossip_chunk.artifact_id,
                gossip_chunk.chunk_id,
                peer_id
            );
            if let P2PErrorCode::NotFound = error.p2p_error_code {
                // If the artifact is not found on the sender's side, drop the
                // advert from the context for this peer to prevent it from
                // being requested again from this peer.
                self.delete_advert_from_peer(
                    peer_id,
                    &gossip_chunk.artifact_id,
                    self.artifacts_under_construction
                        .write()
                        .unwrap()
                        .deref_mut(),
                )
            }
            return;
        }

        // increment received chunks counter
        self.metrics.chunks_received.inc();

        // feed the chunk to artifact tracker
        let mut artifacts_under_construction = self.artifacts_under_construction.write().unwrap();

        // Find the tracker to feed the chunk
        let artifact_tracker = artifacts_under_construction.get_tracker(&gossip_chunk.artifact_id);
        if artifact_tracker.is_none() {
            trace!(
                self.log,
                "Chunk received although artifact is complete or dropped from under construction list (e.g., due to priority function change) {:?} chunk {:?} from peer {:?}",
                gossip_chunk.artifact_id,
                gossip_chunk.chunk_id,
                peer_id.get()
            );
            let _ = self.prioritizer.delete_advert_from_peer(
                &gossip_chunk.artifact_id,
                peer_id,
                AdvertTrackerFinalAction::Abort,
            );
            self.metrics.chunks_redundant_residue.inc();
            return;
        }
        let artifact_tracker = artifact_tracker.unwrap();

        // feed the chunk to the tracker
        let completed_artifact = match artifact_tracker
            .chunkable
            .add_chunk(gossip_chunk.artifact_chunk.unwrap())
        {
            // Artifact assembly is complete
            Ok(artifact) => Some(artifact),
            Err(ArtifactErrorCode::ChunksMoreNeeded) => None,
            Err(ArtifactErrorCode::ChunkVerificationFailed) => {
                trace!(
                    self.log,
                    "Chunk verification failed for artifact{:?} chunk {:?} from peer {:?}",
                    gossip_chunk.artifact_id,
                    gossip_chunk.chunk_id,
                    peer_id
                );
                self.metrics.chunks_verification_failed.inc();
                None
            }
        }; // End Match feeding the chunk

        if completed_artifact.is_none() {
            return;
        }

        // record metrics
        self.metrics.artifacts_received.inc();

        let completed_artifact = completed_artifact.unwrap();

        // Check whether the artifact matches the advertised integrity hash
        // Get the advert so one could extract the IH
        let advert = match self
            .prioritizer
            .get_advert_from_peer(&gossip_chunk.artifact_id, &peer_id)
        {
            Ok(Some(advert)) => advert,
            Err(_) | Ok(None) => {
                trace!(
                self.log,
                "The advert for {:?} chunk {:?} from peer {:?} was not found, seems the peer never sent it.",
                gossip_chunk.artifact_id,
                gossip_chunk.chunk_id,
                peer_id.clone().get()
            );
                return;
            }
        };
        // Check if the artifacts IH matches the advertized one
        // This construct is not nice, but it works until there is a better way
        // to compute the integrity hash over all variants of an enum.
        let expected_ih = match &completed_artifact {
            Artifact::ConsensusMessage(msg) => ic_crypto::crypto_hash(msg).get(),
            Artifact::IngressMessage(msg) => ic_crypto::crypto_hash(msg).get(),
            Artifact::CertificationMessage(msg) => ic_crypto::crypto_hash(msg).get(),
            Artifact::DkgMessage(msg) => ic_crypto::crypto_hash(msg).get(),
            // FileTreeSync is not of ArtifactKind kind, and it's used only for testing.
            // Thus, we make up the integrity_hash.
            Artifact::FileTreeSync(_msg) => CryptoHash(vec![]),
            Artifact::StateSync(msg) => ic_crypto::crypto_hash(msg).get(),
        };

        if expected_ih != advert.integrity_hash {
            warn!(
                self.log,
                "The integrity hash for {:?} from peer {:?} does not match. Expected {:?}, got {:?}.",
                gossip_chunk.artifact_id,
                peer_id.clone().get(),
                expected_ih,
                advert.integrity_hash;
            );
            self.metrics.integrity_hash_check_failed.inc();

            // Now we must delete the advert from this particular peer and leave
            // to Gossip to refetch the artifact from another node.
            let _ = self.prioritizer.delete_advert_from_peer(
                &gossip_chunk.artifact_id,
                peer_id,
                AdvertTrackerFinalAction::Abort,
            );
            return;
        }

        // Add artifact hash to receive check set
        let charged_peer = artifact_tracker.peer_id;
        self.receive_check_caches
            .write()
            .unwrap()
            .get_mut(&charged_peer)
            .unwrap()
            .put(advert.integrity_hash.clone(), ());

        // Artifact is complete and integrity hash is ok!! cleanup the all
        // its adverts from all peers
        let _ = self
            .prioritizer
            .delete_advert(&gossip_chunk.artifact_id, AdvertTrackerFinalAction::Success);
        artifacts_under_construction.remove_tracker(&gossip_chunk.artifact_id);

        // Drop the locks before calling client callbacks
        std::mem::drop(artifacts_under_construction);
        std::mem::drop(current_peers);

        // Client callbacks
        trace!(
            self.log,
            "Node-{:?} received artifact from Node-{:?} ->{:?}",
            self.node_id,
            peer_id,
            gossip_chunk.artifact_id
        );
        match self
            .artifact_manager
            .on_artifact(completed_artifact, advert, &peer_id)
        {
            Ok(_) => (),
            Err(err) => warn!(
                self.log,
                "Artifact is not processed successfully by Artifact Manager: {:?}", err
            ),
        }
    }

    fn peer_connection_down(&self, peer_id: NodeId) {
        self.metrics.connection_down_events.inc();
        let now = SystemTime::now();
        let mut current_peers = self.current_peers.lock().unwrap();
        if let Some(peer_context) = current_peers.get_mut(&peer_id) {
            peer_context.disconnect_time = Some(now);
            trace!(
                self.log,
                "Gossip On Disconnect event with peer: {:?} at time {:?}",
                peer_id,
                now
            );
        };
    }

    fn peer_connection_up(&self, peer_id: NodeId) {
        self.metrics.connection_up_events.inc();
        let _now = SystemTime::now();

        let last_disconnect = self
            .current_peers
            .lock()
            .unwrap()
            .get_mut(&peer_id)
            .and_then(|res| res.disconnect_time);
        match last_disconnect {
            Some(last_disconnect) => {
                match last_disconnect.elapsed() {
                    Ok(elapsed) => {
                        trace!(
                            self.log,
                            "Disconnect to peer {:?} for {:?} seconds",
                            peer_id,
                            elapsed
                        );

                        // Clear the send queues and send re-transmission request to the peer on
                        // connect.
                        self.transport
                            .clear_send_queues(self.transport_client_type, &peer_id);
                    }
                    Err(e) => {
                        warn!(self.log, "Error in elapsed time calculation: {:?}", e);
                    }
                }
            }
            None => {
                trace!(
                    self.log,
                    "No previous disconnect event recorded in peer manager for node : {:?}",
                    peer_id
                );
            }
        }
        self.send_retransmission_request(peer_id);
    }

    fn on_retransmission_request(
        &self,
        gossip_re_request: &GossipRetransmissionRequest,
        peer_id: NodeId,
    ) -> P2PResult<()> {
        const BUSY_ERR: P2PResult<()> = Err(P2PError {
            p2p_error_code: P2PErrorCode::Busy,
        });
        // Throttle processing of incoming re-transmission request
        self.current_peers
            .lock()
            .unwrap()
            .get_mut(&peer_id)
            .ok_or_else(|| {
                warn!(self.log, "Can't find peer context for peer: {:?}", peer_id);
                P2PError {
                    p2p_error_code: P2PErrorCode::NotFound,
                }
            })
            .map_or_else(Err, |peer_context| {
                let elapsed_ms = peer_context
                    .last_retransmission_request_processed_time
                    .elapsed()
                    .as_millis();
                if elapsed_ms < self.gossip_config.retransmission_request_ms as u128 {
                    BUSY_ERR
                } else {
                    peer_context.last_retransmission_request_processed_time = Instant::now();
                    Ok(())
                }
            })?;

        // A retransmission request was received from a peer, so clear the send queues
        // and respond to the re-transmission request by sending all the adverts that
        // satisfy the filter.
        self.transport
            .clear_send_queues(self.transport_client_type, &peer_id);

        let adverts = self
            .artifact_manager
            .get_all_validated_by_filter(&gossip_re_request.filter)
            .into_iter();

        adverts.for_each(|advert| self.send_advert_to_peer_list(advert, vec![peer_id]));
        Ok(())
    }

    fn send_retransmission_request(&self, peer_id: NodeId) {
        let filter = self.artifact_manager.get_filter();
        let message = GossipMessage::RetransmissionRequest(GossipRetransmissionRequest { filter });
        let flow_tag = self.flow_mapper.map(&message);
        let start_time = Instant::now();
        self.transport_send(message, peer_id, flow_tag)
            .map(|_| self.metrics.retransmission_requests_sent.inc())
            .unwrap_or_else(|e| {
                trace!(
                    self.log,
                    "Send retransmission request failed: peer {:?} {:?} ",
                    peer_id,
                    e
                );
                self.metrics.retransmission_request_send_failed.inc();
            });
        self.metrics
            .retransmission_request_time
            .observe(start_time.elapsed().as_millis() as f64)
    }

    fn send_chunk_to_peer(&self, gossip_chunk: GossipChunk, peer_id: NodeId) {
        trace!(
            self.log,
            "Node-{:?} sent chunk data  ->{:?} {:?}",
            self.node_id,
            peer_id,
            gossip_chunk
        );
        let message = GossipMessage::Chunk(gossip_chunk);
        let flow_tag = self.flow_mapper.map(&message);
        self.transport_send(message, peer_id, flow_tag)
            .map(|_| self.metrics.chunks_sent.inc())
            .unwrap_or_else(|e| {
                // Transport and gossip implement fixed sized queues for flow control.
                // Log at a lower level to avoid being log spammed by a misbehaving node.
                // Ignore errors as protocol violations
                trace!(self.log, "Send chunk failed: peer {:?} {:?} ", peer_id, e);
                self.metrics.chunk_send_failed.inc();
            });
    }

    fn on_timer(&self, event_handler: &Arc<dyn P2PEventHandlerControl>) {
        let (update_priority_fns, retransmission_request, refresh_registry) =
            self.get_timer_tasks();
        if update_priority_fns {
            let dropped_adverts = self
                .prioritizer
                .update_priority_functions(self.artifact_manager.as_ref());
            let mut artifacts_under_construction =
                self.artifacts_under_construction.write().unwrap();
            dropped_adverts
                .iter()
                .for_each(|id| artifacts_under_construction.remove_tracker(id));
        }

        if retransmission_request {
            // send retranmission request to all peers
            let current_peers = self.peer_manager.get_current_peer_ids();
            for peer in current_peers {
                self.send_retransmission_request(peer);
            }
        }

        if refresh_registry {
            self.refresh_registry(&event_handler);
        }

        // Process peers for timeout chunks
        let mut timedout_peers = Vec::new();
        for (node_id, peer_context) in self.current_peers.lock().unwrap().iter_mut() {
            if self.process_timedout_requests(node_id, peer_context) {
                timedout_peers.push(*node_id);
            }
        }

        // Process timeout artifacts
        self.process_timedout_artifacts();

        // calculate the set of peers that need to evaluated by the download manager.
        let peer_ids = if update_priority_fns {
            self.peer_manager.get_current_peer_ids().into_iter()
        } else {
            timedout_peers.into_iter()
        };

        for peer_id in peer_ids {
            let _ = self.download_next(peer_id);
        }
    }
}

impl DownloadManagerImpl {
    /// constructor
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: NodeId,
        subnet_id: SubnetId,
        registry_client: Arc<dyn RegistryClient>,
        artifact_manager: Arc<dyn ArtifactManager>,
        transport: Arc<dyn Transport>,
        event_handler: Arc<P2PEventHandlerImpl>,
        flow_mapper: Arc<FlowMapper>,
        log: ReplicaLogger,
        prioritizer: Arc<dyn DownloadPrioritizer>,
        metrics: DownloadManagementMetrics,
    ) -> Result<Self, String> {
        let transport_client_type = TransportClientType::P2P;
        let gossip_config =
            crate::p2p::P2P::fetch_gossip_config(registry_client.clone(), subnet_id);

        // TODO use it in construction of peer management and download manager
        let current_peers = Arc::new(Mutex::new(PeerContextDictionary::default()));
        let peer_manager = Arc::new(PeerManagerImpl {
            node_id,
            _subnet_id: subnet_id,
            log: log.clone(),
            transport: transport.clone(),
            transport_client_type,
            current_peers: current_peers.clone(),
        });

        let download_manager = DownloadManagerImpl {
            node_id,
            subnet_id,
            registry_client,
            artifact_manager,
            prioritizer,
            peer_manager,
            current_peers,
            transport: transport.clone(),
            flow_mapper,
            transport_client_type,
            artifacts_under_construction: RwLock::new(ArtifactDownloadListImpl::new(log.clone())),
            log,
            metrics,
            gossip_config,
            receive_check_caches: RwLock::new(HashMap::new()),
            pfn_invocation_instant: Mutex::new(Instant::now()),
            registry_refresh_instant: Mutex::new(Instant::now()),
            retransmission_request_instant: Mutex::new(Instant::now()),
        };
        transport
            .register_client(TransportClientType::P2P, event_handler.clone())
            .map_err(|e| format!("transport registration failed: {:?}", e))
            .map(|_| {
                download_manager.refresh_registry(&(event_handler as Arc<_>));
                download_manager
            })
    }

    // HELPER: get a list of task to be performed by this timer invocation
    fn get_timer_tasks(&self) -> (bool, bool, bool) {
        let mut update_priority_fns = false;
        let mut refresh_registry = false;
        let mut retransmission_request = false;
        // check if priority function should be updated
        {
            let mut pfn_invocation_instant = self.pfn_invocation_instant.lock().unwrap();
            if pfn_invocation_instant.elapsed().as_millis()
                >= self.gossip_config.pfn_evaluation_period_ms as u128
            {
                update_priority_fns = true;
                *pfn_invocation_instant = Instant::now();
            }
        }

        // Check if retransmission request needs to be sent
        {
            let mut retransmission_request_instant =
                self.retransmission_request_instant.lock().unwrap();
            if retransmission_request_instant.elapsed().as_millis()
                >= self.gossip_config.retransmission_request_ms as u128
            {
                retransmission_request = true;
                *retransmission_request_instant = Instant::now();
            }
        }

        // Check if registry has to be refreshed
        {
            let mut registry_refresh_instant = self.registry_refresh_instant.lock().unwrap();
            if registry_refresh_instant.elapsed().as_millis()
                >= self.gossip_config.pfn_evaluation_period_ms as u128
            {
                refresh_registry = true;
                *registry_refresh_instant = Instant::now();
            }
            (
                update_priority_fns,
                retransmission_request,
                refresh_registry,
            )
        }
    }

    // Update the peer_manager state based on the latest registry value
    pub fn refresh_registry(&self, event_handler: &Arc<dyn P2PEventHandlerControl>) {
        let registry_version = self.registry_client.get_latest_version();
        self.registry_client
            .get_subnet_transport_infos(self.subnet_id, registry_version)
            .map_or(None, |opt_vec| opt_vec)
            .map_or(vec![], |vec| vec)
            .into_iter()
            .for_each(|(node_id, node_record)| {
                if self
                    .peer_manager
                    .add_peer(node_id, &node_record, registry_version, event_handler)
                    .is_ok()
                {
                    self.receive_check_caches.write().unwrap().insert(
                        node_id,
                        ReceiveCheckCache::new(
                            self.gossip_config.receive_check_cache_size as usize,
                        ),
                    );
                }
            })
    }

    /// Transport helpers
    fn transport_send(
        &self,
        message: GossipMessage,
        peer_id: NodeId,
        flow_tag: FlowTag,
    ) -> Result<(), TransportErrorCode> {
        let _timer = self
            .metrics
            .op_duration
            .with_label_values(&["transport_send"])
            .start_timer();
        let message = TransportPayload(pb::GossipMessage::proxy_encode(message).unwrap());
        Ok(self
            .transport
            .send(self.transport_client_type, &peer_id, flow_tag, message)
            .map_err(|e| {
                trace!(
                    self.log,
                    "failed to send gossip message to peer {:?}: {:?}",
                    peer_id,
                    e
                );
                e
            })?)
    }

    fn send_advert_to_peer_list(&self, gossip_advert: GossipAdvert, peer_ids: Vec<NodeId>) {
        let message = GossipMessage::Advert(gossip_advert.clone());
        let flow_tag = self.flow_mapper.map(&message);
        for peer_id in peer_ids {
            self.transport_send(message.clone(), peer_id, flow_tag)
                .map(|_| self.metrics.adverts_sent.inc())
                .unwrap_or_else(|_e| {
                    // Ignore advert send failures
                    self.metrics.adverts_send_failed.inc();
                });

            // Debugging
            trace!(
                self.log,
                "Node-{:?} sent gossip advert ->{:?} {:?}",
                self.node_id,
                peer_id,
                gossip_advert
            );
        }
    }

    fn send_chunk_requests(&self, requests: Vec<GossipChunkRequest>, peer_id: NodeId) {
        for request in requests {
            let message = GossipMessage::ChunkRequest(request);
            let flow_tag = self.flow_mapper.map(&message);
            // Debugging
            trace!(
                self.log,
                "Node-{:?} sending chunk request ->{:?} {:?}",
                self.node_id,
                peer_id,
                message
            );
            self.transport_send(message, peer_id, flow_tag)
                .map(|_| self.metrics.chunks_requested.inc())
                .unwrap_or_else(|_e| {
                    // Ingore chunk send failures. Points to a misbehaving peer
                    self.metrics.chunk_request_send_failed.inc();
                });
        }
    }

    // Pre-flight check for initiating downloads from a peer.
    // A peer may not be ready for downloads for various reasons like.
    // - Peer's download request capacity has been reached.
    // - The peer is not a current peer (peer rotated or unknown peer)
    // - Peer was disconnected (TODO)
    fn is_peer_ready_for_download<'a>(
        &self,
        peer_id: NodeId,
        peer_dictionary: &'a PeerContextDictionary,
    ) -> Result<&'a PeerContext, P2PError> {
        match peer_dictionary.get(&peer_id) {
            // Check the peer is present
            // and
            // We have available capacity to stream chunks from this peer.
            Some(peer_context)
                if peer_context.requested.len()
                    < self.gossip_config.max_artifact_streams_per_peer as usize =>
            {
                Ok(peer_context)
            }
            _ => Err(P2PError {
                p2p_error_code: P2PErrorCode::Busy,
            }),
        }
    }

    // Get the request tracker for in-flight chunk request from a peer.
    fn get_peer_chunk_tracker<'a>(
        &self,
        peer_id: &NodeId,
        peers: &'a PeerContextDictionary,
        artifact_id: &ArtifactId,
        chunk_id: ChunkId,
    ) -> Option<&'a GossipRequestTracker> {
        let peer_context = peers.get(peer_id)?;
        peer_context.requested.get(&GossipRequestTrackerKey {
            artifact_id: artifact_id.clone(),
            chunk_id,
        })
    }

    // Helper function for download_next
    //
    // Consolidated checks and conditions that dictate a chunks
    // download eligibility from a peer.
    //
    // Parameter:
    // peers                   peers for this node
    // peer_id:                id for peer being evaluated
    //
    // artifact_id+chunk_id   identifiers for the chunk under download
    //                         consideration
    //
    // Returns true if the chunk can be downloaded from a peer.
    fn get_chunk_request(
        &self,
        peers: &PeerContextDictionary,
        peer_id: NodeId,
        advert_tracker: &AdvertTracker,
        chunk_id: ChunkId,
    ) -> Option<GossipChunkRequest> {
        // Skip if the chunk download has been already attempted by
        // this peer it doesn't matter if node currently downloading
        // it OR has a failed attempted in this round.
        if advert_tracker.peer_attempted(chunk_id, &peer_id) {
            None?
        }

        // Skip if some other peer are downloading the chunk and max
        // duplicity has been reached
        let duplicity = advert_tracker
            .peers
            .iter()
            .filter_map(|advertiser| {
                self.get_peer_chunk_tracker(
                    advertiser,
                    peers,
                    &advert_tracker.advert.artifact_id,
                    chunk_id,
                )
            })
            .count();

        if duplicity >= self.gossip_config.max_duplicity as usize {
            None?
        }

        // peer has not attempted a chunk download in this round and will not
        // violate duplicity constraints
        Some(GossipChunkRequest {
            artifact_id: advert_tracker.advert.artifact_id.clone(),
            chunk_id,
        })
    }

    // Helper function for download_next
    //
    // download_next_compute_work()
    //
    //  Looks at current state of peer manager and returns the next
    //  set of downloads that can be initiated within the constraints
    //  of the ICP protocol
    fn download_next_compute_work(
        &self,
        peer_id: NodeId,
    ) -> Result<Vec<GossipChunkRequest>, impl Error> {
        // get peer context
        let mut current_peers = self.current_peers.lock().unwrap();
        let peer_context = self.is_peer_ready_for_download(peer_id, &current_peers)?;
        let requested_instant = Instant::now(); // function granularity for instant is good enough
        let max_streams_per_peer = self.gossip_config.max_artifact_streams_per_peer as usize;

        assert!(peer_context.requested.len() <= max_streams_per_peer);
        let num_downloadable_chunks = max_streams_per_peer - peer_context.requested.len();
        if num_downloadable_chunks == 0 {
            return Err(Box::new(P2PError {
                p2p_error_code: P2PErrorCode::Busy,
            }));
        }

        let mut requests = Vec::new();
        let mut artifacts_under_construction = self.artifacts_under_construction.write().unwrap();
        // Prioritized iterator
        let peer_advert_queues = self.prioritizer.get_peer_priority_queues(peer_id);
        let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();

        let mut visited = 0;
        for (_, advert_tracker) in peer_advert_map.iter() {
            visited += 1;
            if requests.len() >= num_downloadable_chunks {
                break;
            }

            let mut advert_tracker = advert_tracker.write().unwrap();
            let advert_tracker = advert_tracker.deref_mut();

            // Try begin a download for the artifact and collect its chunk requests
            if let Some(artifact_tracker) = artifacts_under_construction.schedule_download(
                peer_id,
                &advert_tracker.advert,
                &self.gossip_config,
                current_peers.len() as u32,
                self.artifact_manager.as_ref(),
            ) {
                // Collect gossip requests that can be initiated for this artifact.
                // get_chunk_request() returns chunk request for chunks that satisfy chunk
                // download constraints  we collect them and record the download
                // attempt
                let new_chunk_requests = artifact_tracker
                    .chunkable
                    .chunks_to_download()
                    .filter_map(|id: ChunkId| {
                        self.get_chunk_request(&current_peers, peer_id, advert_tracker, id)
                            .map(|req| {
                                advert_tracker.record_attempt(id, &peer_id);
                                req
                            })
                    })
                    .take(num_downloadable_chunks - requests.len());

                // Extend the requests to be send out to this peer
                requests.extend(new_chunk_requests);
            }
        }

        self.metrics.download_next_visited.set(visited as i64);
        self.metrics
            .download_next_selected
            .set(requests.len() as i64);

        let peer_context = current_peers.get_mut(&peer_id).unwrap();
        peer_context.requested.extend(requests.iter().map(|req| {
            (
                GossipRequestTrackerKey {
                    artifact_id: req.artifact_id.clone(),
                    chunk_id: req.chunk_id,
                },
                GossipRequestTracker { requested_instant },
            )
        }));

        assert!(peer_context.requested.len() <= max_streams_per_peer);
        Ok(requests)
    }

    /// Delete an advert from a particular peer.  If the deletion
    /// results zero peers downloading the advert then cleanup the
    /// under_construction entry too.
    fn delete_advert_from_peer(
        &self,
        peer_id: NodeId,
        artifact_id: &ArtifactId,
        artifacts_under_construction: &mut dyn ArtifactDownloadList,
    ) {
        let ret = self.prioritizer.delete_advert_from_peer(
            artifact_id,
            peer_id,
            AdvertTrackerFinalAction::Abort,
        );
        // remove the artifact from the under construction list
        // if this peer was the last peer that with an advert
        // tracker for this artifact, indicated by the previous
        // call's return value.
        if ret.is_ok() {
            artifacts_under_construction.remove_tracker(&artifact_id);
        }
    }

    // Called by on_timer(), checks if there are any timed out artifacts in the
    // under construction list and removes them from the underconstruction list
    fn process_timedout_artifacts(&self) {
        // prune from the under construction list
        let expired_downloads = self
            .artifacts_under_construction
            .write()
            .unwrap()
            .deref_mut()
            .prune_expired_downloads();

        self.metrics
            .artifact_timeouts
            .inc_by(expired_downloads.len() as i64);

        // add the timed-out adverts to the end of their respective
        // priority queue in the prioritizer
        expired_downloads.into_iter().for_each(|artifact_id| {
            let _ = self.prioritizer.reinsert_advert_at_tail(&artifact_id);
        });
    }

    // Called by on_timer(), checks if there are any chunk request that timed out
    // from this peer, returns true if this is the case
    fn process_timedout_requests(&self, node_id: &NodeId, peer_context: &mut PeerContext) -> bool {
        // Mark timeout chunks
        let mut timedout_chunks: Vec<_> = Vec::new();
        let mut peer_timed_out: bool = false;
        peer_context.requested.retain(|key, tracker| {
            let timedout = tracker.requested_instant.elapsed().as_millis()
                >= self.gossip_config.max_chunk_wait_ms as u128;
            if timedout {
                self.metrics.chunks_timedout.inc();
                timedout_chunks.push((*node_id, key.chunk_id, key.artifact_id.clone()));
                peer_timed_out = true;
                trace!(
                    self.log,
                    "Chunk timeout Key {:?} Tracker {:?} elapsed{:?} requested {:?} Now {:?}",
                    key,
                    tracker,
                    tracker.requested_instant.elapsed().as_millis(),
                    tracker.requested_instant,
                    std::time::Instant::now()
                )
            }
            // Retain chunks that have not timeout
            !timedout
        });

        for (node_id, chunk_id, artifact_id) in timedout_chunks.into_iter() {
            self.process_timedout_chunk(&node_id, artifact_id, chunk_id)
        }

        peer_timed_out
    }

    fn process_timedout_chunk(&self, node_id: &NodeId, artifact_id: ArtifactId, chunk_id: ChunkId) {
        // Timeout chunk entry. Drop it and switch the
        // preferred primary, so that the next node that
        // advertised the chunk picks it up.
        let _ = self
            .prioritizer
            .get_advert_tracker_by_id(&artifact_id)
            .map(|advert_tracker| {
                // unset the in progress flag.
                let mut advert_tracker = advert_tracker.write().unwrap();
                advert_tracker.unset_in_progress(chunk_id);
                // If we have exhausted a round of download attempts
                // (i.e. each peer that advertised has timeout once).
                //
                // Then
                // we reset the attempts history so that peers can be
                // probed once for the next round.
                if advert_tracker.is_attempts_round_complete(chunk_id) {
                    advert_tracker.attempts_round_reset(chunk_id)
                }
            });
        #[rustfmt::skip]
        trace!(self.log, "Timedout: Peer{:?} Artifact{:?} Chunk{:?}",
               node_id, chunk_id, artifact_id);
    }
}

impl PeerManager for PeerManagerImpl {
    fn get_current_peer_ids(&self) -> Vec<NodeId> {
        self.current_peers
            .lock()
            .unwrap()
            .iter()
            .map(|(k, _v)| k.to_owned())
            .collect()
    }

    // This method takes the list of the new nodes and update the current peers
    // accordingly. It will remove all the peers that are not in the list, and add
    // new ones.
    // TODO: Allow for keeping several iterations of the current peers, per
    // design spec.
    fn set_current_peer_ids(&self, new_peers: Vec<NodeId>) {
        let mut peers = self.current_peers.lock().unwrap();

        // Remove peers that are not in the list of new peers
        let seen_peers: HashSet<NodeId> = new_peers.iter().map(|p| p.to_owned()).collect();
        peers.retain(|k, _| seen_peers.contains(k));

        // Then add new entries
        for peer in new_peers {
            // If there is no such entry, we need to add it
            peers
                .entry(peer)
                .or_insert_with(|| PeerContext::from(peer.to_owned()));
        }
    }

    fn add_peer(
        &self,
        node_id: NodeId,
        node_record: &NodeRecord,
        registry_version: RegistryVersion,
        event_handler: &Arc<dyn P2PEventHandlerControl>,
    ) -> P2PResult<()> {
        if node_id == self.node_id {
            // Only add other peers to peer list
            return Err(P2PError {
                p2p_error_code: P2PErrorCode::Failed,
            });
        }

        // Add to the event handler & current peer and drop the lock before calling into
        // transport
        {
            let mut current_peers = self.current_peers.lock().unwrap();

            if current_peers.contains_key(&node_id) {
                Err(P2PError {
                    p2p_error_code: P2PErrorCode::Exists,
                })
            } else {
                current_peers
                    .entry(node_id)
                    .or_insert_with(|| PeerContext::from(node_id.to_owned()));
                event_handler.add_node(node_id);
                info!(self.log, "Nodes {:0} added", node_id);
                Ok(())
            }?;
        }

        // Failed to start transport connection, so now remove the
        // node from current peer list. This removal allows for
        // re-connection attempt on the next registry refresh.
        //
        // TODO: DFN-1650 1. transport.start_connection() should be non
        // fallible.  Instead, connection failures should be retried
        // internally in transport.
        //
        // TODO: 2. Remove node from the event handler. Removal is
        // not needed if TODO1 is implemented.
        self.transport
            .start_connections(
                self.transport_client_type,
                &node_id,
                &node_record,
                registry_version,
            )
            .map_err(|e| {
                let mut current_peers = self.current_peers.lock().unwrap();
                current_peers.remove(&node_id);
                warn!(self.log, "start connections failed {:?} {:?}", node_id, e);
                P2PError {
                    p2p_error_code: P2PErrorCode::InitFailed,
                }
            })
    }

    fn remove_peer(&self, node_id: NodeId, registry_version: RegistryVersion) {
        let mut current_peers = self.current_peers.lock().unwrap();
        if let Err(e) =
            self.transport
                .stop_connections(self.transport_client_type, &node_id, registry_version)
        {
            warn!(self.log, "stop connection failed {:?}: {:?}", node_id, e);
        }
        // Remove the peer irrespective of status transport removal
        current_peers.remove(&node_id);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::download_prioritization::DownloadPrioritizerImpl;
    use crate::event_handler::{tests::new_test_event_handler, MAX_ADVERT_BUFFER};
    use crate::metrics::DownloadPrioritizerMetrics;
    use ic_interfaces::artifact_manager::OnArtifactError;
    use ic_logger::LoggerImpl;
    use ic_metrics::MetricsRegistry;
    use ic_registry_client::client::RegistryClientImpl;
    use ic_test_utilities::port_allocation::allocate_ports;
    use ic_test_utilities::{
        p2p::*,
        thread_transport::*,
        types::ids::{node_id_to_u64, node_test_id, subnet_test_id},
    };
    use ic_types::artifact::StateSyncMessage;
    use ic_types::crypto::CryptoHash;
    use ic_types::NodeId;
    use ic_types::{
        artifact,
        artifact::{Artifact, ArtifactAttribute, ArtifactPriorityFn, Priority},
        chunkable::{ArtifactChunk, ArtifactChunkData, Chunkable, ChunkableArtifact},
        state_sync::{ChunkInfo, FileInfo, Manifest},
        CryptoHashOfState, Height,
    };
    use proptest::prelude::*;
    use std::ops::Range;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    fn priority_fn_fetch_now_all(_: &ArtifactId, _: &ArtifactAttribute) -> Priority {
        Priority::FetchNow
    }

    #[derive(Default)]
    pub(crate) struct TestArtifactManager {
        pub quota: usize,
        pub num_chunks: u32,
    }

    struct TestArtifact {
        num_chunks: u32,
        chunks: Vec<ArtifactChunk>,
    }

    impl Chunkable for TestArtifact {
        fn get_artifact_hash(&self) -> CryptoHash {
            unimplemented!()
        }

        fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>> {
            Box::new(
                (0..self.num_chunks as u32)
                    .map(ChunkId::from)
                    .collect::<Vec<_>>()
                    .into_iter(),
            )
        }

        fn get_artifact_indentifier(&self) -> CryptoHash {
            unimplemented!()
        }

        fn add_chunk(
            &mut self,
            _artifact_chunk: ArtifactChunk,
        ) -> Result<Artifact, ArtifactErrorCode> {
            self.chunks.push(_artifact_chunk);
            if self.chunks.len() == self.num_chunks as usize {
                Ok(Artifact::StateSync(receive_check_test_create_message()))
            } else {
                Err(ArtifactErrorCode::ChunksMoreNeeded)
            }
        }

        fn is_complete(&self) -> bool {
            false
        }

        fn get_chunk_size(&self, _chunk_id: ChunkId) -> usize {
            0
        }
    }

    impl ArtifactManager for TestArtifactManager {
        fn on_artifact(
            &self,
            mut _msg: artifact::Artifact,
            _advert: GossipAdvert,
            _peer_id: &NodeId,
        ) -> Result<(), OnArtifactError<artifact::Artifact>> {
            Ok(())
        }

        fn has_artifact(&self, _message_id: &artifact::ArtifactId) -> bool {
            unimplemented!()
        }

        fn get_validated_by_identifier(
            &self,
            _message_id: &artifact::ArtifactId,
        ) -> Option<Box<dyn ChunkableArtifact + '_>> {
            unimplemented!()
        }

        fn get_filter(&self) -> artifact::ArtifactFilter {
            unimplemented!()
        }

        fn get_all_validated_by_filter(
            &self,
            _filter: &artifact::ArtifactFilter,
        ) -> Vec<GossipAdvert> {
            unimplemented!()
        }

        fn get_remaining_quota(
            &self,
            _tag: artifact::ArtifactTag,
            _peer_id: NodeId,
        ) -> Option<usize> {
            Some(self.quota)
        }

        fn get_priority_function(&self, _: artifact::ArtifactTag) -> Option<ArtifactPriorityFn> {
            Some(Box::new(priority_fn_fetch_now_all))
        }

        fn get_chunk_tracker(
            &self,
            _id: &artifact::ArtifactId,
        ) -> Option<Box<dyn Chunkable + Send + Sync>> {
            let chunks = vec![];
            Some(Box::new(TestArtifact {
                num_chunks: self.num_chunks,
                chunks,
            }))
        }
    }

    fn get_transport(
        instance_id: u32,
        hub: Arc<Mutex<Hub>>,
        logger: &LoggerImpl,
    ) -> Arc<ThreadPort> {
        let log: ReplicaLogger = logger.root.clone().into();
        ThreadPort::new(node_test_id(instance_id as u64), hub, log)
    }

    fn new_test_download_manager(num_replicas: u32, logger: &LoggerImpl) -> DownloadManagerImpl {
        let log: ReplicaLogger = logger.root.clone().into();
        // AM
        let artifact_manager = TestArtifactManager {
            quota: 2 * 1024 * 1024 * 1024,
            num_chunks: 1,
        };

        // Transport
        let hub_access: HubAccess = Arc::new(Mutex::new(Default::default()));
        for instance_id in 0..num_replicas {
            let thread_port = get_transport(instance_id, hub_access.clone(), logger);
            hub_access
                .lock()
                .unwrap()
                .insert(node_test_id(instance_id as u64), thread_port);
        }

        let transport_hub = hub_access.lock().unwrap();
        let tp = transport_hub.get(&node_test_id(0));

        // prioritizer
        let metrics_registry = MetricsRegistry::new();
        let prioritizer = Arc::new(DownloadPrioritizerImpl::new(
            &artifact_manager,
            DownloadPrioritizerMetrics::new(&metrics_registry),
        ));

        let flow_tags = vec![FlowTag::from(0)];
        let flow_mapper = Arc::new(FlowMapper::new(flow_tags));
        // setup test registry
        let allocated_ports = allocate_ports("127.0.0.1", num_replicas as u16)
            .expect("Port allocation for test failed");
        let node_port_allocation: Vec<u16> = allocated_ports.iter().map(|np| np.port).collect();
        assert_eq!(num_replicas as usize, node_port_allocation.len());
        let node_port_allocation = Arc::new(node_port_allocation);

        let data_provider =
            test_group_set_registry(subnet_test_id(P2P_SUBNET_ID_DEFAULT), node_port_allocation);
        let registry_client = Arc::new(RegistryClientImpl::new(data_provider, None));
        registry_client.fetch_and_start_polling().unwrap();

        // Create fake peers
        let artifact_manager = Arc::new(artifact_manager);
        let event_handler = Arc::new(new_test_event_handler(MAX_ADVERT_BUFFER, node_test_id(0)));
        DownloadManagerImpl::new(
            node_test_id(0),
            subnet_test_id(0),
            registry_client,
            artifact_manager,
            tp,
            event_handler,
            flow_mapper,
            log,
            prioritizer,
            DownloadManagementMetrics::new(&metrics_registry),
        )
        .unwrap()
    }

    fn test_add_adverts(
        download_manager: &impl DownloadManager,
        range: Range<u32>,
        node_id: NodeId,
    ) {
        for advert_id in range {
            let gossip_advert = GossipAdvert {
                artifact_id: ArtifactId::FileTreeSync(advert_id.to_string()),
                attribute: ArtifactAttribute::FileTreeSync(advert_id.to_string()),
                size: 0,
                integrity_hash: CryptoHash(vec![]),
            };
            download_manager.on_advert(gossip_advert, node_id)
        }
    }

    fn test_timeout_peer(download_manager: &DownloadManagerImpl, node_id: &NodeId) {
        let sleep_duration = std::time::Duration::from_millis(
            (download_manager.gossip_config.max_chunk_wait_ms * 2) as u64,
        );
        std::thread::sleep(sleep_duration);
        let mut current_peers = download_manager.current_peers.lock().unwrap();
        let peer_context = current_peers.get_mut(node_id).unwrap();
        download_manager.process_timedout_requests(node_id, peer_context);
        assert_eq!(peer_context.requested.len(), 0);
    }

    #[tokio::test]
    async fn build_new_download_manager() {
        let logger = p2p_test_setup_logger();
        let _download_manager = new_test_download_manager(1, &logger);
    }

    #[tokio::test]
    async fn download_manager_add_adverts() {
        let logger = p2p_test_setup_logger();
        let download_manager = new_test_download_manager(2, &logger);
        test_add_adverts(&download_manager, 0..1000, node_test_id(1));
    }

    #[tokio::test]
    async fn download_manager_compute_work_basic() {
        let logger = p2p_test_setup_logger();
        let num_replicas = 2;
        let download_manager = new_test_download_manager(num_replicas, &logger);
        test_add_adverts(
            &download_manager,
            0..1000,
            node_test_id(num_replicas as u64 - 1),
        );
        let chunks_to_be_downloaded = download_manager
            .download_next_compute_work(node_test_id(num_replicas as u64 - 1))
            .unwrap();
        assert!(
            chunks_to_be_downloaded.len()
                == download_manager.gossip_config.max_artifact_streams_per_peer as usize
        );
        for (i, chunk_req) in chunks_to_be_downloaded.iter().enumerate() {
            assert_eq!(
                chunk_req.artifact_id,
                ArtifactId::FileTreeSync(i.to_string())
            );
            assert_eq!(chunk_req.chunk_id, ChunkId::from(0));
        }
    }

    #[tokio::test]
    async fn download_manager_single_chunked_timeout() {
        // Advertise
        // MAX_ARTIFACT_STREAMS_PER_PEER count number of adverts from N peers.
        // i.e. all peers advertise the same set of adverts.
        //
        // Initiate the download from first peer, time it out and check it chunks get
        // requested from next peer. Test that all peers are probed for the chunks.
        let num_replicas = 4;
        let logger = p2p_test_setup_logger();
        let mut download_manager = new_test_download_manager(num_replicas, &logger);
        download_manager.gossip_config.max_chunk_wait_ms = 1000;

        let test_assert_compute_work_len =
            |download_manager: &DownloadManagerImpl, node_id, compute_work_count: usize| {
                let chunks_to_be_downloaded = download_manager
                    .download_next_compute_work(node_id)
                    .unwrap();
                assert_eq!(chunks_to_be_downloaded.len(), compute_work_count);
                for (i, chunk_req) in chunks_to_be_downloaded.iter().enumerate() {
                    assert_eq!(
                        chunk_req.artifact_id,
                        ArtifactId::FileTreeSync(i.to_string())
                    );
                    assert_eq!(chunk_req.chunk_id, ChunkId::from(0));
                }
            };
        let request_queue_size =
            download_manager.gossip_config.max_artifact_streams_per_peer as usize;

        // Skip 0th peer as its the requesting node
        for peer_id in 1..num_replicas {
            test_add_adverts(
                &download_manager,
                0..request_queue_size as u32,
                node_test_id(peer_id as u64),
            );
        }

        for peer_id in 1..num_replicas {
            test_assert_compute_work_len(
                &download_manager,
                node_test_id(peer_id as u64),
                request_queue_size,
            );
            for other_peer in 1..num_replicas {
                if other_peer != peer_id {
                    test_assert_compute_work_len(
                        &download_manager,
                        node_test_id(other_peer as u64),
                        0,
                    );
                }
            }
            test_timeout_peer(&download_manager, &node_test_id(peer_id as u64));
            if peer_id != num_replicas - 1 {
                test_assert_compute_work_len(&download_manager, node_test_id(peer_id as u64), 0);
            }
        }

        // Test
        //
        // all peers have been probed once thus this attempt round is
        // exhausted and new download attempts can start afresh
        for advert_id in 0..request_queue_size as u32 {
            let artifact_id = ArtifactId::FileTreeSync(advert_id.to_string());
            let advert_tracker = download_manager
                .prioritizer
                .get_advert_tracker_by_id(&artifact_id)
                .unwrap();
            let mut advert_tracker = advert_tracker.write().unwrap();
            assert_eq!(
                advert_tracker.is_attempts_round_complete(ChunkId::from(0)),
                false
            );
            for peer_id in 0..num_replicas {
                assert_eq!(
                    advert_tracker.peer_attempted(ChunkId::from(0), &node_test_id(peer_id as u64)),
                    false
                );
            }
        }
    }

    #[tokio::test]
    async fn download_manager_timeout_artifact() {
        let num_replicas = 3;
        let logger = p2p_test_setup_logger();
        let mut download_manager = new_test_download_manager(num_replicas, &logger);
        download_manager.gossip_config.max_artifact_streams_per_peer = 1;
        download_manager.gossip_config.max_chunk_wait_ms = 1000;
        // Node 1 and 2 both advertise advert 1 & 2
        for i in 1..num_replicas {
            test_add_adverts(
                &download_manager,
                1..num_replicas as u32,
                node_test_id(i as u64),
            )
        }

        // Advert 1 and 2 are now being downloaded by node 1 and 2.
        for i in 1..num_replicas {
            let chunks_to_be_downloaded = download_manager
                .download_next_compute_work(node_test_id(i as u64))
                .unwrap();
            assert_eq!(
                chunks_to_be_downloaded.len(),
                download_manager.gossip_config.max_artifact_streams_per_peer as usize
            );
        }

        // Timeout the artifact as well as the chunks
        let sleep_duration = std::time::Duration::from_millis(
            (download_manager.gossip_config.max_chunk_wait_ms * 2) as u64,
        );
        std::thread::sleep(sleep_duration);

        // Node 1 and 2 now both have moved forward and now advertise advert 3 &
        // 4 while advert 1 & 2 have timed out
        for i in 1..num_replicas {
            test_add_adverts(&download_manager, 3..5, node_test_id(i as u64))
        }

        // Test that chunks have timed out
        for i in 1..num_replicas {
            test_timeout_peer(&download_manager, &node_test_id(i as u64))
        }
        // Test that artifacts also have timed out
        download_manager.process_timedout_artifacts();
        {
            let artifacts_under_construction = download_manager
                .artifacts_under_construction
                .read()
                .unwrap();
            assert_eq!(artifacts_under_construction.len(), 0);
        }

        // After advert 1 &  2 timeout download manager  must start downloading
        // next artifact 3 & 4 now.
        for i in 1..num_replicas {
            let chunks_to_be_downloaded = download_manager
                .download_next_compute_work(node_test_id(i as u64))
                .unwrap();
            assert_eq!(
                chunks_to_be_downloaded.len(),
                download_manager.gossip_config.max_artifact_streams_per_peer as usize
            );
        }

        {
            let artifacts_under_construction = download_manager
                .artifacts_under_construction
                .read()
                .unwrap();
            for (idx, (id, _)) in artifacts_under_construction.iter().enumerate() {
                assert_eq!(
                    *id,
                    ArtifactId::FileTreeSync((idx + num_replicas as usize).to_string())
                )
            }
        }
    }

    #[tokio::test]
    async fn download_manager_multichunked_artifacts_are_linearly_striped() {
        // A artifact is multiple chunks is downloaded in parallel
        // from multiple peer.  If 2 peers advertise a artifact with
        // 40 chunks and each we have 20 download slots available for
        // transport.
        let num_peers = 3;
        let logger = p2p_test_setup_logger();
        let mut download_manager = new_test_download_manager(num_peers, &logger);
        let request_queue_size = download_manager.gossip_config.max_artifact_streams_per_peer;
        download_manager.artifact_manager = Arc::new(TestArtifactManager {
            quota: 2 * 1024 * 1024 * 1024,
            num_chunks: request_queue_size * num_peers,
        });

        // Each peer should be dowloading the node_id'th range of chunks. i.e.
        //  Node1 downloads 0..20  half open range
        //  Node2 download  20..40 half open range
        //
        let test_assert_compute_work_is_striped =
            |download_manager: &DownloadManagerImpl, node_id: NodeId, compute_work_count: u64| {
                let chunks_to_be_downloaded = download_manager
                    .download_next_compute_work(node_id)
                    .unwrap();
                assert_eq!(chunks_to_be_downloaded.len() as u64, compute_work_count);
                for (i, chunk_req) in chunks_to_be_downloaded.iter().enumerate() {
                    assert_eq!(
                        chunk_req.artifact_id,
                        ArtifactId::FileTreeSync(0.to_string())
                    );
                    let chunk_num =
                        ((node_id_to_u64(node_id) - 1) * request_queue_size as u64) + i as u64;
                    assert_eq!(chunk_req.chunk_id, ChunkId::from(chunk_num as u32));
                }
            };

        // advertise the artifact from all peers
        for i in 1..num_peers {
            test_add_adverts(&download_manager, 0..1, node_test_id(i as u64))
        }

        for i in 1..num_peers {
            test_assert_compute_work_is_striped(
                &download_manager,
                node_test_id(i as u64),
                request_queue_size as u64,
            );
        }
    }

    fn arb_nodeid() -> BoxedStrategy<NodeId> {
        any::<u64>().prop_map(node_test_id).boxed()
    }

    fn arb_peer_list(min_size: usize) -> BoxedStrategy<Vec<NodeId>> {
        prop::collection::hash_set(arb_nodeid(), min_size..100)
            .prop_map(|hs| hs.into_iter().collect())
            .boxed()
    }

    fn receive_check_test_create_message() -> StateSyncMessage {
        StateSyncMessage {
            height: Height::from(1),
            checkpoint_root: PathBuf::new(),
            manifest: Manifest {
                version: 0,
                file_table: Vec::<FileInfo>::new(),
                chunk_table: Vec::<ChunkInfo>::new(),
            },
            root_hash: CryptoHashOfState::from(CryptoHash(vec![])),
            get_state_sync_chunk: None,
        }
    }

    fn receive_check_test_create_chunk(chunk_id: ChunkId, artifact_id: ArtifactId) -> GossipChunk {
        let payload = vec![0; 8];
        let artifact_chunk = ArtifactChunk {
            chunk_id,
            witness: Vec::with_capacity(0),
            artifact_chunk_data: ArtifactChunkData::SemiStructuredChunkData(payload),
        };

        GossipChunk {
            artifact_id,
            chunk_id,
            artifact_chunk: Ok(artifact_chunk),
        }
    }

    fn receive_check_test_create_adverts(range: Range<u32>) -> Vec<GossipAdvert> {
        let mut result = vec![];
        let msg = receive_check_test_create_message();
        for advert_id in range {
            let gossip_advert = GossipAdvert {
                artifact_id: ArtifactId::FileTreeSync(advert_id.to_string()),
                attribute: ArtifactAttribute::FileTreeSync(advert_id.to_string()),
                size: 0,
                integrity_hash: ic_crypto::crypto_hash(&msg).get(),
            };
            result.push(gossip_advert);
        }
        result
    }

    #[tokio::test]
    async fn receive_check_test() {
        // Initialize test
        let logger = p2p_test_setup_logger();
        let download_manager = new_test_download_manager(2, &logger);
        //test_add_adverts(&download_manager, 0..1000, node_test_id(0));
        let node_id = node_test_id(1);
        let max_adverts = download_manager.gossip_config.max_artifact_streams_per_peer;
        let adverts = receive_check_test_create_adverts(0..max_adverts);
        for gossip_advert in &adverts {
            download_manager.on_advert(gossip_advert.clone(), node_id);
        }
        let chunks_to_be_downloaded = download_manager
            .download_next_compute_work(node_id)
            .unwrap();

        // Add chunk(s)
        for (i, chunk_req) in chunks_to_be_downloaded.iter().enumerate() {
            assert_eq!(
                chunk_req.artifact_id,
                ArtifactId::FileTreeSync(i.to_string())
            );
            assert_eq!(chunk_req.chunk_id, ChunkId::from(0));

            let gossip_chunk = receive_check_test_create_chunk(
                chunks_to_be_downloaded[i].chunk_id,
                chunks_to_be_downloaded[i].artifact_id.clone(),
            );

            download_manager.on_chunk(gossip_chunk, node_id);
        }

        // Test that the cache has the artifact(s)
        let receive_check_caches = download_manager.receive_check_caches.read().unwrap();
        let cache = &receive_check_caches.get(&node_id).unwrap();
        for gossip_advert in &adverts {
            assert!(cache.contains(&gossip_advert.integrity_hash));
        }
        std::mem::drop(receive_check_caches);

        // Test that when seeing the artifact again we ignore it
        // (or don't, depending on expect_dedup)
        for gossip_advert in &adverts {
            download_manager.on_advert(gossip_advert.clone(), node_id);
        }
        let new_chunks_to_be_downloaded = download_manager
            .download_next_compute_work(node_id)
            .unwrap();

        assert!(new_chunks_to_be_downloaded.is_empty());
    }

    proptest! {
        #[test]
        fn setting_same_set_of_nodes_changes_nothing(
            peers in arb_peer_list(0)
        ) {
            let peers_dictionary: PeerContextDictionary = peers
                .iter()
                .map(|node_id| (*node_id, PeerContext::from(node_id.to_owned())))
                .collect();
            let current_peers = Arc::new(Mutex::new(peers_dictionary));

            let logger = p2p_test_setup_logger();

            // Transport
            let hub_access: HubAccess = Arc::new(Mutex::new(Default::default()));
            let transport = get_transport(0, hub_access, &logger);

            // Context
            let transport_client_type = TransportClientType::P2P;
            transport.register_client(transport_client_type, Arc::new(new_test_event_handler( MAX_ADVERT_BUFFER, node_test_id(0)))).unwrap();
            let peer_manager = PeerManagerImpl {
                node_id: node_test_id(0),
                _subnet_id: subnet_test_id(0),
                log: p2p_test_setup_logger().root.clone().into(),
                current_peers,
                transport,
                transport_client_type,
            };

            let current_peers = peer_manager.get_current_peer_ids();
            peer_manager.set_current_peer_ids(peers);
            let new_peers = peer_manager.get_current_peer_ids();
            prop_assert_eq!(new_peers, current_peers)
        }

        #[test]
        fn when_setting_new_peers_old_ones_preserved(
            peer_list in arb_peer_list(3)
        ) {
            // get the original peer list, split into three: a + b + c
            // then produce:
            // old = a + b
            // new = a + c
            let orig_len = peer_list.len();
            let mut peers_common = peer_list;
            let mut peers_old = peers_common.split_off(orig_len / 3);
            let mut peers_new = peers_old.split_off(peers_old.len() / 2);

            let first_common = peers_common[0];

            peers_old.append(& mut peers_common.clone());
            peers_new.append(& mut peers_common);

            let peers_dictionary: PeerContextDictionary = peers_old
                .iter()
                .map(|node_id| (*node_id, PeerContext::from(node_id.to_owned())))
                .collect();
            let peers_dictionary = Mutex::new(peers_dictionary);
            let current_peers = Arc::new(peers_dictionary);

            let logger = p2p_test_setup_logger();
            let hub_access: HubAccess = Arc::new(Mutex::new(Default::default()));
            let transport = get_transport(0, hub_access, &logger);

            // Context
            let transport_client_type = TransportClientType::P2P;
            transport.register_client(transport_client_type, Arc::new(new_test_event_handler(MAX_ADVERT_BUFFER, node_test_id(0)))).unwrap();
            let peer_manager = PeerManagerImpl {
                node_id: node_test_id(0),
                _subnet_id: subnet_test_id(0),
                log: p2p_test_setup_logger().root.clone().into(),
                current_peers,
                transport,
                transport_client_type,
            };

            // set property on one node
            let mut current_peers = peer_manager.current_peers.lock().unwrap();
            let peer_context = current_peers.get_mut(&first_common);
            prop_assert!(peer_context.is_some());
            if let Some(peer_context) = peer_context {
                peer_context.disconnect_time = Some(SystemTime::now());
            }
            std::mem::drop(current_peers);

            // check that the new peers are correctly set
            peer_manager.set_current_peer_ids(peers_new.clone());
            let mut new_peers = peer_manager.get_current_peer_ids();
            new_peers.sort_unstable();
            peers_new.sort_unstable();
            prop_assert_eq!(new_peers, peers_new);

            // check that an old peer has preserved the property
            let mut current_peers = peer_manager.current_peers.lock().unwrap();
            let peer_context = current_peers.get_mut(&first_common);
            prop_assert!(peer_context.is_some());
            if let Some(peer_context) = current_peers.get_mut(&first_common) {
                prop_assert!(peer_context.disconnect_time.is_some());
            }
            std::mem::drop(current_peers);
        }
    }
}
