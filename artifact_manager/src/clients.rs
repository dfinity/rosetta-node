//! Implementations of the artifact client trait.

use crate::artifact::*;
use ic_interfaces::{
    artifact_manager::{ArtifactAcceptance, ArtifactClient},
    artifact_pool::{ArtifactPoolError, ReplicaVersionMismatch},
    certification::{CertificationPool, CertifierGossip},
    consensus::ConsensusGossip,
    consensus_pool::{ConsensusPool, ConsensusPoolCache},
    dkg::{DkgGossip, DkgPool},
    gossip_pool::{CertificationGossipPool, ConsensusGossipPool, DkgGossipPool, IngressGossipPool},
    ingress_pool::IngressPool,
    time_source::TimeSource,
};
use ic_logger::{debug, ReplicaLogger};
use ic_types::{
    artifact::*,
    chunkable::*,
    consensus::{
        certification::CertificationMessage, dkg::Message as DkgMessage, ConsensusMessage,
        HasVersion,
    },
    ingress::MAX_INGRESS_TTL,
    messages::{SignedIngress, SignedRequestBytes},
    NodeId, ReplicaVersion,
};
use std::convert::TryInto;
use std::sync::{Arc, RwLock};

/// Consensus 'ArtifactClient' to be managed by 'ArtifactManager'.
pub struct ConsensusClient<Pool> {
    consensus_pool: Arc<RwLock<Pool>>,
    client: Arc<dyn ConsensusGossip>,
    _log: ReplicaLogger,
}

impl<Pool> ConsensusClient<Pool> {
    pub fn new<T: ConsensusGossip + 'static>(
        consensus_pool: Arc<RwLock<Pool>>,
        consensus: T,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            consensus_pool,
            client: Arc::new(consensus),
            _log: log,
        }
    }
}

/// Check if the given artifact matches default protocol version, and return
/// error if it does not.
fn check_protocol_version<T: HasVersion>(artifact: &T) -> Result<(), ReplicaVersionMismatch> {
    let version = artifact.version();
    let expected_version = ReplicaVersion::default();
    if version != &expected_version {
        Err(ReplicaVersionMismatch {
            expected: expected_version,
            artifact: version.clone(),
        })
    } else {
        Ok(())
    }
}

impl<Pool: ConsensusPool + ConsensusGossipPool + Send + Sync> ArtifactClient<ConsensusArtifact>
    for ConsensusClient<Pool>
{
    fn check_artifact_acceptance(
        &self,
        msg: ConsensusMessage,
        _peer_id: &NodeId,
    ) -> Result<ArtifactAcceptance<ConsensusMessage>, ArtifactPoolError> {
        check_protocol_version(&msg)?;
        Ok(ArtifactAcceptance::AcceptedForProcessing(msg))
    }

    fn has_artifact(&self, msg_id: &ConsensusMessageId) -> bool {
        self.consensus_pool.read().unwrap().contains(msg_id)
    }

    fn get_validated_by_identifier<'b>(
        &self,
        msg_id: &'b ConsensusMessageId,
    ) -> Option<ConsensusMessage> {
        self.consensus_pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    fn get_filter(&self) -> ConsensusMessageFilter {
        self.client.get_filter()
    }

    fn get_all_validated_by_filter(
        &self,
        filter: &ConsensusMessageFilter,
    ) -> Vec<Advert<ConsensusArtifact>> {
        self.consensus_pool
            .read()
            .unwrap()
            .get_all_validated_by_filter(filter.height)
            .map(|msg| ConsensusArtifact::to_advert(&msg))
            .collect()
    }

    fn get_priority_function(
        &self,
    ) -> Option<PriorityFn<ConsensusMessageId, ConsensusMessageAttribute>> {
        let consensus_pool = &*self.consensus_pool.read().unwrap();
        Some(self.client.get_priority_function(consensus_pool))
    }

    fn get_chunk_tracker(&self, _id: &ConsensusMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Consensus)
    }
}

/// Ingress 'ArtifactClient' to be managed by 'ArtifactManager'.
pub struct IngressClient<Pool> {
    time_source: Arc<dyn TimeSource>,
    ingress_pool: Arc<RwLock<Pool>>,
    log: ReplicaLogger,
}

impl<Pool> IngressClient<Pool> {
    pub fn new(
        time_source: Arc<dyn TimeSource>,
        ingress_pool: Arc<RwLock<Pool>>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            time_source,
            ingress_pool,
            log,
        }
    }
}

impl<Pool: IngressPool + IngressGossipPool + Send + Sync> ArtifactClient<IngressArtifact>
    for IngressClient<Pool>
{
    fn check_artifact_acceptance(
        &self,
        bytes: SignedRequestBytes,
        peer_id: &NodeId,
    ) -> Result<ArtifactAcceptance<SignedIngress>, ArtifactPoolError> {
        // Here we account for a bit of drift and accepts messages with a bit longer
        // than MAX_INGRESS_TTL into the ingress pool. The purpose is to be a bit more
        // permissive than http_handler when the ingress was first accepted, because
        // here the ingress may have come from the network.
        let permitted_drift = std::time::Duration::from_secs(60);
        let msg: SignedIngress = bytes
            .try_into()
            .map_err(|err| ArtifactPoolError::ArtifactRejected(Box::new(err)))?;
        let time_now = self.time_source.get_relative_time();
        let time_plus_ttl = time_now + MAX_INGRESS_TTL + permitted_drift;
        let msg_expiry_time = msg.expiry_time();
        if msg_expiry_time < time_now {
            Err(ArtifactPoolError::MessageExpired)
        } else if msg_expiry_time > time_plus_ttl {
            debug!(
                self.log,
                "check_artifact_acceptance";
                ingress_message.message_id => format!("{}", msg.id()),
                ingress_message.reason => "message_expiry_too_far_in_future",
                ingress_message.expiry_time => Some(msg_expiry_time.as_nanos_since_unix_epoch()),
                ingress_message.batch_time => Some(time_now.as_nanos_since_unix_epoch()),
                ingress_message.batch_time_plus_ttl => Some(time_plus_ttl.as_nanos_since_unix_epoch())
            );
            Err(ArtifactPoolError::MessageExpiryTooLong)
        } else {
            self.ingress_pool
                .read()
                .unwrap()
                .check_quota(&msg, peer_id)?;
            Ok(ArtifactAcceptance::AcceptedForProcessing(msg))
        }
    }

    fn has_artifact(&self, msg_id: &IngressMessageId) -> bool {
        self.ingress_pool.read().unwrap().contains(msg_id)
    }

    fn get_validated_by_identifier<'b>(
        &self,
        msg_id: &'b IngressMessageId,
    ) -> Option<SignedIngress> {
        self.ingress_pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    fn get_filter(&self) -> IngressMessageFilter {
        Default::default()
    }

    fn get_all_validated_by_filter(
        &self,
        _filter: &IngressMessageFilter,
    ) -> Vec<Advert<IngressArtifact>> {
        // TODO: Send adverts of ingress messages which are generated on this node (not
        // relayed from other node). P2P-381
        Vec::new()
    }

    fn get_priority_function(
        &self,
    ) -> Option<PriorityFn<IngressMessageId, IngressMessageAttribute>> {
        let start = self.time_source.get_relative_time();
        let range = start..=start + MAX_INGRESS_TTL;
        Some(Box::new(move |ingress_id, _| {
            if range.contains(&ingress_id.expiry()) {
                Priority::Fetch
            } else {
                Priority::Drop
            }
        }))
    }

    fn get_chunk_tracker(&self, _id: &IngressMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Ingress)
    }
}

/// Certification 'ArtifactClient' to be managed by 'ArtifactManager'.
pub struct CertificationClient<PoolCertification> {
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    certification_pool: Arc<RwLock<PoolCertification>>,
    client: Arc<dyn CertifierGossip>,
    _log: ReplicaLogger,
}

impl<PoolCertification> CertificationClient<PoolCertification> {
    pub fn new<T: CertifierGossip + 'static>(
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        certification_pool: Arc<RwLock<PoolCertification>>,
        certifier: T,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            consensus_pool_cache,
            certification_pool,
            client: Arc::new(certifier),
            _log: log,
        }
    }
}

impl<PoolCertification: CertificationPool + CertificationGossipPool + Send + Sync>
    ArtifactClient<CertificationArtifact> for CertificationClient<PoolCertification>
{
    fn check_artifact_acceptance(
        &self,
        msg: CertificationMessage,
        _peer_id: &NodeId,
    ) -> Result<ArtifactAcceptance<CertificationMessage>, ArtifactPoolError> {
        Ok(ArtifactAcceptance::AcceptedForProcessing(msg))
    }

    fn has_artifact(&self, msg_id: &CertificationMessageId) -> bool {
        self.certification_pool.read().unwrap().contains(msg_id)
    }

    fn get_validated_by_identifier<'b>(
        &self,
        msg_id: &'b CertificationMessageId,
    ) -> Option<CertificationMessage> {
        self.certification_pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    fn get_filter(&self) -> CertificationMessageFilter {
        self.client.get_filter()
    }

    fn get_all_validated_by_filter(
        &self,
        filter: &CertificationMessageFilter,
    ) -> Vec<Advert<CertificationArtifact>> {
        self.certification_pool
            .read()
            .unwrap()
            .get_all_validated_by_filter(filter.height)
            .map(|msg| CertificationArtifact::to_advert(&msg))
            .collect()
    }

    fn get_priority_function(
        &self,
    ) -> Option<PriorityFn<CertificationMessageId, CertificationMessageAttribute>> {
        let consensus_pool_cache = self.consensus_pool_cache.as_ref();
        let certification_pool = &*self.certification_pool.read().unwrap();
        Some(
            self.client
                .get_priority_function(consensus_pool_cache, certification_pool),
        )
    }

    fn get_chunk_tracker(&self, _id: &CertificationMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Certification)
    }
}

pub struct DkgClient<Pool> {
    dkg_pool: Arc<RwLock<Pool>>,
    client: Arc<dyn DkgGossip>,
    _log: ReplicaLogger,
}

impl<Pool> DkgClient<Pool> {
    pub fn new<T: DkgGossip + 'static>(
        dkg_pool: Arc<RwLock<Pool>>,
        dkg: T,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            dkg_pool,
            client: Arc::new(dkg),
            _log: log,
        }
    }
}

impl<Pool: DkgPool + DkgGossipPool + Send + Sync> ArtifactClient<DkgArtifact> for DkgClient<Pool> {
    fn check_artifact_acceptance(
        &self,
        msg: DkgMessage,
        _peer_id: &NodeId,
    ) -> Result<ArtifactAcceptance<DkgMessage>, ArtifactPoolError> {
        check_protocol_version(&msg)?;
        Ok(ArtifactAcceptance::AcceptedForProcessing(msg))
    }

    fn has_artifact(&self, msg_id: &DkgMessageId) -> bool {
        self.dkg_pool.read().unwrap().contains(msg_id)
    }

    fn get_validated_by_identifier<'b>(&self, msg_id: &'b DkgMessageId) -> Option<DkgMessage> {
        self.dkg_pool
            .read()
            .unwrap()
            .get_validated_by_identifier(msg_id)
    }

    fn get_priority_function(&self) -> Option<PriorityFn<DkgMessageId, DkgMessageAttribute>> {
        let dkg_pool = &*self.dkg_pool.read().unwrap();
        Some(self.client.get_priority_function(dkg_pool))
    }

    fn get_chunk_tracker(&self, _id: &DkgMessageId) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(SingleChunked::Dkg)
    }
}
