// Artifact download list. This data structure tracks artifacts being
// currently downloaded by P2P. The tracking is done using 2 indices.
//
// a. The artifact index
//
//    Artifacts being downloaded can be looked up using their artifact
//    IDs using this index. Artifact download schedule is determined
//    by advert priority class i.e. higher priority adverts are
//    scheduled for download ahead of lower priority adverts. Within
//    the same priority class adverts are scheduled for download in a
//    first come first serve order.
//
// b. Download Expiry Index
//
//    Artifacts downloads are allotted a finite time duration to
//    conclude (artifact timeout). This duration is roughly based on
//    the size of the artifact and the count of unique peers that may
//    be contacted for the artifact. Artifact downloads thus expire at
//    a future time instant called the expiry-instant. The expiry
//    index orders the downloads in increasing order of their
//    expiry-instant. Note: This index may contain multiple downloads
//    expiring at a given expiry-instant.
pub(crate) trait ArtifactDownloadList: Send + Sync {
    // Schedule a download to occur.
    //
    //     Admission control for the artifact download list. Given a
    //     advert checks if the download can be scheduled without
    //     violating the IC download constraints. Returns an artifact
    //     download tracker if the download scheduling succeeds.
    //
    // Parameters:
    //
    //     peer_id: peer from which download is to be initiated. This
    //              peers quota will be charged for the download
    //     advert:  advert for the artifact being downloaded
    //     download_config: download configuration for the p2p instance
    //
    //     max_peer: estimated number of peers that can
    //               be contacted for this download.
    //     artifact_manager: AM associated with this p2p instance.
    fn schedule_download(
        &mut self,
        peer_id: NodeId,
        advert: &GossipAdvert,
        gossip_config: &GossipConfig,
        max_peers: u32,
        artifact_manager: &dyn ArtifactManager,
    ) -> Option<&ArtifactTracker>;

    /// Remove and return expired artifact downloads from the list.
    ///
    /// Returns:
    ///    Vec<ArtifactId>: Vector of ids for the expired downloads.
    fn prune_expired_downloads(&mut self) -> Vec<ArtifactId>;

    /// Get the artifact download tracker associated by its artifact_id
    ///
    /// Parameters:
    ///     artifact_id: artifact id for the query
    ///
    /// Returns:
    ///     Option for the tracker
    fn get_tracker(&mut self, artifact_id: &ArtifactId) -> Option<&mut ArtifactTracker>;

    /// Remove any artifact download tracker from the download list.
    ///
    /// Does nothing if the download tracker does not exist.
    ///
    /// Parameters:
    ///    artifact_id: id for the download that needs to be removed.
    fn remove_tracker(&mut self, artifact_id: &ArtifactId);
}

use linked_hash_map::LinkedHashMap;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub(crate) struct ArtifactTracker {
    expiry_instant: Instant, // time limit for the artifact download
    pub chunkable: Box<dyn Chunkable + Send + Sync>, // Chunkable interface
    pub peer_id: NodeId,     // The node whose quota is charged for this artifact
}

use core::ops::Deref;
use ic_interfaces::artifact_manager::ArtifactManager;
use ic_logger::replica_logger::ReplicaLogger;
use ic_logger::warn;
use ic_protobuf::registry::subnet::v1::GossipConfig;
use ic_types::{artifact::ArtifactId, chunkable::Chunkable, p2p::GossipAdvert, NodeId};

pub(crate) struct ArtifactDownloadListImpl {
    // Artifact list is a LinkedHashmap. This ensures fairness by
    // ordering items by their download initiation time while providing O(1) lookup using artifact
    // ID.
    //
    // Collections like BTreeMap are ordered based on the key. A
    // key ordered data structure would incorrectly favor smaller
    // artifacts with smaller ids for download selection
    artifacts: LinkedHashMap<ArtifactId, ArtifactTracker>,
    expiry_index: BTreeMap<Instant, Vec<ArtifactId>>,
    log: ReplicaLogger,
}

// Hides indexing complexities and allows the list to be manipulated
// using standard container API.
impl Deref for ArtifactDownloadListImpl {
    type Target = LinkedHashMap<ArtifactId, ArtifactTracker>;
    fn deref(&self) -> &Self::Target {
        &self.artifacts
    }
}

impl ArtifactDownloadListImpl {
    pub fn new(log: ReplicaLogger) -> Self {
        ArtifactDownloadListImpl {
            log,
            artifacts: Default::default(),
            expiry_index: Default::default(),
        }
    }
}
impl ArtifactDownloadList for ArtifactDownloadListImpl {
    fn schedule_download(
        &mut self,
        peer_id: NodeId,
        advert: &GossipAdvert,
        gossip_config: &GossipConfig,
        max_advertizing_peer: u32,
        artifact_manager: &dyn ArtifactManager,
    ) -> Option<&ArtifactTracker> {
        // schedule a download of an artifact that are not currently
        // being downloaded
        if !self.artifacts.contains_key(&advert.artifact_id) {
            let artifact_id = &advert.artifact_id;
            match artifact_manager.get_remaining_quota(artifact_id.into(), peer_id) {
                None => return None,
                Some(quota_size) if quota_size < advert.size => return None,
                Some(_) => { /* enough quota remaining */ }
            }

            if let Some(chunk_tracker) = artifact_manager.get_chunk_tracker(&advert.artifact_id) {
                let requested_instant = Instant::now();
                // Calculate the worst-case time estimate for the
                // artifact download.  This worst-case estimate
                // assumes that all chunks for the artifact will
                // timeout for each peer that has advertised the
                // artifact.
                //
                // TODO: Revisit this in the context of NNS sub net: DFN-1661
                let download_eta_ms =
                    std::cmp::max(advert.size as u64 / gossip_config.max_chunk_size as u64, 1)
                        * max_advertizing_peer as u64
                        * gossip_config.max_chunk_wait_ms as u64;
                let expiry_instant = requested_instant + Duration::from_millis(download_eta_ms);
                self.artifacts.insert(
                    advert.artifact_id.clone(),
                    ArtifactTracker {
                        expiry_instant,
                        chunkable: chunk_tracker,
                        peer_id,
                    },
                );
                self.expiry_index
                    .entry(expiry_instant)
                    .and_modify(|expired_artifacts| expired_artifacts.push(artifact_id.clone()))
                    .or_insert_with(|| (vec![artifact_id.clone()]));
            } else {
                warn!(self.log, "Chunk tracker not found for advert {:?}", advert);
            }
        }
        self.artifacts.get(&advert.artifact_id)
    }

    fn prune_expired_downloads(&mut self) -> Vec<ArtifactId> {
        let now_instant = Instant::now();

        // 2 phase pruning of the expired downloads.
        //
        // In the first phase, we walk the time ordered expired-instants
        // collecting instants until we are past the current time instant.
        //
        // In the second phase we extract artifacts from
        // expired-instants collected in phase 1. Finally we delete
        // the expired-instant entries.

        // collect the expired instances
        let expired_instances: Vec<_> = self
            .expiry_index
            .iter()
            .take_while(|(expiry_instant, _)| **expiry_instant < now_instant)
            .map(|(expiry_instant, expired_artifacts)| (*expiry_instant, expired_artifacts.clone()))
            .collect();

        // extract artifact ids from the expired instances
        let mut expired_artifacts = Vec::new();
        expired_instances
            .iter()
            .for_each(|(_expiry_instant, artifact_ids)| {
                artifact_ids.iter().for_each(|artifact_id| {
                    self.artifacts.remove(&artifact_id);
                    expired_artifacts.push(artifact_id.clone());
                });
            });

        // Remove the expired instances
        expired_instances.into_iter().for_each(|(instant, _)| {
            self.expiry_index.remove(&instant);
        });
        expired_artifacts
    }

    fn get_tracker(&mut self, artifact_id: &ArtifactId) -> Option<&mut ArtifactTracker> {
        self.artifacts.get_mut(&artifact_id)
    }

    fn remove_tracker(&mut self, artifact_id: &ArtifactId) {
        // remove from the artifact id index
        if let Some(tracker) = self.artifacts.remove(&artifact_id) {
            // remove from the expiry index
            if let Some(expiry_entry) = self.expiry_index.get_mut(&tracker.expiry_instant) {
                expiry_entry.retain(|expired_artifacts_id| expired_artifacts_id != artifact_id);
                // remove expiry entry if no more artifacts are expiring at that instant
                if expiry_entry.is_empty() {
                    self.expiry_index.remove(&tracker.expiry_instant);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download_management::tests::TestArtifactManager;
    use ic_test_utilities::p2p::p2p_test_setup_logger;
    use ic_test_utilities::types::ids::node_test_id;
    use ic_types::artifact::ArtifactAttribute;
    use ic_types::crypto::CryptoHash;
    use ic_types::p2p;

    fn try_begin_download(
        num_adverts: i32,
        gossip_config: &GossipConfig,
        artifact_manager: &dyn ArtifactManager,
        artifact_download_list: &mut ArtifactDownloadListImpl,
    ) -> std::time::Instant {
        // insert and remove artifacts
        let mut max_expiry = std::time::Instant::now();
        for advert_id in 0..num_adverts {
            let gossip_advert = GossipAdvert {
                artifact_id: ArtifactId::FileTreeSync(advert_id.to_string()),
                attribute: ArtifactAttribute::FileTreeSync(advert_id.to_string()),
                size: 0,
                // This is ok, this is just a test
                integrity_hash: CryptoHash(vec![]),
            };
            let tracker = artifact_download_list
                .schedule_download(
                    node_test_id(0),
                    &gossip_advert,
                    &gossip_config,
                    1,
                    artifact_manager,
                )
                .unwrap();

            if tracker.expiry_instant > max_expiry {
                max_expiry = tracker.expiry_instant;
            }
        }
        max_expiry
    }

    #[test]
    fn dowload_list_expire_test() {
        // insert and timeout artifacts
        let artifact_manager = TestArtifactManager {
            quota: std::usize::MAX,
            num_chunks: 0,
        };
        let logger = p2p_test_setup_logger();
        let log: ReplicaLogger = logger.root.clone().into();
        let mut artifact_download_list = ArtifactDownloadListImpl::new(log);
        let mut gossip_config = p2p::build_default_gossip_config();
        gossip_config.max_chunk_wait_ms = 1000;
        let num_adverts = 30;
        let max_expiry = try_begin_download(
            num_adverts,
            &gossip_config,
            &artifact_manager,
            &mut artifact_download_list,
        );

        while std::time::Instant::now() < max_expiry {
            std::thread::sleep(std::time::Duration::from_millis(
                gossip_config.max_chunk_wait_ms as u64,
            ));
        }

        let expired = artifact_download_list.prune_expired_downloads();
        assert_eq!(expired.len(), num_adverts as usize);
        assert_eq!(artifact_download_list.len(), 0);

        // check that expired artifact list is empty
        let expired = artifact_download_list.prune_expired_downloads();
        assert_eq!(expired.len(), 0);
        assert_eq!(artifact_download_list.len(), 0);
    }

    #[test]
    fn dowload_list_remove_test() {
        let artifact_manager = TestArtifactManager {
            quota: std::usize::MAX,
            num_chunks: 0,
        };
        let logger = p2p_test_setup_logger();
        let log: ReplicaLogger = logger.root.clone().into();
        let mut artifact_download_list = ArtifactDownloadListImpl::new(log);
        let mut gossip_config = p2p::build_default_gossip_config();
        gossip_config.max_chunk_wait_ms = 1000;
        let num_adverts = 30;
        let _max_expiry = try_begin_download(
            num_adverts,
            &gossip_config,
            &artifact_manager,
            &mut artifact_download_list,
        );

        for advert_id in 0..num_adverts {
            let artifact_id = ArtifactId::FileTreeSync(advert_id.to_string());
            artifact_download_list.get_tracker(&artifact_id).unwrap();
            artifact_download_list.remove_tracker(&artifact_id);
        }
        assert_eq!(artifact_download_list.len(), 0);
    }
}
