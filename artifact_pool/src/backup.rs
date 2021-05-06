//! This module implements a backup mechanism for essential consensus artifacts.
//! These back ups will allow us to obtain a relevant state, and recover a
//! subnet from that state.
//!
//! To re-compute a state at any height, we need to follow the finalized chain
//! starting from the genesis block, executing all block proposals one by one,
//! using their payloads (ingress + xnet) and the random tape as inputs. We can
//! use CUPs as checkpoints, to verify the hash of the re-computed state. We
//! can use finalizations to verify the authenticity of each stored proposal of
//! the finalized chain. We can use notarizations to verify the authenticity of
//! all proposals behind the latest finalized block (if the situation applies).
//! Since consensus purges only after a new CUP was stored in the validated pool
//! and since we backup all artifacts instantly after the pool update, there is
//! no possibility to inject purging (or any other deletion) of artifacts
//! between the pool update and the backup.

use ic_interfaces::{
    consensus_pool::{ConsensusPool, HeightRange},
    time_source::TimeSource,
};
use ic_protobuf::types::v1 as pb;
use ic_types::{
    consensus::{
        BlockProposal, CatchUpPackage, ConsensusMessage, Finalization, HasHeight, Notarization,
        RandomBeacon, RandomTape,
    },
    crypto::CryptoHashOf,
    time::{Time, UNIX_EPOCH},
    Height,
};
use prost::Message;
use std::{fs, io::Write, path::PathBuf, sync::RwLock, thread, time::Duration};

#[allow(clippy::large_enum_variant)]
enum BackupArtifact {
    Finalization(Finalization),
    Notarization(Notarization),
    BlockProposal(BlockProposal),
    RandomBeacon(RandomBeacon),
    RandomTape(RandomTape),
    CatchUpPackage(CatchUpPackage),
}

pub(super) struct Backup {
    // Path pointing to <backup_dir>/<subnet_id>/<replica_version>
    path: PathBuf,
    // The timestamp of the last backup purge.
    time_of_last_purge: RwLock<Time>,
    // Thread handle of the thread executing the backup.
    pending_backup: RwLock<Option<thread::JoinHandle<()>>>,
    // Thread handle of the thread executing the purging.
    pending_purging: RwLock<Option<thread::JoinHandle<()>>>,
    // The maximum age backup artifacts can reach before purging.
    age_threshold_secs: Duration,
    // Time interval between purges.
    purge_interval_secs: Duration,
}

impl Backup {
    pub fn new(
        pool: &dyn ConsensusPool,
        path: PathBuf,
        age_threshold_secs: Duration,
        purge_interval_secs: Duration,
    ) -> Self {
        let backup = Self {
            path: path.clone(),
            time_of_last_purge: RwLock::new(UNIX_EPOCH),
            pending_purging: Default::default(),
            pending_backup: Default::default(),
            age_threshold_secs,
            purge_interval_secs,
        };

        // Due to the fact that the backup is synced to the disk completely
        // independently of the consensus pool and always after the consensus pool was
        // mutated, we might run into an inconsistent state between the pool and the
        // backup data if the replica gets killed by the node manager. To avoid this
        // situation, on the instantiation of the consensus pool and the backup
        // component, we need to synchronize the backup with the pool in a blocking
        // manner.
        let artifacts = get_all_persisted_artifacts(pool);
        store_sync(artifacts, path);
        backup
    }

    // Filters the new artifacts and asynchronously writes the relevant artifacts
    // to the disk.
    pub fn store(&self, time_source: &dyn TimeSource, artifacts: Vec<ConsensusMessage>) {
        // We block until the previous write has finished. This should never happen, as
        // writing of the artifacts should take less than one consensus round, otherwise
        // a full backup is infeasible.
        self.sync_backup();
        let path = self.path.clone();
        let handle = std::thread::spawn(move || {
            store_sync(artifacts, path);
        });
        *self.pending_backup.write().unwrap() = Some(handle);

        // If we didn't purge within the last PURGE_INTERVAL, trigger a new purge.
        // This way we avoid a too frequent purging. We also block if the previous
        // purging has not finished yet, which is not expected with sufficiently
        // large PURGE_INTERVAL.
        let time_of_last_purge = *self.time_of_last_purge.read().unwrap();
        if time_source.get_relative_time() - time_of_last_purge > self.purge_interval_secs {
            self.sync_purging();
            let path = self.path.clone();
            let threshold = self.age_threshold_secs;
            let handle = std::thread::spawn(move || {
                purge(threshold, path)
                    .unwrap_or_else(|err| panic!("Backup purging failed: {:?}", err))
            });
            *self.pending_backup.write().unwrap() = Some(handle);
            *self.time_of_last_purge.write().unwrap() = time_source.get_relative_time();
        }
    }

    // Joins on the backup thread handle and blocks until the thread has finished.
    fn sync_backup(&self) {
        if let Some(handle) = self.pending_backup.write().unwrap().take() {
            handle
                .join()
                .expect("Couldn't finish writing backup files: {:?}");
        }
    }

    // Joins on the purging thread handle and blocks until the thread has finished.
    fn sync_purging(&self) {
        if let Some(handle) = self.pending_purging.write().unwrap().take() {
            handle
                .join()
                .expect("Couldn't finish purging backup files: {:?}");
        }
    }
}

// Write all backup files to the disk. For the sake of simplicity, we write all
// artifacts sequentially.
fn store_sync(artifacts: Vec<ConsensusMessage>, path: PathBuf) {
    use ConsensusMessage::*;
    artifacts
        .into_iter()
        .filter_map(|artifact| match artifact {
            Finalization(artifact) => Some(BackupArtifact::Finalization(artifact)),
            Notarization(artifact) => Some(BackupArtifact::Notarization(artifact)),
            BlockProposal(artifact) => Some(BackupArtifact::BlockProposal(artifact)),
            RandomTape(artifact) => Some(BackupArtifact::RandomTape(artifact)),
            RandomBeacon(artifact) => Some(BackupArtifact::RandomBeacon(artifact)),
            CatchUpPackage(artifact) => Some(BackupArtifact::CatchUpPackage(artifact)),
            // Do not replace by a `_` so that we evaluate at this place if we want to
            // backup a new artifact!
            RandomBeaconShare(_)
            | NotarizationShare(_)
            | FinalizationShare(_)
            | RandomTapeShare(_)
            | CatchUpPackageShare(_) => None,
        })
        .for_each(|artifact| {
            artifact
                .write_to_disk(&path)
                .unwrap_or_else(|err| panic!("Couldn't write artifact to disk: {:?}", err))
        });
}

// Purges all backup artifacts grouped by heights older than the specified
// threshold.
fn purge(threshold_secs: Duration, path: PathBuf) -> Result<(), std::io::Error> {
    let height_dirs: Vec<_> = fs::read_dir(&path)?
        .map(|dir_entry| {
            dir_entry.unwrap_or_else(|err| panic!("Couldn't read the path: {:?}", err))
        })
        .flat_map(|entry| {
            fs::read_dir(entry.path())
                .expect("Couldn't read the height group directory")
                .map(|entry| entry.expect("Couldn't read the entry"))
        })
        .collect();
    for entry in height_dirs {
        let age = entry
            .metadata()?
            .modified()?
            .elapsed()
            .unwrap_or_else(|err| panic!("System time error: {:?}", err));
        if age > threshold_secs {
            fs::remove_dir_all(entry.path())?;
        }
    }
    // After we purged expired heights, let's purge empty purged groups.
    let group_dirs: Vec<_> = fs::read_dir(&path)?
        .map(|dir_entry| {
            dir_entry.unwrap_or_else(|err| panic!("Couldn't read the path: {:?}", err))
        })
        .collect();
    for entry in group_dirs {
        let age = entry
            .metadata()?
            .modified()?
            .elapsed()
            .unwrap_or_else(|err| panic!("System time error: {:?}", err));
        if age > threshold_secs && entry.path().read_dir()?.next().is_none() {
            fs::remove_dir_all(entry.path())?;
        }
    }

    Ok(())
}

// Returns all artifacts starting from the latest catch-up package height.
fn get_all_persisted_artifacts(pool: &dyn ConsensusPool) -> Vec<ConsensusMessage> {
    let cup_height = pool.as_cache().catch_up_package().height();
    let notarization_pool = pool.validated().notarization();
    let notarization_range = HeightRange::new(
        cup_height,
        notarization_pool
            .max_height()
            .unwrap_or_else(|| Height::from(0)),
    );
    let finalization_pool = pool.validated().finalization();
    let finalization_range = HeightRange::new(
        cup_height,
        finalization_pool
            .max_height()
            .unwrap_or_else(|| Height::from(0)),
    );
    let block_proposal_pool = pool.validated().block_proposal();
    let block_proposal_range = HeightRange::new(
        cup_height,
        block_proposal_pool
            .max_height()
            .unwrap_or_else(|| Height::from(0)),
    );
    let catch_up_package_pool = pool.validated().catch_up_package();
    let catch_up_package_range = HeightRange::new(
        cup_height,
        catch_up_package_pool
            .max_height()
            .unwrap_or_else(|| Height::from(0)),
    );
    let random_tape_pool = pool.validated().random_tape();
    let random_tape_range = HeightRange::new(
        cup_height,
        random_tape_pool
            .max_height()
            .unwrap_or_else(|| Height::from(0)),
    );
    let random_beacon_pool = pool.validated().random_beacon();
    let random_beacon_range = HeightRange::new(
        cup_height,
        random_beacon_pool
            .max_height()
            .unwrap_or_else(|| Height::from(0)),
    );

    finalization_pool
        .get_by_height_range(finalization_range)
        .map(ConsensusMessage::Finalization)
        .chain(
            notarization_pool
                .get_by_height_range(notarization_range)
                .map(ConsensusMessage::Notarization),
        )
        .chain(
            catch_up_package_pool
                .get_by_height_range(catch_up_package_range)
                .map(ConsensusMessage::CatchUpPackage),
        )
        .chain(
            random_tape_pool
                .get_by_height_range(random_tape_range)
                .map(ConsensusMessage::RandomTape),
        )
        .chain(
            random_beacon_pool
                .get_by_height_range(random_beacon_range)
                .map(ConsensusMessage::RandomBeacon),
        )
        .chain(
            block_proposal_pool
                .get_by_height_range(block_proposal_range)
                .map(ConsensusMessage::BlockProposal),
        )
        .collect()
}

impl Drop for Backup {
    fn drop(&mut self) {
        self.sync_backup();
        self.sync_purging();
    }
}

impl BackupArtifact {
    // Writes the protobuf serialization of the artifact into a file in the given
    // directory.
    fn write_to_disk(&self, path: &PathBuf) -> Result<(), std::io::Error> {
        let (file_directory, file_name) = self.file_location(path);
        // Create the path if necessary.
        fs::create_dir_all(&file_directory)?;
        let full_path = file_directory.join(file_name);
        // If the file exists, it will be overwritten (this is required on
        // intializations).
        let mut file = fs::File::create(&full_path)?;
        file.write_all(&self.serialize())
    }

    // Serializes the artifact to protobuf.
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        use BackupArtifact::*;
        match self {
            Finalization(artifact) => pb::Finalization::from(artifact).encode(&mut buf),
            Notarization(artifact) => pb::Notarization::from(artifact).encode(&mut buf),
            BlockProposal(artifact) => pb::BlockProposal::from(artifact).encode(&mut buf),
            RandomTape(artifact) => pb::RandomTape::from(artifact).encode(&mut buf),
            RandomBeacon(artifact) => pb::RandomBeacon::from(artifact).encode(&mut buf),
            CatchUpPackage(artifact) => pb::CatchUpPackage::from(artifact).encode(&mut buf),
        }
        .expect("Couldn't serialize backup artifact to protobuf.");
        buf
    }

    // Each artifact will be stored separately used the following path:
    //
    // <subnet_id>/<(height / N) * N>/height/<artifact_specific_name>.bin
    //
    // Note that the artifact specific name must contain all parameters to be
    // differentiated not only across other artifacts of the same replica, but also
    // across artifacts from all replicas. E.g., since we use multi-signatures for
    // notarizations and finalizations, these artifacts can be created in different
    // ways on different replicas, so we need to put their hashes into the artifact
    // name.
    fn file_location(&self, path: &PathBuf) -> (PathBuf, String) {
        // Create a subdir for the height
        use BackupArtifact::*;
        let (height, file_name) = match self {
            Finalization(artifact) => (
                artifact.height(),
                format!(
                    "finalization_{}_{}.bin",
                    bytes_to_hex_str(&artifact.content.block),
                    bytes_to_hex_str(&ic_crypto::crypto_hash(artifact)),
                ),
            ),
            Notarization(artifact) => (
                artifact.height(),
                format!(
                    "notarization_{}_{}.bin",
                    bytes_to_hex_str(&artifact.content.block),
                    bytes_to_hex_str(&ic_crypto::crypto_hash(artifact)),
                ),
            ),
            BlockProposal(artifact) => (
                artifact.height(),
                format!(
                    "block_proposal_{}_{}.bin",
                    bytes_to_hex_str(&artifact.content.get_hash()),
                    bytes_to_hex_str(&ic_crypto::crypto_hash(artifact)),
                ),
            ),
            RandomTape(artifact) => (artifact.height(), "random_tape.bin".to_string()),
            RandomBeacon(artifact) => (artifact.height(), "random_beacon.bin".to_string()),
            CatchUpPackage(artifact) => (artifact.height(), "catch_up_package.bin".to_string()),
        };
        // We group heights by directories to avoid running into any kind of unexpected
        // FS inode limitations. Each group directory will contain at most
        // `group_size` heights.
        let group_size = 10000;
        let group_key = (height.get() / group_size) * group_size;
        let path_with_height = path.join(group_key.to_string()).join(height.to_string());
        (path_with_height, file_name)
    }
}

// Dumps a CryptoHash to a hex-encoded string.
pub(super) fn bytes_to_hex_str<T>(hash: &CryptoHashOf<T>) -> String {
    hash.clone()
        .get()
        .0
        .iter()
        .fold(String::new(), |mut hash, byte| {
            hash.push_str(&format!("{:X}", byte));
            hash
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_test_utilities::{consensus::fake::*, mock_time, types::ids::node_test_id};
    use ic_types::{
        batch::*,
        consensus::*,
        crypto::{CryptoHash, CryptoHashOf},
        RegistryVersion,
    };
    use std::convert::TryFrom;

    #[test]
    fn test_random_tape_conversion() {
        let artifact = RandomTape::fake(RandomTapeContent::new(Height::from(22)));
        let mut buf = Vec::new();
        pb::RandomTape::from(&artifact).encode(&mut buf).unwrap();
        assert_eq!(
            artifact,
            RandomTape::try_from(pb::RandomTape::decode(buf.as_slice()).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_finalization_conversion() {
        let artifact = Finalization::fake(FinalizationContent::new(
            Height::from(22),
            CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
        ));
        let mut buf = Vec::new();
        pb::Finalization::from(&artifact).encode(&mut buf).unwrap();
        assert_eq!(
            artifact,
            Finalization::try_from(pb::Finalization::decode(buf.as_slice()).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_notarization_conversion() {
        let artifact = Notarization::fake(NotarizationContent::new(
            Height::from(22),
            CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
        ));
        let mut buf = Vec::new();
        pb::Notarization::from(&artifact).encode(&mut buf).unwrap();
        assert_eq!(
            artifact,
            Notarization::try_from(pb::Notarization::decode(buf.as_slice()).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_block_proposal_conversion() {
        let artifact = BlockProposal::fake(
            Block::new(
                CryptoHashOf::from(CryptoHash(Vec::new())),
                Payload::new(
                    ic_crypto::crypto_hash,
                    ic_types::consensus::dkg::Summary::fake().into(),
                ),
                Height::from(123),
                Rank(456),
                ValidationContext {
                    registry_version: RegistryVersion::from(99),
                    certified_height: Height::from(42),
                    time: mock_time(),
                },
            ),
            node_test_id(333),
        );
        let mut buf = Vec::new();
        pb::BlockProposal::from(&artifact).encode(&mut buf).unwrap();
        assert_eq!(
            artifact,
            BlockProposal::try_from(pb::BlockProposal::decode(buf.as_slice()).unwrap()).unwrap()
        );
    }
}
