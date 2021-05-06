// Needs to be `pub` so that the benchmarking code in `state_manager/benches`
// can access it.
pub mod checkpoint;
pub mod labeled_tree_visitor;
pub mod manifest;
pub mod state_sync;
pub mod stream_encoding;
pub mod tree_diff;
pub mod tree_hash;

use crossbeam_channel::{unbounded, Sender};
use ic_config::state_manager::Config;
use ic_cow_state::CowMemoryManager;
use ic_crypto_tree_hash::{
    recompute_digest, Digest, HashTree, LabeledTree, MixedHashTree, WitnessGenerator,
    WitnessGeneratorImpl,
};
use ic_interfaces::{
    certification::Verifier,
    certified_stream_store::{CertifiedStreamStore, DecodeStreamError, EncodeStreamError},
    state_manager::{
        CertificationMask, CertificationScope, Labeled, StateManager, StateManagerError,
        StateManagerResult, StateReader, CERT_CERTIFIED, CERT_UNCERTIFIED,
    },
};
use ic_logger::{debug, error, fatal, info, warn, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_protobuf::proxy::{ProtoProxy, ProxyDecodeError};
use ic_protobuf::{messaging::xnet::v1, state::v1 as pb};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{page_map::PersistenceError, ReplicatedState};
use ic_state_layout::{error::LayoutError, StateLayout};
use ic_types::{
    artifact::StateSyncArtifactId,
    chunkable::Chunkable,
    consensus::certification::Certification,
    crypto::CryptoHash,
    malicious_flags::MaliciousFlags,
    state_sync::Manifest,
    xnet::{CertifiedStreamSlice, StreamIndex, StreamSlice},
    CryptoHashOfPartialState, CryptoHashOfState, ExecutionRound, Height, RegistryVersion, SubnetId,
};
use ic_utils::{ic_features::*, thread::JoinOnDrop};
use prometheus::{HistogramVec, IntCounterVec, IntGauge};
use prost::Message;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::TryFrom;
use std::fmt;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

#[derive(Clone)]
pub struct StateManagerMetrics {
    state_manager_error_count: IntCounterVec,
    checkpoint_op_duration: HistogramVec,
    api_call_duration: HistogramVec,
    last_diverged: IntGauge,
    state_sync_size: IntCounterVec,
    state_sync_duration: HistogramVec,
}

// Note [Metrics preallocation]
// ============================
//
// If vectorized metrics are used for events that happen rarely (like state
// sync), it becomes a challenge to visualize them.  As Prometheus doesn't know
// which label values are going to be used in advance, the values are simply
// missing until they are set for the first time.  This leads to
// rate(metric[period]) returning 0 because the value switched from NONE to,
// say, 1, not from 0 to 1.  So only the next update of the metric will result
// in a meaningful rate, which in the case of state sync might never appear.
//
// In order to solve this, we "preallocate" metrics with values of labels we
// expect to see. This makes initial vectorized metric values equal to 0, so the
// very first metric update should be visible to Prometheus.

impl StateManagerMetrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
        let checkpoint_op_duration = metrics_registry.histogram_vec(
            "state_manager_checkpoint_op_duration_seconds",
            "Duration of checkpoint operations in seconds.",
            // 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, …, 10s, 20s, 50s
            decimal_buckets(-3, 1),
            &["op"],
        );
        let api_call_duration = metrics_registry.histogram_vec(
            "state_manager_api_call_duration_seconds",
            "Duration of a StateManager API call in seconds.",
            // 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, …, 10s, 20s, 50s
            decimal_buckets(-3, 1),
            &["op"],
        );

        let state_manager_error_count = metrics_registry.int_counter_vec(
            "state_manager_error_count",
            "Total number of errors encountered in the state manager.",
            &["source"],
        );

        let last_diverged = metrics_registry.int_gauge(
            "state_manager_last_diverged_state_timestamp",
            "The (UTC) timestamp of the last diverged state report.",
        );

        let state_sync_size = metrics_registry.int_counter_vec(
            "state_sync_size_bytes_total",
            "Size of chunks synchronized by different operations ('fetch', 'copy', 'preallocate') during all the state sync in bytes.",
            &["op"],
        );

        // Note [Metrics preallocation]
        for op in &["fetch", "copy"] {
            state_sync_size.with_label_values(&[*op]);
        }

        let state_sync_duration = metrics_registry.histogram_vec(
            "state_sync_duration_seconds",
            "Duration of state sync in seconds indexed by status ('ok', 'already_exists', 'unrecoverable', 'io_err').",
            // 1s, 2s, 5s, 10s, 20s, 50s, …, 1000s, 2000s, 5000s
            decimal_buckets(0, 3),
            &["status"],
        );

        // Note [Metrics preallocation]
        for status in &["ok", "already_exists", "unrecoverable", "io_err"] {
            state_sync_duration.with_label_values(&[*status]);
        }

        Self {
            checkpoint_op_duration,
            api_call_duration,
            state_manager_error_count,
            last_diverged,
            state_sync_size,
            state_sync_duration,
        }
    }
}

type StatesMetadata = BTreeMap<Height, StateMetadata>;
type CertificationsMetadata = BTreeMap<Height, CertificationMetadata>;

#[derive(Debug, Default)]
struct StateMetadata {
    // We don't persist the checkpoint reference because we re-create it every
    // time we discover a checkpoint on disk.
    checkpoint_ref: Option<CheckpointRef>,
    // Manifest and root hash are computed asynchronously, so they are set to
    // None before the values are computed.
    root_hash: Option<CryptoHashOfState>,
    manifest: Option<Manifest>,
}

impl From<&StateMetadata> for pb::StateMetadata {
    fn from(metadata: &StateMetadata) -> Self {
        Self {
            manifest: metadata.manifest.as_ref().map(|m| m.clone().into()),
        }
    }
}

impl TryFrom<pb::StateMetadata> for StateMetadata {
    type Error = ProxyDecodeError;

    fn try_from(proto: pb::StateMetadata) -> Result<Self, ProxyDecodeError> {
        match proto.manifest {
            None => Ok(Default::default()),
            Some(manifest) => {
                let manifest = Manifest::try_from(manifest)?;
                let root_hash = CryptoHashOfState::from(CryptoHash(
                    crate::manifest::manifest_hash(&manifest).to_vec(),
                ));
                Ok(Self {
                    checkpoint_ref: None,
                    manifest: Some(manifest),
                    root_hash: Some(root_hash),
                })
            }
        }
    }
}

/// This type holds per-height metadata related to certification.
#[derive(Debug)]
struct CertificationMetadata {
    /// Fully materialized hash tree built from the part of the state that is
    /// certified every round.  Dropped as soon as a higher state is certified.
    hash_tree: Option<Arc<HashTree>>,
    /// Root hash of the tree above. It's stored even if the hash tree is
    /// dropped.
    certified_state_hash: CryptoHash,
    /// Certification of the root hash delivered by consensus via
    /// `deliver_state_certification()`.
    certification: Option<Certification>,
}

struct Snapshot {
    height: Height,
    state: Arc<ReplicatedState>,
}

/// This struct contains all the data required to read/delete a checkpoint from
/// disk.
///
/// It also holds a `marked_deleted` flag that controls whether the
/// corresponding checkpoint needs to be deleted when the context goes out of
/// scope.
struct CheckpointContext {
    log: ReplicaLogger,
    metrics: StateManagerMetrics,
    state_layout: StateLayout,
    height: Height,
    marked_deleted: AtomicBool,
}

impl Drop for CheckpointContext {
    fn drop(&mut self) {
        if !self.marked_deleted.load(Ordering::Relaxed) {
            return;
        }

        let start = Instant::now();
        if let Err(err) = self.state_layout.remove_checkpoint(self.height) {
            self.metrics
                .state_manager_error_count
                .with_label_values(&["remove_checkpoint"])
                .inc();
            error!(
                self.log,
                "Failed to remove the checkpoint with height {}: {}", self.height, err
            );
        } else {
            let elapsed = start.elapsed();
            info!(
                self.log,
                "Removed checkpoint @{} in {:?}", self.height, elapsed
            );
            self.metrics
                .checkpoint_op_duration
                .with_label_values(&["remove"])
                .observe(elapsed.as_secs_f64());
        }
    }
}

/// CheckpointRef is a value indicating that a checkpoint is being used.
///
/// When the last reference goes away, the checkpoint will be deleted if it was
/// marked as deleted.
///
/// We need this mechanism to be able to hash checkpoint data in background: if
/// `remove_states_below(H)` is called while we hash the checkpoint @H, eagerly
/// removing the checkpoint might cause a crash in the hasher that won't be able
/// to find deleted files anymore.
///
/// NOTE: We must ensure that we never construct two distinct references
/// (i.e. one is not a clone of another) to the same checkpoint.
#[derive(Clone)]
pub struct CheckpointRef(Arc<CheckpointContext>);

impl CheckpointRef {
    /// Construct a new checkpoint reference.
    fn new(
        log: ReplicaLogger,
        metrics: StateManagerMetrics,
        state_layout: StateLayout,
        height: Height,
    ) -> Self {
        Self(Arc::new(CheckpointContext {
            log,
            metrics,
            state_layout,
            height,
            marked_deleted: AtomicBool::new(false),
        }))
    }

    /// Request removal of this checkpoint when the last reference to this
    /// checkpoint goes out of scope.
    fn mark_deleted(&self) {
        self.0.marked_deleted.store(true, Ordering::Relaxed);
    }
}

impl fmt::Debug for CheckpointRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "checkpoint reference #{}", self.0.height)
    }
}

struct ComputeManifestRequest {
    checkpoint_ref: CheckpointRef,
}

/// SharedState is mutable state that can be accessed from multiple threads.
struct SharedState {
    certifications_metadata: CertificationsMetadata,
    states_metadata: StatesMetadata,
    // A list of states present in the memory.  This list is guranteed to not be
    // empty as it should always contain the state at height=0.
    snapshots: VecDeque<Snapshot>,
    // The last checkpoint that was advertised.
    last_advertised: Height,
    // The state we are are trying to fetch.
    fetch_state: Option<(Height, CryptoHashOfState)>,
    // State representing the on disk mutable state
    tip: Option<(Height, ReplicatedState)>,
    // The last witness generator used. Cached because creating a
    // `WitnessGenerator` from a `HashTree` is expensive.
    last_witness_generator: Option<Arc<WitnessGeneratorImpl>>,
}

impl SharedState {
    fn disable_state_fetch_below(&mut self, height: Height) {
        if let Some((sync_height, _hash)) = &self.fetch_state {
            if *sync_height <= height {
                self.fetch_state = None
            }
        }
    }
}

// We send complex objects to a different thread to free them. This will spread
// the cost of deallocation over a longer period of time, and avoid long pauses.
type Deallocation = Box<dyn std::any::Any + Send + 'static>;

// We will not use the deallocation thread when the number of pending
// deallocation objects goes above the threshold.
const DEALLOCATION_BACKLOG_THRESHOLD: usize = 500;

/// The number of diverged states to keep before we start deleting the old ones.
const MAX_DIVERGED_STATES_TO_KEEP: usize = 2;

pub struct StateManagerImpl {
    log: ReplicaLogger,
    metrics: StateManagerMetrics,
    state_layout: StateLayout,
    states: Arc<parking_lot::RwLock<SharedState>>,
    verifier: Arc<dyn Verifier>,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    compute_manifest_request_sender: Sender<ComputeManifestRequest>,
    deallocation_sender: Sender<Deallocation>,
    // Cached latest state height.  We cache it separately because it's
    // requested quite often and this causes high contention on the lock.
    latest_state_height: AtomicU64,
    latest_certified_height: AtomicU64,
    _state_hasher_handle: JoinOnDrop<()>,
    _deallocation_handle: JoinOnDrop<()>,
}

fn load_checkpoint(
    state_layout: &StateLayout,
    height: Height,
    metrics: &StateManagerMetrics,
    own_subnet_type: SubnetType,
) -> Result<ReplicatedState, CheckpointError> {
    state_layout
        .checkpoint(height)
        .map_err(|e| e.into())
        .and_then(|layout| {
            let _timer = metrics
                .checkpoint_op_duration
                .with_label_values(&["recover"])
                .start_timer();
            checkpoint::load_checkpoint(&layout, own_subnet_type)
        })
}

fn load_checkpoint_as_tip(
    log: &ReplicaLogger,
    state_layout: &StateLayout,
    height: Height,
    own_subnet_type: SubnetType,
) -> ReplicatedState {
    info!(log, "Recovering checkpoint @{} as tip", height);

    state_layout
        .reset_tip_to(height)
        .unwrap_or_else(|err| fatal!(log, "Failed to reset tip to checkpoint height: {:?}", err));

    let tip_layout = state_layout
        .tip()
        .unwrap_or_else(|err| fatal!(log, "Failed to retrieve tip {:?}", err));

    let tip = checkpoint::load_checkpoint(&tip_layout, own_subnet_type)
        .unwrap_or_else(|err| fatal!(log, "Failed to reset tip to checkpoint height: {:?}", err));

    let mut tip = match checkpoint::handle_disk_format_changes(&tip_layout, &tip) {
        Ok(needs_reload) => {
            if needs_reload {
                // Reload the checkpoint to factor in the upgrades/downgrades
                checkpoint::load_checkpoint(&tip_layout, own_subnet_type).unwrap_or_else(|err| {
                    fatal!(log, "Failed to reset tip to checkpoint height: {:?}", err)
                })
            } else {
                tip
            }
        }
        Err(err) => fatal!(log, "Failed to upgrade/downgrade tip {:?}", err),
    };

    checkpoint::reopen_state_as_tip(&tip_layout, &mut tip)
        .unwrap_or_else(|err| fatal!(log, "Failed to reopen tip {:?}", err));

    tip
}

/// Deletes obsolete diverged states and state backups, keeping at most
/// MAX_DIVERGED_STATES_TO_KEEP.
fn cleanup_diverged_states(log: &ReplicaLogger, layout: &StateLayout) {
    if let Ok(diverged_heights) = layout.diverged_checkpoint_heights() {
        if diverged_heights.len() > MAX_DIVERGED_STATES_TO_KEEP {
            let to_remove = diverged_heights.len() - MAX_DIVERGED_STATES_TO_KEEP;
            for h in diverged_heights.iter().take(to_remove) {
                match layout.remove_diverged_checkpoint(*h) {
                    Ok(()) => info!(log, "Successfully removed diverged state {}", *h),
                    Err(err) => info!(log, "{}", err),
                }
            }
        }
    }
    if let Ok(backup_heights) = layout.backup_heights() {
        if backup_heights.len() > MAX_DIVERGED_STATES_TO_KEEP {
            let to_remove = backup_heights.len() - MAX_DIVERGED_STATES_TO_KEEP;
            for h in backup_heights.iter().take(to_remove) {
                match layout.remove_backup(*h) {
                    Ok(()) => info!(log, "Successfully removed backup {}", *h),
                    Err(err) => info!(log, "Failed to remove backup {}", err),
                }
            }
        }
    }
}

fn report_last_diverged_checkpoint(
    log: &ReplicaLogger,
    metrics: &StateManagerMetrics,
    state_layout: &StateLayout,
) {
    match state_layout.diverged_checkpoint_heights() {
        Err(e) => warn!(log, "failed to enumerate diverged checkpoints: {}", e),
        Ok(heights) => {
            use std::time::SystemTime;

            let mut last_time = SystemTime::UNIX_EPOCH;
            for h in heights {
                let p = state_layout.diverged_checkpoint_path(h);
                match p
                    .metadata()
                    .and_then(|m| m.created().or_else(|_| m.modified()))
                {
                    Ok(ctime) => {
                        last_time = last_time.max(ctime);
                    }
                    Err(e) => info!(
                        log,
                        "Failed to stat diverged checkpoint directory {}: {}",
                        p.display(),
                        e
                    ),
                }
            }
            metrics.last_diverged.set(
                last_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
            )
        }
    }
}

/// Strips away the deltas from all page maps of the replicated state.
/// We execute this procedure before making a checkpoint because we
/// don't want those deltas to be persisted to TIP as we apply deltas
/// incrementally after every round.
fn strip_page_map_deltas(state: &mut ReplicatedState) {
    for canister in state.canisters_iter_mut() {
        canister.system_state.stable_memory.strip_delta();
        if let Some(execution_state) = &mut canister.execution_state {
            execution_state.page_map.strip_delta();
        }
    }
}

/// Copy heap and stable memory of the canisters stored in page maps from the
/// source state to the destination state.
///
/// We do this after every checkpoint to release in-memory deltas captured by
/// page maps and switch to the most recent checkpoint instead.
///
/// Precondition: src and dst have exactly the same set of canisters
fn copy_page_maps(dst: &mut ReplicatedState, src: &ReplicatedState) {
    for (dst_canister, src_canister) in dst.canisters_iter_mut().zip(src.canisters_iter()) {
        assert_eq!(
            dst_canister.system_state.canister_id,
            src_canister.system_state.canister_id
        );
        assert_eq!(
            dst_canister.execution_state.is_some(),
            src_canister.execution_state.is_some(),
            "execution state of canister {} unexpectedly (dis)appeared after creating a checkpoint",
            dst_canister.system_state.canister_id
        );
        dst_canister.system_state.stable_memory = src_canister.system_state.stable_memory.clone();
        if let (Some(dst_state), Some(src_state)) = (
            &mut dst_canister.execution_state,
            &src_canister.execution_state,
        ) {
            dst_state.page_map = src_state.page_map.clone();
        }
    }
}

impl StateManagerImpl {
    /// Height for the initial default state.
    const INITIAL_STATE_HEIGHT: Height = Height::new(0);

    pub fn new(
        verifier: Arc<dyn Verifier>,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
        config: &Config,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        let metrics = StateManagerMetrics::new(metrics_registry);
        info!(
            log,
            "Using path '{}' to manage local state",
            config.state_root().display()
        );
        let state_layout = StateLayout::new(log.clone(), config.state_root());

        let mut states_metadata =
            Self::load_metadata(&log, state_layout.states_metadata().as_path());

        let (certifications_metadata, compute_manifest_requests) = Self::populate_missing_metadata(
            &log,
            &metrics,
            &state_layout,
            &mut states_metadata,
            own_subnet_type,
        );

        let checkpoint_heights = state_layout
            .checkpoint_heights()
            .unwrap_or_else(|err| fatal!(&log, "Failed to retrieve checkpoint heights: {:?}", err));

        state_layout
            .cleanup_tip()
            .unwrap_or_else(|err| fatal!(&log, "Failed to cleanup old tip {:?}", err));

        cleanup_diverged_states(&log, &state_layout);

        let latest_state_height = AtomicU64::new(0);
        let latest_certified_height = AtomicU64::new(0);
        let last_checkpoint = checkpoint_heights.last();
        let height_and_state = match last_checkpoint {
            Some(height) => {
                // Set latest state height in metadata to be last checkpoint height
                latest_state_height.store(height.get(), Ordering::Relaxed);

                (
                    *height,
                    load_checkpoint_as_tip(&log, &state_layout, *height, own_subnet_type),
                )
            }
            None => (
                Self::INITIAL_STATE_HEIGHT,
                ReplicatedState::new_rooted_at(
                    own_subnet_id,
                    own_subnet_type,
                    state_layout.tip_path(),
                ),
            ),
        };

        let initial_snapshot = Snapshot {
            height: Self::INITIAL_STATE_HEIGHT,
            state: Arc::new(initial_state(own_subnet_id, own_subnet_type).take()),
        };

        let maybe_last_snapshot = last_checkpoint.map(|height| {
            let state = load_checkpoint(&state_layout, *height, &metrics, own_subnet_type)
                .unwrap_or_else(|err| {
                    fatal!(
                        log,
                        "Failed to load the latest checkpoint {} on start: {}",
                        height,
                        err
                    )
                });
            Snapshot {
                height: *height,
                state: Arc::new(state),
            }
        });

        let snapshots: VecDeque<_> = std::iter::once(initial_snapshot)
            .chain(maybe_last_snapshot.into_iter())
            .collect();

        let states = Arc::new(parking_lot::RwLock::new(SharedState {
            certifications_metadata,
            states_metadata,
            snapshots,
            last_advertised: Self::INITIAL_STATE_HEIGHT,
            fetch_state: None,
            tip: Some(height_and_state),
            last_witness_generator: None,
        }));

        let (compute_manifest_request_sender, compute_manifest_request_receiver) = unbounded();

        let _state_hasher_handle = JoinOnDrop::new(
            std::thread::Builder::new()
                .name("StateHasher".to_string())
                .spawn({
                    let log = log.clone();
                    let states = Arc::clone(&states);
                    let metrics = metrics.clone();
                    move || {
                        while let Ok(req) = compute_manifest_request_receiver.recv() {
                            Self::handle_compute_manifest_request(
                                &metrics,
                                &log,
                                &states,
                                req,
                                &malicious_flags,
                            );
                        }
                    }
                })
                .expect("failed to spawn background state hasher"),
        );

        let (deallocation_sender, deallocation_receiver) = unbounded();
        let _deallocation_handle = JoinOnDrop::new(
            std::thread::Builder::new()
                .name("StateDeallocation".to_string())
                .spawn({
                    move || {
                        while let Ok(object) = deallocation_receiver.recv() {
                            std::mem::drop(object);
                            // The sleep below is to spread out the load on memory allocator
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                    }
                })
                .expect("failed to spawn background deallocation thread"),
        );

        for req in compute_manifest_requests {
            compute_manifest_request_sender
                .send(req)
                .expect("failed to send ComputeManifestRequest");
        }

        report_last_diverged_checkpoint(&log, &metrics, &state_layout);

        Self {
            log,
            metrics,
            state_layout,
            states,
            verifier,
            own_subnet_id,
            own_subnet_type,
            compute_manifest_request_sender,
            deallocation_sender,
            latest_state_height,
            latest_certified_height,
            _state_hasher_handle,
            _deallocation_handle,
        }
    }

    /// Returns `StateLayout` pointing to the directory managed by this
    /// StateManager.
    pub fn state_layout(&self) -> &StateLayout {
        &self.state_layout
    }

    /// Returns requested state as a Chunkable artifact for StateSync.
    pub fn create_chunkable_state(
        &self,
        id: &StateSyncArtifactId,
    ) -> Box<dyn Chunkable + Send + Sync> {
        Box::new(crate::state_sync::chunkable::IncompleteState::new(
            self.log.clone(),
            id.height,
            id.hash.clone(),
            self.state_layout.clone(),
            self.latest_manifest(),
            self.metrics.clone(),
            self.own_subnet_type,
        ))
    }

    /// Constructs a new ref-counted checkpoint token.
    ///
    /// NOTE: this function should not be called twice with the same value of
    /// `h`.
    fn new_checkpoint_ref(&self, h: Height) -> CheckpointRef {
        CheckpointRef::new(
            self.log.clone(),
            self.metrics.clone(),
            self.state_layout.clone(),
            h,
        )
    }

    /// Reads states metadata file, returning an empty one if any errors occurs.
    ///
    /// It's OK to miss some (or all) metadata entries as it will be re-computed
    /// as part of the recovery procedure.
    fn load_metadata(log: &ReplicaLogger, path: &Path) -> StatesMetadata {
        use std::io::Read;

        let mut file = match OpenOptions::new().read(true).open(path) {
            Ok(file) => file,
            Err(io_err) if io_err.kind() == std::io::ErrorKind::NotFound => {
                return Default::default();
            }
            Err(io_err) => {
                error!(
                    log,
                    "Failed to open system metadata file {}: {}",
                    path.display(),
                    io_err
                );
                return Default::default();
            }
        };

        let mut buf = vec![];
        if let Err(e) = file.read_to_end(&mut buf) {
            warn!(
                log,
                "Failed to read metadata file {}: {}",
                path.display(),
                e
            );
            return Default::default();
        }

        match pb::StatesMetadata::decode(&buf[..]) {
            Ok(pb_meta) => {
                let mut map = StatesMetadata::new();
                for (h, pb) in pb_meta.by_height {
                    match StateMetadata::try_from(pb) {
                        Ok(meta) => {
                            map.insert(Height::new(h), meta);
                        }
                        Err(e) => {
                            warn!(log, "Failed to decode metadata for state {}: {}", h, e);
                        }
                    }
                }
                map
            }
            Err(err) => {
                warn!(
                    log,
                    "Failed to deserialize states metadata at {}: {}",
                    path.display(),
                    err
                );
                Default::default()
            }
        }
    }

    fn persist_metadata_or_die(&self, metadata: &StatesMetadata) {
        use std::io::Write;

        let started_at = Instant::now();
        let tmp = self
            .state_layout
            .tmp()
            .unwrap_or_else(|err| fatal!(self.log, "Failed to create temporary directory: {}", err))
            .join("tmp_states_metadata.pb");

        ic_utils::fs::write_atomically_using_tmp_file(
            self.state_layout.states_metadata(),
            &tmp,
            |w| {
                let mut pb_meta = pb::StatesMetadata::default();
                for (h, m) in metadata.iter() {
                    pb_meta.by_height.insert(h.get(), m.into());
                }
                let mut buf = vec![];
                pb_meta.encode(&mut buf).unwrap_or_else(|e| {
                    fatal!(
                        self.log,
                        "Failed to encode states metadata to protobuf: {}",
                        e
                    );
                });
                w.write_all(&buf[..])
            },
        )
        .unwrap_or_else(|err| {
            fatal!(
                self.log,
                "Failed to serialize states metadata to {}: {}",
                tmp.display(),
                err
            )
        });
        let elapsed = started_at.elapsed();
        self.metrics
            .checkpoint_op_duration
            .with_label_values(&["persist_meta"])
            .observe(elapsed.as_secs_f64());

        debug!(self.log, "Persisted states metadata in {:?}", elapsed);
    }

    fn handle_compute_manifest_request(
        metrics: &StateManagerMetrics,
        log: &ReplicaLogger,
        states: &Arc<parking_lot::RwLock<SharedState>>,
        req: ComputeManifestRequest,
        #[allow(unused_variables)] malicious_flags: &MaliciousFlags,
    ) {
        // As long as CheckpointRef object is in scope, it should be safe to
        // access the checkpoint data as it's guaranteed to not be removed.
        let height = req.checkpoint_ref.0.height;
        let checkpoint_layout = req
            .checkpoint_ref
            .0
            .state_layout
            .checkpoint(height)
            .unwrap_or_else(|err| {
                fatal!(
                    log,
                    "Failed to get checkpoint path for height {}: {}",
                    height,
                    err
                )
            });

        let system_metadata = checkpoint_layout
            .system_metadata()
            .deserialize()
            .unwrap_or_else(|err| {
                fatal!(log, "Failed to decode system metadata @{}: {}", height, err)
            });

        let start = Instant::now();
        let manifest = crate::manifest::compute_manifest(
            system_metadata.state_sync_version,
            checkpoint_layout.raw_path(),
            crate::manifest::DEFAULT_CHUNK_SIZE,
        )
        .unwrap_or_else(|err| {
            fatal!(
                log,
                "Failed to compute manifest for checkpoint @{} after {:?}: {}",
                height,
                start.elapsed(),
                err
            )
        });

        let elapsed = start.elapsed();
        metrics
            .checkpoint_op_duration
            .with_label_values(&["compute_manifest"])
            .observe(elapsed.as_secs_f64());

        info!(
            log,
            "Computed manifest of state @{} in {:?}", height, elapsed
        );

        #[cfg(not(feature = "malicious_code"))]
        let root_hash = CryptoHashOfState::from(CryptoHash(
            crate::manifest::manifest_hash(&manifest).to_vec(),
        ));

        // This is where we maliciously alter the root_hash!
        #[cfg(feature = "malicious_code")]
        let root_hash = maliciously_return_wrong_hash(&manifest, log, malicious_flags, height);

        let mut states = states.write();

        if let Some(metadata) = states.states_metadata.get_mut(&height) {
            metadata.root_hash = Some(root_hash);
            metadata.manifest = Some(manifest);
        }
    }

    fn latest_certified_state(
        &self,
    ) -> Option<(Arc<ReplicatedState>, Certification, Arc<HashTree>)> {
        let (height, certification, hash_tree) = self
            .states
            .read()
            .certifications_metadata
            .iter()
            .rev()
            .find_map(|(height, metadata)| {
                let hash_tree = metadata.hash_tree.as_ref()?;
                metadata
                    .certification
                    .clone()
                    .map(|certification| (*height, certification, Arc::clone(hash_tree)))
            })?;
        let state = self.get_state_at(height).ok()?;
        Some((state.take(), certification, hash_tree))
    }

    /// Returns the manifest of the latest checkpoint on disk with its
    /// checkpoint ref.
    fn latest_manifest(&self) -> Option<(Manifest, CheckpointRef)> {
        self.state_layout
            .checkpoint_heights()
            .unwrap_or_else(|err| {
                fatal!(self.log, "Failed to gather checkpoint heights: {:?}", err)
            })
            .iter()
            .rev()
            .find_map(|checkpointed_height| {
                let states = self.states.read();
                let metadata = states.states_metadata.get(checkpointed_height)?;
                let manifest = metadata.manifest.clone()?;
                let checkpoint_ref = metadata.checkpoint_ref.clone()?;
                Some((manifest, checkpoint_ref))
            })
    }

    fn compute_certification_metadata(
        metrics: &StateManagerMetrics,
        log: &ReplicaLogger,
        state: &ReplicatedState,
    ) -> CertificationMetadata {
        let started_hashing_at = Instant::now();
        let hash_tree = tree_hash::hash_partial_state(&state);
        let elapsed = started_hashing_at.elapsed();
        debug!(log, "Computed hash tree in {:?}", elapsed);

        metrics
            .checkpoint_op_duration
            .with_label_values(&["hash_tree"])
            .observe(elapsed.as_secs_f64());

        let certified_state_hash = crypto_hash_of_tree(&hash_tree);

        CertificationMetadata {
            hash_tree: Some(Arc::new(hash_tree)),
            certified_state_hash,
            certification: None,
        }
    }

    fn populate_missing_metadata(
        log: &ReplicaLogger,
        metrics: &StateManagerMetrics,
        layout: &StateLayout,
        metadata: &mut StatesMetadata,
        own_subnet_type: SubnetType,
    ) -> (CertificationsMetadata, Vec<ComputeManifestRequest>) {
        let mut compute_manifest_requests = Vec::<ComputeManifestRequest>::new();

        let heights = match layout.checkpoint_heights() {
            Ok(heights) => heights,
            Err(err) => {
                error!(log, "Failed to load checkpoint heights: {}", err);
                return (Default::default(), compute_manifest_requests);
            }
        };

        let mut certifications_metadata = CertificationsMetadata::default();

        // Populate the missing metadata from the higher checkpoints to the lower ones.
        // Then the manifest of the latest checkpoint will be the first one available
        // for state sync.
        for height in heights.into_iter().rev() {
            let cp_layout = layout.checkpoint(height).unwrap_or_else(|err| {
                fatal!(
                    log,
                    "Failed to create checkpoint layout @{}: {}",
                    height,
                    err
                )
            });

            let state =
                checkpoint::load_checkpoint(&cp_layout, own_subnet_type).unwrap_or_else(|err| {
                    fatal!(log, "Failed to load checkpoint @{}: {}", height, err)
                });

            certifications_metadata.insert(
                height,
                Self::compute_certification_metadata(metrics, log, &state),
            );

            let checkpoint_ref =
                CheckpointRef::new(log.clone(), metrics.clone(), layout.clone(), height);

            if let Some(state_metadata) = metadata.get_mut(&height) {
                state_metadata.checkpoint_ref = Some(checkpoint_ref.clone());
                if state_metadata.manifest.is_some() {
                    // Do not compute the manifest if it's already present.
                    continue;
                }
            }

            compute_manifest_requests.push(ComputeManifestRequest {
                checkpoint_ref: checkpoint_ref.clone(),
            });

            metadata.insert(
                height,
                StateMetadata {
                    checkpoint_ref: Some(checkpoint_ref),
                    manifest: None,
                    root_hash: None,
                },
            );
        }

        (certifications_metadata, compute_manifest_requests)
    }

    fn populate_extra_metadata(&self, state: &mut ReplicatedState, height: Height) {
        state.metadata.state_sync_version = manifest::CURRENT_STATE_SYNC_VERSION;
        state.metadata.certification_version = ic_canonical_state::CURRENT_CERTIFICATION_VERSION;

        if height == Self::INITIAL_STATE_HEIGHT {
            return;
        }
        let prev_height = height - Height::from(1);

        if prev_height == Self::INITIAL_STATE_HEIGHT {
            // This code is executed at most once per subnet, no need to
            // optimize this.
            let hash_tree = tree_hash::hash_partial_state(
                initial_state(self.own_subnet_id, self.own_subnet_type).get_ref(),
            );
            state.metadata.prev_state_hash = Some(CryptoHashOfPartialState::from(
                crypto_hash_of_tree(&hash_tree),
            ));
            return;
        }

        let states = self.states.read();
        if let Some(metadata) = states.certifications_metadata.get(&prev_height) {
            state.metadata.prev_state_hash = Some(CryptoHashOfPartialState::from(
                metadata.certified_state_hash.clone(),
            ));
            return;
        }

        warn!(
            self.log,
            "Couldn't populate previous state hash for height {}", height,
        );
    }

    /// Flushes to disk all the canister heap deltas accumulated in memory
    /// during one round of execution.
    fn flush_page_maps(&self, tip_state: &mut ReplicatedState) {
        let tip_layout = self
            .state_layout
            .tip()
            .unwrap_or_else(|err| fatal!(self.log, "Failed to access @TIP: {}", err));

        for canister in tip_state.canisters_iter_mut() {
            let canister_id = canister.canister_id();

            let canister_layout = tip_layout.canister(&canister_id).unwrap_or_else(|err| {
                fatal!(
                    self.log,
                    "Failed to access canister {} layout @TIP {}: {}",
                    canister_id,
                    tip_layout.raw_path().display(),
                    err
                )
            });
            let stable_deltas = canister.system_state.stable_memory.take_round_delta();
            if !stable_deltas.is_empty() {
                let stable_memory_path = &canister_layout.stable_memory_blob();
                stable_deltas
                    .persist(&stable_memory_path)
                    .unwrap_or_else(|err| {
                        fatal!(
                            self.log,
                            "Failed to persist stable page delta of canister {} to file {}: {}",
                            canister_id,
                            stable_memory_path.display(),
                            err
                        )
                    });
            }
            if let Some(execution_state) = &mut canister.execution_state {
                let round_delta = execution_state.page_map.take_round_delta();
                if round_delta.is_empty() {
                    continue;
                }

                let memory_path = &canister_layout.vmemory_0();
                round_delta.persist(&memory_path).unwrap_or_else(|err| {
                    fatal!(
                        self.log,
                        "Failed to persist page delta of canister {} to file {}: {}",
                        canister_id,
                        memory_path.display(),
                        err
                    )
                });
            }
        }
    }

    fn get_witness_generator(&self, hash_tree: &HashTree) -> Arc<WitnessGeneratorImpl> {
        let last_witness_generator =
            { self.states.read().last_witness_generator.as_ref().cloned() };

        match last_witness_generator {
            Some(witness_generator)
                if crypto_hash_of_tree(witness_generator.hash_tree())
                    == crypto_hash_of_tree(&hash_tree) =>
            {
                // The cached witness generator corresponds to the given `hash_tree`.
                witness_generator
            }
            _ => {
                // The cached witness generator doesn't exist or doesn't correspond to the given
                // `hash_tree`. Compute and cache a new witness generator.
                let witness_generator = WitnessGeneratorImpl::try_from(hash_tree.clone())
                    .expect("Failed to construct witness generator");
                let witness_generator = Arc::new(witness_generator);
                {
                    let mut states = self.states.write();
                    states.last_witness_generator = Some(witness_generator.clone());
                }
                witness_generator
            }
        }
    }

    fn clone_checkpoint(&self, from: Height, to: Height) -> Result<(), LayoutError> {
        let target_layout = self.state_layout.checkpoint_to_scratchpad(from)?;
        self.state_layout
            .scratchpad_to_checkpoint(target_layout, to)?;
        Ok(())
    }

    fn find_checkpoint_by_root_hash(
        &self,
        root_hash: &CryptoHashOfState,
    ) -> Option<(Height, Manifest)> {
        self.states
            .read()
            .states_metadata
            .iter()
            .find_map(|(h, metadata)| {
                match (metadata.root_hash.as_ref(), metadata.manifest.as_ref()) {
                    (Some(hash), Some(manifest)) if hash == root_hash => {
                        Some((*h, manifest.clone()))
                    }
                    _ => None,
                }
            })
    }

    fn on_synced_checkpoint(
        &self,
        state: ReplicatedState,
        height: Height,
        manifest: Manifest,
        root_hash: CryptoHashOfState,
    ) {
        if self
            .state_layout
            .diverged_checkpoint_heights()
            .unwrap_or_default()
            .contains(&height)
        {
            // We have just fetched a state that was marked as diverged
            // before. We make a backup of the pristine state for future
            // investigation and debugging.
            if let Err(err) = self.state_layout.backup_checkpoint(height) {
                info!(
                    self.log,
                    "Failed to backup a pristine version of diverged state {}: {}", height, err
                );
            }
        }

        let mut states = self.states.write();
        states.disable_state_fetch_below(height);

        if let Some(snapshot) = states.snapshots.back() {
            if snapshot.height >= height {
                info!(
                    self.log,
                    "Completed StateSync for state {} that we already have locally", height
                );
                return;
            }
        }

        let hash_tree = crate::tree_hash::hash_partial_state(&state);

        states.snapshots.push_back(Snapshot {
            height,
            state: Arc::new(state),
        });

        states.certifications_metadata.insert(
            height,
            CertificationMetadata {
                certified_state_hash: crypto_hash_of_tree(&hash_tree),
                hash_tree: Some(Arc::new(hash_tree)),
                certification: None,
            },
        );

        states.states_metadata.insert(
            height,
            StateMetadata {
                manifest: Some(manifest),
                checkpoint_ref: Some(self.new_checkpoint_ref(height)),
                root_hash: Some(root_hash),
            },
        );
        update_latest_height(&self.latest_state_height, height);
        self.persist_metadata_or_die(&states.states_metadata);
    }

    fn first_known_height(&self) -> Height {
        let states = self.states.read();
        states
            .snapshots
            .get(1)
            .map(|s| s.height)
            .unwrap_or_else(|| Height::new(0))
    }
}

fn initial_state(own_subnet_id: SubnetId, own_subnet_type: SubnetType) -> Labeled<ReplicatedState> {
    Labeled::new(
        StateManagerImpl::INITIAL_STATE_HEIGHT,
        ReplicatedState::new_rooted_at(own_subnet_id, own_subnet_type, "Initial".into()),
    )
}

fn crypto_hash_of_tree(t: &HashTree) -> CryptoHash {
    CryptoHash(t.digest().0.to_vec())
}

fn update_latest_height(cached: &AtomicU64, h: Height) {
    // Replace  with 'fetch_max'  after 'atomic_min_max'  is stable.   See issue
    // https://github.com/rust-lang/rust/issues/48655 for more information

    let mut prev = cached.load(Ordering::Relaxed);
    while prev < h.get() {
        let updated = cached.compare_and_swap(prev, h.get(), Ordering::Relaxed);
        if updated == prev {
            break;
        }
        prev = updated;
    }
}

fn purge_cow_rounds_below(state: &mut ReplicatedState, height: Height) {
    if cow_state_feature::is_enabled(cow_state_feature::cow_state) {
        for cs in state.canisters_iter_mut() {
            if let Some(es) = &mut cs.execution_state {
                es.cow_mem_mgr.remove_states_below(height.get());
            }
        }
    }
}

impl StateManager for StateManagerImpl {
    /// Note that this function intentionally does not use
    /// `latest_state_height()` to figure out if state at the requested height
    /// has been committed yet or not because `latest_state_height()` consults
    /// the disk to figure out what the latest state is.  So if the state at the
    /// requested height is only available on disk, there is still no snapshot
    /// of the state so the root_hash is not available.
    fn get_state_hash_at(&self, height: Height) -> StateManagerResult<Option<CryptoHashOfState>> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["get_state_hash_at"])
            .start_timer();

        let states = self.states.read();

        states
            .states_metadata
            .get(&height)
            .ok_or_else(
                || match states.certifications_metadata.iter().rev().next() {
                    Some((key, _)) => {
                        if *key < height {
                            StateManagerError::StateNotCommittedYet(height)
                        } else {
                            StateManagerError::StateRemoved(height)
                        }
                    }
                    None => StateManagerError::StateNotCommittedYet(height),
                },
            )
            .map(|metadata| metadata.root_hash.clone())
    }

    fn take_tip(&self) -> (Height, ReplicatedState) {
        let mut states = self.states.write();
        let (tip_height, tip) = states.tip.take().expect("failed to get TIP");
        let checkpoints = self
            .state_layout
            .checkpoint_heights()
            .unwrap_or_else(|err| fatal!(self.log, "Failed to gather checkpoint heights: {}", err));
        if let Some(checkpoint_height) = checkpoints.last() {
            // This can happen if state sync fetched a fresh state in the
            // background.
            if *checkpoint_height > tip_height {
                let new_tip = load_checkpoint_as_tip(
                    &self.log,
                    &self.state_layout,
                    *checkpoint_height,
                    self.own_subnet_type,
                );
                return (*checkpoint_height, new_tip);
            }
        }
        (tip_height, tip)
    }

    fn take_tip_at(&self, height: Height) -> StateManagerResult<ReplicatedState> {
        let (tip_height, state) = self.take_tip();

        let mut states = self.states.write();
        assert!(states.tip.is_none());

        if height < tip_height {
            states.tip = Some((tip_height, state));
            return Err(StateManagerError::StateRemoved(height));
        }
        if tip_height < height {
            states.tip = Some((tip_height, state));
            return Err(StateManagerError::StateNotCommittedYet(height));
        }

        Ok(state)
    }

    fn fetch_state(&self, height: Height, root_hash: CryptoHashOfState) {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["fetch_state"])
            .start_timer();

        match self.get_state_hash_at(height) {
            Ok(Some(hash)) => assert_eq!(
                hash, root_hash,
                "The hash of requested state {:?} at height {} doesn't match the locally computed hash {:?}",
                root_hash, height, hash
            ),
            Ok(None) => {
                // The state is already available, but we haven't finished
                // computing the hash yet.
            }
            Err(StateManagerError::StateRemoved(_)) => {
                // No need to fetch an old state, nothing to do.
                info!(
                    self.log,
                    "Requested fetch of an old state @{}, hash = {:?}", height, root_hash
                );
            }
            Err(StateManagerError::StateNotCommittedYet(_)) => {

                // Let's see if we already have this state locally.  This might
                // be the case if we are in disaster recovery mode and
                // re-introducing some old state with a new hight.
                if let Some((checkpoint_height, manifest)) = self.find_checkpoint_by_root_hash(&root_hash) {
                    info!(self.log,
                          "Copying checkpoint {} with root hash {:?} under new height {}",
                          checkpoint_height, root_hash, height);

                    match self.clone_checkpoint(checkpoint_height, height) {
                        Ok(_) => {
                            let state = load_checkpoint(&self.state_layout, height, &self.metrics, self.own_subnet_type)
                                .expect("failed to load checkpoint");
                            self.on_synced_checkpoint(state, height, manifest, root_hash);
                            return;
                        }
                        Err(e) => {
                            warn!(self.log,
                                  "Failed to clone checkpoint {} => {}: {}",
                                  checkpoint_height, height, e
                            );
                        }
                    }
                }

                // Normal path: we don't have the state locally, let's fetch it.
                let mut states = self.states.write();
                match &states.fetch_state {
                    None => {
                        info!(
                            self.log,
                            "Setting new target state to fetch: height = {}, hash = {:?}",
                            height,
                            root_hash
                        );
                        states.fetch_state = Some((height, root_hash));
                    }
                    Some((prev_height, prev_hash)) => {
                        use std::cmp::Ordering;

                        match prev_height.cmp(&height) {
                            Ordering::Less => {
                                info!(
                                    self.log,
                                    "Updating target state to fetch from {} to {}",
                                    prev_height,
                                    height
                                );
                                states.fetch_state = Some((height, root_hash))
                            }
                            Ordering::Equal => {
                                assert_eq!(
                                    *prev_hash, root_hash,
                                    "Requested to fetch the same state {} twice with different hashes: first {:?}, then {:?}",
                                    height, prev_hash, root_hash
                                );
                            }
                            Ordering::Greater => {
                                info!(self.log, "Ignoring request to fetch state {} below current target state {}", height, prev_height);
                            }
                        }
                    }
                }
            }
        }
    }

    fn list_state_hashes_to_certify(&self) -> Vec<(Height, CryptoHashOfPartialState)> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["list_state_hashes_to_certify"])
            .start_timer();

        self.states
            .read()
            .certifications_metadata
            .iter()
            .filter(|(_, metadata)| metadata.certification.is_none())
            .map(|(height, metadata)| {
                (
                    *height,
                    CryptoHashOfPartialState::from(metadata.certified_state_hash.clone()),
                )
            })
            .collect()
    }

    fn deliver_state_certification(&self, certification: Certification) {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["deliver_state_certification"])
            .start_timer();

        let certification_height = certification.height;
        let mut states = self.states.write();
        if let Some(metadata) = states
            .certifications_metadata
            .get_mut(&certification.height)
        {
            let hash = metadata.certified_state_hash.clone();
            assert_eq!(
                certification.signed.content.hash.get_ref(),
                &hash,
                "delivered certification has invalid hash, expected {:?}, received {:?}",
                hash,
                certification.signed.content.hash
            );
            update_latest_height(&self.latest_certified_height, certification.height);
            metadata.certification = Some(certification);
        }

        for (_, certification_metadata) in states
            .certifications_metadata
            .range_mut(Self::INITIAL_STATE_HEIGHT..certification_height)
        {
            if let Some(tree) = certification_metadata.hash_tree.take() {
                self.deallocation_sender
                    .send(Box::new(tree))
                    .expect("failed to send object to deallocation thread");
            }
        }
    }

    /// # Panics
    ///
    /// This method panics if checkpoint labels can not be retrieved
    /// from the disk.
    fn list_state_heights(&self, cert_mask: CertificationMask) -> Vec<Height> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["list_state_heights"])
            .start_timer();

        fn matches(cert: Option<&Certification>, mask: CertificationMask) -> bool {
            match cert {
                Some(_) => mask.is_set(CERT_CERTIFIED),
                None => mask.is_set(CERT_UNCERTIFIED),
            }
        }

        let states = self.states.read();

        let heights: BTreeSet<_> = self
            .state_layout
            .checkpoint_heights()
            .unwrap_or_else(|err| {
                fatal!(self.log, "Failed to gather checkpoint heights: {:?}", err)
            })
            .into_iter()
            .chain(states.snapshots.iter().map(|snapshot| snapshot.height))
            .filter(|h| {
                matches(
                    states
                        .certifications_metadata
                        .get(h)
                        .and_then(|metadata| metadata.certification.as_ref()),
                    cert_mask,
                )
            })
            .collect();

        // convert the b-tree into a vector
        heights.into_iter().collect()
    }

    fn remove_states_below(&self, requested_height: Height) {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["remove_states_below"])
            .start_timer();

        let checkpoint_heights = self
            .state_layout
            .checkpoint_heights()
            .unwrap_or_else(|err| {
                fatal!(self.log, "Failed to gather checkpoint heights: {:?}", err)
            });

        let last_checkpoint = checkpoint_heights.last();

        // The last checkpoint and higher states will be kept.
        let last_height_to_keep = last_checkpoint
            .map(|h| (*h).min(requested_height))
            .unwrap_or(requested_height);

        let heights_to_remove = std::ops::Range {
            start: Height::new(1),
            end: last_height_to_keep,
        };

        let mut states = self.states.write();

        // Send object to deallocation thread if it has capacity.
        let deallocate = |x| {
            if self.deallocation_sender.len() < DEALLOCATION_BACKLOG_THRESHOLD {
                self.deallocation_sender
                    .send(x)
                    .expect("failed to send object to deallocation thread");
            } else {
                std::mem::drop(x);
            }
        };

        let (removed, retained) = states
            .snapshots
            .drain(0..)
            .partition(|snapshot| heights_to_remove.contains(&snapshot.height));
        states.snapshots = retained;

        let latest_height = states
            .snapshots
            .back()
            .map(|s| s.height)
            .unwrap_or(Self::INITIAL_STATE_HEIGHT);

        self.latest_state_height
            .store(latest_height.get(), Ordering::Relaxed);

        // Send removed snapshot to deallocator thread
        deallocate(Box::new(removed));

        for (_, ref metadata) in states.states_metadata.range(heights_to_remove) {
            if let Some(ref checkpoint_ref) = metadata.checkpoint_ref {
                checkpoint_ref.mark_deleted();
            }
        }

        let mut certifications_metadata = states
            .certifications_metadata
            .split_off(&last_height_to_keep);

        std::mem::swap(
            &mut certifications_metadata,
            &mut states.certifications_metadata,
        );

        // Send removed certification metadata to deallocator thread
        deallocate(Box::new(certifications_metadata));

        let latest_certified_height = states
            .certifications_metadata
            .iter()
            .rev()
            .find_map(|(h, m)| m.certification.as_ref().map(|_| *h))
            .unwrap_or(Self::INITIAL_STATE_HEIGHT);
        self.latest_certified_height
            .store(latest_certified_height.get(), Ordering::Relaxed);

        states.states_metadata = states.states_metadata.split_off(&last_height_to_keep);

        self.persist_metadata_or_die(&states.states_metadata);
    }

    fn commit_and_certify(
        &self,
        mut state: Self::State,
        height: Height,
        scope: CertificationScope,
    ) {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["commit_and_certify"])
            .start_timer();

        if cow_state_feature::is_enabled(cow_state_feature::cow_state) {
            for cs in state.canisters_iter_mut() {
                if let Some(es) = &mut cs.execution_state {
                    let last_executed_round = ExecutionRound::from(height.get());
                    if es.last_executed_round == ExecutionRound::from(0) {
                        // This can happen in 1 conditions only:
                        // 1. Canister install/reinstall/upgrade when new execution state is created
                        es.last_executed_round = last_executed_round;
                    }

                    if es.last_executed_round == last_executed_round {
                        es.cow_mem_mgr.create_snapshot(last_executed_round.get());
                    }
                }
            }
        }

        self.populate_extra_metadata(&mut state, height);
        self.flush_page_maps(&mut state);

        let checkpointed_state = match scope {
            CertificationScope::Full => {
                let start = Instant::now();

                // We don't need to persist the deltas to the tip because we
                // flush deltas separately every round, see flush_page_maps.
                strip_page_map_deltas(&mut state);
                let result = checkpoint::make_checkpoint(&state, height, &self.state_layout);
                purge_cow_rounds_below(&mut state, self.first_known_height());

                let elapsed = start.elapsed();
                match result {
                    Ok(checkpointed_state) => {
                        copy_page_maps(&mut state, &checkpointed_state);
                        info!(self.log, "Created checkpoint @{} in {:?}", height, elapsed);
                        self.metrics
                            .checkpoint_op_duration
                            .with_label_values(&["create"])
                            .observe(elapsed.as_secs_f64());
                        checkpointed_state
                    }
                    Err(CheckpointError::AlreadyExists(_)) => {
                        warn!(
                                self.log,
                                "Failed to create checkpoint @{} because it already exists, re-loading the checkpoint from disk", height
                            );

                        self.state_layout
                            .checkpoint(height)
                            .map_err(|e| e.into())
                            .and_then(|layout| {
                                let _timer = self
                                    .metrics
                                    .checkpoint_op_duration
                                    .with_label_values(&["recover"])
                                    .start_timer();

                                checkpoint::load_checkpoint(&layout, self.own_subnet_type)
                            })
                            .unwrap_or_else(|err| {
                                fatal!(
                                    self.log,
                                    "Failed to load existing checkpoint @{}: {}",
                                    height,
                                    err
                                )
                            })
                    }
                    Err(err) => fatal!(
                        self.log,
                        "Failed to make a checkpoint @{}: {:?}",
                        height,
                        err
                    ),
                }
            }
            CertificationScope::Metadata => state.clone(),
        };

        let certification_metadata =
            Self::compute_certification_metadata(&self.metrics, &self.log, &checkpointed_state);

        let mut states = self.states.write();

        // The following assert validates that we don't have two clients
        // modifying TIP at the same time and that each commit_and_certify()
        // is preceded by a call to take_tip().
        if let Some((tip_height, _)) = &states.tip {
            fatal!(
                self.log,
                "Attempt to commit state not borrowed from this StateManager, height = {}, tip_height = {}",
                height,
                tip_height,
            );
        }

        // It's possible that we already computed this state before.  We
        // validate that hashes agree to spot bugs causing non-determinism as
        // early as possible.
        if let Some(prev_metadata) = states.certifications_metadata.get(&height) {
            use crate::tree_diff::{diff, PrettyPrintedChanges};

            let prev_hash = &prev_metadata.certified_state_hash;
            let hash = &certification_metadata.certified_state_hash;
            assert_eq!(
                prev_hash, hash,
                "Committed state @{} twice with different hashes: first with {:?}, then with {:?}, old/new tree diff: {:?}",
                height, prev_hash, hash,
                match (prev_metadata.hash_tree.as_ref(), certification_metadata.hash_tree.as_ref()) {
                    (Some(l), Some(r)) => PrettyPrintedChanges(&diff(l, r)).to_string(),
                    _ => "unknown".to_string(),
                }
            );
        }

        let (tip_height, tip) = match states.snapshots.back() {
            Some(latest_snapshot) if height <= latest_snapshot.height => {
                // This state is older than the one we already have.  This can
                // happen if we state-sync and apply blocks in parallel.
                info!(
                    self.log,
                    "Skip committing an outdated state {}, latest state is {}",
                    height,
                    latest_snapshot.height
                );
                if height == latest_snapshot.height {
                    (height, state)
                } else {
                    // Will crash if it's not a checkpoint, which is reasonable
                    // for now as we can only get fresher states from state
                    // sync.
                    (
                        latest_snapshot.height,
                        load_checkpoint_as_tip(
                            &self.log,
                            &self.state_layout,
                            latest_snapshot.height,
                            self.own_subnet_type,
                        ),
                    )
                }
            }
            _ => {
                states.snapshots.push_back(Snapshot {
                    height,
                    state: Arc::new(checkpointed_state),
                });

                if scope == CertificationScope::Full {
                    let checkpoint_ref = self.new_checkpoint_ref(height);
                    states.states_metadata.insert(
                        height,
                        StateMetadata {
                            checkpoint_ref: Some(checkpoint_ref.clone()),
                            manifest: None,
                            root_hash: None,
                        },
                    );

                    self.compute_manifest_request_sender
                        .send(ComputeManifestRequest { checkpoint_ref })
                        .expect("failed to send ComputeManifestRequest message");
                    self.persist_metadata_or_die(&states.states_metadata);
                }

                states
                    .certifications_metadata
                    .insert(height, certification_metadata);

                update_latest_height(&self.latest_state_height, height);

                (height, state)
            }
        };

        states.tip = Some((tip_height, tip));
    }

    fn report_diverged_state(&self, height: Height) {
        let start = Instant::now();
        let mut states = self.states.write();
        let mut heights = self
            .state_layout
            .checkpoint_heights()
            .unwrap_or_else(|err| {
                fatal!(self.log, "Failed to retrieve checkpoint heights: {}", err);
            });

        while let Some(h) = heights.pop() {
            info!(self.log, "Removing potentially diverged checkpoint @{}", h);
            if let Err(err) = self.state_layout.mark_checkpoint_diverged(h) {
                error!(
                    self.log,
                    "Failed to mark checkpoint @{} diverged: {}", h, err
                );
            }
            if h <= height {
                break;
            }
        }

        states.states_metadata.split_off(&height);
        self.persist_metadata_or_die(&states.states_metadata);

        self.metrics
            .api_call_duration
            .with_label_values(&["report_diverged_state"])
            .observe(start.elapsed().as_secs_f64());

        fatal!(self.log, "Replica diverged at height {}", height)
    }
}

impl StateReader for StateManagerImpl {
    type State = ReplicatedState;

    fn latest_state_height(&self) -> Height {
        Height::new(self.latest_state_height.load(Ordering::Relaxed))
    }

    fn latest_certified_height(&self) -> Height {
        Height::new(self.latest_certified_height.load(Ordering::Relaxed))
    }

    fn get_latest_state(&self) -> Labeled<Arc<Self::State>> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["get_latest_state"])
            .start_timer();

        self.states
            .read()
            .snapshots
            .back()
            .map(|snapshot| Labeled::new(snapshot.height, snapshot.state.clone()))
            .unwrap_or_else(|| {
                Labeled::new(
                    Self::INITIAL_STATE_HEIGHT,
                    Arc::new(initial_state(self.own_subnet_id, self.own_subnet_type).take()),
                )
            })
    }

    fn get_state_at(&self, height: Height) -> StateManagerResult<Labeled<Arc<Self::State>>> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["get_state_at"])
            .start_timer();

        if self.latest_state_height() < height {
            return Err(StateManagerError::StateNotCommittedYet(height));
        }
        match self
            .states
            .read()
            .snapshots
            .iter()
            .find(|snapshot| snapshot.height == height)
            .map(|snapshot| Labeled::new(height, snapshot.state.clone()))
        {
            Some(state) => Ok(state),
            None => match load_checkpoint(
                &self.state_layout,
                height,
                &self.metrics,
                self.own_subnet_type,
            ) {
                Ok(state) => Ok(Labeled::new(height, Arc::new(state))),
                Err(CheckpointError::NotFound(_)) => Err(StateManagerError::StateRemoved(height)),
                Err(err) => {
                    self.metrics
                        .state_manager_error_count
                        .with_label_values(&["recover_checkpoint"])
                        .inc();
                    error!(self.log, "Failed to recover state @{}: {}", height, err);

                    Err(StateManagerError::StateRemoved(height))
                }
            },
        }
    }

    fn read_certified_state(
        &self,
        paths: &LabeledTree<()>,
    ) -> Option<(Arc<Self::State>, MixedHashTree, Certification)> {
        use ic_canonical_state::lazy_tree::materialize::materialize_partial;
        use ic_canonical_state::lazy_tree::LazyTree;

        let (state, certification, hash_tree) = self.latest_certified_state()?;
        let mixed_hash_tree = {
            let lazy_tree = LazyTree::from(&*state);
            let partial_tree = materialize_partial(&lazy_tree, paths)?;
            let witness_generator = self.get_witness_generator(hash_tree.as_ref());
            witness_generator.mixed_hash_tree(&partial_tree).ok()?
        };

        Some((state, mixed_hash_tree, certification))
    }
}

impl CertifiedStreamStore for StateManagerImpl {
    fn encode_certified_stream_slice(
        &self,
        remote_subnet: SubnetId,
        witness_begin: Option<StreamIndex>,
        msg_begin: Option<StreamIndex>,
        msg_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> Result<CertifiedStreamSlice, EncodeStreamError> {
        match (witness_begin, msg_begin) {
            (None, None) => {}
            (Some(witness_begin), Some(msg_begin)) if witness_begin <= msg_begin => {}
            _ => {
                return Err(EncodeStreamError::InvalidSliceIndices {
                    witness_begin,
                    msg_begin,
                })
            }
        }

        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["encode_certified_stream"])
            .start_timer();

        let (state, certification, hash_tree) = self
            .latest_certified_state()
            .ok_or_else(|| EncodeStreamError::NoStreamForSubnet(remote_subnet))?;

        let stream = state
            .get_stream(remote_subnet)
            .ok_or_else(|| EncodeStreamError::NoStreamForSubnet(remote_subnet))?;

        let validate_slice_begin = |begin| {
            if begin < stream.messages.begin() || stream.messages.end() < begin {
                return Err(EncodeStreamError::InvalidSliceBegin {
                    slice_begin: begin,
                    stream_begin: stream.messages.begin(),
                    stream_end: stream.messages.end(),
                });
            }
            Ok(())
        };
        let msg_from = msg_begin.unwrap_or_else(|| stream.messages.begin());
        validate_slice_begin(msg_from)?;
        let witness_from = witness_begin.unwrap_or(msg_from);
        validate_slice_begin(witness_from)?;

        let to = msg_limit
            .map(|n| msg_from + StreamIndex::new(n as u64))
            .filter(|end| end <= &stream.messages.end())
            .unwrap_or_else(|| stream.messages.end());

        let witness_generator = WitnessGeneratorImpl::try_from(hash_tree.as_ref().clone())
            .expect("Failed to construct witness generator");

        let (slice_as_tree, to) =
            stream_encoding::encode_stream_slice(&state, remote_subnet, msg_from, to, byte_limit);

        let witness_partial_tree =
            stream_encoding::stream_slice_partial_tree(remote_subnet, witness_from, to);
        let witness = witness_generator
            .witness(&witness_partial_tree)
            .expect("Failed to generate witness.");

        Ok(CertifiedStreamSlice {
            payload: stream_encoding::encode_tree(slice_as_tree),
            merkle_proof: v1::Witness::proxy_encode(witness).expect("Failed to serialize witness."),
            certification,
        })
    }

    fn decode_certified_stream_slice(
        &self,
        remote_subnet: SubnetId,
        registry_version: RegistryVersion,
        certified_slice: &CertifiedStreamSlice,
    ) -> Result<StreamSlice, DecodeStreamError> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["decode_certified_stream"])
            .start_timer();

        fn crypto_hash_of_partial_state(d: &Digest) -> CryptoHashOfPartialState {
            CryptoHashOfPartialState::from(CryptoHash(d.0.to_vec()))
        }
        fn verify_recomputed_digest(
            verifier: &Arc<dyn Verifier>,
            remote_subnet: SubnetId,
            certification: &Certification,
            registry_version: RegistryVersion,
            digest: Digest,
        ) -> bool {
            crypto_hash_of_partial_state(&digest) == certification.signed.content.hash
                && verifier
                    .validate(remote_subnet, certification, registry_version)
                    .is_ok()
        }

        let tree = stream_encoding::decode_labeled_tree(&certified_slice.payload)?;

        // The function `decode_stream_slice` already checks internally whether the
        // slice only contains a stream for a single destination subnet.
        let (subnet_id, slice) = stream_encoding::decode_slice_from_tree(&tree)?;

        if subnet_id != self.own_subnet_id {
            return Err(DecodeStreamError::InvalidDestination {
                sender: remote_subnet,
                receiver: subnet_id,
            });
        }

        let witness = v1::Witness::proxy_decode(&certified_slice.merkle_proof).map_err(|e| {
            DecodeStreamError::SerializationError(format!("Failed to deserialize witness: {:?}", e))
        })?;

        let digest = recompute_digest(&tree, &witness).map_err(|e| {
            DecodeStreamError::SerializationError(format!("Failed to recompute digest: {:?}", e))
        })?;

        if !verify_recomputed_digest(
            &self.verifier,
            remote_subnet,
            &certified_slice.certification,
            registry_version,
            digest,
        ) {
            return Err(DecodeStreamError::InvalidSignature(remote_subnet));
        }

        Ok(slice)
    }

    fn decode_valid_certified_stream_slice(
        &self,
        certified_slice: &CertifiedStreamSlice,
    ) -> Result<StreamSlice, DecodeStreamError> {
        let (_subnet, slice) = stream_encoding::decode_stream_slice(&certified_slice.payload)?;
        Ok(slice)
    }

    fn subnets_with_certified_streams(&self) -> Vec<SubnetId> {
        self.get_latest_state()
            .get_ref()
            .subnets_with_available_streams()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CheckpointError {
    /// Wraps a stringified `std::io::Error`, a message and the path of the
    /// affected file/directory.
    IoError {
        path: PathBuf,
        message: String,
        io_err: String,
    },
    /// The layout of state root on disk is corrupted.
    CorruptedLayout { path: PathBuf, message: String },
    /// Wraps a stringified `ic_protobuf::proxy::ProxyDecodeError`, a field and
    /// the path of the affected file.
    ProtoError {
        path: std::path::PathBuf,
        field: String,
        proto_err: String,
    },
    /// Checkpoint at the specified height already exists.
    AlreadyExists(Height),
    /// Checkpoint for the requested height not found.
    NotFound(Height),
    /// Wraps a PageMap error.
    Persistence(PersistenceError),
}

impl std::error::Error for CheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CheckpointError::Persistence(err) => Some(err),
            _ => None,
        }
    }
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckpointError::IoError {
                path,
                message,
                io_err,
            } => write!(f, "{}: {}: {}", path.display(), message, io_err),

            CheckpointError::CorruptedLayout { path, message } => {
                write!(f, "{}: {}", path.display(), message)
            }

            CheckpointError::ProtoError {
                path,
                field,
                proto_err,
            } => write!(
                f,
                "{}: failed to deserialize {}: {}",
                path.display(),
                field,
                proto_err
            ),

            CheckpointError::AlreadyExists(height) => write!(
                f,
                "failed to create checkpoint at height {} because it already exists",
                height
            ),

            CheckpointError::NotFound(height) => {
                write!(f, "checkpoint at height {} not found", height)
            }

            CheckpointError::Persistence(err) => write!(f, "persistence error: {}", err),
        }
    }
}

impl From<PersistenceError> for CheckpointError {
    fn from(err: PersistenceError) -> Self {
        CheckpointError::Persistence(err)
    }
}

impl From<LayoutError> for CheckpointError {
    fn from(err: LayoutError) -> Self {
        match err {
            LayoutError::IoError {
                path,
                message,
                io_err,
            } => CheckpointError::IoError {
                path,
                message,
                io_err: io_err.to_string(),
            },
            LayoutError::CorruptedLayout { path, message } => {
                CheckpointError::CorruptedLayout { path, message }
            }
            LayoutError::NotFound(h) => CheckpointError::NotFound(h),
            LayoutError::AlreadyExists(h) => CheckpointError::AlreadyExists(h),
        }
    }
}

#[cfg(feature = "malicious_code")]
/// When maliciously_corrupt_own_state_at_heights contains the given height,
/// this function returns a false hash that contains all 0s.
fn maliciously_return_wrong_hash(
    manifest: &Manifest,
    log: &ReplicaLogger,
    malicious_flags: &MaliciousFlags,
    height: Height,
) -> CryptoHashOfState {
    use ic_protobuf::log::malicious_behaviour_log_entry::v1::{
        MaliciousBehaviour, MaliciousBehaviourLogEntry,
    };

    if malicious_flags
        .maliciously_corrupt_own_state_at_heights
        .contains(&height.get())
    {
        ic_logger::info!(
            log,
            "[MALICIOUS] corrupting the hash of the state at height {}",
            height.get();
            malicious_behaviour => MaliciousBehaviourLogEntry { malicious_behaviour: MaliciousBehaviour::CorruptOwnStateAtHeights as i32}
        );
        CryptoHashOfState::from(CryptoHash(vec![0u8; 32]))
    } else {
        CryptoHashOfState::from(CryptoHash(
            crate::manifest::manifest_hash(&manifest).to_vec(),
        ))
    }
}
