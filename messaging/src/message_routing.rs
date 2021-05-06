use crate::{
    routing, scheduling,
    state_machine::{StateMachine, StateMachineImpl},
};
use actix::{Actor, SyncContext};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_interfaces::state_manager::{CertificationScope, StateManagerError};
use ic_interfaces::{
    certified_stream_store::CertifiedStreamStore,
    execution_environment::{ExecutionEnvironment, IngressHistoryWriter},
    messaging::{MessageRouting, MessageRoutingError},
    registry::RegistryClient,
    state_manager::StateManager,
};
use ic_logger::{debug, fatal, info, warn, ReplicaLogger};
use ic_metrics::buckets::{add_bucket, decimal_buckets};
use ic_metrics::{MetricsRegistry, Timer};
use ic_registry_client::helper::{
    crypto::CryptoRegistry,
    node::NodeRegistry,
    provisional_whitelist::ProvisionalWhitelistRegistry,
    routing_table::RoutingTableRegistry,
    subnet::{SubnetListRegistry, SubnetRegistry},
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CanisterState, NetworkTopology, NodeTopology, ReplicatedState, SubnetTopology,
};
use ic_types::{
    batch::Batch,
    ingress::IngressStatus,
    messages::MessageId,
    registry::RegistryClientError,
    xnet::{StreamHeader, StreamIndex},
    CanisterId, Height, NodeId, NumBytes, RegistryVersion, SubnetId,
};
use ic_utils::thread::JoinOnDrop;
#[cfg(test)]
use mockall::automock;
use prometheus::{Histogram, HistogramVec, IntCounterVec, IntGauge};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::TryFrom;
use std::ops::Range;
use std::sync::mpsc::{sync_channel, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::sleep;

// How many batches we allow in the execution queue before we start rejecting
// incoming batches.
const BATCH_QUEUE_BUFFER_SIZE: usize = 16;

const METRIC_DELIVER_BATCH_COUNT: &str = "mr_deliver_batch_count";
pub(crate) const METRIC_TIME_IN_BACKLOG: &str = "mr_time_in_backlog";
pub(crate) const METRIC_TIME_IN_STREAM: &str = "mr_time_in_stream";

const LABEL_STATUS: &str = "status";
pub(crate) const LABEL_SUBNET: &str = "subnet";

const STATUS_IGNORED: &str = "ignored";
const STATUS_QUEUE_FULL: &str = "queue_full";
const STATUS_SUCCESS: &str = "success";

const PHASE_LOAD_STATE: &str = "load_state";
const PHASE_COMMIT: &str = "commit";

const METRIC_PROCESS_BATCH_DURATION: &str = "mr_process_batch_duration_seconds";
const METRIC_PROCESS_BATCH_PHASE_DURATION: &str = "mr_process_batch_phase_duration_seconds";

/// Records the timestamp when a message and those before/after it up to the
/// next `MessageTime` were first learned about in a stream.
struct MessageTime {
    index: StreamIndex,
    time: Timer,
}

impl MessageTime {
    fn new(index: StreamIndex) -> Self {
        MessageTime {
            index,
            time: Timer::start(),
        }
    }
}

/// A timeline consisting of the timestamps of messages in a stream (usually at
/// block boundaries) providing the base for computing the time spent in the
/// stream / time spent in the backlog by each message; plus a histogram to
/// record these observations.
struct StreamTimeline {
    entries: VecDeque<MessageTime>,
    histogram: Histogram,
}

impl StreamTimeline {
    fn new(histogram: Histogram) -> Self {
        StreamTimeline {
            entries: VecDeque::new(),
            histogram,
        }
    }

    fn add_entry(&mut self, index: StreamIndex) {
        match self.entries.back() {
            None => self.entries.push_back(MessageTime::new(index)),
            Some(observation) if observation.index < index => {
                self.entries.push_back(MessageTime::new(index));
            }
            _ => { /* do nothing */ }
        };
    }

    fn observe(&mut self, index_range: Range<StreamIndex>) {
        for index in index_range.start.get()..index_range.end.get() {
            let entry = loop {
                match self.entries.front() {
                    // Discard all timeline entries with indexes smaller than the
                    // observed index.
                    Some(entry) if entry.index <= index.into() => {
                        self.entries.pop_front().unwrap();
                        continue;
                    }
                    Some(entry) => break entry,
                    _ => return,
                }
            };

            self.histogram.observe(entry.time.elapsed());
        }
    }
}

/// Bundle of message latency metrics for incoming or outgoing streams and the
/// corresponding [`StreamTimelines`](StreamTimeline) needed to compute them.
pub(crate) struct LatencyMetrics {
    timelines: BTreeMap<SubnetId, StreamTimeline>,
    histograms: HistogramVec,
}

impl LatencyMetrics {
    fn new(metrics_registry: &MetricsRegistry, name: &str, description: &str) -> Self {
        let mut buckets = decimal_buckets(0, 2);
        buckets = add_bucket(7.5, buckets);
        buckets = add_bucket(12.5, buckets);
        buckets = add_bucket(15.0, buckets);
        buckets = add_bucket(17.5, buckets);

        Self {
            timelines: BTreeMap::new(),
            histograms: metrics_registry.histogram_vec(name, description, buckets, &[LABEL_SUBNET]),
        }
    }

    pub(crate) fn new_time_in_stream(metrics_registry: &MetricsRegistry) -> LatencyMetrics {
        LatencyMetrics::new(
            metrics_registry,
            METRIC_TIME_IN_STREAM,
            "Time messages spend in the stream before they are garbage collected based\
                            on a signal from the receiving subnet",
        )
    }

    pub(crate) fn new_time_in_backlog(metrics_registry: &MetricsRegistry) -> LatencyMetrics {
        LatencyMetrics::new(
            metrics_registry,
            METRIC_TIME_IN_BACKLOG,
            "Average time it takes to consume a message from the backlog, per sending subnet",
        )
    }

    fn with_timeline(&mut self, subnet_id: SubnetId, f: impl FnOnce(&mut StreamTimeline)) {
        use std::collections::btree_map::Entry;

        match self.timelines.entry(subnet_id) {
            Entry::Occupied(mut o) => f(o.get_mut()),
            Entry::Vacant(v) => {
                let backlog = self.histograms.with_label_values(&[&subnet_id.to_string()]);
                f(v.insert(StreamTimeline::new(backlog)))
            }
        }
    }

    pub(crate) fn observe_header(&mut self, subnet_id: SubnetId, header: &StreamHeader) {
        self.with_timeline(subnet_id, |t| t.add_entry(header.end));
    }

    pub(crate) fn observe_indexes(&mut self, subnet_id: SubnetId, index_range: Range<StreamIndex>) {
        self.with_timeline(subnet_id, |t| t.observe(index_range));
    }
}

/// Metrics for [`MessageRoutingImpl`].
pub(crate) struct MessageRoutingMetrics {
    /// Number of `deliver_batch()` calls, by status.
    deliver_batch_count: IntCounterVec,
    /// Batch processing durations.
    process_batch_duration: Histogram,
    /// Batch processing phase durations, by phase.
    pub process_batch_phase_duration: HistogramVec,
    /// The memory footprint of all the canisters on this subnet. Note that this
    /// counter is from the perspective of the canisters and does not account
    /// for the extra copies of the state that the protocol has to store for
    /// correct operations.
    canisters_memory_usage_bytes: IntGauge,
}

impl MessageRoutingMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        let deliver_batch_count = metrics_registry.int_counter_vec(
            METRIC_DELIVER_BATCH_COUNT,
            "Number of `deliver_batch()` calls, by status.",
            &[LABEL_STATUS],
        );
        for status in &[STATUS_IGNORED, STATUS_QUEUE_FULL, STATUS_SUCCESS] {
            deliver_batch_count.with_label_values(&[status]);
        }
        Self {
            deliver_batch_count,
            process_batch_duration: metrics_registry.histogram(
                METRIC_PROCESS_BATCH_DURATION,
                "Batch processing durations.",
                // 1ms - 50s
                decimal_buckets(-3, 1),
            ),
            process_batch_phase_duration: metrics_registry.histogram_vec(
                METRIC_PROCESS_BATCH_PHASE_DURATION,
                "Batch processing phase durations, by phase.",
                // 1ms - 50s
                decimal_buckets(-3, 1),
                &["phase"],
            ),
            canisters_memory_usage_bytes: metrics_registry.int_gauge(
                "canister_memory_usage_bytes",
                "Total memory footprint of all canisters on this subnet.",
            ),
        }
    }
}

/// Implementation of the `MessageRouting` trait.
pub struct MessageRoutingImpl {
    last_seen_batch: RwLock<Height>,
    batch_sender: std::sync::mpsc::SyncSender<Batch>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    metrics: Arc<MessageRoutingMetrics>,
    log: ReplicaLogger,
    // Handle to the batch processor thread.  Stored so that in `drop`, we can wait
    // for it to exit. It must be declared after `batch_sender` so that the
    // thread is joined after the channel is destroyed.
    _batch_processor_handle: JoinOnDrop<()>,
}

/// The message routing implementation realizes a synchronous
/// actor. Namely, it has a synchronous context, that processes each
/// request without preemption. Note that threads of execution running
/// in a SyncContext are supervised by the main system via a
/// SyncArbiter and run on dedicated threads -- in this case it should
/// be a single thread.
impl Actor for MessageRoutingImpl {
    type Context = SyncContext<Self>;
}

/// A component that executes Consensus [batches](Batch) sequentially, by
/// retrieving the matching state, applying the batch and committing the result.
#[cfg_attr(test, automock)]
trait BatchProcessor: Send {
    fn process_batch(&self, batch: Batch);
}

/// Implementation of [`BatchProcessor`].
struct BatchProcessorImpl {
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    state_machine: Box<dyn StateMachine>,
    registry: Arc<dyn RegistryClient>,
    metrics: Arc<MessageRoutingMetrics>,
    log: ReplicaLogger,
}

impl BatchProcessorImpl {
    fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        state_machine: Box<dyn StateMachine>,
        registry: Arc<dyn RegistryClient>,
        metrics: Arc<MessageRoutingMetrics>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            state_manager,
            state_machine,
            registry,
            metrics,
            log,
        }
    }

    /// Adds an observation to the `METRIC_PROCESS_BATCH_PHASE_DURATION`
    /// histogram for the given phase.
    fn observe_phase_duration(&self, phase: &str, timer: &Timer) {
        self.metrics
            .process_batch_phase_duration
            .with_label_values(&[phase])
            .observe(timer.elapsed());
    }

    fn observe_canisters_memory_usage(&self, state: &ReplicatedState) {
        let mut memory_usage = NumBytes::from(0);
        for canister in state.canister_states.values() {
            memory_usage += canister.memory_usage();
        }

        // Based on
        // https://prometheus.io/docs/introduction/faq/#why-are-all-sample-values-64-bit-floats-i-want-integers,
        // this number cannot be larger than 2^53. 2^53 is 8192 TiB. We will
        // probably not be supporting so much storage on a single subnet anytime
        // soon.
        let ceiling: i64 = 1 << 53;
        let memory_usage = std::cmp::min(
            i64::try_from(memory_usage.get()).unwrap_or_else(|_| ceiling),
            ceiling,
        );
        self.metrics.canisters_memory_usage_bytes.set(memory_usage);
    }

    // Retrieve the `ProvisionalWhitelist` from the registry.  We do this at the
    // start of the "deterministic state machine" to ensure that we do not start
    // any processing till we have all the necessary information required to
    // finish it.
    //
    // # Warning
    // If the registry is unavailable, this method keeps trying again forever until
    // the registry becomes available.
    fn get_provisional_whitelist(&self, registry_version: RegistryVersion) -> ProvisionalWhitelist {
        let provisional_whitelist = loop {
            match self.registry.get_provisional_whitelist(registry_version) {
                Ok(record) => break record,
                Err(err) => {
                    warn!(
                        self.log,
                        "Unable to read the provisional whitelist: {}. Trying again...",
                        err.to_string(),
                    );
                }
            }
            sleep(std::time::Duration::from_millis(100));
        };
        provisional_whitelist.unwrap_or_else(|| ProvisionalWhitelist::Set(BTreeSet::new()))
    }

    // Populates a `NetworkTopology` from the registry at a specific version.
    //
    // # Warning
    // If the registry is unavailable, this method keeps trying again forever until
    // the registry becomes available.
    fn populate_network_topology(&self, registry_version: RegistryVersion) -> NetworkTopology {
        loop {
            match self.try_to_populate_network_topology(registry_version) {
                Ok(network_topology) => break network_topology,
                Err(err) => {
                    warn!(
                        self.log,
                        "Unable to populate network topology: {}. Trying again...",
                        err.to_string(),
                    );
                }
            }
            sleep(std::time::Duration::from_millis(100));
        }
    }

    // Tries to populate a `NetworkTopology` from the registry.
    fn try_to_populate_network_topology(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<NetworkTopology, RegistryClientError> {
        // Return the list of subnets present in the registry. If no subnet list is
        // defined, as could be the case in tests, an empty `Vec` is returned.
        let subnet_ids_record = self.registry.get_subnet_ids(registry_version)?;
        let subnet_ids = subnet_ids_record.unwrap_or_default();

        // Populate subnet topologies.
        let mut subnets: BTreeMap<SubnetId, SubnetTopology> = BTreeMap::new();

        for subnet_id in &subnet_ids {
            let mut nodes: BTreeMap<NodeId, NodeTopology> = BTreeMap::new();

            // Return the list of nodes present in the registry. If no nodes are
            // defined, as could be the case in tests, an empty `Vec` is returned.
            let node_ids_record = self
                .registry
                .get_node_ids_on_subnet(*subnet_id, registry_version)?;
            let node_ids = node_ids_record.unwrap_or_default();

            for node_id in node_ids {
                // Get the node
                let node_record = match self
                    .registry
                    .get_transport_info(node_id, registry_version)?
                {
                    Some(node_record) => node_record,
                    None => {
                        warn!(
                            self.log,
                            "No NodeRecord found for node {}. Skipping...", node_id
                        );
                        continue;
                    }
                };

                let http_info = match node_record.http {
                    Some(http_info) => http_info,
                    None => {
                        warn!(
                            self.log,
                            "NodeRecord for node {} does not contain an http connection endpoint. Skipping...",
                            node_id
                        );
                        continue;
                    }
                };

                let http_port = match u16::try_from(http_info.port) {
                    Ok(http_port) => http_port,
                    _ => {
                        warn!(
                            self.log,
                            "Invalid HTTP port {} defined for node {}. Skipping...",
                            http_info.port,
                            node_id,
                        );
                        continue;
                    }
                };

                nodes.insert(
                    node_id,
                    NodeTopology {
                        ip_address: http_info.ip_addr,
                        http_port,
                    },
                );
            }

            let public_key =
                get_subnet_public_key(Arc::clone(&self.registry), *subnet_id, registry_version)?;
            let subnet_type = self.get_subnet_type(*subnet_id, registry_version);
            subnets.insert(
                *subnet_id,
                SubnetTopology {
                    public_key,
                    nodes,
                    subnet_type,
                },
            );
        }

        let routing_table_record = self.registry.get_routing_table(registry_version)?;
        let routing_table = routing_table_record.unwrap_or_default();
        let nns_subnet_id = self.get_nns_subnet_id(subnet_ids, registry_version);

        Ok(NetworkTopology {
            subnets,
            routing_table,
            nns_subnet_id,
        })
    }

    fn get_nns_subnet_id(
        &self,
        subnet_ids: Vec<SubnetId>,
        registry_version: RegistryVersion,
    ) -> SubnetId {
        for subnet_id in subnet_ids {
            if self.get_subnet_type(subnet_id, registry_version) == SubnetType::System {
                return subnet_id;
            }
        }
        unreachable!("Could not find the NNS subnet id.");
    }

    fn get_subnet_type(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> SubnetType {
        loop {
            match self.registry.get_subnet_record(subnet_id, registry_version) {
                Ok(subnet_record) => {
                    break match subnet_record {
                        Some(record) => SubnetType::try_from(record.subnet_type)
                            .expect("Could not parse SubnetType"),
                        // This can only happen if the registry is corrupted, so better to crash.
                        None => fatal!(
                            self.log,
                            "Failed to find a subnet record for subnet: {} in the registry.",
                            subnet_id
                        ),
                    };
                }
                Err(err) => {
                    warn!(
                        self.log,
                        "Unable to read the subnet record: {}. Trying again...",
                        err.to_string(),
                    );
                }
            }
            sleep(std::time::Duration::from_millis(100));
        }
    }
}

fn get_subnet_public_key(
    registry: Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
) -> Result<Vec<u8>, RegistryClientError> {
    use ic_crypto::threshold_sig_public_key_to_der;
    Ok(registry
        .get_initial_dkg_transcripts(subnet_id, registry_version)?
        .value
        .map(|transcripts| {
            let transcript = transcripts.high_threshold;
            let pk = transcript.public_key();
            threshold_sig_public_key_to_der(pk).unwrap_or_else(|err| {
                panic!("Invalid public key for subnet {}: {:?}", subnet_id, err)
            })
        })
        .expect("Initial DKG transcripts not found."))
}

impl BatchProcessor for BatchProcessorImpl {
    fn process_batch(&self, batch: Batch) {
        let timer = Timer::start();

        // Fetch the mutable tip from StateManager
        let state = match self
            .state_manager
            .take_tip_at(batch.batch_number.decrement())
        {
            Ok(state) => state,
            Err(StateManagerError::StateRemoved(_)) => {
                info!(
                    self.log,
                    "Ignoring batch {} as we already have state {}",
                    batch.batch_number,
                    self.state_manager.latest_state_height()
                );
                return;
            }
            Err(StateManagerError::StateNotCommittedYet(_)) => fatal!(
                self.log,
                "Cannot apply batch {}, to state {}",
                batch.batch_number,
                self.state_manager.latest_state_height()
            ),
        };
        self.observe_phase_duration(PHASE_LOAD_STATE, &timer);

        debug!(self.log, "Processing batch {}", batch.batch_number);
        let commit_height = Height::from(batch.batch_number.get());

        let certification_scope = if batch.requires_full_state_hash {
            CertificationScope::Full
        } else {
            CertificationScope::Metadata
        };

        // TODO (MR-29) Cache network topology and only populate if version
        // referenced in batch changes.
        let network_topology = self.populate_network_topology(batch.registry_version);
        let provisional_whitelist = self.get_provisional_whitelist(batch.registry_version);

        let batch_requires_full_state_hash = batch.requires_full_state_hash;
        let mut state_after_round =
            self.state_machine
                .execute_round(state, network_topology, batch, provisional_whitelist);
        self.observe_canisters_memory_usage(&state_after_round);

        // See documentation around the definition of `heap_delta_estimate` for
        // an explanation.
        if batch_requires_full_state_hash {
            state_after_round.metadata.heap_delta_estimate = NumBytes::from(0);
        }

        let phase_timer = Timer::start();

        self.state_manager.commit_and_certify(
            state_after_round,
            commit_height,
            certification_scope,
        );
        self.observe_phase_duration(PHASE_COMMIT, &phase_timer);

        self.metrics.process_batch_duration.observe(timer.elapsed());
    }
}

pub(crate) struct FakeBatchProcessorImpl {
    stream_builder: Box<dyn routing::stream_builder::StreamBuilder>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    log: ReplicaLogger,
}

impl FakeBatchProcessorImpl {
    pub fn new(
        log: ReplicaLogger,
        stream_builder: Box<dyn routing::stream_builder::StreamBuilder>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    ) -> Self {
        Self {
            stream_builder,
            state_manager,
            ingress_history_writer,
            log,
        }
    }
}

fn update_state(
    ingress_history_writer: &dyn IngressHistoryWriter<State = ReplicatedState>,
    not_run_canisters: BTreeMap<CanisterId, CanisterState>,
    state: &mut ReplicatedState,
    all_canister_states: Vec<CanisterState>,
    all_ingress_execution_results: Vec<(MessageId, IngressStatus)>,
) {
    state.put_canister_states(
        all_canister_states
            .into_iter()
            .map(|canister| (canister.canister_id(), canister))
            .chain(not_run_canisters.into_iter())
            .collect(),
    );

    for (msg_id, status) in all_ingress_execution_results {
        ingress_history_writer.set_status(state, msg_id, status);
    }
}

impl BatchProcessor for FakeBatchProcessorImpl {
    fn process_batch(&self, batch: Batch) {
        // Fetch the mutable tip from StateManager
        let mut state = match self
            .state_manager
            .take_tip_at(batch.batch_number.decrement())
        {
            Ok(state) => state,
            Err(StateManagerError::StateRemoved(_)) => {
                info!(
                    self.log,
                    "Ignoring batch {} as we already have state {}",
                    batch.batch_number,
                    self.state_manager.latest_state_height()
                );
                return;
            }
            Err(StateManagerError::StateNotCommittedYet(_)) => fatal!(
                self.log,
                "Cannot apply batch {}, to state {}",
                batch.batch_number,
                self.state_manager.latest_state_height()
            ),
        };

        debug!(self.log, "Processing batch {}", batch.batch_number);
        let commit_height = Height::from(batch.batch_number.get());

        let mut metadata = state.system_metadata().clone();
        let time = batch.time;
        metadata.batch_time = time;
        state.set_system_metadata(metadata);

        // Get only ingress and ignore xnet messages
        let (signed_ingress_msgs, _certified_stream_slices) =
            batch.payload.into_messages().unwrap();

        // Treat all ingress messages as already executed.
        let canisters = state.take_canister_states();
        let all_canister_states = Vec::new();
        let all_ingress_execution_results = signed_ingress_msgs
            .into_iter()
            .map(|ingress| {
                // It is safe to assume valid expiry time here
                (
                    ingress.id(),
                    ic_types::ingress::IngressStatus::Completed {
                        receiver: ingress.canister_id().get(),
                        user_id: ingress.sender(),
                        // The byte content mimicks a good reply for the counter example
                        result: ic_types::ingress::WasmResult::Reply(vec![68, 73, 68, 76, 0, 0]),
                        time,
                    },
                )
            })
            .collect::<Vec<_>>();
        update_state(
            self.ingress_history_writer.as_ref(),
            canisters,
            &mut state,
            all_canister_states,
            all_ingress_execution_results,
        );
        state.prune_ingress_history();

        // Postprocess the state and consolidate the Streams.
        let state_after_stream_builder = self.stream_builder.build_streams(state);

        let certification_scope = if batch.requires_full_state_hash {
            CertificationScope::Full
        } else {
            CertificationScope::Metadata
        };

        self.state_manager.commit_and_certify(
            state_after_stream_builder,
            commit_height,
            certification_scope,
        );
    }
}

impl MessageRoutingImpl {
    fn from_batch_processor(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        batch_processor: Box<dyn BatchProcessor>,
        metrics: Arc<MessageRoutingMetrics>,
        log: ReplicaLogger,
    ) -> Self {
        let (batch_sender, batch_receiver) = sync_channel(BATCH_QUEUE_BUFFER_SIZE);

        let _batch_processor_handle = JoinOnDrop::new(
            std::thread::Builder::new()
                .name("MR Batch Processor".to_string())
                .spawn(move || {
                    while let Ok(batch) = batch_receiver.recv() {
                        batch_processor.process_batch(batch);
                    }
                })
                .expect("Can spawn a batch processing thread in MR"),
        );

        Self {
            last_seen_batch: RwLock::new(Height::from(0)),
            batch_sender,
            state_manager,
            metrics,
            log,
            _batch_processor_handle,
        }
    }

    /// Creates a new `MessageRoutingImpl` for the given subnet using the
    /// provided `StateManager` and `ExecutionEnvironment`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState> + 'static>,
        exec_env: Arc<
            dyn ExecutionEnvironment<State = ReplicatedState, CanisterState = CanisterState>
                + 'static,
        >,
        cycles_account_manager: Arc<CyclesAccountManager>,
        scheduler_config: ic_config::subnet_config::SchedulerConfig,
        subnet_id: SubnetId,
        subnet_type: SubnetType,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
        registry: Arc<dyn RegistryClient>,
    ) -> Self {
        let scheduler = Box::new(scheduling::scheduler::SchedulerImpl::new(
            scheduler_config,
            subnet_id,
            subnet_type,
            Arc::clone(&ingress_history_writer),
            exec_env,
            Arc::clone(&cycles_account_manager),
            metrics_registry,
            log.clone(),
        ));
        let time_in_stream_metrics = Arc::new(Mutex::new(LatencyMetrics::new_time_in_stream(
            metrics_registry,
        )));
        let stream_handler = Box::new(routing::stream_handler::StreamHandlerImpl::new(
            subnet_id,
            metrics_registry,
            Arc::clone(&time_in_stream_metrics),
            log.clone(),
        ));
        let vsr = Box::new(scheduling::valid_set_rule::ValidSetRuleImpl::new(
            ingress_history_writer,
            cycles_account_manager,
            metrics_registry,
            subnet_id,
            log.clone(),
        ));
        let demux = Box::new(routing::demux::DemuxImpl::new(
            vsr,
            stream_handler,
            certified_stream_store,
            log.clone(),
        ));
        let stream_builder = Box::new(routing::stream_builder::StreamBuilderImpl::new(
            subnet_id,
            metrics_registry,
            time_in_stream_metrics,
            log.clone(),
        ));
        let metrics = Arc::new(MessageRoutingMetrics::new(metrics_registry));
        let state_machine = Box::new(StateMachineImpl::new(
            scheduler,
            demux,
            stream_builder,
            log.clone(),
            Arc::clone(&metrics),
        ));

        let batch_processor = Box::new(BatchProcessorImpl::new(
            state_manager.clone(),
            state_machine,
            registry,
            Arc::clone(&metrics),
            log.clone(),
        ));

        Self::from_batch_processor(state_manager, batch_processor, Arc::clone(&metrics), log)
    }

    /// Creates a new `MessageRoutingImpl` for the given subnet using a fake
    /// `BatchProcessor` and the provided `StateManager`.
    pub fn new_fake(
        subnet_id: SubnetId,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState> + 'static>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        let stream_builder = Box::new(routing::stream_builder::StreamBuilderImpl::new(
            subnet_id,
            metrics_registry,
            Arc::new(Mutex::new(LatencyMetrics::new_time_in_stream(
                &metrics_registry,
            ))),
            log.clone(),
        ));

        let batch_processor = FakeBatchProcessorImpl::new(
            log.clone(),
            stream_builder,
            Arc::clone(&state_manager),
            ingress_history_writer,
        );
        let metrics = Arc::new(MessageRoutingMetrics::new(metrics_registry));

        Self::from_batch_processor(
            state_manager,
            Box::new(batch_processor),
            Arc::clone(&metrics),
            log,
        )
    }

    fn inc_deliver_batch(&self, status: &str) {
        self.metrics
            .deliver_batch_count
            .with_label_values(&[status])
            .inc();
    }
}

impl MessageRouting for MessageRoutingImpl {
    fn deliver_batch(&self, batch: Batch) -> Result<(), MessageRoutingError> {
        let batch_number = batch.batch_number;
        let expected_number = self.expected_batch_height();
        if batch_number != expected_number {
            self.inc_deliver_batch(STATUS_IGNORED);
            info!(
                self.log,
                "Ignoring batch {}, expected batch: {}", batch_number, expected_number,
            );
            return Err(MessageRoutingError::Ignored {
                expected_height: expected_number,
                actual_height: batch_number,
            });
        }

        match self.batch_sender.try_send(batch) {
            Ok(_) => {
                self.inc_deliver_batch(STATUS_SUCCESS);
                debug!(self.log, "Inserted batch {}", batch_number);
                *self.last_seen_batch.write().unwrap() = batch_number;
                Ok(())
            }
            // If the queue is already full, we pretend that we never received
            // the batch. It's important not to block Consensus, it will try to
            // resend the overflowing batches later.
            Err(TrySendError::Full(_)) => {
                self.inc_deliver_batch(STATUS_QUEUE_FULL);
                info!(
                    self.log,
                    "Rejecting batch {}: execution queue overflow ({} batches queued)",
                    batch_number,
                    BATCH_QUEUE_BUFFER_SIZE
                );
                Err(MessageRoutingError::QueueIsFull)
            }
            Err(TrySendError::Disconnected(_)) => fatal!(
                self.log,
                "Failed to send batch {}: background worker is dead",
                batch_number,
            ),
        }
    }

    fn expected_batch_height(&self) -> Height {
        self.last_seen_batch
            .read()
            .unwrap()
            .increment()
            .max(self.state_manager.latest_state_height().increment())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_test_utilities::{
        metrics::{fetch_int_counter_vec, metric_vec},
        notification::{Notification, WaitResult},
        state_manager::MockStateManager,
        types::batch::BatchBuilder,
        with_test_replica_logger,
    };
    use std::sync::Arc;
    use std::time::Duration;

    /// Helper function for testing the values of the
    /// `METRIC_DELIVER_BATCH_COUNT` metric.
    fn assert_deliver_batch_count_eq(
        ignored: u64,
        queue_full: u64,
        success: u64,
        metrics_registry: &MetricsRegistry,
    ) {
        assert_eq!(
            metric_vec(&[
                (&[(LABEL_STATUS, STATUS_IGNORED)], ignored),
                (&[(LABEL_STATUS, STATUS_QUEUE_FULL)], queue_full),
                (&[(LABEL_STATUS, STATUS_SUCCESS)], success),
            ]),
            fetch_int_counter_vec(metrics_registry, METRIC_DELIVER_BATCH_COUNT)
        );
    }

    #[test]
    fn message_routing_does_not_block() {
        with_test_replica_logger(|log| {
            let timeout = Duration::from_secs(10);

            let mut mock = MockBatchProcessor::new();
            let started_notification = Arc::new(Notification::new());
            let notification = Arc::new(Notification::new());
            mock.expect_process_batch().returning({
                let notification = Arc::clone(&notification);
                let started_notification = Arc::clone(&started_notification);
                move |_| {
                    started_notification.notify(());
                    assert_eq!(
                        notification.wait_with_timeout(timeout),
                        WaitResult::Notified(())
                    );
                }
            });

            let mock_box = Box::new(mock);
            let mut state_manager = MockStateManager::new();
            state_manager
                .expect_latest_state_height()
                .return_const(Height::from(0));

            let state_manager = Arc::new(state_manager);
            let metrics_registry = MetricsRegistry::new();
            let metrics = Arc::new(MessageRoutingMetrics::new(&metrics_registry));
            let mr = MessageRoutingImpl::from_batch_processor(
                state_manager,
                mock_box,
                metrics,
                log.clone(),
            );
            // We need to submit one extra batch because the very first one
            // is removed from the queue by the background worker.
            for batch_number in 1..BATCH_QUEUE_BUFFER_SIZE + 2 {
                let batch_number = Height::from(batch_number as u64);
                info!(log, "Delivering batch {}", batch_number);
                assert_eq!(batch_number, mr.expected_batch_height());
                mr.deliver_batch(BatchBuilder::default().batch_number(batch_number).build())
                    .unwrap();
                assert_eq!(
                    started_notification.wait_with_timeout(timeout),
                    WaitResult::Notified(())
                );
                assert_deliver_batch_count_eq(0, 0, batch_number.get(), &metrics_registry);
            }

            let last_batch = Height::from(BATCH_QUEUE_BUFFER_SIZE as u64 + 2);
            assert_eq!(last_batch, mr.expected_batch_height());
            assert_eq!(
                mr.deliver_batch(BatchBuilder::default().batch_number(last_batch).build()),
                Err(MessageRoutingError::QueueIsFull)
            );
            assert_deliver_batch_count_eq(
                0,
                1,
                1 + BATCH_QUEUE_BUFFER_SIZE as u64,
                &metrics_registry,
            );
            notification.notify(());
        });
    }
}
