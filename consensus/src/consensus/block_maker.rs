#![deny(missing_docs)]
use crate::{
    consensus::{
        membership::Membership, metrics::BlockMakerMetrics, payload_builder::PayloadBuilder,
        pool_reader::PoolReader, prelude::*, utils::*, ConsensusCrypto,
    },
    dkg::create_payload,
};
use ic_interfaces::{
    dkg::DkgPool, ingress_pool::IngressPoolSelect, messaging::XNetPayloadError,
    registry::RegistryClient, state_manager::StateManager, time_source::TimeSource,
};
use ic_logger::{debug, error, trace, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{consensus::dkg, replica_config::ReplicaConfig, ReplicaVersion};
use std::cmp::Ordering;
use std::sync::Arc;
use std::sync::{Mutex, RwLock};

// Wait for VALIDATED_DEALING_AGE_THRESHOLD_MSECS (from the time an entry was
// added to the validated pool) before selecting it for inclusion in a block.
// This (opportunistically) gives enough time for the entries to be
// gossiped/validated/included in the DKG pools of the peers. And so that
// the block validation path can skip the expensive crypto validation.
const VALIDATED_DEALING_AGE_THRESHOLD_MSECS: u64 = 10;

/// A consensus subcomponent that is responsible for creating block proposals.
pub struct BlockMaker {
    time_source: Arc<dyn TimeSource>,
    replica_config: ReplicaConfig,
    registry_client: Arc<dyn RegistryClient>,
    membership: Arc<Membership>,
    crypto: Arc<dyn ConsensusCrypto>,
    payload_builder: Arc<dyn PayloadBuilder>,
    dkg_pool: Arc<RwLock<dyn DkgPool>>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    metrics: BlockMakerMetrics,
    log: ReplicaLogger,
    payload_context_cache: Mutex<Option<(CryptoHashOf<Block>, ValidationContext)>>,
}

impl BlockMaker {
    /// Construct a [BlockMaker] from its dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        time_source: Arc<dyn TimeSource>,
        replica_config: ReplicaConfig,
        registry_client: Arc<dyn RegistryClient>,
        membership: Arc<Membership>,
        crypto: Arc<dyn ConsensusCrypto>,
        payload_builder: Arc<dyn PayloadBuilder>,
        dkg_pool: Arc<RwLock<dyn DkgPool>>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        metrics_registry: MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            time_source,
            replica_config,
            registry_client,
            membership,
            crypto,
            payload_builder,
            dkg_pool,
            state_manager,
            log,
            metrics: BlockMakerMetrics::new(metrics_registry),
            payload_context_cache: Mutex::new(None),
        }
    }

    /// If a block should be proposed, propose it.
    pub fn on_state_change(
        &self,
        pool: &PoolReader<'_>,
        ingress_pool: &dyn IngressPoolSelect,
    ) -> Option<BlockProposal> {
        trace!(self.log, "on_state_change");
        let my_node_id = self.replica_config.node_id;
        let (beacon, parent) = get_dependencies(&pool)?;
        let height = beacon.content.height.increment();
        match self
            .membership
            .get_block_maker_rank(height, &beacon, my_node_id)
        {
            Ok(Some(rank)) => {
                if !already_proposed(pool, height, my_node_id)
                    && !self.is_better_block_proposal_available(pool, height, rank)
                    && is_time_to_make_block(
                        &self.log,
                        self.registry_client.as_ref(),
                        self.replica_config.subnet_id,
                        pool,
                        height,
                        rank,
                        self.time_source.as_ref(),
                    )
                {
                    self.propose_block(pool, ingress_pool, rank, parent)
                        .map(|proposal| {
                            debug!(
                                self.log,
                                "Make proposal {:?} {:?} {:?}",
                                proposal.content.get_hash(),
                                proposal.as_ref().payload.get_hash(),
                                proposal.as_ref().payload.as_ref()
                            );
                            self.log_block(proposal.as_ref());
                            proposal
                        })
                } else {
                    None
                }
            }
            Ok(None) => {
                // this replica is not elected as block maker this round
                None
            }
            Err(err) => {
                debug!(
                    self.log,
                    "Not proposing a block due to get_node_rank error {:?}", err
                );
                None
            }
        }
    }

    /// Return true if the validated pool contains a better (lower ranked) block
    /// proposal than the given rank, for the given height.
    fn is_better_block_proposal_available(
        &self,
        pool: &PoolReader<'_>,
        height: Height,
        rank: Rank,
    ) -> bool {
        if let Some(block) = find_lowest_ranked_proposals(pool, height).first() {
            return block.rank() < rank;
        }
        false
    }

    /// Construct a block proposal
    fn propose_block(
        &self,
        pool: &PoolReader<'_>,
        ingress_pool: &dyn IngressPoolSelect,
        rank: Rank,
        parent: Block,
    ) -> Option<BlockProposal> {
        let parent_hash = ic_crypto::crypto_hash(&parent);
        let height = parent.height.increment();
        let certified_height = self.state_manager.latest_certified_height();

        // Note that we will skip blockmaking if registry versions or replica_versions
        // are missing or temporarily not retrievable.
        let registry_version = pool.registry_version(height)?;
        let replica_version = lookup_replica_version(
            self.registry_client.as_ref(),
            self.replica_config.subnet_id,
            &self.log,
            registry_version,
        )?;

        // If we have previously tried to make a payload but got an error at the given
        // height, We should try again with the same context. Otherwise create a
        // new context.
        let context = match self.payload_context_cache.lock().unwrap().take() {
            Some((hash, context)) if hash == parent_hash => context,
            _ => ValidationContext {
                certified_height,
                registry_version: self.registry_client.get_latest_version(),
                // Below we skip proposing the block if this context is behind the parent's context.
                // We set the time so that block making is not skipped due to local time being
                // behind the network time.
                time: std::cmp::max(self.time_source.get_relative_time(), parent.context.time),
            },
        };

        match context.partial_cmp(&parent.context) {
            None | Some(Ordering::Less) => {
                // the values in our validation context are not monotonically increasing the
                // values included in the parent block. To avoid proposing an
                // invalid block, we simply do not propose a block now.
                warn!(
                    self.log,
                    "Cannot propose block as the locally available validation context is smaller than the parent validation context (locally available={:?}, parent context={:?})",
                    context,
                    &parent.context
                );
                return None;
            }
            _ => {}
        }

        let batch_payload = {
            // Use empty payload if the (agreed) replica_version is not supported.
            if replica_version != ReplicaVersion::default() {
                // if latest finalized CUP block has a version that is different,
                // we should stop making blocks.
                let finalized_replica_version = pool
                    .get_replica_version_from_highest_catch_up_package(
                        self.registry_client.as_ref(),
                        &self.replica_config,
                        &self.log,
                    )?;
                if finalized_replica_version != ReplicaVersion::default() {
                    debug!(
                        self.log,
                        "Skip making blocks after the upgrade catch-up package has finalized."
                    );
                    return None;
                }
                BatchPayload::default()
            } else {
                let past_payloads =
                    pool.get_payloads_from_height(certified_height.increment(), parent.clone());
                match self.payload_builder.get_payload(
                    height,
                    ingress_pool,
                    &past_payloads,
                    &context,
                ) {
                    Ok(payload) => {
                        self.metrics
                            .get_payload_calls
                            .with_label_values(&["success"])
                            .inc();
                        payload
                    }
                    Err(XNetPayloadError::Pending) => {
                        // In case xnet payload builder has yet to finish preparing a payload, we
                        // will try again later.
                        //
                        // The necessary context is remembered in a local cache so that we can use
                        // the same context when trying again.
                        *self.payload_context_cache.lock().unwrap() = Some((parent_hash, context));
                        self.metrics
                            .get_payload_calls
                            .with_label_values(&["pending"])
                            .inc();
                        return None;
                    }
                }
            }
        };

        self.construct_block_proposal(
            pool,
            context,
            parent,
            parent_hash,
            height,
            rank,
            replica_version,
            registry_version,
            batch_payload,
        )
    }

    /// Construct a block proposal with specified validation context, parent
    /// block, rank, and batch payload. This function completes the block by
    /// adding a DKG payload and signs the block to obtain a block proposal.
    #[allow(clippy::too_many_arguments)]
    fn construct_block_proposal(
        &self,
        pool: &PoolReader<'_>,
        context: ValidationContext,
        parent: Block,
        parent_hash: CryptoHashOf<Block>,
        height: Height,
        rank: Rank,
        replica_version: ReplicaVersion,
        registry_version: RegistryVersion,
        batch_payload: BatchPayload,
    ) -> Option<BlockProposal> {
        let max_dealings_per_block = dkg_dealings_per_block(
            &*self.registry_client,
            registry_version,
            self.replica_config.subnet_id,
        )
        .map_err(|err| warn!(self.log, "{:?}", err))
        .ok()?;

        let dkg_payload = create_payload(
            self.replica_config.subnet_id,
            &*self.registry_client,
            &*self.crypto,
            &pool,
            Arc::clone(&self.dkg_pool),
            parent,
            &*self.state_manager,
            &context,
            self.log.clone(),
            max_dealings_per_block,
            VALIDATED_DEALING_AGE_THRESHOLD_MSECS,
        )
        .map_err(|err| warn!(self.log, "Payload construction has failed: {:?}", err))
        .ok()?;

        let payload = Payload::new(
            ic_crypto::crypto_hash,
            match dkg_payload {
                dkg::Payload::Summary(summary) => summary.into(),
                dkg::Payload::Dealings(dealings) => {
                    if replica_version != ReplicaVersion::default() {
                        // Use empty DKG dealings if the (agreed) replica_version is not supported.
                        (
                            batch_payload,
                            dkg::Dealings::new_empty(dealings.start_height),
                        )
                            .into()
                    } else {
                        (batch_payload, dealings).into()
                    }
                }
            },
        );
        let block = Block::new(parent_hash, payload, height, rank, context);
        let hashed_block = hashed::Hashed::new(ic_crypto::crypto_hash, block);
        match self
            .crypto
            .sign(&hashed_block, self.replica_config.node_id, registry_version)
        {
            Ok(signature) => Some(BlockProposal {
                signature,
                content: hashed_block,
            }),
            Err(err) => {
                error!(self.log, "Couldn't create a signature: {:?}", err);
                None
            }
        }
    }

    /// Log an entry for the proposed block and each of its ingress messages
    fn log_block(&self, block: &Block) {
        let hash = get_block_hash_string(block);
        let block_log_entry = block.log_entry(hash.clone());
        debug!(
            self.log,
            "block_proposal";
            block => block_log_entry
        );
        let empty_batch = BatchPayload::default();
        let batch = if block.payload.is_summary() {
            &empty_batch
        } else {
            block.payload.as_ref().as_batch_payload()
        };

        for message_id in batch.ingress.message_ids() {
            debug!(
                self.log,
                "ingress_message_insert_into_block";
                ingress_message.message_id => format!("{}", message_id),
                block.hash => hash,
            );
        }
    }

    /// Maliciously propose blocks irrespective of the rank, based on the flags
    /// received. If maliciously_propose_empty_blocks is set, propose only empty
    /// blocks. If maliciously_equivocation_blockmaker is set, propose
    /// multiple blocks at once.
    #[cfg(feature = "malicious_code")]
    pub(crate) fn maliciously_propose_blocks(
        &self,
        pool: &PoolReader<'_>,
        ingress_pool: &dyn IngressPoolSelect,
        maliciously_propose_empty_blocks: bool,
        maliciously_equivocation_blockmaker: bool,
    ) -> Vec<BlockProposal> {
        use ic_protobuf::log::malicious_behaviour_log_entry::v1::{
            MaliciousBehaviour, MaliciousBehaviourLogEntry,
        };
        use std::time::Duration;
        trace!(self.log, "maliciously_propose_blocks");
        let number_of_proposals = 5;

        let my_node_id = self.replica_config.node_id;
        let (beacon, parent) = match get_dependencies(&pool) {
            Some((b, p)) => (b, p),
            None => {
                return Vec::new();
            }
        };
        let height = beacon.content.height.increment();
        let registry_version = match pool.registry_version(height) {
            Some(v) => v,
            None => {
                return Vec::new();
            }
        };

        // If this node is a blockmaker, use its rank. If not, use rank 0.
        // If the rank is not yet available, wait further.
        let maybe_rank = match self
            .membership
            .get_block_maker_rank(height, &beacon, my_node_id)
        {
            Ok(Some(rank)) => Some(rank),
            Ok(None) => Some(Rank(0)),
            Err(_) => None,
        };

        if let Some(rank) = maybe_rank {
            if !already_proposed(pool, height, my_node_id) {
                // If maliciously_propose_empty_blocks is set, propose only empty blocks.
                let maybe_proposal = match maliciously_propose_empty_blocks {
                    true => self.maliciously_propose_empty_block(pool, rank, parent),
                    false => self.propose_block(pool, ingress_pool, rank, parent),
                };

                if let Some(proposal) = maybe_proposal {
                    let mut proposals = vec![];

                    match maliciously_equivocation_blockmaker {
                        false => {}
                        true => {
                            let original_block = Block::from(proposal.clone());
                            // Generate more valid proposals based on this proposal, by slightly
                            // increasing the time in the context of
                            // this block.
                            for i in 1..(number_of_proposals - 1) {
                                let mut new_block = original_block.clone();
                                new_block.context.time += Duration::from_nanos(i);
                                let hashed_block =
                                    hashed::Hashed::new(ic_crypto::crypto_hash, new_block);
                                if let Ok(signature) = self.crypto.sign(
                                    &hashed_block,
                                    self.replica_config.node_id,
                                    registry_version,
                                ) {
                                    proposals.push(BlockProposal {
                                        signature,
                                        content: hashed_block,
                                    });
                                }
                            }
                        }
                    };
                    proposals.push(proposal);

                    if maliciously_propose_empty_blocks {
                        ic_logger::info!(
                            self.log,
                            "[MALICIOUS] proposing empty blocks";
                            malicious_behaviour => MaliciousBehaviourLogEntry { malicious_behaviour: MaliciousBehaviour::ProposeEmptyBlocks as i32}
                        );
                    }
                    if maliciously_equivocation_blockmaker {
                        ic_logger::info!(
                            self.log,
                            "[MALICIOUS] proposing {} equivocation blocks",
                            proposals.len();
                            malicious_behaviour => MaliciousBehaviourLogEntry { malicious_behaviour: MaliciousBehaviour::ProposeEquivocatingBlocks as i32}
                        );
                    }

                    return proposals;
                }
            }
        }
        Vec::new()
    }

    /// Maliciously construct a block proposal with valid DKG, but with empty
    /// batch payload.
    #[cfg(feature = "malicious_code")]
    fn maliciously_propose_empty_block(
        &self,
        pool: &PoolReader<'_>,
        rank: Rank,
        parent: Block,
    ) -> Option<BlockProposal> {
        let parent_hash = ic_crypto::crypto_hash(&parent);
        let height = parent.height.increment();
        let context = parent.context.clone();

        // Note that we will skip blockmaking if registry versions or replica_versions
        // are missing or temporarily not retrievable.
        let registry_version = pool.registry_version(height)?;
        let replica_version = lookup_replica_version(
            self.registry_client.as_ref(),
            self.replica_config.subnet_id,
            &self.log,
            registry_version,
        )?;

        self.construct_block_proposal(
            pool,
            context,
            parent,
            parent_hash,
            height,
            rank,
            replica_version,
            registry_version,
            BatchPayload::default(),
        )
    }
}

/// Return the parent random beacon and block of the latest round for which
/// this node might propose a block.
/// Return None otherwise.
fn get_dependencies(pool: &PoolReader<'_>) -> Option<(RandomBeacon, Block)> {
    let notarized_height = pool.get_notarized_height();
    let beacon = pool.get_random_beacon(notarized_height)?;
    let parent = pool
        .get_notarized_blocks(notarized_height)
        .min_by(|block1, block2| block1.rank().cmp(&block2.rank()))?;
    Some((beacon, parent))
}

/// Return true if this node has already made a proposal at the given height.
fn already_proposed(pool: &PoolReader<'_>, h: Height, this_node: NodeId) -> bool {
    pool.pool()
        .validated()
        .block_proposal()
        .get_by_height(h)
        .any(|p| p.signature.signer == this_node)
}

/// Determine how many DKG dealings are allowed in a single block by obtaining
/// this value from the registry.
fn dkg_dealings_per_block(
    registry_client: &dyn RegistryClient,
    version: RegistryVersion,
    subnet_id: SubnetId,
) -> Result<usize, String> {
    registry_client
        .get_dkg_dealings_per_block(subnet_id, version)
        .map_err(|err| format!("Registry error: {:?}", err))?
        .ok_or_else(|| {
            panic!(
                "No subnet record found for registry version={:?} and subnet_id={:?}",
                version, subnet_id,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::mocks::{
        dependencies_with_subnet_params, Dependencies, MockPayloadBuilder,
    };
    use ic_interfaces::consensus_pool::ConsensusPool;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_test_artifact_pool::ingress_pool::TestIngressPool;
    use ic_test_utilities::{
        registry::SubnetRecordBuilder,
        types::ids::{node_test_id, subnet_test_id},
    };
    use ic_types::*;
    use ic_types::{batch::*, consensus::dkg};
    use std::sync::{Arc, RwLock};
    #[test]
    fn test_block_maker() {
        let subnet_id = subnet_test_id(0);
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let node_ids = vec![
                node_test_id(0),
                node_test_id(1),
                node_test_id(3),
                node_test_id(4),
            ];
            let dkg_interval_length = 300;
            let Dependencies {
                mut pool,
                membership,
                registry,
                crypto,
                time_source,
                replica_config,
                state_manager,
                ..
            } = dependencies_with_subnet_params(
                pool_config.clone(),
                subnet_id,
                vec![
                    (
                        1,
                        SubnetRecordBuilder::from(&node_ids)
                            .with_dkg_interval_length(dkg_interval_length)
                            .build(),
                    ),
                    (
                        10,
                        SubnetRecordBuilder::from(&node_ids)
                            .with_dkg_interval_length(dkg_interval_length)
                            .build(),
                    ),
                ],
            );
            pool.advance_round_normal_operation_n(4);

            let payload_builder = MockPayloadBuilder::new();
            let dkg_pool = Arc::new(RwLock::new(ic_artifact_pool::dkg_pool::DkgPoolImpl::new(
                MetricsRegistry::new(),
            )));
            let certified_height = Height::from(1);
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(certified_height);

            let block_maker = BlockMaker::new(
                Arc::clone(&time_source) as Arc<_>,
                replica_config.clone(),
                Arc::clone(&registry) as Arc<dyn RegistryClient>,
                membership.clone(),
                crypto.clone(),
                Arc::new(payload_builder),
                dkg_pool.clone(),
                state_manager.clone(),
                MetricsRegistry::new(),
                no_op_logger(),
            );
            let ingress_pool = TestIngressPool::new(pool_config);

            // Check first block is created immediately because rank 1 has to wait.
            let run_block_maker = || {
                let reader = PoolReader::new(&pool);
                block_maker.on_state_change(&reader, &ingress_pool)
            };
            assert!(run_block_maker().is_none());

            // Check that block creation works properly.
            pool.advance_round_normal_operation_n(4);

            let mut payload_builder = MockPayloadBuilder::new();
            let start = pool.validated().block_proposal().get_highest().unwrap();
            let next_height = start.height().increment();
            let start_hash = start.content.get_hash();
            let expected_payloads = PoolReader::new(&pool)
                .get_payloads_from_height(certified_height.increment(), start.as_ref().clone());
            let matches_expected_payloads =
                move |payloads: &[(Height, Time, Payload)]| payloads == &*expected_payloads;
            let returned_payload =
                dkg::Payload::Dealings(dkg::Dealings::new_empty(Height::from(0)));
            let expected_context = ValidationContext {
                certified_height,
                registry_version: RegistryVersion::from(10),
                time: time_source.get_relative_time()
                    + get_block_maker_delay(
                        &no_op_logger(),
                        registry.as_ref(),
                        subnet_id,
                        RegistryVersion::from(10),
                        Rank(1),
                    )
                    .unwrap(),
            };
            let expected_block = Block::new(
                start_hash.clone(),
                Payload::new(ic_crypto::crypto_hash, returned_payload.into()),
                next_height,
                Rank(1),
                expected_context.clone(),
            );

            payload_builder
                .expect_get_payload()
                .withf(move |_, _, payloads, context| {
                    matches_expected_payloads(payloads) && context == &expected_context
                })
                .return_const(Ok(BatchPayload::default()));

            let pool_reader = PoolReader::new(&pool);
            let replica_config = ReplicaConfig {
                node_id: (0..4)
                    .map(node_test_id)
                    .find(|node_id| {
                        let h = pool_reader.get_notarized_height();
                        let prev_beacon = pool_reader.get_random_beacon(h).unwrap();
                        membership.get_block_maker_rank(h.increment(), &prev_beacon, *node_id)
                            == Ok(Some(Rank(1)))
                    })
                    .unwrap(),
                subnet_id: replica_config.subnet_id,
            };

            let block_maker = BlockMaker::new(
                Arc::clone(&time_source) as Arc<_>,
                replica_config,
                registry.clone(),
                membership,
                Arc::clone(&crypto) as Arc<_>,
                Arc::new(payload_builder),
                dkg_pool,
                state_manager,
                MetricsRegistry::new(),
                no_op_logger(),
            );
            let run_block_maker = || {
                let reader = PoolReader::new(&pool);
                block_maker.on_state_change(&reader, &ingress_pool)
            };

            // kick start another round
            assert!(run_block_maker().is_none());

            time_source
                .set_time(
                    time_source.get_relative_time()
                        + get_block_maker_delay(
                            &no_op_logger(),
                            registry.as_ref(),
                            subnet_id,
                            RegistryVersion::from(10),
                            Rank(1),
                        )
                        .unwrap(),
                )
                .unwrap();
            if let Some(proposal) = run_block_maker() {
                assert_eq!(proposal.as_ref(), &expected_block);
            } else {
                panic!("Expected a new block proposal");
            }

            // insert a rank 0 block for the current round
            let next_block = pool.make_next_block();
            // ensure that `make_next_block` creates a rank 0 block
            assert_eq!(next_block.rank(), Rank(0));
            pool.insert_validated(pool.make_next_block());

            let run_block_maker = || {
                let reader = PoolReader::new(&pool);
                block_maker.on_state_change(&reader, &ingress_pool)
            };

            // check that the block maker does not create a block, as a lower ranked block
            // is already available.
            assert!(run_block_maker().is_none());
        })
    }

    // We expect block maker to correctly detect version change and start
    // making only empty blocks.
    #[test]
    fn test_protocol_upgrade() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let dkg_interval_length = 3;
            let node_ids = [node_test_id(0)];
            let Dependencies {
                mut pool,
                registry,
                crypto,
                time_source,
                replica_config,
                state_manager,
                ..
            } = dependencies_with_subnet_params(
                pool_config.clone(),
                subnet_test_id(0),
                vec![
                    (
                        1,
                        SubnetRecordBuilder::from(&node_ids)
                            .with_dkg_interval_length(dkg_interval_length)
                            .build(),
                    ),
                    (
                        10,
                        SubnetRecordBuilder::from(&node_ids)
                            .with_dkg_interval_length(dkg_interval_length)
                            .with_replica_version("0xBEEF")
                            .build(),
                    ),
                ],
            );
            let ingress_pool = TestIngressPool::new(pool_config);

            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(Some(CryptoHashOfState::from(CryptoHash(Vec::new())))));
            let certified_height = Height::from(1);
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(certified_height);
            state_manager
                .get_mut()
                .expect_get_state_at()
                .return_const(Ok(ic_interfaces::state_manager::Labeled::new(
                    Height::new(0),
                    Arc::new(ic_test_utilities::state::get_initial_state(0, 0)),
                )));

            let mut payload_builder = MockPayloadBuilder::new();
            payload_builder
                .expect_get_payload()
                .return_const(Ok(BatchPayload::default()));
            let membership =
                Membership::new(pool.get_cache(), registry.clone(), replica_config.subnet_id);
            let membership = Arc::new(membership);

            let block_maker = BlockMaker::new(
                Arc::clone(&time_source) as Arc<_>,
                replica_config.clone(),
                Arc::clone(&registry) as Arc<dyn RegistryClient>,
                membership.clone(),
                crypto.clone(),
                Arc::new(payload_builder),
                Arc::new(RwLock::new(ic_artifact_pool::dkg_pool::DkgPoolImpl::new(
                    MetricsRegistry::new(),
                ))),
                state_manager.clone(),
                MetricsRegistry::new(),
                no_op_logger(),
            );

            // Skip the first DKG interval
            pool.advance_round_normal_operation_n(dkg_interval_length);

            let proposal = block_maker.on_state_change(&PoolReader::new(&pool), &ingress_pool);
            assert!(proposal.is_some());
            let mut proposal = proposal.unwrap();
            let block = proposal.content.as_mut();
            assert!(block.payload.is_summary());
            pool.advance_round_with_block(&proposal);
            pool.insert_validated(pool.make_catch_up_package(proposal.height()));

            // Skip the second DKG interval
            pool.advance_round_normal_operation_n(dkg_interval_length);
            assert_eq!(
                PoolReader::new(&pool).registry_version(Height::from(dkg_interval_length * 2)),
                Some(RegistryVersion::from(1))
            );

            // 2. Make CUP block at next start block

            // We do not anticipate payload builder to be called since we will be making
            // empty blocks (including the next CUP block).
            let mut payload_builder = MockPayloadBuilder::new();
            payload_builder
                .expect_get_payload()
                .return_const(Ok(BatchPayload::default()));

            let block_maker = BlockMaker::new(
                Arc::clone(&time_source) as Arc<_>,
                replica_config,
                Arc::clone(&registry) as Arc<dyn RegistryClient>,
                membership,
                crypto,
                Arc::new(payload_builder),
                Arc::new(RwLock::new(ic_artifact_pool::dkg_pool::DkgPoolImpl::new(
                    MetricsRegistry::new(),
                ))),
                state_manager,
                MetricsRegistry::new(),
                no_op_logger(),
            );

            // Check CUP block is made.
            let proposal = block_maker.on_state_change(&PoolReader::new(&pool), &ingress_pool);
            assert!(proposal.is_some());
            let cup_proposal = proposal.unwrap();
            let cup_height = cup_proposal.height();
            let block = cup_proposal.content.as_ref();
            assert!(block.payload.is_summary());
            assert_eq!(block.context.registry_version, RegistryVersion::from(10));

            // only notarized but not finalize this CUP block.
            pool.insert_validated(cup_proposal.clone());
            pool.insert_validated(pool.make_next_beacon());
            pool.notarize(&cup_proposal);

            // 3. Make one more block, payload builder should not have been called.
            let proposal = block_maker.on_state_change(&PoolReader::new(&pool), &ingress_pool);
            assert!(proposal.is_some());
            let proposal = proposal.unwrap();
            let block = proposal.content.as_ref();
            // blocks still uses default version, not the new version.
            assert_eq!(block.version(), &ReplicaVersion::default());
            // registry version 10 becomes effective.
            assert_eq!(
                PoolReader::new(&pool).registry_version(proposal.height()),
                Some(RegistryVersion::from(10))
            );

            // 4. finalize and try making another block, should not be able to.
            pool.finalize(&cup_proposal);
            let catch_up_package = pool.make_catch_up_package(cup_height);
            pool.insert_validated(catch_up_package);
            let proposal = block_maker.on_state_change(&PoolReader::new(&pool), &ingress_pool);
            assert!(proposal.is_none());
        })
    }
}
