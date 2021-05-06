use crate::IngressManager;
use ic_interfaces::{
    ingress_manager::IngressHandler,
    ingress_pool::{
        ChangeAction::{
            MoveToValidated, PurgeBelowExpiry, RemoveFromUnvalidated, RemoveFromValidated,
        },
        ChangeSet, IngressPool,
    },
};
use ic_logger::{debug, warn};
use ic_types::{
    artifact::{IngressMessageAttribute, IngressMessageId},
    ingress::IngressStatus,
    ingress::MAX_INGRESS_TTL,
    CountBytes,
};
use ic_validator::validate_request;

impl IngressHandler for IngressManager {
    // looks at the unvalidated ingress messages and
    // 1. either discards them
    // 2. or moves them to validated and starts advertising them
    #[allow(clippy::cognitive_complexity)]
    fn on_state_change(&self, pool: &dyn IngressPool) -> ChangeSet {
        // Skip on_state_change when ingress_message_setting is not available in
        // registry.
        let registry_version = self.registry_client.get_latest_version();
        let ingress_message_settings = match self.get_ingress_message_settings(registry_version) {
            Some(settings) => settings,
            None => {
                warn!(
                    self.log,
                    "Missing ingress_message_settings in registry version {}", registry_version
                );
                return ChangeSet::new();
            }
        };

        let _timer = self.metrics.ingress_handler_time.start_timer();
        let get_status = self.ingress_hist_reader.get_latest_status();

        // Do not run on_state_change if consensus_time is not initialized yet.
        let consensus_time = match self.consensus_pool_cache.consensus_time() {
            None => return ChangeSet::new(),
            Some(time) => time,
        };

        let mut change_set = Vec::new();

        // Purge only when consensus_time has changed.
        let mut last_purge_time = self.last_purge_time.write().unwrap();
        if consensus_time != *last_purge_time {
            *last_purge_time = consensus_time;
            change_set.push(PurgeBelowExpiry(consensus_time));
        }

        let expiry_range = consensus_time..=(consensus_time + MAX_INGRESS_TTL);
        for unvalidated_artifact in pool
            .unvalidated()
            .get_all_by_expiry_range(expiry_range.clone())
        {
            let ingress_object = &unvalidated_artifact.message;
            let ingress_message = &ingress_object.signed_ingress;
            let max_ingress_bytes_per_message =
                ingress_message_settings.max_ingress_bytes_per_message;
            // If the message is too large, consider the ingress message invalid
            let size = ingress_object.count_bytes();
            if size > max_ingress_bytes_per_message {
                warn!(
                    self.log,
                    "ingress_message_remove_unvalidated";
                    ingress_message.message_id => format!("{}", ingress_object.message_id),
                    ingress_message.reason => "message_too_large",
                    ingress_message.size => size as u64,
                );
                change_set.push(RemoveFromUnvalidated(IngressMessageId::from(
                    ingress_object,
                )));
                continue;
            }

            // Check status of the ingress message against IngressHistoryReader,
            // If Unknown, consider the ingress message valid
            let status = get_status(&ingress_object.message_id);
            if status != IngressStatus::Unknown {
                debug!(
                    self.log,
                    "ingress_message_remove_unvalidated";
                    ingress_message.message_id => format!("{}", ingress_object.message_id),
                    ingress_message.reason => format!("unexpected_status_{}", status.as_str()),
                );

                change_set.push(RemoveFromUnvalidated(IngressMessageId::from(
                    ingress_object,
                )));
                continue;
            }

            // Check signatures, remove from unvalidated if they can't be
            // verified, add to validated otherwise
            match validate_request(
                ingress_message.as_ref(),
                self.ingress_signature_crypto.as_ref(),
                consensus_time,
                registry_version,
            ) {
                Err(err) => {
                    debug!(
                        self.log,
                        "ingress_message_remove_unvalidated";
                        ingress_message.message_id => format!("{}", ingress_object.message_id),
                        ingress_message.reason => format!("auth_failure: {}", err),
                    );
                    change_set.push(RemoveFromUnvalidated(IngressMessageId::from(
                        ingress_object,
                    )));
                }
                Ok(()) => {
                    debug!(
                        self.log,
                        "ingress_message_insert_validated";
                        ingress_message.message_id => format!("{}", ingress_object.message_id),
                    );
                    let integrity_hash = ic_crypto::crypto_hash(ingress_message.binary()).get();
                    change_set.push(MoveToValidated((
                        IngressMessageId::from(ingress_object),
                        size,
                        IngressMessageAttribute::new(ingress_message),
                        integrity_hash,
                    )));
                }
            }
        }

        // Check validated messages and remove if they are not required anymore (i.e.
        // IngressHistoryReader returns status other than Unknown).
        for validated_artifact in pool.validated().get_all_by_expiry_range(expiry_range) {
            let ingress_object = &validated_artifact.msg;

            // Check status of the ingress message against IngressHistoryReader,
            // If Unknown, consider the ingress message valid
            let status = get_status(&ingress_object.message_id);
            if status != IngressStatus::Unknown {
                debug!(
                    self.log,
                    "ingress_message_remove_validated";
                    ingress_message.message_id => format!("{}", ingress_object.message_id),
                    ingress_message.reason => format!("{:?}", status),
                );
                change_set.push(RemoveFromValidated(IngressMessageId::from(ingress_object)));
            }
        }

        // Also include finalized messages that were requested to purge.
        let mut to_purge = self.messages_to_purge.write().unwrap();
        while let Some(message_ids) = to_purge.pop() {
            message_ids
                .into_iter()
                .for_each(|id| change_set.push(RemoveFromValidated(id)))
        }

        change_set
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::setup_with_params;
    use ic_interfaces::artifact_pool::UnvalidatedArtifact;
    use ic_interfaces::ingress_pool::{ChangeAction, MutableIngressPool};
    use ic_interfaces::state_manager::StateManager;
    use ic_interfaces::time_source::TimeSource;
    use ic_test_utilities::{
        consensus::MockConsensusCache,
        history::MockIngressHistory,
        mock_time,
        state_manager::FakeStateManager,
        types::ids::{canister_test_id, node_test_id, user_test_id},
        types::messages::SignedIngressBuilder,
        FastForwardTimeSource,
    };
    use ic_types::time::UNIX_EPOCH;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn test_ingress_on_state_change_valid() {
        let time_source = FastForwardTimeSource::new();
        let state_manager = FakeStateManager::new();
        let (_height, state) = state_manager.take_tip();
        let time = state.system_metadata().batch_time + Duration::from_secs(1);
        let mut consensus_pool_cache = MockConsensusCache::new();
        consensus_pool_cache
            .expect_consensus_time()
            .return_const(Some(time));
        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_latest_status()
            .returning(|| Box::new(|_| IngressStatus::Unknown {}));

        setup_with_params(
            Some(ingress_hist_reader),
            None,
            Some(Arc::new(consensus_pool_cache)),
            None,
            |ingress_manager, mut ingress_pool| {
                let ingress_message = SignedIngressBuilder::new()
                    .expiry_time(time + MAX_INGRESS_TTL)
                    .nonce(2)
                    .sign_for_randomly_generated_sender()
                    .build();
                let attribute = IngressMessageAttribute::new(&ingress_message);
                let message_id = IngressMessageId::from(&ingress_message);
                let timestamp = time_source.get_relative_time();
                let integrity_hash = ic_crypto::crypto_hash(ingress_message.binary()).get();

                ingress_pool.insert(UnvalidatedArtifact {
                    message: ingress_message.clone(),
                    peer_id: node_test_id(0),
                    timestamp,
                });
                let change_set = ingress_manager.on_state_change(&ingress_pool);
                let size = ingress_message.count_bytes();
                let expected_change_action =
                    ChangeAction::MoveToValidated((message_id, size, attribute, integrity_hash));
                assert!(change_set.contains(&expected_change_action));
            },
        )
    }

    #[tokio::test]
    async fn test_ingress_on_state_change_invalid() {
        let time_source = FastForwardTimeSource::new();
        let state_manager = FakeStateManager::new();
        let (_height, state) = state_manager.take_tip();
        let time = state.system_metadata().batch_time + Duration::from_secs(1);

        let mut consensus_pool_cache = MockConsensusCache::new();
        consensus_pool_cache
            .expect_consensus_time()
            .return_const(Some(time));

        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_latest_status()
            .returning(|| {
                Box::new(|_| IngressStatus::Received {
                    receiver: canister_test_id(0).get(),
                    user_id: user_test_id(0),
                    time: mock_time(),
                })
            });

        setup_with_params(
            Some(ingress_hist_reader),
            None,
            Some(Arc::new(consensus_pool_cache)),
            None,
            |ingress_manager, mut ingress_pool| {
                let ingress_message = SignedIngressBuilder::new()
                    .expiry_time(time + MAX_INGRESS_TTL)
                    .nonce(2)
                    .build();
                let message_id = IngressMessageId::from(&ingress_message);
                ingress_pool.insert(UnvalidatedArtifact {
                    message: ingress_message,
                    peer_id: node_test_id(0),
                    timestamp: time_source.get_relative_time(),
                });
                let change_set = ingress_manager.on_state_change(&ingress_pool);
                let expected_change_action = ChangeAction::RemoveFromUnvalidated(message_id);
                assert!(change_set.contains(&expected_change_action));
            },
        )
    }

    /// Verify that a message with an expiry time after MAX_INGRESS_TTL is
    /// removed from the unvalidated pool
    #[tokio::test]
    async fn test_ingress_on_state_change_invalid_expiry() {
        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_latest_status()
            .returning(|| Box::new(|_| IngressStatus::Unknown));

        let time_source = FastForwardTimeSource::new();
        let state_manager = FakeStateManager::new();
        let (_height, state) = state_manager.take_tip();
        let batch_time = state.system_metadata().batch_time + Duration::from_secs(1);

        let mut consensus_pool_cache = MockConsensusCache::new();
        consensus_pool_cache
            .expect_consensus_time()
            .return_const(Some(batch_time));

        setup_with_params(
            Some(ingress_hist_reader),
            None,
            Some(Arc::new(consensus_pool_cache)),
            None,
            |ingress_manager, mut ingress_pool| {
                // Message should expire at the current time, and should not be selected
                let ingress_message = SignedIngressBuilder::new()
                    .expiry_time(batch_time + MAX_INGRESS_TTL + Duration::from_nanos(1))
                    .nonce(2)
                    .build();
                ingress_pool.insert(UnvalidatedArtifact {
                    message: ingress_message,
                    peer_id: node_test_id(0),
                    timestamp: time_source.get_relative_time(),
                });
                let change_set = ingress_manager.on_state_change(&ingress_pool);
                // Since we changed to PurgeBelowExpiry insteads of invidivual removal,
                // It is enough to check if there is PurgeBelowExpiry, and nothing being
                // moved to validated.
                assert_eq!(change_set.len(), 1);
                let expected_action = PurgeBelowExpiry(batch_time);
                assert!(change_set.contains(&expected_action));
            },
        )
    }

    #[tokio::test]
    async fn test_ingress_on_state_change_remove_validated() {
        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_latest_status()
            .times(1)
            .returning(|| Box::new(|_| IngressStatus::Unknown));
        ingress_hist_reader
            .expect_get_latest_status()
            .times(1)
            .returning(|| {
                Box::new(|_| IngressStatus::Received {
                    receiver: canister_test_id(0).get(),
                    user_id: user_test_id(0),
                    time: mock_time(),
                })
            });

        let time_source = FastForwardTimeSource::new();
        let state_manager = FakeStateManager::new();
        let (_height, state) = state_manager.take_tip();
        let time = state.system_metadata().batch_time + Duration::from_secs(1);

        let mut consensus_pool_cache = MockConsensusCache::new();
        consensus_pool_cache
            .expect_consensus_time()
            .return_const(Some(time));

        setup_with_params(
            Some(ingress_hist_reader),
            None,
            Some(Arc::new(consensus_pool_cache)),
            None,
            |ingress_manager, mut ingress_pool| {
                let ingress_message = SignedIngressBuilder::new()
                    .expiry_time(time + MAX_INGRESS_TTL)
                    .nonce(2)
                    .sign_for_randomly_generated_sender()
                    .build();
                let message_id = IngressMessageId::from(&ingress_message);
                ingress_pool.insert(UnvalidatedArtifact {
                    message: ingress_message,
                    peer_id: node_test_id(0),
                    timestamp: time_source.get_relative_time(),
                });
                let change_set = ingress_manager.on_state_change(&ingress_pool);
                ingress_pool.apply_changeset(change_set);
                let change_set = ingress_manager.on_state_change(&ingress_pool);
                let expected_change_action = ChangeAction::RemoveFromValidated(message_id);
                assert!(change_set.contains(&expected_change_action));
            },
        )
    }

    #[tokio::test]
    async fn test_ingress_signature_verification() {
        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_latest_status()
            .returning(|| Box::new(|_| IngressStatus::Unknown));

        // Ensure that there is a state with a time of our choosing, so
        // we can select an appropriate expiry time for the message.
        // Furthermore, the time of choosing needs to be set to the current
        // time so that conversion to SignedIngress does not fail.
        let time_source = FastForwardTimeSource::new();
        let now = std::time::SystemTime::now();
        let since_epoch = now
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time wrapped around");
        let current_time = UNIX_EPOCH + since_epoch;
        let batch_time = current_time + Duration::from_secs(1);

        let mut consensus_pool_cache = MockConsensusCache::new();
        consensus_pool_cache
            .expect_consensus_time()
            .return_const(Some(batch_time));

        setup_with_params(
            Some(ingress_hist_reader),
            None,
            Some(Arc::new(consensus_pool_cache)),
            None,
            |ingress_manager, mut ingress_pool| {
                let good_msg = SignedIngressBuilder::new()
                    .expiry_time(current_time + MAX_INGRESS_TTL / 2)
                    .sign_for_randomly_generated_sender()
                    .build();
                let attribute = IngressMessageAttribute::new(&good_msg);
                let good_msg_integrity_hash = ic_crypto::crypto_hash(good_msg.binary()).get();
                let bad_msg = SignedIngressBuilder::new()
                    .expiry_time(current_time + MAX_INGRESS_TTL)
                    .sign_for_randomly_generated_sender()
                    .nonce(4)
                    .build();

                ingress_pool.insert(UnvalidatedArtifact {
                    message: good_msg.clone(),
                    peer_id: node_test_id(0),
                    timestamp: time_source.get_relative_time(),
                });
                ingress_pool.insert(UnvalidatedArtifact {
                    message: bad_msg.clone(),
                    peer_id: node_test_id(0),
                    timestamp: time_source.get_relative_time(),
                });

                let good_id = IngressMessageId::from(&good_msg);
                let bad_id = IngressMessageId::from(&bad_msg);
                let change_set = ingress_manager.on_state_change(&ingress_pool);
                let expected_change_action0 = PurgeBelowExpiry(batch_time);
                let expected_change_action1 = ChangeAction::MoveToValidated((
                    good_id,
                    good_msg.count_bytes(),
                    attribute,
                    good_msg_integrity_hash,
                ));
                let expected_change_action2 = ChangeAction::RemoveFromUnvalidated(bad_id);
                assert_eq!(change_set.len(), 3);
                assert!(change_set.contains(&expected_change_action0));
                assert!(change_set.contains(&expected_change_action1));
                assert!(change_set.contains(&expected_change_action2));
            },
        )
    }
}
