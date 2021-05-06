use ic_canonical_state::{Control, Visitor};
use ic_crypto_tree_hash::{HashTree, HashTreeBuilder, HashTreeBuilderImpl, Label};
use ic_replicated_state::ReplicatedState;

/// A visitor that constructs a hash tree by traversing a replicated
/// state.
#[derive(Default)]
pub struct HashingVisitor<T> {
    tree_hasher: T,
}

impl<T> Visitor for HashingVisitor<T>
where
    T: HashTreeBuilder,
{
    type Output = T;

    fn start_subtree(&mut self) -> Result<(), Self::Output> {
        self.tree_hasher.start_subtree();
        Ok(())
    }

    fn enter_edge(&mut self, label: &[u8]) -> Result<Control, Self::Output> {
        self.tree_hasher.new_edge(Label::from(label));
        Ok(Control::Continue)
    }

    fn end_subtree(&mut self) -> Result<(), Self::Output> {
        self.tree_hasher.finish_subtree();
        Ok(())
    }

    fn visit_num(&mut self, num: u64) -> Result<(), Self::Output> {
        self.tree_hasher.start_leaf();
        self.tree_hasher.write_leaf(&num.to_le_bytes()[..]);
        self.tree_hasher.finish_leaf();
        Ok(())
    }

    fn visit_blob(&mut self, blob: &[u8]) -> Result<(), Self::Output> {
        self.tree_hasher.start_leaf();
        self.tree_hasher.write_leaf(blob);
        self.tree_hasher.finish_leaf();
        Ok(())
    }

    fn finish(self) -> Self::Output {
        self.tree_hasher
    }
}

/// Compute the hash tree corresponding to the partial state.
pub fn hash_partial_state(state: &ReplicatedState) -> HashTree {
    ic_canonical_state::traverse_partial(state, HashingVisitor::<HashTreeBuilderImpl>::default())
        .into_hash_tree()
        .unwrap()
}

/// Compute the hash tree corresponding to the full replicated state.
pub fn hash_state(state: &ReplicatedState) -> HashTree {
    ic_canonical_state::traverse(state, HashingVisitor::<HashTreeBuilderImpl>::default())
        .into_hash_tree()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::metadata_state::Stream;
    use ic_replicated_state::{
        page_map::{PageDelta, PageIndex, PAGE_SIZE},
        ExecutionState, ExportedFunctions, Global, NumWasmPages, PageMap, ReplicatedState,
    };
    use ic_test_utilities::types::ids::{
        canister_test_id, message_test_id, subnet_test_id, user_test_id,
    };
    use ic_types::{
        xnet::{StreamIndex, StreamIndexedQueue},
        Cycles, ExecutionRound,
    };

    use hex::FromHex;
    use ic_base_types::NumSeconds;
    use ic_cow_state::CowMemoryManagerImpl;
    use ic_crypto_tree_hash::Digest;
    use ic_test_utilities::{state::new_canister_state, types::messages::ResponseBuilder};
    use ic_types::ingress::IngressStatus;
    use ic_types::messages::RequestOrResponse;
    use ic_wasm_types::BinaryEncodedWasm;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

    #[test]
    fn partial_hash_reflects_streams() {
        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            "NOT_USED".into(),
        );

        let hash_of_empty_state = hash_partial_state(&state);

        let mut streams = state.take_streams();
        streams.insert(
            subnet_test_id(5),
            Stream {
                messages: StreamIndexedQueue::with_begin(StreamIndex::new(4)),
                signals_end: StreamIndex::new(10),
            },
        );
        state.put_streams(streams);

        let hash_of_state_with_streams = hash_partial_state(&state);

        assert!(
            hash_of_empty_state != hash_of_state_with_streams,
            "Expected the hash tree of the empty state {:?} to different from the hash tree with streams {:?}",
            hash_of_empty_state, hash_of_state_with_streams
        );
    }

    #[test]
    fn partial_hash_detects_changes_in_streams() {
        use ic_replicated_state::metadata_state::Stream;
        use ic_types::xnet::{StreamIndex, StreamIndexedQueue};

        let mut state = ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            "NOT_USED".into(),
        );

        let stream = Stream {
            messages: StreamIndexedQueue::with_begin(StreamIndex::from(4)),
            signals_end: StreamIndex::new(10),
        };

        let mut streams = state.take_streams();
        streams.insert(subnet_test_id(5), stream);
        state.put_streams(streams);

        let hash_of_state_one = hash_partial_state(&state);

        let stream = Stream {
            messages: StreamIndexedQueue::with_begin(StreamIndex::from(14)),
            signals_end: StreamIndex::new(11),
        };
        let mut streams = state.take_streams();
        streams.insert(subnet_test_id(6), stream);
        state.put_streams(streams);

        let hash_of_state_two = hash_partial_state(&state);

        assert!(
            hash_of_state_one != hash_of_state_two,
            "Expected the hash tree of one stream {:?} to different from the hash tree with two streams {:?}",
            hash_of_state_one, hash_of_state_two
        );
    }

    #[test]
    fn test_backward_compatibility() {
        fn state_fixture(certification_version: u32) -> ReplicatedState {
            let mut state = ReplicatedState::new_rooted_at(
                subnet_test_id(1),
                SubnetType::Application,
                "NOT_USED".into(),
            );

            let canister_id = canister_test_id(2);
            let controller = user_test_id(24);
            let mut canister_state = new_canister_state(
                canister_id,
                controller.get(),
                INITIAL_CYCLES,
                NumSeconds::from(100_000),
            );
            let mut page_map = PageMap::default();
            page_map.update(PageDelta::from(
                &[(PageIndex::from(1), &vec![0u8; *PAGE_SIZE][..])][..],
            ));
            let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
            let wasm_binary = BinaryEncodedWasm::new(vec![]);
            let execution_state = ExecutionState {
                canister_root: "NOT_USED".into(),
                session_nonce: None,
                wasm_binary,
                page_map,
                exported_globals: vec![Global::I32(1)],
                heap_size: NumWasmPages::from(2),
                exports: ExportedFunctions::new(BTreeSet::new()),
                embedder_cache: None,
                last_executed_round: ExecutionRound::from(0),
                cow_mem_mgr: Arc::new(CowMemoryManagerImpl::open_readwrite(tmpdir.path().into())),
                mapped_state: None,
            };
            canister_state.execution_state = Some(execution_state);

            state.put_canister_state(canister_state);

            let mut stream = Stream {
                messages: StreamIndexedQueue::with_begin(StreamIndex::from(4)),
                signals_end: StreamIndex::new(10),
            };

            for _ in 1..6 {
                stream
                    .messages
                    .push(RequestOrResponse::Response(ResponseBuilder::new().build()));
            }

            let mut streams = state.take_streams();
            streams.insert(subnet_test_id(5), stream);
            state.put_streams(streams);

            for i in 1..6 {
                state.set_ingress_status(message_test_id(i), IngressStatus::Unknown);
            }

            state.metadata.certification_version = certification_version;

            state
        }

        fn assert_partial_state_hash_matches(certification_version: u32, expected_hash: &str) {
            let state = state_fixture(certification_version);

            assert_eq!(
                hash_partial_state(&state).digest(),
                &Digest::from(<[u8; 32]>::from_hex(expected_hash,).unwrap()),
                "Mismatched partial state hash computed according to certification version {}. \
                Perhaps you made a change that requires writing backward compatibility code?",
                certification_version
            );
        }

        // WARNING: IF THIS TEST FAILS IT IS LIKELY BECAUSE OF A CHANGE THAT BREAKS
        // BACKWARD COMPATIBILITY OF PARTIAL STATE HASHING. IF THAT IS THE CASE
        // PLEASE INCREMENT THE CERTIFICATION VERSION AND PROVIDE APPROPRIATE
        // BACKWARD COMPATIBILITY CODE FOR OLD CERTIFICATION VERSIONS THAT
        // NEED TO BE SUPPORTED.
        assert_partial_state_hash_matches(
            // certification_version
            0,
            // expected_hash
            "17F99A07189E1CCB2D33DC43354C823E77549D99EE848736D7017D2FF344482E",
        );
        assert_partial_state_hash_matches(
            // certification_version
            1,
            // expected_hash
            "00315DC9D438336FDA0E4C3FB496736E89351B08B5B2103E0827720E1020A3DF",
        );
    }
}
