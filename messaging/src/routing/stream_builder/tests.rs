use super::*;
use ic_base_types::NumSeconds;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::testing::CanisterStateTesting;
use ic_replicated_state::canister_state::QUEUE_INDEX_NONE;
use ic_replicated_state::testing::CanisterQueuesTesting;
use ic_replicated_state::{metadata_state::Streams, CanisterState, ReplicatedState, Stream};
use ic_test_utilities::{
    metrics::{
        fetch_histogram_stats, fetch_int_counter_vec, fetch_int_gauge_vec, metric_vec,
        nonzero_values, MetricVec,
    },
    state::new_canister_state,
    types::{
        ids::{canister_test_id, user_test_id, SUBNET_27, SUBNET_42},
        messages::RequestBuilder,
    },
    with_test_replica_logger,
};
use ic_types::{
    ic00::Method,
    messages::{CallbackId, Payload, RejectContext, Request, RequestOrResponse, Response},
    user_error::RejectCode,
    xnet::{StreamIndex, StreamIndexedQueue},
    CanisterId, Cycles, Funds, SubnetId, ICP,
};
use lazy_static::lazy_static;
use maplit::btreemap;
use std::collections::BTreeMap;

const LOCAL_SUBNET: SubnetId = SUBNET_27;
const REMOTE_SUBNET: SubnetId = SUBNET_42;

const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);

lazy_static! {
    static ref INITIAL_CYCLES: Cycles =
        CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
}

#[test]
fn reject_local_request() {
    with_test_replica_logger(|log| {
        let sender = canister_test_id(3);
        let receiver = canister_test_id(4);

        let (stream_builder, mut state, _) = new_fixture(&log);

        // A CanisterState to test on.
        let canister_id = canister_test_id(3);
        let mut canister_state = new_canister_state(
            canister_id,
            user_test_id(1).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );

        // With a reservation on an input queue.
        let payment = Cycles::from(100);
        let msg = generate_message_for_test(sender, receiver, "method".to_string(), payment);

        canister_state.push_output_request(msg.clone()).unwrap();
        canister_state.pop_canister_output(&msg.receiver).unwrap();

        let mut expected_canister_state = canister_state.clone();

        state.put_canister_state(canister_state);

        // Reject the message.
        let reject_message = "Reject response";
        stream_builder.reject_local_request(
            &mut state,
            msg.clone(),
            RejectCode::SysFatal,
            reject_message.to_string(),
        );

        // Which should result in a reject Response being enqueued onto the input queue.
        expected_canister_state
            .push_input(
                QUEUE_INDEX_NONE,
                Response {
                    originator: msg.sender,
                    respondent: msg.receiver,
                    originator_reply_callback: msg.sender_reply_callback,
                    refund: msg.payment,
                    response_payload: Payload::Reject(RejectContext {
                        code: RejectCode::SysFatal,
                        message: reject_message.to_string(),
                    }),
                }
                .into(),
            )
            .unwrap();

        assert_eq!(
            &expected_canister_state,
            state.canister_state(&canister_id).unwrap()
        );
    });
}

#[test]
fn reject_local_request_for_subnet() {
    with_test_replica_logger(|log| {
        let (stream_builder, mut state, _) = new_fixture(&log);

        // With a reservation on the subnet input queue.
        let payment = Cycles::from(100);
        let subnet_id = state.metadata.own_subnet_id;
        let subnet_id_as_canister_id = CanisterId::from(subnet_id);
        let msg = generate_message_for_test(
            subnet_id_as_canister_id,
            canister_test_id(0),
            "method".to_string(),
            payment,
        );

        state
            .subnet_queues
            .push_output_request(msg.clone())
            .unwrap();
        state
            .subnet_queues
            .pop_canister_output(&msg.receiver)
            .unwrap();

        let mut expected_subnet_queues = state.subnet_queues.clone();

        // Reject the message.
        let reject_message = "Reject response";
        stream_builder.reject_local_request(
            &mut state,
            msg.clone(),
            RejectCode::SysFatal,
            reject_message.to_string(),
        );

        // Which should result in a reject Response being enqueued onto the subnet
        // queue.
        expected_subnet_queues
            .push_input(
                QUEUE_INDEX_NONE,
                Response {
                    originator: msg.sender,
                    respondent: msg.receiver,
                    originator_reply_callback: msg.sender_reply_callback,
                    refund: msg.payment,
                    response_payload: Payload::Reject(RejectContext {
                        code: RejectCode::SysFatal,
                        message: reject_message.to_string(),
                    }),
                }
                .into(),
            )
            .unwrap();

        assert_eq!(&expected_subnet_queues, &state.subnet_queues,);
    });
}

// Tests that the OutputQueues are fully drained.
#[test]
fn build_streams_success() {
    with_test_replica_logger(|log| {
        let (stream_builder, mut provided_state, metrics_registry) = new_fixture(&log);
        provided_state.metadata.network_topology.routing_table = RoutingTable::new(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xfff) } => REMOTE_SUBNET,
        });
        let mut expected_state = provided_state.clone();

        let msgs = generate_messages_for_test(/* senders = */ 2, /* receivers = */ 2);

        // Set up the expected Stream from the messages.
        let expected_stream = Stream {
            messages: requests_into_queue(StreamIndex::from(0), msgs.clone()),
            ..Stream::default()
        };

        let mut expected_streams = BTreeMap::new();
        expected_streams.insert(REMOTE_SUBNET, expected_stream);

        // Set up the provided_canister_states and expected_canister_states.
        let provided_canister_states = generate_provided_canister_states(msgs.clone());
        let expected_canister_states = generate_expected_canister_states(msgs);

        // Establish the expected ReplicatedState that holds the expected_stream_state
        // and expected_canister_states
        expected_state.put_streams(expected_streams);
        expected_state.put_canister_states(expected_canister_states);
        // Establish that the provided_state has the provided_canister_states.
        provided_state.put_canister_states(provided_canister_states);

        let result_state = stream_builder.build_streams(provided_state);

        assert_eq!(result_state.canister_states, expected_state.canister_states);
        assert_eq!(result_state.metadata, expected_state.metadata);
        assert_eq!(result_state, expected_state);

        assert_routed_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_STATUS_SUCCESS),
                ],
                14,
            )]),
            &metrics_registry,
        );
        assert_eq!(14, fetch_routed_payload_count(&metrics_registry));
        assert_eq!(
            metric_vec(&[(&[(LABEL_DESTINATION, &REMOTE_SUBNET.to_string()),], 14,)]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_MESSAGES)
        );
    });
}

// Tests that messages between local canisters get routed.
#[test]
fn build_streams_local_canisters() {
    with_test_replica_logger(|log| {
        let (stream_builder, mut provided_state, metrics_registry) = new_fixture(&log);
        let mut expected_state = provided_state.clone();

        let msgs = generate_messages_for_test(/* senders = */ 2, /* receivers = */ 2);

        // The provided_canister_states contains the source canisters with outgoing
        // messages, but also the destination canisters of all messages.
        let mut provided_canister_states = generate_provided_canister_states(msgs.clone());
        for msg in &msgs {
            provided_canister_states
                .entry(msg.receiver)
                .or_insert_with(|| {
                    new_canister_state(
                        msg.receiver,
                        msg.sender.get(),
                        *INITIAL_CYCLES,
                        NumSeconds::from(100_000),
                    )
                });
        }

        // Establish that the provided_state has the provided_canister_states.
        provided_state.put_canister_states(provided_canister_states);

        // Ensure the routing table knows about the `LOCAL_SUBNET`.
        let routing_table = RoutingTable::new(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xfff) } => LOCAL_SUBNET,
        });
        provided_state.metadata.network_topology.routing_table = routing_table.clone();

        // Set up the expected Stream from the messages.
        let expected_stream = Stream {
            messages: requests_into_queue(StreamIndex::from(0), msgs.clone()),
            ..Stream::default()
        };

        // Set up the expected Stream
        let mut expected_stream_state = Streams::new();
        expected_stream_state.insert(LOCAL_SUBNET, expected_stream);

        // The expected_canister_states contains both the source canisters with consumed
        // messages, but also the destination canisters of all messages.
        let mut expected_canister_states = generate_expected_canister_states(msgs.clone());
        for msg in &msgs {
            expected_canister_states
                .entry(msg.receiver)
                .or_insert_with(|| {
                    new_canister_state(
                        msg.receiver,
                        msg.sender.get(),
                        *INITIAL_CYCLES,
                        NumSeconds::from(100_000),
                    )
                });
        }

        // Establish the expected ReplicatedState that holds the expected_stream_state
        // and expected_canister_states
        expected_state.put_streams(expected_stream_state);
        expected_state.put_canister_states(expected_canister_states);

        expected_state.metadata.network_topology.routing_table = routing_table;

        let result_state = stream_builder.build_streams(provided_state);

        assert_eq!(result_state.canister_states, expected_state.canister_states);
        assert_eq!(result_state.metadata, expected_state.metadata);
        assert_eq!(result_state, expected_state);

        assert_routed_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_STATUS_SUCCESS),
                ],
                14,
            )]),
            &metrics_registry,
        );
        assert_eq!(14, fetch_routed_payload_count(&metrics_registry));
        assert_eq!(
            metric_vec(&[(&[(LABEL_DESTINATION, &LOCAL_SUBNET.to_string()),], 14,)]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_MESSAGES)
        );
    });
}

// Tests that messages addressed to canisters not mapped to a known subnet
// result in reject Responses.
#[test]
fn build_streams_reject_response_on_unknown_destination_subnet() {
    with_test_replica_logger(|log| {
        let msgs = generate_messages_for_test(/* senders = */ 2, /* receivers = */ 2);

        let (stream_builder, mut provided_state, metrics_registry) = new_fixture(&log);
        let mut expected_state = provided_state.clone();

        // Set up the provided_canister_states and expected_canister_states.
        let provided_canister_states = generate_provided_canister_states(msgs.clone());
        let expected_canister_states = generate_expected_canister_states(msgs.clone());

        // Establish that the provided_state has the provided_canister_states.
        provided_state.put_canister_states(provided_canister_states);

        // Establish the expected ReplicatedState that holds the expected_stream_state
        // and expected_canister_states
        // expected_state.put_stream_state(expected_stream_state);
        expected_state.put_canister_states(expected_canister_states);

        // Build up the expected stream: one reject Response for each request.
        for msg in msgs {
            let receiver = msg.receiver;
            stream_builder.reject_local_request(
                &mut expected_state,
                msg,
                RejectCode::DestinationInvalid,
                format!("Canister {} does not exist", receiver),
            );
        }

        let result_state = stream_builder.build_streams(provided_state);

        assert_eq!(result_state.canister_states, expected_state.canister_states);
        assert_eq!(result_state.metadata, expected_state.metadata);
        assert_eq!(result_state, expected_state);

        assert_routed_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_STATUS_CANISTER_NOT_FOUND),
                ],
                14,
            )]),
            &metrics_registry,
        );
        assert_eq!(0, fetch_routed_payload_count(&metrics_registry));
        assert_eq!(
            btreemap! {},
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_MESSAGES)
        );
    });
}

#[test]
fn build_streams_with_messages_targeted_to_other_subnets() {
    with_test_replica_logger(|log| {
        let msgs = vec![generate_message_for_test(
            canister_test_id(0),
            CanisterId::from(REMOTE_SUBNET),
            Method::CanisterStatus.to_string(),
            Cycles::new(0),
        )];

        let (stream_builder, mut provided_state, metrics_registry) = new_fixture(&log);

        // Ensure the routing table knows about the `REMOTE_SUBNET`.
        provided_state.metadata.network_topology.routing_table = RoutingTable::new(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xfff) } => REMOTE_SUBNET,
        });
        let mut expected_state = provided_state.clone();

        // Set up the expected Stream from the messages.
        let expected_stream = Stream {
            messages: requests_into_queue(StreamIndex::from(0), msgs.clone()),
            ..Stream::default()
        };

        let mut expected_streams = BTreeMap::new();
        expected_streams.insert(REMOTE_SUBNET, expected_stream);

        // Set up the provided_canister_states and expected_canister_states.
        let provided_canister_states = generate_provided_canister_states(msgs.clone());
        let expected_canister_states = generate_expected_canister_states(msgs);

        // Establish the expected ReplicatedState that holds the expected_stream_state
        // and expected_canister_states
        expected_state.put_streams(expected_streams);
        expected_state.put_canister_states(expected_canister_states);
        // Establish that the provided_state has the provided_canister_states.
        provided_state.put_canister_states(provided_canister_states);

        let result_state = stream_builder.build_streams(provided_state);

        assert_eq!(result_state.canister_states, expected_state.canister_states);
        assert_eq!(result_state.metadata, expected_state.metadata);
        assert_eq!(result_state, expected_state);

        assert_routed_messages_eq(
            metric_vec(&[(
                &[
                    (LABEL_TYPE, LABEL_VALUE_TYPE_REQUEST),
                    (LABEL_STATUS, LABEL_VALUE_STATUS_SUCCESS),
                ],
                1,
            )]),
            &metrics_registry,
        );
        assert_eq!(1, fetch_routed_payload_count(&metrics_registry));
        assert_eq!(
            metric_vec(&[(&[(LABEL_DESTINATION, &REMOTE_SUBNET.to_string()),], 1)]),
            fetch_int_gauge_vec(&metrics_registry, METRIC_STREAM_MESSAGES)
        );
    });
}

/// Sets up the `StreamHandlerImpl`, `ReplicatedState` and `Metricsregistry` to
/// be used by a test.
fn new_fixture(log: &ReplicaLogger) -> (StreamBuilderImpl, ReplicatedState, MetricsRegistry) {
    let state =
        ReplicatedState::new_rooted_at(LOCAL_SUBNET, SubnetType::Application, "NOT_USED".into());
    let metrics_registry = MetricsRegistry::new();
    let stream_handler = StreamBuilderImpl::new(
        LOCAL_SUBNET,
        &metrics_registry,
        Arc::new(Mutex::new(LatencyMetrics::new_time_in_stream(
            &metrics_registry,
        ))),
        log.clone(),
    );

    (stream_handler, state, metrics_registry)
}

fn requests_into_queue(
    start: StreamIndex,
    requests: Vec<Request>,
) -> StreamIndexedQueue<RequestOrResponse> {
    let mut queue = StreamIndexedQueue::with_begin(start);
    for request in requests {
        queue.push(RequestOrResponse::Request(request))
    }
    queue
}

// Generates a collection of messages for test purposes based on the number of
// canisters that should send/receive messages.
fn generate_messages_for_test(senders: u64, receivers: u64) -> Vec<Request> {
    let mut messages = Vec::new();
    for snd in 3..(3 + senders) {
        let sender = canister_test_id(snd);
        let payment = Cycles::from(100);
        for rcv in 700..(700 + receivers) {
            let receiver = canister_test_id(rcv);
            for i in snd..2 * snd {
                messages.push(generate_message_for_test(
                    sender,
                    receiver,
                    format!("req_{}_{}_{}", snd, rcv, i),
                    payment,
                ));
            }
        }
    }
    messages
}

fn generate_message_for_test(
    sender: CanisterId,
    receiver: CanisterId,
    method_name: String,
    payment: Cycles,
) -> Request {
    RequestBuilder::default()
        .sender(sender)
        .receiver(receiver)
        .method_name(method_name)
        .payment(Funds::new(payment, ICP::zero()))
        .sender_reply_callback(CallbackId::from(999))
        .build()
}

// Generates a `BTreeMap` of provided `CanisterStates`, with the given messages
// in output queues.
fn generate_provided_canister_states(msgs: Vec<Request>) -> BTreeMap<CanisterId, CanisterState> {
    let mut provided_canister_states = BTreeMap::<CanisterId, CanisterState>::new();

    for msg in msgs {
        let provided_canister_state =
            provided_canister_states
                .entry(msg.sender)
                .or_insert_with(|| {
                    new_canister_state(
                        msg.sender,
                        msg.sender.get(),
                        *INITIAL_CYCLES,
                        NumSeconds::from(100_000),
                    )
                });
        provided_canister_state.push_output_request(msg).unwrap();
    }

    provided_canister_states
}

// Generates a `BTreeMap` of expected `CanisterStates`, after the given messages
// have been popped from the output queues.
fn generate_expected_canister_states(msgs: Vec<Request>) -> BTreeMap<CanisterId, CanisterState> {
    let mut expected_canister_states = BTreeMap::<CanisterId, CanisterState>::new();

    for msg in msgs {
        let expected_canister_state =
            expected_canister_states
                .entry(msg.sender)
                .or_insert_with(|| {
                    new_canister_state(
                        msg.sender,
                        msg.sender.get(),
                        *INITIAL_CYCLES,
                        NumSeconds::from(100_000),
                    )
                });

        // The output_queue can only be constructed with index = 0, so push and pop
        // each message to bump its next queue index.
        let receiver = msg.receiver;
        expected_canister_state.push_output_request(msg).unwrap();
        expected_canister_state
            .pop_canister_output(&receiver)
            .unwrap();
    }

    expected_canister_states
}

/// Asserts that the values of the `METRIC_ROUTED_MESSAGES` metric
/// match for the given statuses and are zero for all other statuses.
fn assert_routed_messages_eq(expected: MetricVec<u64>, metrics_registry: &MetricsRegistry) {
    assert_eq!(
        expected,
        nonzero_values(fetch_int_counter_vec(
            metrics_registry,
            METRIC_ROUTED_MESSAGES
        ))
    );
}

/// Retrieves the `METRIC_ROUTED_PAYLOAD_SIZES` histogram's count.
fn fetch_routed_payload_count(metrics_registry: &MetricsRegistry) -> u64 {
    fetch_histogram_stats(metrics_registry, METRIC_ROUTED_PAYLOAD_SIZES)
        .unwrap_or_else(|| panic!("Histogram not found: {}", METRIC_ROUTED_PAYLOAD_SIZES))
        .count
}
