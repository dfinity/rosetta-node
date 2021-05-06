use super::*;
use ic_base_types::NumSeconds;
use ic_config::subnet_config::SchedulerConfig;
use ic_interfaces::execution_environment::{EarlyResult, ExecuteMessageResult};
use ic_interfaces::messages::CanisterInputMessage;
use ic_logger::replica_logger::no_op_logger;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_replicated_state::{
    canister_state::testing::CanisterStateTesting, CallOrigin, ExportedFunctions, NumWasmPages,
};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder,
    execution_environment::MockExecutionEnvironment,
    history::MockIngressHistory,
    metrics::{fetch_histogram_stats, fetch_int_counter, fetch_int_gauge_vec, metric_vec},
    mock_time,
    state::{
        arb_replicated_state, get_initial_state, get_running_canister, get_stopped_canister,
        get_stopping_canister, initial_execution_state, new_canister_state, CanisterStateBuilder,
    },
    types::{
        ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id},
        messages::{RequestBuilder, SignedIngressBuilder},
    },
    with_test_replica_logger,
};
use ic_types::{
    ingress::WasmResult,
    methods::WasmMethod,
    time::UNIX_EPOCH,
    user_error::{ErrorCode, UserError},
    ComputeAllocation, Cycles, NumBytes,
};
use lazy_static::lazy_static;
use maplit::btreemap;
use mockall::predicate::always;
use proptest::prelude::*;
use std::cmp::min;
use std::collections::{BTreeSet, HashMap};
use std::{convert::TryFrom, path::PathBuf, time::Duration};

const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);
const MAX_INSTRUCTIONS_PER_MESSAGE: NumInstructions = NumInstructions::new(1 << 30);
const LAST_ROUND_MAX: u64 = 100;
const MAX_SUBNET_AVAILABLE_MEMORY: NumBytes = NumBytes::new(std::u64::MAX);

lazy_static! {
    static ref INITIAL_CYCLES: Cycles =
        CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
}

fn assert_floats_are_equal(val0: f64, val1: f64) {
    if val0 > val1 {
        assert!(val0 - val1 < 0.1);
    } else {
        assert!(val1 - val0 < 0.1);
    }
}

#[test]
fn can_fully_execute_canisters_with_one_input_message_each() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(1 << 30),
            max_instructions_per_message: num_instructions_consumed_per_msg
                + NumInstructions::from(1),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 1,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        3,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(3);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.ingress_queue_size(), 0);
                assert_eq!(
                    canister_state.scheduler_state.last_full_execution_round,
                    round
                );
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .skipped_round_due_to_no_messages,
                    0
                );
                assert_eq!(canister_state.system_state.canister_metrics.executed, 1);
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .interruped_during_execution,
                    0
                );
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn stops_executing_messages_when_heap_delta_capacity_reached() {
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            subnet_heap_delta_capacity: NumBytes::from(10),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 2,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        2,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(4096),
    ));
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(2));

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for canister_state in state.canisters_iter_mut() {
                assert_eq!(canister_state.ingress_queue_size(), 0);
            }

            for canister_state in state.canisters_iter_mut() {
                canister_state.push_ingress(
                    SignedIngressBuilder::new()
                        .canister_id(canister_state.canister_id())
                        .build()
                        .into(),
                );
            }
            let round = ExecutionRound::from(2);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );

            for canister_state in state.canisters_iter_mut() {
                assert_eq!(canister_state.ingress_queue_size(), 1);
            }

            assert_eq!(
                scheduler
                    .metrics
                    .round_skipped_due_to_current_heap_delta_above_limit
                    .get(),
                1
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

/// This test ensures that inner_loop() breaks out of the loop when the loop did
/// not consume any instructions.
#[test]
fn inner_loop_stops_when_no_instructions_consumed() {
    // Create a canister with 1 input message that consumes half of
    // max_instructions_per_round. This message is executed in the first
    // iteration of the loop and in the second iteration of the loop, no
    // instructions are consumed.
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::new(100),
            max_instructions_per_message: NumInstructions::new(50),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 1,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        1,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(4096),
    ));
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(1));

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for canister_state in state.canisters_iter_mut() {
                assert_eq!(canister_state.ingress_queue_size(), 0);
            }
            assert_eq!(scheduler.metrics.execute_round_called.get(), 1);
            assert_eq!(
                scheduler
                    .metrics
                    .inner_round_loop_consumed_max_instructions
                    .get(),
                0
            );
            assert_eq!(
                scheduler
                    .metrics
                    .inner_loop_consumed_non_zero_instructions_count
                    .get(),
                1
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

/// This test ensures that inner_loop() breaks out of the loop when the loop
/// consumes max_instructions_per_round.
#[test]
fn inner_loop_stops_when_max_instructions_per_round_consumed() {
    // Create a canister with 3 input messages. 2 of them consume all of
    // max_instructions_per_round. The 2 messages are executed in the first
    // iteration of the loop and then the loop breaks.
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::new(100),
            max_instructions_per_message: NumInstructions::new(50),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 3,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        2,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(4096),
    ));
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(2));

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for canister_state in state.canisters_iter_mut() {
                assert_eq!(canister_state.ingress_queue_size(), 1);
            }
            assert_eq!(scheduler.metrics.execute_round_called.get(), 1);
            assert_eq!(
                scheduler
                    .metrics
                    .inner_round_loop_consumed_max_instructions
                    .get(),
                1
            );
            assert_eq!(
                scheduler
                    .metrics
                    .inner_loop_consumed_non_zero_instructions_count
                    .get(),
                1
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

/// A test to ensure that there are multiple iterations of the loop in
/// inner_round().
#[test]
fn test_multiple_interations_of_inner_loop() {
    // Create two canisters on the same subnet. In the first iteration, the
    // first sends a message to the second. In the second iteration, the second
    // executes the received message.
    let mut exec_env = MockExecutionEnvironment::new();
    exec_env
        .expect_subnet_available_memory()
        .times(..)
        .returning(move |_| NumBytes::from(10));
    exec_env
        .expect_execute_canister_message()
        .times(2)
        .returning(move |mut canister, _, msg, _, _, _, _| {
            let canister0 = canister_test_id(0);
            let canister1 = canister_test_id(1);
            let canister_id = canister.canister_id();
            if canister_id == canister0 {
                canister
                    .push_output_request(
                        RequestBuilder::new()
                            .sender(canister0)
                            .receiver(canister1)
                            .build(),
                    )
                    .unwrap();
                if let CanisterInputMessage::Ingress(msg) = msg {
                    EarlyResult::new(ExecuteMessageResult {
                        canister: canister.clone(),
                        num_instructions_left: NumInstructions::new(0),
                        ingress_status: Some((
                            msg.message_id,
                            IngressStatus::Processing {
                                receiver: canister.canister_id().get(),
                                user_id: user_test_id(0),
                                time: mock_time(),
                            },
                        )),
                        heap_delta: NumBytes::from(1),
                    })
                } else {
                    unreachable!("Only ingress messages are expected.")
                }
            } else if canister_id == canister1 {
                EarlyResult::new(ExecuteMessageResult {
                    canister,
                    num_instructions_left: NumInstructions::from(0),
                    ingress_status: None,
                    heap_delta: NumBytes::from(1),
                })
            } else {
                unreachable!(
                    "message should be directed to {} or {}",
                    canister0, canister1
                );
            }
        });
    let exec_env = Arc::new(exec_env);
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(1));
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::new(200),
            max_instructions_per_message: NumInstructions::new(50),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 0,
    };

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            let routing_table = RoutingTable::new(btreemap! {
                CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => scheduler.own_subnet_id,
            });
            state.metadata.network_topology.routing_table = routing_table;

            let canister_id = canister_test_id(0);
            state
                .canister_state_mut(&canister_id)
                .unwrap()
                .push_ingress(
                    SignedIngressBuilder::new()
                        .canister_id(canister_id)
                        .build()
                        .into(),
                );

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for canister_state in state.canisters_iter_mut() {
                assert_eq!(canister_state.ingress_queue_size(), 0);
            }
            assert_eq!(scheduler.metrics.execute_round_called.get(), 1);
            assert_eq!(
                scheduler
                    .metrics
                    .inner_round_loop_consumed_max_instructions
                    .get(),
                0
            );
            assert_eq!(
                scheduler
                    .metrics
                    .inner_loop_consumed_non_zero_instructions_count
                    .get(),
                2
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn validate_consumed_instructions_metric() {
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_message: NumInstructions::from(50),
            max_instructions_per_round: NumInstructions::from(400),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 1,
        message_num_per_canister: 2,
    };
    let exec_env = Arc::new(default_exec_env_mock(
        &scheduler_test_fixture,
        2,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(4096),
    ));
    let ingress_history_writer = Arc::new(default_ingress_history_writer_mock(2));

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for canister_state in state.canisters_iter_mut() {
                assert_eq!(canister_state.ingress_queue_size(), 0);
            }
            assert_eq!(
                scheduler
                    .metrics
                    .instructions_consumed_per_round
                    .get_sample_count(),
                2
            );
            assert_floats_are_equal(
                scheduler
                    .metrics
                    .instructions_consumed_per_round
                    .get_sample_sum(),
                100_f64,
            );
            assert_eq!(
                scheduler
                    .metrics
                    .instructions_consumed_per_message
                    .get_sample_count(),
                2
            );
            assert_floats_are_equal(
                scheduler
                    .metrics
                    .instructions_consumed_per_message
                    .get_sample_sum(),
                100_f64,
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn dont_execute_any_canisters_if_not_enough_cycles() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: num_instructions_consumed_per_msg
                - NumInstructions::from(1),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 1,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        0,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(0);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.ingress_queue_size(), 1);
                assert_eq!(
                    canister_state.scheduler_state.last_full_execution_round,
                    ExecutionRound::from(0)
                );
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .skipped_round_due_to_no_messages,
                    0
                );
                assert_eq!(canister_state.system_state.canister_metrics.executed, 0);
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .interruped_during_execution,
                    0
                );
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

// Creates an initial state with some canisters that contain very few cycles.
// Ensures that after `execute_round` returns, the canisters have been
// uninstalled.
#[test]
fn canisters_with_insufficient_cycles_are_uninstalled() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let num_canisters = 3;
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: num_instructions_consumed_per_msg
                - NumInstructions::from(1),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: num_canisters,
        message_num_per_canister: 0,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        0,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(0);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(0, 0);
            // Set the cycles balance of all canisters to small enough amount so
            // that they cannot pay for their resource usage but also do not set
            // it to 0 as that is a simpler test.
            for i in 0..num_canisters {
                let canister_state = CanisterStateBuilder::new()
                    .with_canister_id(canister_test_id(i))
                    .with_cycles(Cycles::from(100))
                    .with_wasm(vec![1; 1 << 30])
                    .build();
                state.put_canister_state(canister_state);
            }
            state.metadata.batch_time = UNIX_EPOCH + Duration::from_secs(2);

            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH + Duration::from_secs(1),
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for (_, canister) in state.canister_states.iter() {
                assert!(canister.execution_state.is_none());
                assert_eq!(
                    canister.scheduler_state.compute_allocation,
                    ComputeAllocation::zero()
                );
                assert!(canister.system_state.memory_allocation.is_none());
            }
            assert_eq!(
                scheduler
                    .metrics
                    .num_canisters_uninstalled_out_of_cycles
                    .get() as u64,
                num_canisters
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn can_execute_messages_with_just_enough_cycles() {
    // In this test we have 3 canisters with 1 message each and the maximum allowed
    // round cycles is 3 times the instructions consumed by each message. Thus, we
    // expect that we have just enough instructions to execute all messages.
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: num_instructions_consumed_per_msg * 3,
            max_instructions_per_message: num_instructions_consumed_per_msg,
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 1,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        3,
        scheduler_test_fixture
            .scheduler_config
            .max_instructions_per_message,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(3);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.ingress_queue_size(), 0);
                assert_eq!(
                    canister_state.scheduler_state.last_full_execution_round,
                    ExecutionRound::from(1)
                );
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .skipped_round_due_to_no_messages,
                    0
                );
                assert_eq!(canister_state.system_state.canister_metrics.executed, 1);
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .interruped_during_execution,
                    0
                );
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn execute_only_canisters_with_messages() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(1 << 30),
            max_instructions_per_message: num_instructions_consumed_per_msg
                + NumInstructions::from(1),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 1,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        3,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(3);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            state.put_canister_state(new_canister_state(
                canister_test_id(3),
                user_test_id(24).get(),
                *INITIAL_CYCLES,
                NumSeconds::from(100_000),
            ));
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.ingress_queue_size(), 0);
                // We won't update `last_full_execution_round` for the canister without any
                // input messages.
                if canister_state.canister_id() == canister_test_id(3) {
                    assert_eq!(
                        canister_state.scheduler_state.last_full_execution_round,
                        ExecutionRound::from(0)
                    );
                    assert_eq!(
                        canister_state
                            .system_state
                            .canister_metrics
                            .skipped_round_due_to_no_messages,
                        1
                    );
                } else {
                    assert_eq!(
                        canister_state.scheduler_state.last_full_execution_round,
                        ExecutionRound::from(1)
                    );
                    assert_eq!(
                        canister_state
                            .system_state
                            .canister_metrics
                            .skipped_round_due_to_no_messages,
                        0
                    );
                    assert_eq!(canister_state.system_state.canister_metrics.executed, 1);
                    assert_eq!(
                        canister_state
                            .system_state
                            .canister_metrics
                            .interruped_during_execution,
                        0
                    );
                }
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn can_fully_execute_multiple_canisters_with_multiple_messages_each() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(1 << 30),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 5,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        15,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(15);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            let round = ExecutionRound::from(4);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.ingress_queue_size(), 0);
                assert_eq!(
                    canister_state.scheduler_state.last_full_execution_round,
                    round
                );
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .skipped_round_due_to_no_messages,
                    0
                );
                assert_eq!(canister_state.system_state.canister_metrics.executed, 1);
                assert_eq!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .interruped_during_execution,
                    0
                );
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn can_fully_execute_canisters_deterministically_until_out_of_cycles() {
    // In this test we have 5 canisters with 10 input messages each. The maximum
    // instructions that an execution round can consume is 51 (per core). Each
    // message consumes 5 instructions, therefore we can execute fully 1
    // canister per core in one round.
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(51),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 5,
        message_num_per_canister: 10,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        20,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(20);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for canister_state in state.canisters_iter() {
                let id = &canister_state.canister_id();
                if id == &canister_test_id(0) || id == &canister_test_id(1) {
                    assert_eq!(canister_state.ingress_queue_size(), 0);
                    assert_eq!(
                        canister_state.scheduler_state.last_full_execution_round,
                        round
                    );
                } else {
                    assert_eq!(canister_state.ingress_queue_size(), 10);
                    assert_eq!(
                        canister_state.scheduler_state.last_full_execution_round,
                        ExecutionRound::from(0)
                    );
                }
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn can_execute_messages_from_multiple_canisters_until_out_of_instructions() {
    // In this test we have 2 canisters with 10 input messages each. The maximum
    // instructions that an execution round can consume is 18 (per core). Each core
    // executes 1 canister until we don't have any instructions left anymore. Since
    // each message consumes 5 instructions, we can execute 3 messages from each
    // canister.
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 2,
            max_instructions_per_round: NumInstructions::from(18),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 2,
        message_num_per_canister: 10,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        6,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(6);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.ingress_queue_size(), 7);
                assert_ne!(
                    canister_state
                        .system_state
                        .canister_metrics
                        .interruped_during_execution,
                    0
                );
                assert_eq!(
                    canister_state.scheduler_state.last_full_execution_round,
                    round
                );
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
// This test verifies that we can successfully record metrics from a single
// scheduler thread. We feed the `thread` with a single canister which has 3
// ingress messages. The first one runs out of instructions while the other two
// are executed successfully.
fn can_record_metrics_single_scheduler_thread() {
    ic_test_utilities::with_test_replica_logger(|log| {
        let max_instructions_per_message = NumInstructions::from(5);
        let scheduler_config = SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(18),
            max_instructions_per_message,
            ..SchedulerConfig::application_subnet()
        };

        let mut exec_env = MockExecutionEnvironment::new();
        let canister_id = canister_test_id(0);

        exec_env
            .expect_execute_canister_message()
            .times(1)
            .returning(move |canister, _, _, _, _, _, _| {
                EarlyResult::new(ExecuteMessageResult {
                    canister,
                    num_instructions_left: NumInstructions::from(0),
                    ingress_status: Some((
                        message_test_id(0),
                        IngressStatus::Failed {
                            receiver: canister_id.get(),
                            user_id: user_test_id(0),
                            error: UserError::new(ErrorCode::CanisterOutOfCycles, "".to_string()),
                            time: mock_time(),
                        },
                    )),
                    heap_delta: NumBytes::from(0),
                })
            });

        for message_id in 1..3 {
            exec_env
                .expect_execute_canister_message()
                .times(1)
                .returning(move |canister, _, _, _, _, _, _| {
                    EarlyResult::new(ExecuteMessageResult {
                        canister,
                        num_instructions_left: NumInstructions::from(1),
                        ingress_status: Some((
                            message_test_id(message_id),
                            IngressStatus::Completed {
                                receiver: canister_id.get(),
                                user_id: user_test_id(0),
                                result: WasmResult::Reply(vec![]),
                                time: mock_time(),
                            },
                        )),
                        heap_delta: NumBytes::from(0),
                    })
                });
        }

        let mut canister_state = new_canister_state(
            canister_id,
            user_test_id(24).get(),
            *INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        let mut exports = BTreeSet::new();
        exports.insert(WasmMethod::Update("write".to_string()));
        exports.insert(WasmMethod::Query("read".to_string()));
        let mut execution_state = initial_execution_state(None);
        execution_state.exports = ExportedFunctions::new(exports);
        canister_state.execution_state = Some(execution_state);

        for nonce in 0..3 {
            canister_state.push_ingress(
                SignedIngressBuilder::new()
                    .canister_id(canister_id)
                    .method_name("write".to_string())
                    .nonce(nonce)
                    .build()
                    .into(),
            );
        }

        let metrics_registry = MetricsRegistry::new();
        let metrics = Arc::new(SchedulerMetrics::new(&metrics_registry));

        let exec_round = ExecRound::new(
            vec![vec![canister_state]],
            scheduler_config,
            ExecutionRound::from(0),
            &metrics,
            &log,
            MAX_SUBNET_AVAILABLE_MEMORY,
        );
        let _ = exec_round.execute(
            &exec_env,
            mock_time(),
            Arc::new(RoutingTable::default()),
            Arc::new(BTreeMap::new()),
        );

        let cycles_consumed_per_message_stats = fetch_histogram_stats(
            &metrics_registry,
            "scheduler_instructions_consumed_per_message",
        )
        .unwrap();
        let cycles_consumed_per_round_stats = fetch_histogram_stats(
            &metrics_registry,
            "scheduler_instructions_consumed_per_round",
        )
        .unwrap();
        let msg_execution_duration_stats = fetch_histogram_stats(
            &metrics_registry,
            "scheduler_message_execution_duration_seconds",
        )
        .unwrap();
        let canister_messages_where_cycles_were_charged = fetch_int_counter(
            &metrics_registry,
            "scheduler_canister_messages_where_cycles_were_charged",
        )
        .unwrap();

        assert_eq!(msg_execution_duration_stats.count, 3);
        assert_eq!(cycles_consumed_per_message_stats.count, 3);
        assert_eq!(cycles_consumed_per_round_stats.sum as i64, 13);
        assert_eq!(canister_messages_where_cycles_were_charged, 3);
    });
}

#[test]
fn can_record_metrics_for_a_round() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(51),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 5,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        10,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(10);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    fn update_canister_allocation(
        mut state: ReplicatedState,
        canister_id: CanisterId,
        allocation: ComputeAllocation,
    ) -> ReplicatedState {
        let mut canister_state = state.canister_state(&canister_id).unwrap().clone();
        canister_state.scheduler_state.compute_allocation = allocation;
        state.put_canister_state(canister_state);
        state
    }

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = get_initial_state(
                scheduler_test_fixture.canister_num,
                scheduler_test_fixture.message_num_per_canister,
            );
            // The first two canisters have an `Allocation` of 1 and the last 1/3. We'll be
            // forced to execute the first two and then run out of instructions (based on
            // the limits) which will result in a violation of third canister's
            // `Allocation`.
            for id in 0..2u64 {
                state = update_canister_allocation(
                    state,
                    canister_test_id(id),
                    ComputeAllocation::try_from(100).unwrap(),
                );
            }
            state = update_canister_allocation(
                state,
                canister_test_id(2),
                ComputeAllocation::try_from(33).unwrap(),
            );

            let round = ExecutionRound::from(4);
            scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );

            let registry = &scheduler_test_fixture.metrics_registry;
            assert_eq!(
                fetch_histogram_stats(registry, "scheduler_executable_canisters_per_round")
                    .unwrap()
                    .sum as i64,
                3
            );
            assert_eq!(
                fetch_histogram_stats(registry, "scheduler_canister_age_rounds")
                    .unwrap()
                    .sum as i64,
                4
            );
            assert_eq!(
                fetch_histogram_stats(
                    registry,
                    "scheduler_charge_resource_allocation_and_use_duration"
                )
                .unwrap()
                .count,
                1
            );
            assert_eq!(
                fetch_int_counter(registry, "scheduler_compute_allocation_violations"),
                Some(1)
            );
            assert_eq!(
                fetch_int_counter(
                    registry,
                    "scheduler_canister_messages_where_cycles_were_charged"
                ),
                Some(10)
            );
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn requested_method_does_not_exist() {
    let num_instructions_consumed_per_msg = NumInstructions::from(5);
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(50),
            max_instructions_per_message: num_instructions_consumed_per_msg,
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 0,
        message_num_per_canister: 0,
    };
    let exec_env = default_exec_env_mock(
        &scheduler_test_fixture,
        4,
        num_instructions_consumed_per_msg,
        NumBytes::new(0),
    );
    let exec_env = Arc::new(exec_env);

    let ingress_history_writer = default_ingress_history_writer_mock(4);
    let ingress_history_writer = Arc::new(ingress_history_writer);
    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = ReplicatedState::new_rooted_at(
                subnet_test_id(1),
                SubnetType::Application,
                "NOT_USED".into(),
            );

            let canister_id = canister_test_id(0);
            let mut canister_state = new_canister_state(
                canister_id,
                user_test_id(24).get(),
                *INITIAL_CYCLES,
                NumSeconds::from(100_000),
            );
            let mut exports = BTreeSet::new();
            exports.insert(WasmMethod::Update("write".to_string()));
            exports.insert(WasmMethod::Query("read".to_string()));
            let mut execution_state = initial_execution_state(None);
            execution_state.exports = ExportedFunctions::new(exports);
            canister_state.execution_state = Some(execution_state);

            for nonce in 0..3 {
                canister_state.push_ingress(
                    SignedIngressBuilder::new()
                        .canister_id(canister_id)
                        .method_name("write".to_string())
                        .nonce(nonce)
                        .build()
                        .into(),
                );
            }
            canister_state.push_ingress(
                SignedIngressBuilder::new()
                    .canister_id(canister_id)
                    .method_name("unknown".to_string())
                    .nonce(4)
                    .build()
                    .into(),
            );
            state.put_canister_state(canister_state);

            let round = ExecutionRound::from(1);
            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                round,
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.ingress_queue_size(), 0);
                assert_eq!(
                    canister_state.scheduler_state.last_full_execution_round,
                    round
                );
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn stopping_canisters_are_stopped_when_they_are_ready() {
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(50),
            max_instructions_per_message: NumInstructions::from(5),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 1,
    };

    let mut exec_env = MockExecutionEnvironment::new();
    exec_env
        .expect_subnet_available_memory()
        .times(..)
        .returning(move |_| NumBytes::from(10));
    let exec_env = Arc::new(exec_env);

    // Expect ingress history writer to be called twice to respond to
    // the two stop messages defined below.
    let ingress_history_writer = default_ingress_history_writer_mock(2);
    let ingress_history_writer = Arc::new(ingress_history_writer);

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = ReplicatedState::new_rooted_at(
                subnet_test_id(1),
                SubnetType::Application,
                "NOT_USED".into(),
            );
            // Create a canister in the stopping state and assume that the
            // controller sent two stop messages at the same time.
            let mut canister = get_stopping_canister(canister_test_id(0));

            canister
                .system_state
                .add_stop_context(StopCanisterContext::Ingress {
                    sender: user_test_id(0),
                    message_id: message_test_id(0),
                });

            canister
                .system_state
                .add_stop_context(StopCanisterContext::Ingress {
                    sender: user_test_id(0),
                    message_id: message_test_id(1),
                });

            state.put_canister_state(canister);

            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            assert_eq!(state.canister_states.len(), 1);
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.status(), CanisterStatusType::Stopped);
            }
        },
        ingress_history_writer,
        exec_env,
    );
}

#[test]
fn stopping_canisters_are_not_stopped_if_not_ready() {
    let scheduler_test_fixture = SchedulerTestFixture {
        scheduler_config: SchedulerConfig {
            scheduler_cores: 1,
            max_instructions_per_round: NumInstructions::from(50),
            max_instructions_per_message: NumInstructions::from(5),
            ..SchedulerConfig::application_subnet()
        },
        metrics_registry: MetricsRegistry::new(),
        canister_num: 3,
        message_num_per_canister: 1,
    };

    let mut exec_env = MockExecutionEnvironment::new();
    exec_env
        .expect_subnet_available_memory()
        .times(..)
        .returning(move |_| NumBytes::from(10));

    // Expect ingress history writer to never be called since the canister
    // isn't ready to be stopped.
    let ingress_history_writer = default_ingress_history_writer_mock(0);
    let ingress_history_writer = Arc::new(ingress_history_writer);

    scheduler_test(
        &scheduler_test_fixture,
        |scheduler| {
            let mut state = ReplicatedState::new_rooted_at(
                subnet_test_id(1),
                SubnetType::Application,
                "NOT_USED".into(),
            );
            // Create a canister in the stopping state and assume that the
            // controller sent two stop messages at the same time.
            let mut canister = get_stopping_canister(canister_test_id(0));

            let stop_context_1 = StopCanisterContext::Ingress {
                sender: user_test_id(0),
                message_id: message_test_id(0),
            };

            let stop_context_2 = StopCanisterContext::Ingress {
                sender: user_test_id(0),
                message_id: message_test_id(1),
            };

            canister
                .system_state
                .add_stop_context(stop_context_1.clone());
            canister
                .system_state
                .add_stop_context(stop_context_2.clone());

            // Create a call context. Because there's a call context the
            // canister should _not_ be ready to be stopped, and therefore
            // the scheduler will keep it as-is in its stopping state.
            canister
                .system_state
                .call_context_manager_mut()
                .unwrap()
                .new_call_context(
                    CallOrigin::Ingress(user_test_id(13), message_test_id(14)),
                    Cycles::from(10),
                );

            let expected_ccm = canister
                .system_state
                .call_context_manager()
                .unwrap()
                .clone();

            state.put_canister_state(canister);

            state = scheduler.execute_round(
                state,
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                ExecutionRound::from(1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            assert_eq!(state.canister_states.len(), 1);
            assert_eq!(
                state
                    .canister_state_mut(&canister_test_id(0))
                    .unwrap()
                    .system_state
                    .status,
                CanisterStatus::Stopping {
                    stop_contexts: vec![stop_context_1, stop_context_2],
                    call_context_manager: expected_ccm
                }
            );
            assert!(!state
                .canister_state_mut(&canister_test_id(0))
                .unwrap()
                .system_state
                .ready_to_stop());
        },
        ingress_history_writer,
        Arc::new(exec_env),
    );
}

#[test]
fn replicated_state_metrics_nothing_exported() {
    let state = ReplicatedState::new_rooted_at(
        subnet_test_id(1),
        SubnetType::Application,
        "NOT_USED".into(),
    );

    let registry = MetricsRegistry::new();
    let scheduler_metrics = SchedulerMetrics::new(&registry);

    observe_replicated_state_metrics(&state, &scheduler_metrics);

    // No canisters in the state. There should be nothing exported.
    assert_eq!(
        fetch_int_gauge_vec(&registry, "replicated_state_registered_canisters"),
        metric_vec(&[
            (&[("status", "running")], 0),
            (&[("status", "stopping")], 0),
            (&[("status", "stopped")], 0),
        ]),
    );
}

#[test]
fn replicated_state_metrics_running_canister() {
    let mut state = ReplicatedState::new_rooted_at(
        subnet_test_id(1),
        SubnetType::Application,
        "NOT_USED".into(),
    );

    state.put_canister_state(get_running_canister(canister_test_id(0)));

    let registry = MetricsRegistry::new();
    let scheduler_metrics = SchedulerMetrics::new(&registry);

    observe_replicated_state_metrics(&state, &scheduler_metrics);

    assert_eq!(
        fetch_int_gauge_vec(&registry, "replicated_state_registered_canisters"),
        metric_vec(&[
            (&[("status", "running")], 1),
            (&[("status", "stopping")], 0),
            (&[("status", "stopped")], 0),
        ]),
    );
}

#[test]
fn test_uninstall_canister() {
    let mut canister = CanisterStateBuilder::new()
        .with_canister_id(canister_test_id(0))
        .with_cycles(0)
        .with_wasm(vec![4, 5, 6])
        .with_stable_memory(vec![1, 2, 3])
        .with_memory_allocation(1000)
        .with_compute_allocation(ComputeAllocation::try_from(99).unwrap())
        .build();
    uninstall_canister(
        &no_op_logger(),
        &mut canister,
        &PathBuf::from("NOT_USED"),
        mock_time(),
    );

    // Stable memory and exection state are dropped.
    assert_eq!(
        canister.system_state.stable_memory_size,
        NumWasmPages::new(0)
    );
    assert_eq!(canister.execution_state, None);
}

#[test]
fn replicated_state_metrics_different_canister_statuses() {
    let mut state = ReplicatedState::new_rooted_at(
        subnet_test_id(1),
        SubnetType::Application,
        "NOT_USED".into(),
    );

    state.put_canister_state(get_running_canister(canister_test_id(0)));
    state.put_canister_state(get_stopped_canister(canister_test_id(2)));
    state.put_canister_state(get_stopping_canister(canister_test_id(1)));
    state.put_canister_state(get_stopped_canister(canister_test_id(3)));

    let registry = MetricsRegistry::new();
    let scheduler_metrics = SchedulerMetrics::new(&registry);

    observe_replicated_state_metrics(&state, &scheduler_metrics);

    assert_eq!(
        fetch_int_gauge_vec(&registry, "replicated_state_registered_canisters"),
        metric_vec(&[
            (&[("status", "running")], 1),
            (&[("status", "stopping")], 1),
            (&[("status", "stopped")], 2),
        ]),
    );
}

proptest! {
    // In the following tests we use a notion of `minimum_executed_messages` per
    // execution round. The minimum is defined as `min(available_messages,
    // floor(`max_instructions_per_round` / `max_instructions_per_message`))`. `available_messages` are the sum of
    // messages in the input queues of all canisters.

    #[test]
    // This test verifies that the scheduler will never consume more than
    // `max_instructions_per_round` in a single execution round.
    fn should_never_consume_more_than_max_instructions_per_round_in_a_single_execution_round(
        (num_instructions_consumed_per_msg, max_instructions_per_round) in instructions_limits(),
        state in arb_replicated_state(10, 100, LAST_ROUND_MAX)
    ) {
        let available_messages = get_available_messages(&state);
        let minimum_executed_messages = min(
            available_messages,
            max_instructions_per_round / num_instructions_consumed_per_msg,
        );
        let scheduler_test_fixture = SchedulerTestFixture {
            scheduler_config: SchedulerConfig {
                scheduler_cores: 1,
                max_instructions_per_round,
                max_instructions_per_message: num_instructions_consumed_per_msg,
                ..SchedulerConfig::application_subnet()
            },
            metrics_registry: MetricsRegistry::new(),
            canister_num: 2,
            message_num_per_canister: 10,
        };
        let exec_env = default_exec_env_mock(
            &scheduler_test_fixture,
            minimum_executed_messages as usize,
            num_instructions_consumed_per_msg,
            NumBytes::new(0),
        );
        let ingress_history_writer = default_ingress_history_writer_mock(
            minimum_executed_messages as usize
        );
        let ingress_history_writer = Arc::new(ingress_history_writer);
        scheduler_test(&scheduler_test_fixture, |scheduler| {
            scheduler.execute_round(
                state.clone(),
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                ExecutionRound::from(LAST_ROUND_MAX + 1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
        },
        ingress_history_writer,
        Arc::new(exec_env)
        );
    }

    #[test]
    // This test verifies that the scheduler is deterministic, i.e. given
    // the same input, if we execute a round of computation, we always
    // get the same result.
    fn scheduler_deterministically_produces_same_output_given_same_input(
        (num_instructions_consumed_per_msg, max_instructions_per_round) in instructions_limits(),
        state in arb_replicated_state(10, 100, LAST_ROUND_MAX)
    ) {
        let available_messages = get_available_messages(&state);
        let minimum_executed_messages = min(
            available_messages,
            max_instructions_per_round / num_instructions_consumed_per_msg
        );
        let scheduler_test_fixture = SchedulerTestFixture {
            scheduler_config: SchedulerConfig {
                scheduler_cores: 1,
                max_instructions_per_round,
                max_instructions_per_message: num_instructions_consumed_per_msg,
                ..SchedulerConfig::application_subnet()
            },
            metrics_registry: MetricsRegistry::new(),
            canister_num: 2,
            message_num_per_canister: 10,
        };
        let exec_env = default_exec_env_mock(
            &scheduler_test_fixture,
            2 * minimum_executed_messages as usize,
            num_instructions_consumed_per_msg,
            NumBytes::new(0),
        );
        let ingress_history_writer = default_ingress_history_writer_mock(
            (minimum_executed_messages * 2) as usize
        );
        let ingress_history_writer = Arc::new(ingress_history_writer);
        scheduler_test(&scheduler_test_fixture, |scheduler| {
                let new_state1 = scheduler.execute_round(
                    state.clone(),
                    Randomness::from([0; 32]),
                    UNIX_EPOCH,
                    ExecutionRound::from(LAST_ROUND_MAX + 1),
                    ProvisionalWhitelist::Set(BTreeSet::new()),
                );
                let new_state2 = scheduler.execute_round(
                    state.clone(),
                    Randomness::from([0; 32]),
                    UNIX_EPOCH,
                    ExecutionRound::from(LAST_ROUND_MAX + 1),
                    ProvisionalWhitelist::Set(BTreeSet::new()),
                );
                assert_eq!(new_state1, new_state2);
            },
        ingress_history_writer,
        Arc::new(exec_env),
        );
    }

    #[test]
    // This test verifies that the scheduler can successfully deplete the induction
    // pool given sufficient consecutive execution rounds.
    fn scheduler_can_deplete_induction_pool_given_enough_execution_rounds(
        scheduler_cores in scheduler_cores(),
        (num_instructions_consumed_per_msg, max_instructions_per_round) in instructions_limits(),
        mut state in arb_replicated_state(10, 100, LAST_ROUND_MAX)
    ) {
        let available_messages = get_available_messages(&state);
        let minimum_executed_messages = min(
            available_messages,
            max_instructions_per_round / num_instructions_consumed_per_msg
        );
        let required_rounds = if minimum_executed_messages != 0 {
            available_messages / minimum_executed_messages + 1
        } else {
            1
        };
        let scheduler_test_fixture = SchedulerTestFixture {
            scheduler_config: SchedulerConfig {
                scheduler_cores,
                max_instructions_per_round,
                max_instructions_per_message: num_instructions_consumed_per_msg,
                ..SchedulerConfig::application_subnet()
            },
            metrics_registry: MetricsRegistry::new(),
            canister_num: 0, // Not used in this test
            message_num_per_canister: 0, // Not used in this test
        };
        let exec_env = default_exec_env_mock(
            &scheduler_test_fixture,
            available_messages as usize,
            num_instructions_consumed_per_msg,
            NumBytes::new(0),
        );
        let exec_env = Arc::new(exec_env);

        let start_round = LAST_ROUND_MAX + 1;
        let end_round = required_rounds + start_round;
        let ingress_history_writer = default_ingress_history_writer_mock(available_messages as usize);
        let ingress_history_writer = Arc::new(ingress_history_writer);
        scheduler_test(&scheduler_test_fixture, |scheduler| {
            for round in start_round..end_round {
                state =
                    scheduler.execute_round(
                        state,
                        Randomness::from([0; 32]),
                        UNIX_EPOCH,
                        ExecutionRound::from(round),
                        ProvisionalWhitelist::Set(BTreeSet::new()),
                    );
            }
            for canister_state in state.canisters_iter() {
                assert_eq!(canister_state.ingress_queue_size(), 0);
            }
        },
        ingress_history_writer,
        exec_env);
    }

    #[test]
    // This test verifies that the scheduler does not lose any canisters
    // after an execution round.
    fn scheduler_does_not_lose_canisters(
        (num_instructions_consumed_per_msg, max_instructions_per_round) in instructions_limits(),
        state in arb_replicated_state(10, 100, LAST_ROUND_MAX)
    ) {
        let available_messages = get_available_messages(&state);
        let minimum_executed_messages = min(
            available_messages,
            max_instructions_per_round / num_instructions_consumed_per_msg,
        );
        let scheduler_test_fixture = SchedulerTestFixture {
            scheduler_config: SchedulerConfig {
                scheduler_cores: 1,
                max_instructions_per_round,
                max_instructions_per_message: num_instructions_consumed_per_msg,
                ..SchedulerConfig::application_subnet()
            },
            metrics_registry: MetricsRegistry::new(),
            canister_num: 2,
            message_num_per_canister: 10,
        };
        let exec_env = default_exec_env_mock(
            &scheduler_test_fixture,
            minimum_executed_messages as usize,
            num_instructions_consumed_per_msg,
            NumBytes::new(0),
        );
        let exec_env = Arc::new(exec_env);

        let ingress_history_writer = default_ingress_history_writer_mock(
            minimum_executed_messages as usize
        );
        let ingress_history_writer = Arc::new(ingress_history_writer);
        scheduler_test(&scheduler_test_fixture, |scheduler| {
            let original_canister_count = state.canisters_iter().count();
            let state = scheduler.execute_round(
                state.clone(),
                Randomness::from([0; 32]),
                UNIX_EPOCH,
                ExecutionRound::from(LAST_ROUND_MAX + 1),
                ProvisionalWhitelist::Set(BTreeSet::new()),
            );
            assert_eq!(state.canisters_iter().count(), original_canister_count);
        },
        ingress_history_writer,
        exec_env);
    }

    #[test]
    // Verifies that each canister is scheduled as the first of its thread as
    // much as its compute_allocation requires.
    fn scheduler_respects_compute_allocation(
        mut replicated_state in arb_replicated_state(24, 2, 1),
        mut scheduler_cores in 1..16 as usize
    ) {
        let number_of_canisters = replicated_state.canister_states.len();
        let total_compute_allocation = replicated_state.total_compute_allocation() as usize;

        // Ensure that the capacity is greater than the total_compute_allocation.
        if total_compute_allocation >= 100 * scheduler_cores {
            scheduler_cores = total_compute_allocation / 100 + 1;
        }

        // Count, for each canister, how many times it is the first canister
        // to be executed by a thread.
        let mut scheduled_first_counters = HashMap::<CanisterId, usize>::new();

        // Because we may be left with as little free compute capacity as 1, run for
        // enough rounds that every canister gets a chance to be scheduled at least once
        // for free, i.e. `100 * number_of_canisters` rounds.
        let number_of_rounds = 100 * number_of_canisters;

        for i in 0..number_of_rounds {
            // Ask for partitioning.
            let ordered_canister_ids = apply_scheduler_strategy(
                scheduler_cores,
                ExecutionRound::new(i as u64),
                &mut replicated_state.canister_states,
            );

            // "Schedule" the first `scheduler_cores` canisters.
            for canister_id in ordered_canister_ids
                .iter()
                .take(min(scheduler_cores, ordered_canister_ids.len()))
            {
                let count = scheduled_first_counters.entry(*canister_id).or_insert(0);
                *count += 1;
            }
        }

        // Check that the compute allocations of the canisters are respected.
        for (canister_id, canister) in replicated_state.canister_states.iter() {
            let compute_allocation =
                canister.scheduler_state.compute_allocation.as_percent() as usize;

            let count = scheduled_first_counters.get(canister_id).unwrap_or(&0);

            // Due to `total_compute_allocation < 100 * scheduler_cores`, all canisters
            // except those with an allocation of 100 should have gotten scheduled for free
            // at least once.
            let expected_count = if compute_allocation == 100 {
                number_of_rounds
            } else {
                number_of_rounds / 100 * compute_allocation + 1
            };

            assert!(
                *count >= expected_count,
                "Canister {} (allocation {}) should have been scheduled \
                    {} out of {} rounds, was scheduled only {} rounds instead.",
                canister_id,
                compute_allocation,
                expected_count,
                number_of_rounds,
                *count
            );
        }
    }
}

struct SchedulerTestFixture {
    pub scheduler_config: SchedulerConfig,
    pub metrics_registry: MetricsRegistry,
    pub canister_num: u64,
    pub message_num_per_canister: u64,
}

fn default_exec_env_mock(
    f: &SchedulerTestFixture,
    calls: usize,
    cycles_per_message: NumInstructions,
    heap_delta_per_message: NumBytes,
) -> MockExecutionEnvironment {
    let mut exec_env = MockExecutionEnvironment::new();
    let num_instructions_left =
        f.scheduler_config.max_instructions_per_message - cycles_per_message;

    exec_env
        .expect_subnet_available_memory()
        .times(..)
        .returning(move |_| NumBytes::from(10));
    exec_env
        .expect_execute_canister_message()
        .times(calls)
        .returning(move |canister, _, msg, _, _, _, _| {
            if let CanisterInputMessage::Ingress(msg) = msg {
                EarlyResult::new(ExecuteMessageResult {
                    canister: canister.clone(),
                    num_instructions_left,
                    ingress_status: Some((
                        msg.message_id,
                        IngressStatus::Completed {
                            receiver: canister.canister_id().get(),
                            user_id: user_test_id(0),
                            result: WasmResult::Reply(vec![]),
                            time: mock_time(),
                        },
                    )),
                    heap_delta: heap_delta_per_message,
                })
            } else {
                unreachable!("Only ingress messages are expected.");
            }
        });
    exec_env
}

fn default_ingress_history_writer_mock(calls: usize) -> MockIngressHistory {
    let mut ingress_history_writer = MockIngressHistory::new();
    ingress_history_writer
        .expect_set_status()
        .with(always(), always(), always())
        .times(calls)
        .returning(|_, _, _| {});
    ingress_history_writer
}

fn scheduler_test(
    test_fixture: &SchedulerTestFixture,
    run_test: impl FnOnce(SchedulerImpl),
    ingress_history_writer: Arc<MockIngressHistory>,
    exec_env: Arc<MockExecutionEnvironment>,
) {
    with_test_replica_logger(|log| {
        let cycles_account_manager = Arc::new(
            CyclesAccountManagerBuilder::new()
                .with_max_num_instructions(MAX_INSTRUCTIONS_PER_MESSAGE)
                .build(),
        );
        let scheduler = SchedulerImpl::new(
            test_fixture.scheduler_config.clone(),
            subnet_test_id(1),
            SubnetType::Application,
            ingress_history_writer,
            exec_env,
            cycles_account_manager,
            &test_fixture.metrics_registry,
            log,
        );
        run_test(scheduler);
    });
}

// Returns the sum of messages of the input queues of all canisters.
fn get_available_messages(state: &ReplicatedState) -> u64 {
    state
        .canisters_iter()
        .map(|canister_state| canister_state.ingress_queue_size() as u64)
        .sum()
}

prop_compose! {
    fn scheduler_cores() (scheduler_cores in 1..32usize) -> usize {
        scheduler_cores
    }
}

prop_compose! {
    fn instructions_limits()
    (
        num_instructions_consumed_per_msg in 1..1_000_000u64, max_instructions_per_round in 1_000_000..1_000_000_000u64
    ) -> (NumInstructions, NumInstructions) {
        (NumInstructions::from(num_instructions_consumed_per_msg), NumInstructions::from(max_instructions_per_round))
    }
}
