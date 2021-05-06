use ic_base_types::NumSeconds;
use ic_config::subnet_config::{CyclesAccountManagerConfig, SubnetConfigs};
use ic_cycles_account_manager::{
    freeze_threshold_cycles, IngressInductionCost, IngressInductionCostError,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CyclesAccountError, SystemState};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder,
    state::{new_canister_state, SystemStateBuilder},
    types::{
        ids::{canister_test_id, subnet_test_id, user_test_id},
        messages::SignedIngressBuilder,
    },
    with_test_replica_logger,
};
use ic_types::{
    ic00::{CanisterIdRecord, Payload, IC_00},
    messages::SignedIngressContent,
    CanisterId, ComputeAllocation, Cycles, MemoryAllocation, NumBytes, NumInstructions,
};
use std::{convert::TryFrom, time::Duration};

const CYCLES_LIMIT_PER_CANISTER: Cycles = Cycles::new(100_000_000_000_000);
const INITIAL_CYCLES: Cycles = Cycles::new(5_000_000_000_000);

#[test]
fn test_can_charge_application_subnets() {
    with_test_replica_logger(|log| {
        for subnet_type in &[
            SubnetType::Application,
            SubnetType::System,
            SubnetType::VerifiedApplication,
        ] {
            for memory_allocation in &[
                None,
                Some(MemoryAllocation::try_from(NumBytes::from(1 << 20)).unwrap()),
            ] {
                for freeze_threshold in &[NumSeconds::from(1000), NumSeconds::from(0)] {
                    let cycles_account_manager = CyclesAccountManagerBuilder::new()
                        .with_subnet_type(*subnet_type)
                        .build();
                    let compute_allocation = ComputeAllocation::try_from(20).unwrap();
                    let mut canister = new_canister_state(
                        canister_test_id(1),
                        canister_test_id(2).get(),
                        Cycles::from(0),
                        *freeze_threshold,
                    );
                    canister.system_state.memory_allocation = *memory_allocation;
                    canister.scheduler_state.compute_allocation = compute_allocation;
                    let duration = Duration::from_secs(1);

                    let memory = match memory_allocation {
                        None => canister.memory_usage(),
                        Some(allocation) => allocation.get(),
                    };
                    let expected_fee = cycles_account_manager
                        .compute_allocation_cost(compute_allocation, duration)
                        + cycles_account_manager.memory_cost(memory, duration);
                    let initial_cycles = expected_fee + Cycles::from(100);
                    canister
                        .system_state
                        .cycles_account
                        .add_cycles(initial_cycles);
                    cycles_account_manager
                        .charge_canister_for_resource_allocation_and_usage(&log, canister, duration)
                        .unwrap();
                }
            }
        }
    })
}

#[test]
fn withdraw_cycles_with_not_enough_balance_returns_error() {
    let mut system_state = SystemState::new_running(
        canister_test_id(1),
        canister_test_id(2).get(),
        Cycles::from(100_000),
        NumSeconds::from(0),
    );
    assert_eq!(
        CyclesAccountManagerBuilder::new().build().withdraw_cycles(
            &mut system_state,
            NumBytes::from(0),
            ComputeAllocation::default(),
            Cycles::from(200),
        ),
        Ok(())
    );

    let mut system_state = SystemState::new_running(
        canister_test_id(1),
        canister_test_id(2).get(),
        Cycles::from(100_000),
        NumSeconds::from(60),
    );
    assert_eq!(
        CyclesAccountManagerBuilder::new().build().withdraw_cycles(
            &mut system_state,
            NumBytes::from(0),
            ComputeAllocation::default(),
            Cycles::from(200),
        ),
        Ok(())
    );

    let mut system_state = SystemState::new_running(
        canister_test_id(1),
        canister_test_id(2).get(),
        Cycles::from(100_000),
        NumSeconds::from(0),
    );
    assert_eq!(
        CyclesAccountManagerBuilder::new().build().withdraw_cycles(
            &mut system_state,
            NumBytes::from(4 << 30),
            ComputeAllocation::default(),
            Cycles::from(200),
        ),
        Ok(())
    );

    let mut system_state = SystemState::new_running(
        canister_test_id(1),
        canister_test_id(2).get(),
        Cycles::from(100_000),
        NumSeconds::from(30),
    );
    assert_eq!(
        CyclesAccountManagerBuilder::new().build().withdraw_cycles(
            &mut system_state,
            NumBytes::from(4 << 30),
            ComputeAllocation::default(),
            Cycles::from(200),
        ),
        Err(CyclesAccountError::CanisterOutOfCycles {
            available: Cycles::from(0),
            requested: Cycles::from(200)
        })
    );
}

#[test]
fn add_cycles_does_not_overflow_when_balance_limit() {
    let mut cycles_balance_expected = Cycles::from(0);
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(cycles_balance_expected)
        .build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        cycles_balance_expected
    );

    fn apply_cycle_limit(balance: Cycles) -> Cycles {
        if balance > CYCLES_LIMIT_PER_CANISTER {
            return CYCLES_LIMIT_PER_CANISTER;
        }
        balance
    }

    fn add_limited(balance: Cycles, amount_to_add: Cycles) -> Cycles {
        let result = balance + amount_to_add;
        if result > CYCLES_LIMIT_PER_CANISTER {
            return CYCLES_LIMIT_PER_CANISTER;
        }
        result
    };

    let amount = Cycles::from(CYCLES_LIMIT_PER_CANISTER.get() / 2);
    cycles_balance_expected = add_limited(cycles_balance_expected, amount);
    cycles_account_manager.add_cycles(&mut system_state, amount);
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        apply_cycle_limit(amount)
    );
    assert_eq!(system_state.cycles_account.cycles_balance(), amount);

    let amount = amount - Cycles::from(10);
    cycles_balance_expected = add_limited(cycles_balance_expected, amount);
    cycles_account_manager.add_cycles(&mut system_state, amount);
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        apply_cycle_limit(cycles_balance_expected)
    );
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        CYCLES_LIMIT_PER_CANISTER - Cycles::from(10)
    );

    cycles_account_manager.add_cycles(&mut system_state, Cycles::from(0));
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        apply_cycle_limit(cycles_balance_expected)
    );
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        CYCLES_LIMIT_PER_CANISTER - Cycles::from(10)
    );

    cycles_account_manager.add_cycles(&mut system_state, Cycles::from(10));
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        CYCLES_LIMIT_PER_CANISTER
    );

    cycles_account_manager.add_cycles(&mut system_state, amount);
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        CYCLES_LIMIT_PER_CANISTER
    );
}

#[test]
fn add_cycles_does_not_overflow_when_no_balance_limit() {
    // When there is not `max_cycles_per_canister`,
    // Cycles is capped by u128::MAX
    let cycles_balance_expected = Cycles::from(0);
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(cycles_balance_expected)
        .build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_cycles_limit_per_canister(None)
        .build();
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        cycles_balance_expected
    );

    let amount = Cycles::from(u128::MAX / 2);
    cycles_account_manager.add_cycles(&mut system_state, amount);
    assert_eq!(system_state.cycles_account.cycles_balance(), amount);

    cycles_account_manager.add_cycles(&mut system_state, amount);
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        Cycles::from(u128::MAX - 1)
    );

    cycles_account_manager.add_cycles(&mut system_state, Cycles::from(1));
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        Cycles::from(u128::MAX)
    );

    cycles_account_manager.add_cycles(&mut system_state, Cycles::from(100));
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        Cycles::from(u128::MAX)
    );
}

#[test]
fn verify_no_cycles_charged_for_message_execution_on_system_subnets() {
    let mut system_state = SystemStateBuilder::new().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();

    cycles_account_manager
        .withdraw_execution_cycles(
            &mut system_state,
            NumBytes::from(0),
            ComputeAllocation::default(),
            NumInstructions::from(1_000_000),
        )
        .unwrap();
    assert_eq!(system_state.cycles_account.cycles_balance(), INITIAL_CYCLES);

    cycles_account_manager
        .refund_execution_cycles(&mut system_state, NumInstructions::from(5_000_000));
    assert_eq!(system_state.cycles_account.cycles_balance(), INITIAL_CYCLES);
}

#[test]
fn canister_charge_for_memory_until_zero_works() {
    let mut system_state = SystemStateBuilder::new().build();
    let subnet_type = SubnetType::Application;
    let config = SubnetConfigs::default()
        .own_subnet_config(subnet_type)
        .cycles_account_manager_config;
    let gib_stored_per_second_fee = config.gib_storage_per_second_fee;
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(subnet_type)
        .build();

    // Number of times we want to change
    let iterations = 16;

    // Calculate the amount of memory we need to charge for each time to consume
    // all the cycles in the system state.
    let gibs = system_state.cycles_account.cycles_balance().get()
        / gib_stored_per_second_fee.get()
        / iterations
        * 1024
        * 1024
        * 1024;
    let gibs = NumBytes::from(u64::try_from(gibs).unwrap());

    for _ in 0..iterations {
        assert!(cycles_account_manager
            .charge_for_memory(&mut system_state, gibs, Duration::from_secs(1))
            .is_ok());
    }

    // The fee that will be charged in each iteration
    let fee = cycles_account_manager.memory_cost(gibs, Duration::from_secs(1));
    assert!(system_state.cycles_account.cycles_balance() < fee);
    assert!(cycles_account_manager
        .charge_for_memory(&mut system_state, gibs, Duration::from_secs(1))
        .is_err());
}

#[test]
fn max_cycles_per_canister_none_on_application_subnet() {
    let cycles = Cycles::new(10_000_000_000);
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(CYCLES_LIMIT_PER_CANISTER)
        .build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_cycles_limit_per_canister(None)
        .build();

    assert_eq!(
        cycles_account_manager.check_max_cycles_can_add(&system_state, cycles),
        cycles,
    );

    cycles_account_manager.add_cycles(&mut system_state, cycles);
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        CYCLES_LIMIT_PER_CANISTER + cycles
    );
}

#[test]
fn max_cycles_per_canister_on_application_subnet() {
    let cycles = Cycles::new(10_000_000_000);
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(CYCLES_LIMIT_PER_CANISTER)
        .build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

    assert_eq!(
        cycles_account_manager.check_max_cycles_can_add(&system_state, cycles),
        Cycles::new(0),
    );

    cycles_account_manager.add_cycles(&mut system_state, cycles);
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        CYCLES_LIMIT_PER_CANISTER
    );
}

#[test]
fn max_cycles_per_canister_none_on_system_subnet() {
    let cycles = Cycles::new(10_000_000_000);
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(CYCLES_LIMIT_PER_CANISTER)
        .build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();

    assert_eq!(
        cycles_account_manager.check_max_cycles_can_add(&system_state, cycles),
        cycles,
    );

    // On system subnet, the canister's balance can exceed `max_cycles_per_canister`
    cycles_account_manager.add_cycles(&mut system_state, cycles);
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        CYCLES_LIMIT_PER_CANISTER + cycles
    );
}

#[test]
fn max_cycles_per_canister_on_system_subnet() {
    let cycles = Cycles::new(10_000_000_000);
    // Set balance to `max_cycles_per_canister`.
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(CYCLES_LIMIT_PER_CANISTER)
        .build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();

    assert_eq!(
        cycles_account_manager.check_max_cycles_can_add(&system_state, cycles),
        cycles,
    );

    // On system subnet, the canister's balance can exceed `max_cycles_per_canister`
    cycles_account_manager.add_cycles(&mut system_state, cycles);
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        CYCLES_LIMIT_PER_CANISTER + cycles
    );
}

#[test]
fn ingress_induction_cost_subnet_message_with_invalid_payload() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

    for receiver in [IC_00, CanisterId::from(subnet_test_id(0))].iter() {
        assert_eq!(
            cycles_account_manager.ingress_induction_cost(
                SignedIngressBuilder::new()
                    .sender(user_test_id(0))
                    .canister_id(*receiver)
                    .method_name("start_canister")
                    .method_payload(vec![]) // an invalid payload
                    .build()
                    .content(),
            ),
            Err(IngressInductionCostError::InvalidSubnetPayload)
        );
    }
}

#[test]
fn ingress_induction_cost_subnet_message_with_unknown_method() {
    for receiver in [IC_00, CanisterId::from(subnet_test_id(0))].iter() {
        assert_eq!(
            CyclesAccountManagerBuilder::new()
                .build()
                .ingress_induction_cost(
                    SignedIngressBuilder::new()
                        .sender(user_test_id(0))
                        .canister_id(*receiver)
                        .method_name("unknown_method")
                        .build()
                        .content(),
                ),
            Err(IngressInductionCostError::UnknownSubnetMethod)
        );
    }
}

#[test]
fn ingress_induction_cost_valid_subnet_message() {
    for receiver in [IC_00, CanisterId::from(subnet_test_id(0))].iter() {
        let msg: SignedIngressContent = SignedIngressBuilder::new()
            .sender(user_test_id(0))
            .canister_id(*receiver)
            .method_name("start_canister")
            .method_payload(CanisterIdRecord::from(canister_test_id(0)).encode())
            .build()
            .into();

        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
        let num_bytes = msg.arg().len() + msg.method_name().len();

        assert_eq!(
            cycles_account_manager.ingress_induction_cost(&msg,),
            Ok(IngressInductionCost::Fee {
                payer: canister_test_id(0),
                cost: cycles_account_manager.ingress_message_received_fee()
                    + cycles_account_manager.ingress_byte_received_fee() * num_bytes
            })
        );
    }
}

#[test]
fn charging_removes_canisters_with_insufficient_balance() {
    with_test_replica_logger(|log| {
        let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

        let mut canister = new_canister_state(
            canister_test_id(1),
            canister_test_id(11).get(),
            Cycles::from(std::u128::MAX),
            NumSeconds::from(0),
        );
        canister.scheduler_state.compute_allocation = ComputeAllocation::try_from(50).unwrap();
        canister.system_state.memory_allocation =
            Some(MemoryAllocation::try_from(NumBytes::from(1 << 30)).unwrap());
        cycles_account_manager
            .charge_canister_for_resource_allocation_and_usage(
                &log,
                canister,
                Duration::from_secs(1),
            )
            .unwrap();

        let mut canister = new_canister_state(
            canister_test_id(1),
            canister_test_id(11).get(),
            Cycles::from(0),
            NumSeconds::from(0),
        );
        canister.scheduler_state.compute_allocation = ComputeAllocation::try_from(50).unwrap();
        canister.system_state.memory_allocation =
            Some(MemoryAllocation::try_from(NumBytes::from(1 << 30)).unwrap());
        cycles_account_manager
            .charge_canister_for_resource_allocation_and_usage(
                &log,
                canister,
                Duration::from_secs(1),
            )
            .unwrap_err();

        let mut canister = new_canister_state(
            canister_test_id(1),
            canister_test_id(11).get(),
            Cycles::from(100),
            NumSeconds::from(0),
        );
        canister.scheduler_state.compute_allocation = ComputeAllocation::try_from(50).unwrap();
        canister.system_state.memory_allocation =
            Some(MemoryAllocation::try_from(NumBytes::from(1 << 30)).unwrap());
        cycles_account_manager
            .charge_canister_for_resource_allocation_and_usage(
                &log,
                canister,
                Duration::from_secs(1),
            )
            .unwrap_err();
    })
}

#[test]
fn cycles_withdraw_for_execution() {
    let config = CyclesAccountManagerConfig::application_subnet();

    let gib_storage_per_second_fee = config.gib_storage_per_second_fee;
    let compute_allocation_fee = config.compute_percent_allocated_per_second_fee;
    let memory_usage = NumBytes::from(4 << 30);
    let memory_allocation = None;
    let compute_allocation = ComputeAllocation::try_from(90).unwrap();
    let freeze_threshold = NumSeconds::from(10);
    let freeze_threshold_cycles = freeze_threshold_cycles(
        memory_usage,
        memory_allocation,
        gib_storage_per_second_fee,
        compute_allocation,
        compute_allocation_fee,
        freeze_threshold,
    );

    let initial_amount = std::u128::MAX;
    let initial_cycles = Cycles::from(initial_amount);
    let mut system_state = SystemState::new_running(
        canister_test_id(1),
        canister_test_id(2).get(),
        initial_cycles,
        freeze_threshold,
    );

    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let amount = Cycles::from(initial_amount / 2);
    assert!(cycles_account_manager
        .withdraw_cycles(&mut system_state, memory_usage, compute_allocation, amount)
        .is_ok());
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        initial_cycles - amount
    );
    assert!(cycles_account_manager
        .withdraw_cycles(&mut system_state, memory_usage, compute_allocation, amount)
        .is_err());

    let exec_cycles_max = cycles_account_manager.cycles_balance_above_storage_reserve(
        &system_state,
        memory_usage,
        compute_allocation,
    );
    assert!(cycles_account_manager
        .withdraw_cycles(
            &mut system_state,
            memory_usage,
            compute_allocation,
            exec_cycles_max
        )
        .is_ok());
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        freeze_threshold_cycles
    );
    assert_eq!(
        cycles_account_manager.cycles_balance_above_storage_reserve(
            &system_state,
            memory_usage,
            compute_allocation
        ),
        Cycles::from(0)
    );

    // no more cycles can be withdrawn, the rest is reserved for storage
    assert!(cycles_account_manager
        .withdraw_cycles(
            &mut system_state,
            memory_usage,
            compute_allocation,
            exec_cycles_max
        )
        .is_err());
    assert!(cycles_account_manager
        .withdraw_cycles(
            &mut system_state,
            memory_usage,
            compute_allocation,
            Cycles::from(10u64)
        )
        .is_err());
    assert!(cycles_account_manager
        .withdraw_cycles(
            &mut system_state,
            memory_usage,
            compute_allocation,
            Cycles::from(1u64)
        )
        .is_err());
    assert!(cycles_account_manager
        .withdraw_cycles(
            &mut system_state,
            memory_usage,
            compute_allocation,
            Cycles::from(0u64)
        )
        .is_ok());
    assert_eq!(
        system_state.cycles_account.cycles_balance(),
        freeze_threshold_cycles
    );
}
