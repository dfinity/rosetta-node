//! This module contains the `CyclesAccountManager` which is responsible for
//! updating the cycles account of canisters.
//!
//! A canister has an associated cycles balance, and may `send` a part of
//! this cycles balance to another canister
//! In addition to sending cycles to another canister, a canister `spend`s
//! cycles in the following three ways:
//! a) executing messages,
//! b) sending messages to other canisters,
//! c) storing data over time/rounds
//! Each of the above spending is done in three phases:
//! 1. reserving maximum cycles the operation can require
//! 2. executing the operation and return `cycles_spent`
//! 3. reimburse the canister with `cycles_reserved` - `cycles_spent`

use ic_base_types::NumSeconds;
use ic_config::subnet_config::CyclesAccountManagerConfig;
use ic_logger::{info, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterState, CyclesAccountError, SystemState};
use ic_types::{
    ic00::{
        CanisterIdRecord, InstallCodeArgs, Method, Payload, SetControllerArgs, UpdateSettingsArgs,
    },
    messages::{
        is_subnet_message, Request, Response, SignedIngressContent,
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
    },
    CanisterId, ComputeAllocation, Cycles, MemoryAllocation, NumBytes, NumInstructions, SubnetId,
};
use std::{str::FromStr, time::Duration};

/// Errors returned by the [`CyclesAccountManager`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CyclesAccountManagerError {
    /// One of the API contracts that the cycles account manager enforces was
    /// violated.
    ContractViolation(String),
}

impl std::error::Error for CyclesAccountManagerError {}

impl std::fmt::Display for CyclesAccountManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CyclesAccountManagerError::ContractViolation(msg) => {
                write!(f, "Contract violation: {}", msg)
            }
        }
    }
}

/// Handles any operation related to cycles accounting, such as charging (due to
/// using system resources) or refunding unused cycles.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CyclesAccountManager {
    /// The maximum allowed instructions to be spent on a single message
    /// execution.
    max_num_instructions: NumInstructions,
    /// The maximum amount of cycles a canister can hold.
    /// If set to None, the canisters have no upper limit.
    max_cycles_per_canister: Option<Cycles>,
    /// The subnet type of this [`CyclesAccountManager`].
    own_subnet_type: SubnetType,
    /// The subnet id of this [`CyclesAccountManager`].
    subnet_id: SubnetId,
    /// The configuration of this [`CyclesAccountManager`] controlling the fees
    /// that are charged for various operations.
    config: CyclesAccountManagerConfig,
}

#[doc(hidden)]
pub fn freeze_threshold_cycles(
    memory_usage: NumBytes,
    memory_allocation: Option<MemoryAllocation>,
    gib_storage_per_second_fee: Cycles,
    compute_allocation: ComputeAllocation,
    compute_allocation_fee: Cycles,
    freeze_threshold: NumSeconds,
) -> Cycles {
    let one_gib = 1 << 30;

    let memory_fee = {
        let memory = match memory_allocation {
            Some(memory) => memory.get(),
            None => memory_usage,
        };
        Cycles::from(
            (memory.get() as u128
                * gib_storage_per_second_fee.get()
                * freeze_threshold.get() as u128)
                / one_gib,
        )
    };

    let compute_fee = {
        Cycles::from(
            compute_allocation.as_percent() as u128
                * compute_allocation_fee.get()
                * freeze_threshold.get() as u128,
        )
    };

    memory_fee + compute_fee
}

impl CyclesAccountManager {
    pub fn new(
        // Note: `max_num_instructions` and `max_cycles_per_canister` are passed from different
        // Configs
        max_num_instructions: NumInstructions,
        max_cycles_per_canister: Option<Cycles>,
        own_subnet_type: SubnetType,
        subnet_id: SubnetId,
        config: CyclesAccountManagerConfig,
    ) -> Self {
        Self {
            max_num_instructions,
            max_cycles_per_canister,
            own_subnet_type,
            subnet_id,
            config,
        }
    }

    /// Returns the subnet type of this [`CyclesAccountManager`].
    pub fn subnet_type(&self) -> SubnetType {
        self.own_subnet_type
    }

    ////////////////////////////////////////////////////////////////////////////
    //
    // Execution/Computation
    //
    ////////////////////////////////////////////////////////////////////////////

    /// Returns the fee to create a canister in [`Cycles`].
    pub fn canister_creation_fee(&self) -> Cycles {
        self.config.canister_creation_fee
    }

    /// Returns the fee for receiving an ingress message in [`Cycles`].
    pub fn ingress_message_received_fee(&self) -> Cycles {
        self.config.ingress_message_reception_fee
    }

    /// Returns the fee per byte of ingress message received in [`Cycles`].
    pub fn ingress_byte_received_fee(&self) -> Cycles {
        self.config.ingress_byte_reception_fee
    }

    /// Returns the fee for performing a xnet call in [`Cycles`].
    pub fn xnet_call_performed_fee(&self) -> Cycles {
        self.config.xnet_call_fee
    }

    /// Returns the fee per byte of transmitted xnet call in [`Cycles`].
    pub fn xnet_call_bytes_transmitted_fee(&self, payload_size: NumBytes) -> Cycles {
        self.config.xnet_byte_transmission_fee * Cycles::from(payload_size.get())
    }

    /// Subtracts `cycles` worth of cycles from the canister's balance.
    ///
    /// # Errors
    ///
    /// Returns a `CyclesAccountError::CanisterOutOfCycles` if the
    /// requested amount is greater than the currently available.
    pub fn withdraw_cycles(
        &self,
        system_state: &mut SystemState,
        canister_current_memory_usage: NumBytes,
        canister_compute_allocation: ComputeAllocation,
        cycles: Cycles,
    ) -> Result<(), CyclesAccountError> {
        let threshold = freeze_threshold_cycles(
            canister_current_memory_usage,
            system_state.memory_allocation,
            self.config.gib_storage_per_second_fee,
            canister_compute_allocation,
            self.config.compute_percent_allocated_per_second_fee,
            system_state.freeze_threshold,
        );
        system_state
            .cycles_account
            .withdraw_with_threshold(cycles, threshold)
    }

    /// Subtracts the corresponding cycles worth of the provided
    /// `num_instructions` from the canister's balance.
    ///
    /// # Errors
    ///
    /// Returns a `CyclesAccountError::CanisterOutOfCycles` if the
    /// requested amount is greater than the currently available.
    pub fn withdraw_execution_cycles(
        &self,
        system_state: &mut SystemState,
        canister_current_memory_usage: NumBytes,
        canister_compute_allocation: ComputeAllocation,
        num_instructions: NumInstructions,
    ) -> Result<(), CyclesAccountError> {
        let cycles_to_withdraw = self.execution_cost(num_instructions);
        system_state.cycles_account.withdraw_with_threshold(
            cycles_to_withdraw,
            freeze_threshold_cycles(
                canister_current_memory_usage,
                system_state.memory_allocation,
                self.config.gib_storage_per_second_fee,
                canister_compute_allocation,
                self.config.compute_percent_allocated_per_second_fee,
                system_state.freeze_threshold,
            ),
        )
    }

    /// Refunds the corresponding cycles worth of the provided
    /// `num_instructions` to the canister's balance.
    pub fn refund_execution_cycles(
        &self,
        system_state: &mut SystemState,
        num_instructions: NumInstructions,
    ) {
        let cycles_to_refund = self.config.ten_update_instructions_execution_fee
            * Cycles::from(num_instructions.get() / 10);
        self.refund_cycles(system_state, cycles_to_refund);
    }

    /// Charges the canister for its compute allocation
    ///
    /// # Errors
    ///
    /// Returns a `CyclesAccountError::CanisterOutOfCycles` if the
    /// requested amount is greater than the currently available.
    pub fn charge_for_compute_allocation(
        &self,
        system_state: &mut SystemState,
        compute_allocation: ComputeAllocation,
        duration: Duration,
    ) -> Result<(), CyclesAccountError> {
        let cycles = self.compute_allocation_cost(compute_allocation, duration);

        // Can charge all the way to the empty account (zero cycles)
        system_state
            .cycles_account
            .consume_with_threshold(cycles, Cycles::from(0))
    }

    /// The cost of compute allocation, per round
    #[doc(hidden)] // pub for usage in tests
    pub fn compute_allocation_cost(
        &self,
        compute_allocation: ComputeAllocation,
        duration: Duration,
    ) -> Cycles {
        self.config.compute_percent_allocated_per_second_fee
            * Cycles::from(duration.as_secs())
            * Cycles::from(compute_allocation.as_percent())
    }

    /// Computes the cost of inducting an ingress message.
    ///
    /// Returns a tuple containing:
    ///  - ID of the canister that should pay for the cost.
    ///  - The cost of inducting the message.
    pub fn ingress_induction_cost(
        &self,
        ingress: &SignedIngressContent,
    ) -> Result<IngressInductionCost, IngressInductionCostError> {
        let paying_canister = if is_subnet_message(&ingress, self.subnet_id) {
            // If a subnet message, inspect the payload to figure out who should pay for the
            // message.
            match Method::from_str(ingress.method_name()) {
                Ok(Method::ProvisionalCreateCanisterWithCycles)
                | Ok(Method::ProvisionalTopUpCanister) => {
                    // Provisional methods are free.
                    None
                }
                Ok(Method::StartCanister)
                | Ok(Method::CanisterStatus)
                | Ok(Method::DeleteCanister)
                | Ok(Method::UninstallCode)
                | Ok(Method::StopCanister) => match CanisterIdRecord::decode(ingress.arg()) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => return Err(IngressInductionCostError::InvalidSubnetPayload),
                },
                Ok(Method::UpdateSettings) => match UpdateSettingsArgs::decode(ingress.arg()) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => return Err(IngressInductionCostError::InvalidSubnetPayload),
                },
                Ok(Method::SetController) => match SetControllerArgs::decode(ingress.arg()) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => return Err(IngressInductionCostError::InvalidSubnetPayload),
                },
                Ok(Method::InstallCode) => match InstallCodeArgs::decode(ingress.arg()) {
                    Ok(record) => Some(record.get_canister_id()),
                    Err(_) => return Err(IngressInductionCostError::InvalidSubnetPayload),
                },
                Ok(Method::CreateCanister)
                | Ok(Method::SetupInitialDKG)
                | Ok(Method::DepositFunds)
                | Ok(Method::DepositCycles)
                | Ok(Method::RawRand)
                | Err(_) => {
                    return Err(IngressInductionCostError::UnknownSubnetMethod);
                }
            }
        } else {
            // A message to a canister is always paid for by the receiving canister.
            Some(ingress.canister_id())
        };

        match paying_canister {
            Some(paying_canister) => {
                let bytes_to_charge = ingress.arg().len()
                    + ingress.method_name().len()
                    + ingress.nonce().map(|n| n.len()).unwrap_or(0);
                let cost = self.config.ingress_message_reception_fee
                    + self.config.ingress_byte_reception_fee * bytes_to_charge;
                Ok(IngressInductionCost::Fee {
                    payer: paying_canister,
                    cost,
                })
            }
            None => Ok(IngressInductionCost::Free),
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    //
    // Storage
    //
    ////////////////////////////////////////////////////////////////////////////

    /// Subtracts the cycles cost of using a `bytes` amount of memory.
    ///
    /// Note: The following charges for memory taken by the canister. It
    /// currently takes into account all the pages in the canister's heap and
    /// stable memory (among other things). This will be revised in the future
    /// to take into account charging for dirty/read pages by the canister.
    ///
    /// # Errors
    ///
    /// Returns a `CyclesAccountError::CanisterOutOfCycles` if there's
    /// not enough cycles to charge for memory.
    pub fn charge_for_memory(
        &self,
        system_state: &mut SystemState,
        bytes: NumBytes,
        duration: Duration,
    ) -> Result<(), CyclesAccountError> {
        let cycles_amount = self.memory_cost(bytes, duration);

        // Can charge all the way to the empty account (zero cycles)
        system_state
            .cycles_account
            .consume_with_threshold(cycles_amount, Cycles::from(0))
    }

    /// The cost of using `bytes` worth of memory.
    #[doc(hidden)] // pub for usage in tests
    pub fn memory_cost(&self, bytes: NumBytes, duration: Duration) -> Cycles {
        let one_gib = 1024 * 1024 * 1024;
        Cycles::from(
            (bytes.get() as u128
                * self.config.gib_storage_per_second_fee.get()
                * duration.as_secs() as u128)
                / one_gib,
        )
    }

    ////////////////////////////////////////////////////////////////////////////
    //
    // Request
    //
    ////////////////////////////////////////////////////////////////////////////

    /// When sending a request it's necessary to pay for:
    ///   * The network cost of sending the request payload, which depends on
    ///     the size (bytes) of the request.
    ///   * The max cycles `max_num_instructions` that would be required to
    ///     process the `Response`.
    ///   * The max network cost of receiving the response, since we don't know
    ///     yet the exact size the response will have.
    ///
    /// The leftover cycles is reimbursed after the `Response` for this request
    /// is received and executed. Only at that point will be known how much
    /// cycles receiving and executing the `Response` costs exactly.
    ///
    /// # Errors
    ///
    /// Returns a `CyclesAccountError::CanisterOutOfCycles` if there is
    /// not enough cycles available to send the `Request`.
    pub fn withdraw_request_cycles(
        &self,
        system_state: &mut SystemState,
        canister_current_memory_usage: NumBytes,
        canister_compute_allocation: ComputeAllocation,
        request: &Request,
    ) -> Result<(), CyclesAccountError> {
        // The total amount charged is the fee to do the xnet call (request +
        // response) + the fee to send the request + the fee for the largest
        // possible response + the fee for executing the largest allowed
        // response when it eventually arrives.
        let fee = self.config.xnet_call_fee
            + self.config.xnet_byte_transmission_fee
                * Cycles::from(request.payload_size_bytes().get())
            + self.config.xnet_byte_transmission_fee
                * Cycles::from(MAX_INTER_CANISTER_PAYLOAD_IN_BYTES.get())
            + self.execution_cost(self.max_num_instructions);
        system_state.cycles_account.consume_with_threshold(
            fee,
            freeze_threshold_cycles(
                canister_current_memory_usage,
                system_state.memory_allocation,
                self.config.gib_storage_per_second_fee,
                canister_compute_allocation,
                self.config.compute_percent_allocated_per_second_fee,
                system_state.freeze_threshold,
            ),
        )
    }

    /// Refunds the cycles from the response. In particular, adds leftover
    /// cycles from the what was reserved when the corresponding `Request` was
    /// sent earlier.
    pub fn response_cycles_refund(&self, system_state: &mut SystemState, response: &mut Response) {
        // We originally charged for the maximum number of bytes possible so
        // figure out how many extra bytes we chared for.
        let extra_bytes = MAX_INTER_CANISTER_PAYLOAD_IN_BYTES - response.response_payload.size_of();
        let cycles_to_refund =
            self.config.xnet_byte_transmission_fee * Cycles::from(extra_bytes.get());
        self.refund_cycles(system_state, cycles_to_refund);
    }

    ////////////////////////////////////////////////////////////////////////////
    //
    // Utility functions
    //
    ////////////////////////////////////////////////////////////////////////////

    /// Amount of cycles above the level reserved for storage costs
    pub fn cycles_balance_above_storage_reserve(
        &self,
        system_state: &SystemState,
        canister_current_memory_usage: NumBytes,
        canister_compute_allocation: ComputeAllocation,
    ) -> Cycles {
        let cycles_storage_reserve = freeze_threshold_cycles(
            canister_current_memory_usage,
            system_state.memory_allocation,
            self.config.gib_storage_per_second_fee,
            canister_compute_allocation,
            self.config.compute_percent_allocated_per_second_fee,
            system_state.freeze_threshold,
        );

        if system_state.cycles_account.cycles_balance() > cycles_storage_reserve {
            system_state.cycles_account.cycles_balance() - cycles_storage_reserve
        } else {
            Cycles::from(0)
        }
    }

    fn refund_cycles(&self, system_state: &mut SystemState, cycles: Cycles) {
        system_state.cycles_account.refund_cycles(cycles);
    }

    /// Returns the maximum amount of `Cycles` that can be added to a canister's
    /// balance taking into account the `max_cycles_per_canister` value if
    /// present.
    pub fn check_max_cycles_can_add(
        &self,
        system_state: &SystemState,
        cycles_to_add: Cycles,
    ) -> Cycles {
        match self.own_subnet_type {
            SubnetType::System => cycles_to_add,
            SubnetType::Application | SubnetType::VerifiedApplication => {
                match self.max_cycles_per_canister {
                    None => cycles_to_add,
                    Some(max_cycles) => std::cmp::min(
                        cycles_to_add,
                        max_cycles - system_state.cycles_account.cycles_balance(),
                    ),
                }
            }
        }
    }

    /// Adds `cycles` worth of cycles to the canister's balance.
    /// The cycles balance added in a single go is limited to u64::max_value()
    pub fn add_cycles(&self, system_state: &mut SystemState, cycles_to_add: Cycles) {
        let cycles = self.check_max_cycles_can_add(system_state, cycles_to_add);
        system_state.cycles_account.add_cycles(cycles);
    }

    /// Mints `amount_to_mint` [`Cycles`].
    ///
    /// # Errors
    /// Returns a `CyclesAccountManagerError::ContractViolation` if not on a
    /// system subnet.
    pub fn mint_cycles(
        &self,
        system_state: &mut SystemState,
        amount_to_mint: Cycles,
    ) -> Result<(), CyclesAccountManagerError> {
        match self.own_subnet_type {
            SubnetType::Application | SubnetType::VerifiedApplication => {
                let error_str =
                    "ic0.mint_cycles cannot be executed. Should only be called by a canister on the NNS subnet: {}".to_string();
                Err(CyclesAccountManagerError::ContractViolation(error_str))
            }
            SubnetType::System => {
                self.add_cycles(system_state, amount_to_mint);
                Ok(())
            }
        }
    }

    /// Returns the cost of the provided `num_instructions` in `Cycles`.
    ///
    /// Note that this function is made public to facilitate some logistic in
    /// tests.
    #[doc(hidden)]
    pub fn execution_cost(&self, num_instructions: NumInstructions) -> Cycles {
        self.config.update_message_execution_fee
            + self.config.ten_update_instructions_execution_fee
                * Cycles::from(num_instructions.get() / 10)
    }

    /// Charges a canister for its resource allocation and usage for the
    /// duration specified. If fees were successfully charged, then returns
    /// Ok(CanisterState) else returns Err(CanisterState).
    pub fn charge_canister_for_resource_allocation_and_usage(
        &self,
        log: &ReplicaLogger,
        mut canister: CanisterState,
        duration_between_blocks: Duration,
    ) -> Result<CanisterState, CanisterState> {
        match canister.memory_allocation() {
            // The canister has explicitly asked for a memory allocation, so charge
            // based on it accordingly.
            Some(memory_allocation) => {
                if let Err(err) = self.charge_for_memory(
                    &mut canister.system_state,
                    memory_allocation,
                    duration_between_blocks,
                ) {
                    info!(
                        log,
                        "Charging canister {} for memory allocation failed with {}",
                        canister.canister_id(),
                        err
                    );
                    return Err(canister);
                }
            }
            // The canister has not requested a memory allocation, so charge according
            // to its current memory usage.
            None => {
                let memory_usage = canister.memory_usage();
                if let Err(err) = self.charge_for_memory(
                    &mut canister.system_state,
                    memory_usage,
                    duration_between_blocks,
                ) {
                    info!(
                        log,
                        "Charging canister {} for memory usage failed with {}",
                        canister.canister_id(),
                        err
                    );
                    return Err(canister);
                }
            }
        }

        let compute_allocation = canister.compute_allocation();
        if let Err(err) = self.charge_for_compute_allocation(
            &mut canister.system_state,
            compute_allocation,
            duration_between_blocks,
        ) {
            info!(
                log,
                "Charging canister {} for compute allocation failed with {}",
                canister.canister_id(),
                err
            );
            return Err(canister);
        }
        Ok(canister)
    }
}

/// Encapsulates the payer and cost of inducting an ingress messages.
#[derive(Debug, Eq, PartialEq)]
pub enum IngressInductionCost {
    /// Induction is free.
    Free,
    /// Induction cost and the canister to pay for it.
    Fee { payer: CanisterId, cost: Cycles },
}

impl IngressInductionCost {
    /// Returns the cost of inducting an ingress message in [`Cycles`].
    pub fn cost(&self) -> Cycles {
        match self {
            Self::Free => Cycles::from(0),
            Self::Fee { cost, .. } => *cost,
        }
    }
}

/// Errors returned when computing the cost of receiving an ingress.
#[derive(Debug, Eq, PartialEq)]
pub enum IngressInductionCostError {
    UnknownSubnetMethod,
    InvalidSubnetPayload,
}
