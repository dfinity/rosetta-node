pub mod balance_book;
pub mod certification;
pub mod convert;
pub mod ledger_client;
pub mod models;
pub mod rosetta_server;
pub mod store;
pub mod time;

use crate::convert::{
    account_from_public_key, from_arg, from_hex, from_model_account_identifier,
    from_model_transaction_identifier, from_public_key, internal_error, into_error,
    invalid_request, make_read_state_from_update, neuron_account_from_public_key,
    neuron_subaccount_bytes_from_public_key, requests_to_operations, to_model_account_identifier,
    transaction_id, Request, Stake,
};
use crate::ledger_client::LedgerAccess;

use crate::store::HashedBlock;
use crate::time::Seconds;

use convert::to_arg;
use convert::{SetDissolveTimestamp, StartDissolve, StopDissolve};
use dfn_candid::CandidOne;
use ic_interfaces::crypto::DOMAIN_IC_REQUEST;
use ic_nns_governance::pb::v1::{
    manage_neuron::{self, configure, Command},
    ClaimOrRefreshNeuronFromAccount, ManageNeuron,
};
use ic_types::messages::{
    Blob, HttpCanisterUpdate, HttpReadContent, HttpRequestEnvelope, HttpSubmitContent,
};
use ic_types::{messages::MessageId, CanisterId, PrincipalId};
use on_wire::IntoWire;

use models::*;

use ledger_canister::{BlockHeight, Memo, SendArgs, Transfer, TRANSACTION_FEE};
use serde_json::{map::Map, value::Value};
use std::convert::TryFrom;

use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, warn};

pub const API_VERSION: &str = "1.4.10";
pub const NODE_VERSION: &str = "1.0.5";

fn to_index(height: BlockHeight) -> Result<i128, ApiError> {
    i128::try_from(height).map_err(|_| ApiError::InternalError(true, None))
}

fn verify_network_blockchain(net_id: &NetworkIdentifier) -> Result<(), ApiError> {
    match net_id.blockchain.as_str() {
        "Internet Computer" => Ok(()),
        _ => Err(ApiError::InvalidNetworkId(
            false,
            convert::into_error("unknown blockchain"),
        )),
    }
}

fn verify_network_id(canister_id: &CanisterId, net_id: &NetworkIdentifier) -> Result<(), ApiError> {
    verify_network_blockchain(net_id)?;

    let id: CanisterId = net_id.try_into()?;

    if *canister_id != id {
        return Err(ApiError::InvalidNetworkId(
            false,
            into_error("unknown network"),
        ));
    }

    Ok(())
}

// For the first block, we return the block itself as its parent
fn create_parent_block_id(
    blocks: &ledger_client::Blocks,
    block: &HashedBlock,
) -> Result<BlockIdentifier, ApiError> {
    let idx = std::cmp::max(0, to_index(block.index)? - 1);

    let parent = blocks.get_verified_at(idx as u64)?;
    convert::block_id(&parent)
}

fn get_block(
    blocks: &ledger_client::Blocks,
    block_id: Option<PartialBlockIdentifier>,
) -> Result<HashedBlock, ApiError> {
    let block = match block_id {
        Some(PartialBlockIdentifier {
            index: Some(block_height),
            hash: Some(block_hash),
        }) => {
            let hash: ledger_canister::HashOf<ledger_canister::EncodedBlock> =
                convert::to_hash(&block_hash)?;
            if block_height < 0 {
                return Err(ApiError::InvalidBlockId(false, None));
            }
            let block = blocks.get_verified_at(block_height as u64)?;

            if block.hash != hash {
                return Err(ApiError::InvalidBlockId(false, None));
            }

            block
        }
        Some(PartialBlockIdentifier {
            index: Some(block_height),
            hash: None,
        }) => {
            if block_height < 0 {
                return Err(ApiError::InvalidBlockId(false, None));
            }
            let idx = block_height as usize;
            blocks.get_verified_at(idx as u64)?
        }
        Some(PartialBlockIdentifier {
            index: None,
            hash: Some(block_hash),
        }) => {
            let hash: ledger_canister::HashOf<ledger_canister::EncodedBlock> =
                convert::to_hash(&block_hash)?;
            blocks.get_verified(hash)?
        }
        Some(PartialBlockIdentifier {
            index: None,
            hash: None,
        })
        | None => blocks
            .last_verified()?
            .ok_or(ApiError::BlockchainEmpty(false, None))?,
    };

    Ok(block)
}

#[derive(Clone)]
pub struct RosettaRequestHandler {
    ledger: Arc<dyn LedgerAccess + Send + Sync>,
}

impl RosettaRequestHandler {
    pub fn new<T: 'static + LedgerAccess + Send + Sync>(ledger: Arc<T>) -> Self {
        Self { ledger }
    }

    pub fn network_id(&self) -> NetworkIdentifier {
        let canister_id = self.ledger.ledger_canister_id();
        let net_id = hex::encode(canister_id.get().into_vec());
        NetworkIdentifier::new("Internet Computer".to_string(), net_id)
    }

    /// Get an Account Balance
    pub async fn account_balance(
        &self,
        msg: models::AccountBalanceRequest,
    ) -> Result<AccountBalanceResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let account_id = ledger_canister::AccountIdentifier::from_hex(
            &msg.account_identifier.address,
        )
        .map_err(|e| {
            convert::invalid_account_id(format!(
                "Account {} is not valid address, {}",
                &msg.account_identifier.address, e,
            ))
        })?;
        let blocks = self.ledger.read_blocks().await;
        let block = get_block(&blocks, msg.block_identifier)?;

        let icp = blocks.get_balance(&account_id, block.index)?;
        let amount = convert::amount_(icp)?;
        let b = convert::block_id(&block)?;
        Ok(AccountBalanceResponse::new(b, vec![amount]))
    }

    /// Get a Block
    pub async fn block(&self, msg: models::BlockRequest) -> Result<BlockResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let blocks = self.ledger.read_blocks().await;
        let hb = get_block(&blocks, Some(msg.block_identifier))?;
        let block = hb
            .block
            .decode()
            .map_err(|err| internal_error(format!("Cannot decode block: {}", err)))?;
        let b_id = convert::block_id(&hb)?;
        let parent_id = create_parent_block_id(&blocks, &hb)?;

        let transactions = vec![convert::transaction(&hb)?];
        let block = Some(models::Block::new(
            b_id,
            parent_id,
            convert::timestamp(block.timestamp.into())?,
            transactions,
        ));

        Ok(BlockResponse {
            block,
            other_transactions: None,
        })
    }

    /// Get a Block Transfer
    pub async fn block_transaction(
        &self,
        msg: models::BlockTransactionRequest,
    ) -> Result<BlockTransactionResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let blocks = self.ledger.read_blocks().await;
        let b_id = Some(PartialBlockIdentifier {
            index: Some(msg.block_identifier.index),
            hash: Some(msg.block_identifier.hash),
        });
        let hb = get_block(&blocks, b_id)?;

        let transaction = convert::transaction(&hb)?;

        Ok(BlockTransactionResponse::new(transaction))
    }

    /// Create Network Transfer from Signatures
    // This returns Envelopes encoded in a CBOR string
    pub async fn construction_combine(
        &self,
        msg: models::ConstructionCombineRequest,
    ) -> Result<ConstructionCombineResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let mut signatures_by_sig_data: HashMap<Vec<u8>, _> = HashMap::new();

        for sig in &msg.signatures {
            let sig_data = from_hex(&sig.signing_payload.hex_bytes)?;
            signatures_by_sig_data.insert(sig_data, sig);
        }

        let unsigned_transaction = msg.unsigned_transaction()?;

        let mut envelopes: SignedTransaction = vec![];

        for (request_type, update) in unsigned_transaction.updates {
            let mut request_envelopes = vec![];

            for ingress_expiry in &unsigned_transaction.ingress_expiries {
                let mut update = update.clone();
                update.ingress_expiry = *ingress_expiry;

                let read_state = make_read_state_from_update(&update);

                let transaction_signature = signatures_by_sig_data
                    .get(&make_sig_data(&update.id()))
                    .ok_or_else(|| {
                        internal_error("Could not find signature for transaction".to_string())
                    })?;
                let read_state_signature = signatures_by_sig_data
                    .get(&make_sig_data(&MessageId::from(
                        read_state.representation_independent_hash(),
                    )))
                    .ok_or_else(|| {
                        internal_error("Could not find signature for read-state".to_string())
                    })?;

                assert_eq!(transaction_signature.signature_type, SignatureType::Ed25519);
                assert_eq!(read_state_signature.signature_type, SignatureType::Ed25519);

                let envelope = HttpRequestEnvelope::<HttpSubmitContent> {
                    content: HttpSubmitContent::Call { update },
                    sender_pubkey: Some(Blob(ic_canister_client::ed25519_public_key_to_der(
                        from_public_key(&transaction_signature.public_key)?,
                    ))),
                    sender_sig: Some(Blob(from_hex(&transaction_signature.hex_bytes)?)),
                    sender_delegation: None,
                };

                let read_state_envelope = HttpRequestEnvelope::<HttpReadContent> {
                    content: HttpReadContent::ReadState { read_state },
                    sender_pubkey: Some(Blob(ic_canister_client::ed25519_public_key_to_der(
                        from_public_key(&read_state_signature.public_key)?,
                    ))),
                    sender_sig: Some(Blob(from_hex(&read_state_signature.hex_bytes)?)),
                    sender_delegation: None,
                };

                request_envelopes.push(EnvelopePair {
                    update: envelope,
                    read_state: read_state_envelope,
                });
            }

            envelopes.push((request_type, request_envelopes));
        }

        let envelopes = hex::encode(serde_cbor::to_vec(&envelopes).map_err(|_| {
            ApiError::InternalError(
                false,
                into_error("Serialization of envelope failed".to_string()),
            )
        })?);

        Ok(ConstructionCombineResponse {
            signed_transaction: envelopes,
        })
    }

    /// Derive an AccountIdentifier from a PublicKey
    pub async fn construction_derive(
        &self,
        msg: models::ConstructionDeriveRequest,
    ) -> Result<ConstructionDeriveResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let account_identifier = Some(account_from_public_key(&msg.public_key)?);

        Ok(ConstructionDeriveResponse {
            account_identifier,
            address: None,
            metadata: None,
        })
    }

    /// Derive a neuron account from a public key.
    pub async fn neuron_derive(
        &self,
        msg: models::ConstructionDeriveRequest,
    ) -> Result<ConstructionDeriveResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let account_identifier = Some(neuron_account_from_public_key(
            self.ledger.governance_canister_id(),
            &msg.public_key,
        )?);

        Ok(ConstructionDeriveResponse {
            account_identifier,
            address: None,
            metadata: None,
        })
    }

    /// Get the Hash of a Signed Transfer
    pub async fn construction_hash(
        &self,
        msg: models::ConstructionHashRequest,
    ) -> Result<ConstructionHashResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let envelopes = msg.signed_transaction()?;

        if let Some((request_type, envelope_pairs)) = envelopes.last() {
            Ok(ConstructionHashResponse {
                transaction_identifier: transaction_id(*request_type, &envelope_pairs[0].update)?,
                metadata: Map::new(),
            })
        } else {
            Err(ApiError::InvalidRequest(
                false,
                into_error("There is no hash for this transaction"),
            ))
        }
    }

    /// Get Metadata for Transfer Construction
    pub async fn construction_metadata(
        &self,
        msg: models::ConstructionMetadataRequest,
    ) -> Result<ConstructionMetadataResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let fee = TRANSACTION_FEE;
        let suggested_fee = Some(vec![convert::amount_(fee)?]);
        Ok(ConstructionMetadataResponse::new(Map::new(), suggested_fee))
    }

    /// Parse a Transfer
    pub async fn construction_parse(
        &self,
        msg: models::ConstructionParseRequest,
    ) -> Result<ConstructionParseResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let updates: Vec<_> = match msg.transaction()? {
            ParsedTransaction::Signed(envelopes) => envelopes
                .iter()
                .map(
                    |(request_type, updates)| match updates[0].update.content.clone() {
                        HttpSubmitContent::Call { update } => (*request_type, update),
                    },
                )
                .collect(),
            ParsedTransaction::Unsigned(unsigned_transaction) => unsigned_transaction.updates,
        };

        let mut requests = vec![];
        let mut from_ai = vec![];

        for (request_type, update) in updates {
            let from = PrincipalId::try_from(update.sender.0)
                .map_err(|e| internal_error(e.to_string()))?
                .into();
            if msg.signed {
                from_ai.push(from);
            }

            match request_type {
                RequestType::Send => {
                    let SendArgs {
                        amount, fee, to, ..
                    } = from_arg(update.arg.0)?;

                    requests.push(Request::Transfer(Transfer::Send {
                        from,
                        to,
                        amount,
                        fee,
                    }));
                }
                RequestType::CreateStake => {
                    let _: ClaimOrRefreshNeuronFromAccount =
                        candid::decode_one(update.arg.0.as_ref()).map_err(internal_error)?;
                    requests.push(Request::Stake(Stake { account: from }));
                }
                RequestType::SetDissolveTimestamp => {
                    let manage: ManageNeuron =
                        candid::decode_one(update.arg.0.as_ref()).map_err(internal_error)?;
                    let timestamp = Seconds(match manage.command {
                        Some(Command::Configure(manage_neuron::Configure {
                            operation:
                                Some(manage_neuron::configure::Operation::SetDissolveTimestamp(d)),
                        })) => Ok(d.dissolve_timestamp_seconds),
                        Some(e) => Err(internal_error(format!(
                            "Incompatible manage_neuron command: {:?}",
                            e
                        ))),
                        None => Err(internal_error("Missing manage_neuron command".to_string())),
                    }?);

                    requests.push(Request::SetDissolveTimestamp(SetDissolveTimestamp {
                        account: from,
                        timestamp,
                    }));
                }
                RequestType::StartDissolve => {
                    let manage: ManageNeuron =
                        candid::decode_one(update.arg.0.as_ref()).map_err(internal_error)?;
                    if !matches!(
                        manage.command,
                        Some(Command::Configure(manage_neuron::Configure {
                            operation: Some(manage_neuron::configure::Operation::StartDissolving(
                                manage_neuron::StartDissolving {},
                            )),
                        }))
                    ) {
                        return Err(internal_error(
                            "Incompatible manage_neuron command".to_string(),
                        ));
                    };
                    requests.push(Request::StartDissolve(StartDissolve { account: from }));
                }
                RequestType::StopDissolve => {
                    let manage: ManageNeuron =
                        candid::decode_one(update.arg.0.as_ref()).map_err(internal_error)?;
                    if !matches!(
                        manage.command,
                        Some(Command::Configure(manage_neuron::Configure {
                            operation: Some(manage_neuron::configure::Operation::StopDissolving(
                                manage_neuron::StopDissolving {},
                            )),
                        }))
                    ) {
                        return Err(internal_error(
                            "Incompatible manage_neuron command".to_string(),
                        ));
                    };
                    requests.push(Request::StopDissolve(StopDissolve { account: from }));
                }
            }
        }

        from_ai.sort();
        from_ai.dedup();
        let from_ai = from_ai.iter().map(to_model_account_identifier).collect();

        Ok(ConstructionParseResponse {
            operations: requests_to_operations(&requests)?,
            signers: None,
            account_identifier_signers: Some(from_ai),
            metadata: None,
        })
    }

    /// Generate an Unsigned Transfer and Signing Payloads. The
    /// unsigned_transaction returned from this function is a CBOR
    /// serialized UnsignedTransaction. The data to be signed is a
    /// single hex encoded MessageId.
    pub async fn construction_payloads(
        &self,
        msg: models::ConstructionPayloadsRequest,
    ) -> Result<ConstructionPayloadsResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let ops = msg.operations.clone();

        let pks = msg
            .public_keys
            .clone()
            .ok_or_else(|| internal_error("Expected field 'public_keys' to be populated"))?;
        let transactions = convert::from_operations(&ops, false)?;

        let interval = ic_types::ingress::MAX_INGRESS_TTL
            - ic_types::ingress::PERMITTED_DRIFT
            - Duration::from_secs(120);

        let ingress_start = msg
            .metadata
            .as_ref()
            .and_then(|obj| obj.get("ingress_start"))
            .and_then(|field| field.as_u64())
            .map(ic_types::time::Time::from_nanos_since_unix_epoch)
            .unwrap_or_else(ic_types::time::current_time);
        let ingress_end = msg
            .metadata
            .as_ref()
            .and_then(|obj| obj.get("ingress_end"))
            .and_then(|field| field.as_u64())
            .map(ic_types::time::Time::from_nanos_since_unix_epoch)
            .unwrap_or_else(|| ingress_start + interval);
        let created_at_time: ledger_canister::TimeStamp = msg
            .metadata
            .as_ref()
            .and_then(|obj| obj.get("created_at_time"))
            .and_then(|field| field.as_u64())
            .map(ledger_canister::TimeStamp::from_nanos_since_unix_epoch)
            .unwrap_or_else(|| std::time::SystemTime::now().into());
        // FIXME: the memo field needs to be associated with the operation
        let memo: Memo = msg
            .metadata
            .as_ref()
            .and_then(|obj| obj.get("memo"))
            .and_then(|field| field.as_u64())
            .map(Memo)
            .unwrap_or_else(|| Memo(rand::thread_rng().gen()));

        let mut ingress_expiries = vec![];
        let mut now = ingress_start;
        while now < ingress_end {
            let ingress_expiry = (now + ic_types::ingress::MAX_INGRESS_TTL
                - ic_types::ingress::PERMITTED_DRIFT)
                .as_nanos_since_unix_epoch();
            ingress_expiries.push(ingress_expiry);
            now += interval;
        }

        let mut updates = vec![];
        let mut payloads = vec![];

        let pks_map = pks
            .iter()
            .map(|pk| {
                let pid: PrincipalId = convert::principal_id_from_public_key(&pk)?;
                let account: ledger_canister::AccountIdentifier = pid.into();
                Ok((account, pk))
            })
            .collect::<Result<HashMap<_, _>, ApiError>>()?;

        fn add_payloads(
            payloads: &mut Vec<SigningPayload>,
            ingress_expiries: &[u64],
            account_identifier: &AccountIdentifier,
            update: &HttpCanisterUpdate,
        ) {
            for ingress_expiry in ingress_expiries {
                let mut update = update.clone();
                update.ingress_expiry = *ingress_expiry;

                let message_id = update.id();

                let transaction_payload = SigningPayload {
                    address: None,
                    account_identifier: Some(account_identifier.clone()),
                    hex_bytes: hex::encode(make_sig_data(&message_id)),
                    signature_type: Some(SignatureType::Ed25519),
                };

                payloads.push(transaction_payload);

                let read_state = make_read_state_from_update(&update);

                let read_state_message_id =
                    MessageId::from(read_state.representation_independent_hash());

                let read_state_payload = SigningPayload {
                    address: None,
                    account_identifier: Some(account_identifier.clone()),
                    hex_bytes: hex::encode(make_sig_data(&read_state_message_id)),
                    signature_type: Some(SignatureType::Ed25519),
                };

                payloads.push(read_state_payload);
            }
        }

        let add_neuron_management_payload =
            |request_type: RequestType,
             account: ledger_canister::AccountIdentifier,
             command: Command,
             payloads: &mut Vec<SigningPayload>,
             updates: &mut Vec<(RequestType, HttpCanisterUpdate)>|
             -> Result<(), ApiError> {
                let pk = pks_map.get(&account).ok_or_else(|| {
                    internal_error(format!(
                        "Cannot find public key for account identifier {}",
                        account,
                    ))
                })?;

                let neuron_subaccount = neuron_subaccount_bytes_from_public_key(&pk)?;

                let manage_neuron = ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(manage_neuron::NeuronIdOrSubaccount::Subaccount(
                        neuron_subaccount.to_vec(),
                    )),
                    command: Some(command),
                };

                let update = HttpCanisterUpdate {
                    canister_id: Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()),
                    method_name: "manage_neuron".to_string(),
                    arg: Blob(
                        CandidOne(manage_neuron)
                            .into_bytes()
                            .expect("Serialization failed"),
                    ),
                    nonce: None,
                    sender: Blob(convert::principal_id_from_public_key(&pk)?.into_vec()),
                    ingress_expiry: 0,
                };

                add_payloads(
                    payloads,
                    &ingress_expiries,
                    &to_model_account_identifier(&account),
                    &update,
                );

                updates.push((request_type, update));
                Ok(())
            };

        for t in transactions {
            match t {
                Request::Transfer(Transfer::Send {
                    from,
                    to,
                    amount,
                    fee,
                }) => {
                    let pk = pks_map.get(&from).ok_or_else(|| {
                        internal_error(format!(
                            "Cannot find public key for account identifier {}",
                            from,
                        ))
                    })?;

                    // The argument we send to the canister
                    let send_args = SendArgs {
                        memo,
                        amount,
                        fee,
                        from_subaccount: None,
                        to,
                        created_at_time: Some(created_at_time),
                    };

                    let update = HttpCanisterUpdate {
                        canister_id: Blob(self.ledger.ledger_canister_id().get().to_vec()),
                        method_name: "send_pb".to_string(),
                        arg: Blob(to_arg(send_args)),
                        // This nonce allows you to send two otherwise identical requests to the IC.
                        // We don't use a it here because we never want two transactions with
                        // identical tx IDs to both land on chain.
                        nonce: None,
                        sender: Blob(convert::principal_id_from_public_key(&pk)?.into_vec()),
                        ingress_expiry: 0,
                    };

                    add_payloads(
                        &mut payloads,
                        &ingress_expiries,
                        &to_model_account_identifier(&from),
                        &update,
                    );
                    updates.push((RequestType::Send, update));
                }
                Request::Stake(Stake { account }) => {
                    let pk = pks_map.get(&account).ok_or_else(|| {
                        internal_error(format!(
                            "Cannot find public key for account identifier {}",
                            account,
                        ))
                    })?;

                    // What we send to the governance canister
                    let args = ClaimOrRefreshNeuronFromAccount {
                        controller: None,
                        // Note: this requires the transfer to also
                        // use the default memo value (see
                        // neuron_account_from_public_key()).
                        memo: Memo::default().0,
                    };

                    let update = HttpCanisterUpdate {
                        canister_id: Blob(ic_nns_constants::GOVERNANCE_CANISTER_ID.get().to_vec()),
                        method_name: "claim_or_refresh_neuron_from_account".to_string(),
                        arg: Blob(CandidOne(args).into_bytes().expect("Serialization failed")),
                        // TODO work out whether Rosetta will accept us generating a nonce here
                        // If we don't have a nonce it could cause one of those nasty bugs that
                        // doesn't show it's face until you try to do two
                        // identical transactions at the same time
                        nonce: None,
                        sender: Blob(convert::principal_id_from_public_key(&pk)?.into_vec()),
                        ingress_expiry: 0,
                    };

                    add_payloads(
                        &mut payloads,
                        &ingress_expiries,
                        &to_model_account_identifier(&account),
                        &update,
                    );
                    updates.push((RequestType::CreateStake, update));
                }
                Request::StartDissolve(StartDissolve { account })
                | Request::StopDissolve(StopDissolve { account }) => {
                    let command = Command::Configure(manage_neuron::Configure {
                        operation: Some(if let Request::StartDissolve(_) = t {
                            manage_neuron::configure::Operation::StartDissolving(
                                manage_neuron::StartDissolving {},
                            )
                        } else {
                            manage_neuron::configure::Operation::StopDissolving(
                                manage_neuron::StopDissolving {},
                            )
                        }),
                    });

                    add_neuron_management_payload(
                        if let Request::StartDissolve(_) = t {
                            RequestType::StartDissolve
                        } else {
                            RequestType::StopDissolve
                        },
                        account,
                        command,
                        &mut payloads,
                        &mut updates,
                    )?;
                }
                Request::SetDissolveTimestamp(SetDissolveTimestamp { account, timestamp }) => {
                    let command = Command::Configure(manage_neuron::Configure {
                        operation: Some(configure::Operation::SetDissolveTimestamp(
                            manage_neuron::SetDissolveTimestamp {
                                dissolve_timestamp_seconds: Duration::from(timestamp).as_secs(),
                            },
                        )),
                    });

                    add_neuron_management_payload(
                        RequestType::SetDissolveTimestamp,
                        account,
                        command,
                        &mut payloads,
                        &mut updates,
                    )?;
                }
                _ => panic!("This should be impossible, unhandled request type."),
            }
        }

        Ok(models::ConstructionPayloadsResponse::new(
            &UnsignedTransaction {
                updates,
                ingress_expiries,
            },
            payloads,
        ))
    }

    /// Create a Request to Fetch Metadata
    pub async fn construction_preprocess(
        &self,
        msg: models::ConstructionPreprocessRequest,
    ) -> Result<ConstructionPreprocessResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let transfers = convert::from_operations(&msg.operations, true)?;
        let required_public_keys: Result<HashSet<ledger_canister::AccountIdentifier>, ApiError> =
            transfers
                .into_iter()
                .map(|transfer| match transfer {
                    Request::Transfer(Transfer::Send { from, .. }) => Ok(from),
                    Request::Stake(Stake { account, .. })
                    | Request::SetDissolveTimestamp(SetDissolveTimestamp { account, .. })
                    | Request::StartDissolve(StartDissolve { account })
                    | Request::StopDissolve(StopDissolve { account }) => Ok(account),
                    Request::Transfer(Transfer::Burn { .. }) => Err(invalid_request(
                        "Burn operations are not supported through rosetta",
                    )),
                    Request::Transfer(Transfer::Mint { .. }) => Err(invalid_request(
                        "Mint operations are not supported through rosetta",
                    )),
                })
                .collect();

        let keys: Vec<_> = required_public_keys?
            .into_iter()
            .map(|x| to_model_account_identifier(&x))
            .collect();

        Ok(ConstructionPreprocessResponse {
            required_public_keys: Some(keys),
            options: None,
        })
    }

    /// Submit a Signed Transfer
    // Normally we'd just use the canister client Agent for this but because this
    // request is constructed in such an odd way it's easier to just do it from
    // scratch
    pub async fn construction_submit(
        &self,
        msg: models::ConstructionSubmitRequest,
    ) -> Result<ConstructionSubmitResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let envelopes = msg.signed_transaction()?;

        let results = self.ledger.submit(envelopes).await?;

        let last_result = results
            .last()
            .ok_or_else(|| internal_error("Submit did not produce any results."))?;

        let mut metadata = Map::new();
        metadata.insert(
            "transactions".to_string(),
            Value::Array(
                results
                    .iter()
                    .map(|res| {
                        let mut m = Map::new();
                        m.insert(
                            "transaction_identifier".to_owned(),
                            Value::String(res.transaction_identifier.hash.to_owned()),
                        );
                        if let Some(block_index) = res.block_index {
                            m.insert("block_index".to_owned(), Value::Number(block_index.into()));
                        }
                        Value::Object(m)
                    })
                    .collect::<Vec<_>>(),
            ),
        );

        Ok(ConstructionSubmitResponse {
            transaction_identifier: last_result.transaction_identifier.clone(),
            block_index: last_result.block_index,
            metadata,
        })
    }

    /// Wait until a new block appears that contains the specified
    /// transaction.
    pub async fn wait_for_transaction(
        &self,
        transaction_identifier: &TransactionIdentifier,
        mut prev_chain_length: BlockHeight,
        deadline: std::time::Instant,
    ) -> Result<Option<BlockHeight>, ApiError> {
        debug!(
            "Waiting for transaction {:?} to appear...",
            transaction_identifier
        );

        loop {
            let cur_chain_length = self
                .ledger
                .read_blocks()
                .await
                .last_verified()?
                .map(|hb| hb.index + 1)
                .unwrap_or(0);

            for idx in prev_chain_length..cur_chain_length {
                debug!("Looking at block {}", idx);
                let blocks = self.ledger.read_blocks().await;
                let hb = get_block(
                    &blocks,
                    Some(PartialBlockIdentifier {
                        index: Some(idx as i64),
                        hash: None,
                    }),
                )?;
                let block = hb
                    .block
                    .decode()
                    .map_err(|err| internal_error(format!("Cannot decode block: {}", err)))?;
                let hash = block.transaction.hash();
                if convert::transaction_identifier(&hash) == *transaction_identifier {
                    return Ok(Some(idx));
                }
            }

            prev_chain_length = cur_chain_length;

            if Instant::now() > deadline {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        warn!(
            "Transaction {:?} did not appear within the deadline",
            transaction_identifier
        );

        Ok(None)
    }

    /// Get All Mempool Transactions
    pub async fn mempool(&self, msg: models::NetworkRequest) -> Result<MempoolResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        Ok(MempoolResponse::new(vec![]))
    }

    /// Get a Mempool Transfer
    pub async fn mempool_transaction(
        &self,
        msg: models::MempoolTransactionRequest,
    ) -> Result<MempoolTransactionResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        Err(ApiError::MempoolTransactionMissing(false, None))
    }

    /// Get List of Available Networks
    pub async fn network_list(
        &self,
        _metadata_request: models::MetadataRequest,
    ) -> Result<NetworkListResponse, ApiError> {
        let net_id = self.network_id();
        Ok(NetworkListResponse::new(vec![net_id]))
    }

    /// Get Network Options
    pub async fn network_options(
        &self,
        msg: models::NetworkRequest,
    ) -> Result<NetworkOptionsResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        Ok(NetworkOptionsResponse::new(
            Version::new(
                API_VERSION.to_string(),
                NODE_VERSION.to_string(),
                None,
                None,
            ),
            Allow::new(
                vec![OperationStatus::new("COMPLETED".to_string(), true)],
                vec![
                    "BURN".to_string(),
                    "MINT".to_string(),
                    "TRANSACTION".to_string(),
                    "FEE".to_string(),
                    "STAKE".to_string(),
                    "SET_DISSOLVE_TIMESTAMP".to_string(),
                    "START_DISSOLVING".to_string(),
                    "STOP_DISSOLVING".to_string(),
                ],
                vec![
                    Error::new(&ApiError::InternalError(true, None)),
                    Error::new(&ApiError::InvalidRequest(false, None)),
                    Error::new(&ApiError::NotAvailableOffline(false, None)),
                    Error::new(&ApiError::InvalidNetworkId(false, None)),
                    Error::new(&ApiError::InvalidAccountId(false, None)),
                    Error::new(&ApiError::InvalidBlockId(false, None)),
                    Error::new(&ApiError::InvalidPublicKey(false, None)),
                    Error::new(&ApiError::InvalidTransactionId(false, None)),
                    Error::new(&ApiError::MempoolTransactionMissing(false, None)),
                    Error::new(&ApiError::BlockchainEmpty(false, None)),
                    Error::new(&ApiError::InvalidTransaction(false, None)),
                    Error::new(&ApiError::ICError(false, None)),
                    Error::new(&ApiError::TransactionRejected(false, None)),
                    Error::new(&ApiError::TransactionExpired),
                ],
                true,
            ),
        ))
    }

    /// Get Network Status
    pub async fn network_status(
        &self,
        msg: models::NetworkRequest,
    ) -> Result<NetworkStatusResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let blocks = self.ledger.read_blocks().await;
        let first = blocks
            .first_verified()?
            .ok_or(ApiError::BlockchainEmpty(true, None))?;
        let tip = blocks
            .last_verified()?
            .ok_or(ApiError::BlockchainEmpty(true, None))?;
        let tip_id = convert::block_id(&tip)?;
        let tip_timestamp = convert::timestamp(tip.block.decode().unwrap().timestamp.into())?;
        // Block at index 0 has to be there if tip was present
        let genesis_block = blocks.get_verified_at(0)?;
        let genesis_block_id = convert::block_id(&genesis_block)?;
        let peers = vec![];
        let oldest_block_id = if first.index != 0 {
            Some(convert::block_id(&first)?)
        } else {
            None
        };
        let sync_status = SyncStatus::new(tip.index as i64, None);
        //let sync_status = SyncStatus::new(tip.index as i64, Some(true));
        //sync_status.target_index = Some(sync_status.current_index);

        Ok(NetworkStatusResponse::new(
            tip_id,
            tip_timestamp,
            genesis_block_id,
            oldest_block_id,
            sync_status,
            peers,
        ))
    }

    /// Search for a transaction given its hash
    pub async fn search_transactions(
        &self,
        msg: models::SearchTransactionsRequest,
    ) -> Result<SearchTransactionsResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        if let Some(Operator::Or) = msg.operator {
            return Err(invalid_request("Operator OR not supported"));
        }

        if msg.coin_identifier.is_some() {
            return Err(invalid_request("coin_identifier not supported"));
        }

        if msg.currency.is_some() {
            return Err(invalid_request("currency not supported"));
        }

        if msg.status.is_some() {
            return Err(invalid_request("status not supported"));
        }

        if msg._type.is_some() {
            return Err(invalid_request("type not supported"));
        }

        if msg.address.is_some() {
            return Err(invalid_request("address not supported"));
        }

        if msg.success.is_some() {
            return Err(invalid_request("success not supported"));
        }

        let max_block = match msg.max_block {
            Some(x) => Some(u64::try_from(x).map_err(|e| {
                ApiError::InvalidRequest(false, into_error(format!("Invalid max_block: {}", e)))
            })?),
            None => None,
        };

        let offset = match msg.offset {
            Some(x) => usize::try_from(x).map_err(|e| {
                ApiError::InvalidRequest(false, into_error(format!("Invalid offset: {}", e)))
            })?,
            None => 0,
        };

        let limit = match msg.limit {
            Some(x) => usize::try_from(x).map_err(|e| {
                ApiError::InvalidRequest(false, into_error(format!("Invalid limit: {}", e)))
            })?,
            None => usize::MAX,
        };
        let limit = std::cmp::min(limit, 10_000);

        let blocks = self.ledger.read_blocks().await;

        let last_idx = blocks
            .last_verified()?
            .ok_or(ApiError::BlockchainEmpty(true, None))?
            .index;

        let mut heights = Vec::new();
        let mut total_count = 0;

        if let Some(tid) = &msg.transaction_identifier {
            if msg.account_identifier.is_some() {
                return Err(invalid_request(
                    "Only one of transaction_identitier and account_identifier should be populated",
                ));
            }

            let tid = from_model_transaction_identifier(tid)
                .map_err(|e| ApiError::InvalidTransactionId(false, into_error(e)))?;

            if let Some(i) = blocks.tx_hash_location.get(&tid) {
                heights.push(*i);
                total_count += 1;
            }
        }

        let mut next_offset = None;

        if let Some(aid) = &msg.account_identifier {
            let acc = from_model_account_identifier(aid)
                .map_err(|e| ApiError::InvalidAccountId(false, into_error(e)))?;

            let hist = blocks.balance_book.store.get_history(&acc, max_block);
            heights = hist
                .iter()
                .rev()
                .map(|(h, _)| *h)
                .filter(|h| *h <= last_idx)
                .skip(offset)
                .collect();

            let cnt = offset
                .checked_add(heights.len())
                .ok_or_else(|| internal_error("total count overflow"))?;
            total_count = i64::try_from(cnt).map_err(internal_error)?;

            if heights.len() > limit {
                let next = offset
                    .checked_add(limit)
                    .ok_or_else(|| internal_error("offset + limit overflow"))?;
                next_offset = Some(i64::try_from(next).map_err(internal_error)?);
            }
            heights.truncate(limit);
        }

        let mut txs: Vec<BlockTransaction> = Vec::new();

        for i in heights {
            let hb = blocks.get_verified_at(i)?;
            txs.push(BlockTransaction::new(
                convert::block_id(&hb)?,
                convert::transaction(&hb)?,
            ));
        }

        Ok(SearchTransactionsResponse::new(
            txs,
            total_count,
            next_offset,
        ))
    }
}

pub fn make_sig_data(message_id: &MessageId) -> Vec<u8> {
    // Lifted from canister_client::agent::sign_message_id
    let mut sig_data = vec![];
    sig_data.extend_from_slice(DOMAIN_IC_REQUEST);
    sig_data.extend_from_slice(message_id.as_bytes());
    sig_data
}

pub enum CyclesResponse {
    CanisterCreated(CanisterId),
    CanisterToppedUp(),
    Refunded(String, Option<BlockHeight>),
}
