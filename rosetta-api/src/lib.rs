pub mod convert;
pub mod ledger_client;
pub mod models;
pub mod rosetta_server;
pub mod store;

use crate::convert::account_from_public_key;
use crate::convert::operations;
use crate::convert::{
    from_arg, from_hex, from_model_account_identifier, from_model_transaction_identifier,
    from_public_key, internal_error, into_error, make_read_state_from_update,
    to_model_account_identifier, transaction_id,
};
use crate::ledger_client::LedgerAccess;

use crate::store::HashedBlock;

use convert::to_arg;
use ic_interfaces::crypto::DOMAIN_IC_REQUEST;
use ic_types::messages::{
    Blob, HttpCanisterUpdate, HttpReadContent, HttpRequestEnvelope, HttpSubmitContent,
};
use ic_types::time;
use ic_types::{messages::MessageId, CanisterId, PrincipalId};

use models::*;

use ledger_canister::{BlockHeight, Memo, SendArgs, Transfer, TRANSACTION_FEE};
use serde_json::map::Map;
use std::convert::TryFrom;

use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, warn};

pub const API_VERSION: &str = "1.4.10";
pub const NODE_VERSION: &str = "1.0.2";

fn to_index(height: BlockHeight) -> Result<i128, ApiError> {
    i128::try_from(height).map_err(|_| ApiError::InternalError(true, None))
}

fn verify_network_id(canister_id: &CanisterId, net_id: &NetworkIdentifier) -> Result<(), ApiError> {
    match net_id.blockchain.as_str() {
        "Internet Computer" => (),
        _ => return Err(ApiError::InvalidNetworkId(false, None)),
    }

    let id = hex::decode(&net_id.network)
        .ok()
        .and_then(|x| PrincipalId::try_from(x.as_slice()).ok())
        .and_then(|x| CanisterId::try_from(x).ok())
        .ok_or(ApiError::InvalidNetworkId(false, None))?;

    if *canister_id != id {
        return Err(ApiError::InvalidNetworkId(false, None));
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
    Ok(convert::block_id(&parent)?)
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

fn decode_hex(s: &str) -> Result<Vec<u8>, ApiError> {
    hex::decode(s).map_err(|err| internal_error(format!("Could not hex-decode string: {}", err)))
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

        let icp = blocks
            .get_balances_at(block.index)?
            .account_balance(&account_id);
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

        let ConstructionCombineRequest {
            unsigned_transaction,
            signatures,
            ..
        } = msg;

        let mut signatures_by_sig_data: HashMap<Vec<u8>, _> = HashMap::new();

        for sig in &signatures {
            let sig_data = decode_hex(&sig.signing_payload.hex_bytes)?;
            signatures_by_sig_data.insert(sig_data, sig);
        }

        let unsigned_transaction: UnsignedTransaction =
            serde_cbor::from_slice(&decode_hex(&unsigned_transaction)?).map_err(|_| {
                internal_error("Could not deserialize unsigned transaction".to_string())
            })?;

        let mut envelopes = vec![];

        for ingress_expiry in unsigned_transaction.ingress_expiries {
            let mut update = unsigned_transaction.update.clone();
            update.ingress_expiry = ingress_expiry;

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

            assert_eq!(transaction_signature.signature_type, SignatureType::ED25519);
            assert_eq!(read_state_signature.signature_type, SignatureType::ED25519);

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

            envelopes.push((envelope, read_state_envelope));
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

        let pk = msg.public_key;

        if pk.curve_type != CurveType::EDWARDS25519 {
            return Err(ApiError::InvalidPublicKey(
                false,
                into_error("Only EDWARDS25519 curve type is supported".to_string()),
            ));
        }

        let account_identifier = Some(account_from_public_key(pk)?);
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
        let envelopes: Envelopes = serde_cbor::from_slice(&decode_hex(&msg.signed_transaction)?)
            .map_err(internal_error)?;

        Ok(ConstructionHashResponse {
            transaction_identifier: transaction_id(&envelopes[0].0)?,
            metadata: Map::new(),
        })
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

        let ConstructionParseRequest {
            signed,
            transaction,
            ..
        } = msg;

        let update: HttpCanisterUpdate = if signed {
            let parsed: Envelopes =
                serde_cbor::from_slice(&decode_hex(&transaction)?).map_err(internal_error)?;
            match parsed[0].0.content.clone() {
                HttpSubmitContent::Call { update } => update,
            }
        } else {
            let parsed: UnsignedTransaction =
                serde_cbor::from_slice(&decode_hex(&transaction)?).map_err(internal_error)?;
            parsed.update
        };

        let from = PrincipalId::try_from(update.sender.0)
            .map_err(|e| internal_error(e.to_string()))?
            .into();
        let from_ai = if signed {
            vec![to_model_account_identifier(&from)]
        } else {
            Vec::new()
        };

        // This is always a transaction
        let SendArgs {
            amount, fee, to, ..
        } = from_arg(update.arg.0)?;

        let operations = operations(
            &Transfer::Send {
                from,
                to,
                amount,
                fee,
            },
            false,
        )?;

        Ok(ConstructionParseResponse {
            operations,
            signers: None,
            account_identifier_signers: Some(from_ai),
            metadata: None,
        })
    }

    /// Generate an Unsigned Transfer and Signing Payloads
    /// The unsigned_transaction returned from this function is a CBOR
    /// serialized HttpCanisterUpdate The data to be signed is a single hex
    /// encoded MessageId
    // Currently we insist that there is only one transaction encoded in these
    // operations otherwise the hash operation will not work. This restriction can
    // be loosened if required but it requires us to build transaction hashes into
    // the canister code.
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
        let transactions = convert::from_operations(ops, false)?;
        let tl = transactions.len();
        let pl = pks.len();
        if tl != pl {
            return Err(internal_error(format!(
                "Expected {} public keys in 'public_keys' but found {} keys",
                tl, pl
            )));
        }

        let interval = ic_types::ingress::MAX_INGRESS_TTL
            - ic_types::ingress::PERMITTED_DRIFT
            - Duration::from_secs(120);

        let ingress_start = msg
            .metadata
            .as_ref()
            .and_then(|obj| obj.get("ingress_start"))
            .and_then(|field| field.as_u64())
            .map(time::Time::from_nanos_since_unix_epoch)
            .unwrap_or_else(time::current_time);
        let ingress_end = msg
            .metadata
            .as_ref()
            .and_then(|obj| obj.get("ingress_end"))
            .and_then(|field| field.as_u64())
            .map(time::Time::from_nanos_since_unix_epoch)
            .unwrap_or_else(|| ingress_start + interval);
        let created_at_time: ledger_canister::TimeStamp = msg
            .metadata
            .as_ref()
            .and_then(|obj| obj.get("created_at_time"))
            .and_then(|field| field.as_u64())
            .map(ledger_canister::TimeStamp::from_nanos_since_unix_epoch)
            .unwrap_or_else(|| std::time::SystemTime::now().into());
        let memo: Memo = msg
            .metadata
            .as_ref()
            .and_then(|obj| obj.get("memo"))
            .and_then(|field| field.as_u64())
            .map(Memo)
            .unwrap_or_else(|| Memo(rand::thread_rng().gen()));

        let mut payloads: Vec<_> = transactions
            .into_iter()
            .zip(pks.into_iter())
            .map(|(t, pk)| match t {
                Transfer::Send {
                    from,
                    to,
                    amount,
                    fee,
                } => {
                    let pid: PrincipalId = convert::principal_id_from_public_key(pk.clone())?;
                    let expected_from: ledger_canister::AccountIdentifier = pid.into();
                    if expected_from != from {
                        return Err(internal_error(format!(
                            "Public key {:?} expected a transaction send by account identifier {} but found account identifier {}",
                            pk, expected_from, from,
                        )));
                    }

                    // What we send to the canister
                    let send_args = SendArgs {
                        memo,
                        amount,
                        fee,
                        from_subaccount: None,
                        to,
                        created_at_time: Some(created_at_time),
                    };

                    let account_identifier = to_model_account_identifier(&from);

                    let mut update = HttpCanisterUpdate {
                        canister_id: Blob(self.ledger.ledger_canister_id().get().to_vec()),
                        method_name: "send_pb".to_string(),
                        arg: Blob(to_arg(send_args)),
                        // TODO work out whether Rosetta will accept us generating a nonce here
                        // If we don't have a nonce it could cause one of those nasty bugs that
                        // doesn't show it's face until you try to do two
                        // identical transactions at the same time
                        nonce: None,
                        sender: Blob(pid.into_vec()),
                        // sender: Blob(from.into_vec()),
                        ingress_expiry: 0,
                    };

                    let mut payloads = vec![];
                    let mut ingress_expiries = vec![];

                    let mut now = ingress_start;

                    while now < ingress_end {
                        update.ingress_expiry =
                            (now + ic_types::ingress::MAX_INGRESS_TTL
                             - ic_types::ingress::PERMITTED_DRIFT).as_nanos_since_unix_epoch();

                        let message_id = update.id();

                        let transaction_payload = SigningPayload {
                            address: None,
                            account_identifier: Some(account_identifier.clone()),
                            hex_bytes: hex::encode(make_sig_data(&message_id)),
                            signature_type: Some(SignatureType::ED25519),
                        };

                        payloads.push(transaction_payload);

                        let read_state = make_read_state_from_update(&update);

                        let read_state_message_id =
                            MessageId::from(read_state.representation_independent_hash());

                        let read_state_payload = SigningPayload {
                            address: None,
                            account_identifier: Some(account_identifier.clone()),
                            hex_bytes: hex::encode(make_sig_data(&read_state_message_id)),
                            signature_type: Some(SignatureType::ED25519),
                        };

                        payloads.push(read_state_payload);
                        ingress_expiries.push(update.ingress_expiry);

                        now += interval;
                    }

                    let unsigned_transaction = UnsignedTransaction {
                        update,
                        ingress_expiries,
                    };

                    let unsigned_transaction: String =
                        hex::encode(serde_cbor::to_vec(&unsigned_transaction).unwrap());

                    Ok((
                        unsigned_transaction,
                        payloads
                    ))
                }
                _ => panic!("This should be impossible"),
            })
            .collect::<Result<Vec<_>, ApiError>>()?;

        // TODO remove this restriction
        if payloads.len() == 1 {
            let (unsigned_transaction, payloads) = payloads.pop().unwrap();

            Ok(models::ConstructionPayloadsResponse {
                payloads,
                unsigned_transaction,
            })
        } else {
            Err(ApiError::InvalidTransaction(
                false,
                into_error(format!(
                    "Currently exactly a single transaction can be constructed at a time: found {:?}",
                    &payloads
                )),
            ))
        }
    }

    /// Create a Request to Fetch Metadata
    pub async fn construction_preprocess(
        &self,
        msg: models::ConstructionPreprocessRequest,
    ) -> Result<ConstructionPreprocessResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let transfers = convert::from_operations(msg.operations, true)?;
        let required_public_keys: Result<Vec<models::AccountIdentifier>, ApiError> = transfers
            .into_iter()
            .map(|transfer| match transfer {
                Transfer::Send { from, .. } => Ok(to_model_account_identifier(&from)),
                _ => Err(internal_error(
                    "Mint/Burn operations are not supported through rosetta",
                )),
            })
            .collect();
        Ok(ConstructionPreprocessResponse {
            required_public_keys: Some(required_public_keys?),
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

        let envelopes: Envelopes = serde_cbor::from_slice(&decode_hex(&msg.signed_transaction)?)
            .map_err(|e| {
                internal_error(format!(
                    "Cannot deserialize the submit request in CBOR format because of: {}",
                    e
                ))
            })?;

        let (transaction_identifier, block_index) = self.ledger.submit(envelopes).await?;

        Ok(ConstructionSubmitResponse {
            transaction_identifier,
            block_index,
            metadata: Map::new(),
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
            let cur_chain_length = self.ledger.chain_length().await;

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
            tokio::time::delay_for(Duration::from_secs(1)).await;
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
                ],
                vec![
                    Error::new(&ApiError::InternalError(true, None)),
                    Error::new(&ApiError::InvalidRequest(false, None)),
                    Error::new(&ApiError::NotAvailableOffline(false, None)),
                    Error::new(&ApiError::InvalidNetworkId(false, None)),
                    Error::new(&ApiError::InvalidAccountId(false, None)),
                    Error::new(&ApiError::InvalidBlockId(false, None)),
                    Error::new(&ApiError::InvalidPublicKey(false, None)),
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
        let opt_msg_tid = msg
            .transaction_identifier
            .clone()
            .and_then(|tid| from_model_transaction_identifier(&tid).ok());
        let opt_msg_acc = msg
            .account_identifier
            .and_then(|aid| from_model_account_identifier(&aid).ok());
        let blocks = self.ledger.read_blocks().await;
        let mut heights: Vec<BlockHeight> = Vec::new();
        match opt_msg_tid {
            Some(msg_tid) => blocks
                .tx_hash_location
                .get(&msg_tid)
                .into_iter()
                .for_each(|h| heights.push(*h)),
            None => {
                if let Some(msg_acc) = opt_msg_acc {
                    blocks
                        .account_location
                        .get(&msg_acc)
                        .into_iter()
                        .for_each(|v| heights = v.clone());
                }
            }
        }
        let mut txs: Vec<BlockTransaction> = Vec::new();
        let first_idx = blocks
            .first_verified()?
            .ok_or(ApiError::BlockchainEmpty(true, None))?
            .index;
        let last_idx = blocks
            .last_verified()?
            .ok_or(ApiError::BlockchainEmpty(true, None))?
            .index;
        for i in heights {
            if i < first_idx || i > last_idx {
                continue;
            }
            let hb = blocks.get_verified_at(i)?;
            txs.push(BlockTransaction::new(
                convert::block_id(&hb)?,
                convert::transaction(&hb)?,
            ));
        }
        let total_count = txs.len() as i64;
        Ok(SearchTransactionsResponse::new(txs, total_count))
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
