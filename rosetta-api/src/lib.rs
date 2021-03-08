pub mod convert;
pub mod ledger_client;
pub mod models;
pub mod rosetta_server;
pub mod store;

use crate::convert::account_from_public_key;
use crate::convert::operations;
use crate::convert::{
    account_identifier, from_arg, from_hex, from_public_key, internal_error, into_error, to_hex,
    transaction_id,
};
use crate::ledger_client::LedgerAccess;

use crate::store::HashedBlock;

use convert::{from_metadata, into_metadata, to_arg};
use ic_interfaces::crypto::DOMAIN_IC_REQUEST;
use ic_types::messages::{Blob, HttpCanisterUpdate, HttpRequestEnvelope, HttpSubmitContent};
use ic_types::time::current_time_and_expiry_time;
use ic_types::{CanisterId, PrincipalId};

use models::*;
use rand::Rng;

use ledger_canister::{BlockHeight, Memo, SendArgs, Serializable, Transfer, TRANSACTION_FEE};
use serde_json::{json, map::Map};
use std::convert::TryFrom;

use async_std::task::sleep;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use log::{debug, warn};

pub const API_VERSION: &str = "1.4.10";
pub const NODE_VERSION: &str = "1.0.2";
pub const MIDDLEWARE_VERSION: &str = "0.2.7";

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

    let parent = blocks.get_at(idx as u64)?;
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
            let hash: ledger_canister::HashOf<ledger_canister::Block> =
                convert::to_hash(&block_hash)?;
            if block_height < 0 {
                return Err(ApiError::InvalidBlockId(false, None));
            }
            let block = blocks.get_at(block_height as u64)?;

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
            blocks.get_at(idx as u64)?
        }
        Some(PartialBlockIdentifier {
            index: None,
            hash: Some(block_hash),
        }) => {
            let hash: ledger_canister::HashOf<ledger_canister::Block> =
                convert::to_hash(&block_hash)?;
            blocks.get(hash)?
        }
        Some(PartialBlockIdentifier {
            index: None,
            hash: None,
        })
        | None => blocks
            .last()?
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

        let canister_id = hex::decode(&msg.account_identifier.address)
            .ok()
            .and_then(|x| PrincipalId::try_from(x.as_slice()).ok())
            .and_then(|x| CanisterId::try_from(x).ok())
            .ok_or(ApiError::InvalidAccountId(false, None))?;

        let blocks = self.ledger.read_blocks().await;
        let block = get_block(&blocks, msg.block_identifier)?;

        let icp = blocks
            .get_balances(block.hash)?
            .account_balance(&canister_id.get());
        let amount = convert::amount_(icp)?;
        let b = convert::block_id(&block)?;
        Ok(AccountBalanceResponse::new(b, vec![amount]))
    }

    /// Get a Block
    pub async fn block(&self, msg: models::BlockRequest) -> Result<BlockResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let blocks = self.ledger.read_blocks().await;
        let b = get_block(&blocks, Some(msg.block_identifier))?;
        let b_id = convert::block_id(&b)?;
        let parent_id = create_parent_block_id(&blocks, &b)?;

        let txn = b.block.transaction();
        let t_id = convert::transaction_identifier(&txn.hash());
        let transactions = vec![convert::transaction(&txn.transfer, t_id)?];
        let block = Some(models::Block::new(
            b_id,
            parent_id,
            convert::timestamp(b.block.timestamp().into())?,
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
        let b = get_block(&blocks, b_id)?;

        let txn = b.block.transaction();
        let t_id = convert::transaction_identifier(&txn.hash());
        let transaction = convert::transaction(&txn.transfer, t_id)?;

        Ok(BlockTransactionResponse::new(transaction))
    }

    /// Create Network Transfer from Signatures
    // This returns HttpRequestEnvelope<HttpSubmitContent> encoded in a JSON string
    pub async fn construction_combine(
        &self,
        msg: models::ConstructionCombineRequest,
    ) -> Result<ConstructionCombineResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let ConstructionCombineRequest {
            unsigned_transaction,
            mut signatures,
            ..
        } = msg;

        let signature = if signatures.len() == 1 {
            signatures.pop().unwrap()
        } else {
            return
                Err(ApiError::InvalidTransaction(
                    false,
                    into_error(format!(
                        "Currently exactly a single signed transaction can be combined at a time: found {:?}",
                        &signatures
                    )),
                ));
        };

        let update = serde_json::from_str(&unsigned_transaction).map_err(|_| {
            ApiError::InternalError(
                false,
                into_error("Could not deserialize unsigned transaction".to_string()),
            )
        })?;

        let content = HttpSubmitContent::Call { update };

        let sender_sig = Some(Blob(from_hex(&signature.hex_bytes)?));
        assert_eq!(signature.signature_type, SignatureType::ED25519);
        let sender_pubkey = Some(Blob(ic_canister_client::ed25519_public_key_to_der(
            from_public_key(&signature.public_key)?,
        )));

        let envelope = HttpRequestEnvelope::<HttpSubmitContent> {
            content,
            sender_pubkey,
            sender_sig,
            sender_delegation: None,
        };

        let signed_transaction = serde_json::to_string(&envelope).map_err(|_| {
            ApiError::InternalError(
                false,
                into_error("Serialization of envelope failed".to_string()),
            )
        })?;

        Ok(ConstructionCombineResponse { signed_transaction })
    }

    /// Derive an AccountIdentifier from a PublicKey
    pub async fn construction_derive(
        &self,
        msg: models::ConstructionDeriveRequest,
    ) -> Result<ConstructionDeriveResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let pk = msg.public_key;

        let pk_der = PublicKey::new(
            to_hex(&ic_canister_client::ed25519_public_key_to_der(
                from_public_key(&pk)?,
            )),
            pk.curve_type,
        );
        // Do we need the curve?
        let account_identifier = Some(account_from_public_key(pk_der)?);
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
        let envelope: HttpRequestEnvelope<HttpSubmitContent> =
            serde_json::from_str(&msg.signed_transaction).map_err(internal_error)?;

        Ok(ConstructionHashResponse {
            transaction_identifier: transaction_id(envelope)?,
            metadata: Map::new(),
        })
    }

    /// Get Metadata for Transfer Construction
    pub async fn construction_metadata(
        &self,
        msg: models::ConstructionMetadataRequest,
    ) -> Result<ConstructionMetadataResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let last_index: BlockHeight = match self.ledger.read_blocks().await.last()? {
            Some(hb) => hb.index,
            None => 0,
        };
        let meta = into_metadata(last_index);
        let fee = TRANSACTION_FEE;
        let suggested_fee = Some(vec![convert::amount_(fee)?]);
        Ok(ConstructionMetadataResponse::new(meta, suggested_fee))
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
            let parsed: HttpRequestEnvelope<HttpSubmitContent> =
                serde_json::from_str(&transaction).map_err(internal_error)?;
            match parsed.content {
                HttpSubmitContent::Call { update } => update,
            }
        } else {
            serde_json::from_str(&transaction).map_err(internal_error)?
        };

        let from =
            PrincipalId::try_from(update.sender.0).map_err(|e| internal_error(e.to_string()))?;
        let from_ai = if signed {
            vec![account_identifier(&from)]
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
    /// The unsigned_transaction returned from this function is a JSON
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
        let transactions = convert::from_operations(ops)?;
        let mut payloads: Vec<_> = transactions
            .into_iter()
            .map(|t| match t {
                Transfer::Send {
                    from,
                    to,
                    amount,
                    fee,
                } => {
                    let mut rng = rand::thread_rng();
                    let memo: Memo = Memo(rng.gen());
                    let metadata = msg
                        .metadata
                        .clone()
                        .ok_or_else(|| internal_error("missing metadata"))?;
                    let height = from_metadata(metadata)?;

                    // What we send to the canister
                    let argument = to_arg(SendArgs {
                        memo,
                        amount,
                        fee,
                        from_subaccount: None,
                        to,
                        to_subaccount: None,
                        block_height: Some(height),
                    });

                    let expiry = current_time_and_expiry_time().1;

                    let update = HttpCanisterUpdate {
                        canister_id: Blob(self.ledger.ledger_canister_id().get().to_vec()),
                        method_name: "send".to_string(),
                        arg: Blob(argument),
                        // TODO work out whether Rosetta will accept us generating a nonce here
                        // If we don't have a nonce it could cause one of those nasty bugs that
                        // doesn't show it's face until you try to do two
                        // identical transactions at the same time
                        nonce: None,
                        sender: Blob(from.into_vec()),
                        ingress_expiry: expiry.as_nanos_since_unix_epoch(),
                    };

                    let unsigned_transaction: String = serde_json::to_string(&update).unwrap();

                    let message_id = update.id();

                    // Lifted from canister_client::agent::sign_message_id
                    let mut sig_data = vec![];
                    sig_data.extend_from_slice(DOMAIN_IC_REQUEST);
                    sig_data.extend_from_slice(message_id.as_bytes());

                    let payload = SigningPayload {
                        address: None,
                        account_identifier: Some(account_identifier(&from)),
                        hex_bytes: hex::encode(sig_data),
                        signature_type: Some(SignatureType::ED25519),
                    };

                    Ok((unsigned_transaction, payload))
                }
                _ => panic!("This should be impossible"),
            })
            .collect::<Result<Vec<_>, ApiError>>()?;

        // TODO remove this restriction
        if payloads.len() == 1 {
            let (unsigned_transaction, payload) = payloads.pop().unwrap();

            Ok(models::ConstructionPayloadsResponse {
                payloads: vec![payload],
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
        Ok(ConstructionPreprocessResponse::new())
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

        let request: HttpRequestEnvelope<HttpSubmitContent> =
            serde_json::from_str(&msg.signed_transaction).map_err(|e| {
                internal_error(format!(
                    "Cannot deserialize the submit request in JSON format because of: {}",
                    e
                ))
            })?;

        let transaction_identifier = self.ledger.submit(request).await?;

        Ok(ConstructionSubmitResponse {
            transaction_identifier,
            metadata: Map::new(),
        })
    }

    /// Wait until a new block appears that contains the specified
    /// transaction.
    pub async fn wait_for_transaction(
        &self,
        transaction_identifier: &TransactionIdentifier,
        mut prev_chain_length: BlockHeight,
        deadline: std::time::SystemTime,
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
                let block = get_block(
                    &blocks,
                    Some(PartialBlockIdentifier {
                        index: Some(idx as i64),
                        hash: None,
                    }),
                )?;
                let hash = block.block.transaction().hash();
                if convert::transaction_identifier(&hash) == *transaction_identifier {
                    return Ok(Some(idx));
                }
            }

            prev_chain_length = cur_chain_length;

            if SystemTime::now() > deadline {
                break;
            }
            sleep(Duration::from_secs(1)).await;
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

        // TODO use real struct
        // decide what to do with retriable flags in errors
        let resp = json!({
            "version": {
               "rosetta_version": API_VERSION,
               "node_version": NODE_VERSION,
               "middleware_version": MIDDLEWARE_VERSION,
               "metadata": {}
            },
            "allow": {
                "operation_statuses": [
                {
                    "status": "COMPLETED",
                    "successful": true
                }
                ],
                "operation_types": [
                    "BURN",
                    "MINT",
                    "TRANSACTION",
                    "FEE"
               ],
                "errors": [
                    ApiError::InternalError(true, None),
                    ApiError::InvalidRequest(false, None),
                    ApiError::InvalidNetworkId(false, None),
                    ApiError::InvalidAccountId(false, None),
                    ApiError::InvalidBlockId(false, None),
                    ApiError::MempoolTransactionMissing(false, None),
                    ApiError::BlockchainEmpty(false, None),
                    ApiError::InvalidTransaction(false, None),
                ],
                "historical_balance_lookup": true
            }
        });
        Ok(serde_json::from_value(resp).unwrap())
    }

    /// Get Network Status
    pub async fn network_status(
        &self,
        msg: models::NetworkRequest,
    ) -> Result<NetworkStatusResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let blocks = self.ledger.read_blocks().await;
        let first = blocks
            .first()?
            .ok_or(ApiError::BlockchainEmpty(true, None))?;
        let tip = blocks
            .last()?
            .ok_or(ApiError::BlockchainEmpty(true, None))?;
        let tip_id = convert::block_id(&tip)?;
        let tip_timestamp = convert::timestamp(tip.block.timestamp().into())?;
        // Block at index 0 has to be there if tip was present
        let genesis_block = blocks.get_at(0)?;
        let genesis_block_id = convert::block_id(&genesis_block)?;
        let peers = vec![];
        let oldest_block_id = if first.index != tip.index {
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
}
