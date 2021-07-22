use crate::balance_book::BalanceBook;
use crate::certification::verify_block_hash;
use crate::convert::{ic_error, internal_error, into_error, invalid_block_id, transaction_id};
use crate::models::{
    ApiError, EnvelopePair, RequestType, SignedTransaction, TransactionIdentifier,
};
use crate::store::{BlockStore, BlockStoreError, HashedBlock, InMemoryStore, OnDiskStore};
use async_trait::async_trait;
use core::ops::Deref;
use dfn_protobuf::{ProtoBuf, ToProto};
use ic_canister_client::{Agent, HttpClient, Sender};
use ic_nns_governance::pb::v1::{
    claim_or_refresh_neuron_from_account_response::Result as ClaimOrRefreshResult,
    ClaimOrRefreshNeuronFromAccountResponse,
};
use ic_types::messages::{HttpSubmitContent, MessageId};
use ic_types::CanisterId;
use ic_types::{crypto::threshold_sig::ThresholdSigPublicKey, messages::SignedRequestBytes};
use ledger_canister::protobuf::ArchiveIndexResponse;
use ledger_canister::{
    protobuf::TipOfChainRequest, AccountIdentifier, BlockArg, BlockHeight, BlockRes, EncodedBlock,
    GetBlocksArgs, GetBlocksRes, HashOf, ICPTs, TipOfChainRes, Transaction,
};
use log::{debug, error, info, trace};
use on_wire::{FromWire, IntoWire};

use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use url::Url;

const PRUNE_DELAY: u64 = 1000;

#[async_trait]
pub trait LedgerAccess {
    // Maybe we should just return RwLockReadGuard explicitly and drop the Box
    async fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a>;
    async fn sync_blocks(&self, stopped: Arc<AtomicBool>) -> Result<(), ApiError>;
    fn ledger_canister_id(&self) -> &CanisterId;
    fn governance_canister_id(&self) -> &CanisterId;
    async fn submit(&self, _envelopes: SignedTransaction) -> Result<Vec<SubmitResult>, ApiError>;
}

pub struct SubmitResult {
    pub transaction_identifier: TransactionIdentifier,
    pub block_index: Option<BlockHeight>,
}

pub struct LedgerClient {
    blockchain: RwLock<Blocks>,
    canister_id: CanisterId,
    governance_canister_id: CanisterId,
    canister_access: Option<CanisterAccess>,
    ic_url: Url,
    store_max_blocks: Option<u64>,
    offline: bool,
    root_key: Option<ThresholdSigPublicKey>,
}

impl LedgerClient {
    pub async fn new(
        ic_url: Url,
        canister_id: CanisterId,
        governance_canister_id: CanisterId,
        block_store: Box<dyn BlockStore + Send + Sync>,
        store_max_blocks: Option<u64>,
        offline: bool,
        root_key: Option<ThresholdSigPublicKey>,
    ) -> Result<LedgerClient, ApiError> {
        let mut blocks = Blocks::new(block_store);
        let canister_access = if offline {
            None
        } else {
            let http_client = HttpClient::new();
            let canister_access = CanisterAccess::new(ic_url.clone(), canister_id, http_client);
            Self::verify_store(&blocks, &canister_access).await?;

            if root_key.is_some() {
                // verify if we have the right cerfiticate/we are connecting to the right
                // canister
                let TipOfChainRes {
                    tip_index,
                    certification,
                } = canister_access.query_tip().await?;

                let tip_block = canister_access
                    .query_raw_block(tip_index)
                    .await?
                    .expect("Blockchain in the ledger canister is empty");

                verify_block_hash(certification, tip_block.hash(), &root_key, &canister_id)
                    .map_err(internal_error)?;
            }

            Some(canister_access)
        };

        info!("Loading blocks from store");
        let num_loaded = blocks.load_from_store()?;

        info!(
            "Ledger client is up. Loaded {} blocks from store. First block at {}, last at {}",
            num_loaded,
            blocks
                .first()?
                .map(|x| format!("{}", x.index))
                .unwrap_or_else(|| "None".to_string()),
            blocks
                .last()?
                .map(|x| format!("{}", x.index))
                .unwrap_or_else(|| "None".to_string())
        );

        blocks.try_prune(&store_max_blocks, PRUNE_DELAY)?;

        Ok(Self {
            blockchain: RwLock::new(blocks),
            canister_id,
            governance_canister_id,
            canister_access,
            ic_url,
            store_max_blocks,
            offline,
            root_key,
        })
    }

    async fn verify_store(
        blocks: &Blocks,
        canister_access: &CanisterAccess,
    ) -> Result<(), ApiError> {
        debug!("Verifying store...");
        let first_block = blocks.block_store.first()?;

        match blocks.block_store.get_at(0) {
            Ok(store_genesis) => {
                let genesis = canister_access
                    .query_raw_block(0)
                    .await?
                    .expect("Blockchain in the ledger canister is empty");

                if store_genesis.hash != genesis.hash() {
                    let msg = format!(
                        "Genesis block from the store is different than \
                        in the ledger canister. Store hash: {}, canister hash: {}",
                        store_genesis.hash,
                        genesis.hash()
                    );
                    error!("{}", msg);
                    return Err(internal_error(msg));
                }
            }
            Err(BlockStoreError::NotFound(0)) => {
                if first_block.is_some() {
                    let msg = "Snapshot found, but genesis block not present in the store";
                    error!("{}", msg);
                    return Err(internal_error(msg));
                }
            }
            Err(e) => {
                let msg = format!("Error loading genesis block: {:?}", e);
                error!("{}", msg);
                return Err(internal_error(msg));
            }
        }

        if first_block.is_some() && first_block.as_ref().unwrap().index > 0 {
            let first_block = first_block.unwrap();
            let queried_block = canister_access.query_raw_block(first_block.index).await?;
            if queried_block.is_none() {
                let msg = format!(
                    "Oldest block snapshot does not match the block on \
                    the blockchain. Block with this index not found: {}",
                    first_block.index
                );
                error!("{}", msg);
                return Err(internal_error(msg));
            }
            let queried_block = queried_block.unwrap();
            if first_block.hash != queried_block.hash() {
                let msg = format!(
                    "Oldest block snapshot does not match the block on \
                    the blockchain. Index: {}, snapshot hash: {}, canister hash: {}",
                    first_block.index,
                    first_block.hash,
                    queried_block.hash()
                );
                error!("{}", msg);
                return Err(internal_error(msg));
            }
        }
        debug!("Verifying store done");

        Ok(())
    }
}

async fn send_post_request(
    http_client: &reqwest::Client,
    url: &str,
    body: Vec<u8>,
    timeout: Duration,
) -> Result<(Vec<u8>, reqwest::StatusCode), String> {
    let resp = http_client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(body)
        .timeout(timeout)
        .send()
        .await
        .map_err(|err| format!("sending post request failed with {}: ", err))?;
    let resp_status = resp.status();
    let resp_body = resp
        .bytes()
        .await
        .map_err(|err| format!("receive post response failed with {}: ", err))?
        .to_vec();
    Ok((resp_body, resp_status))
}

#[async_trait]
impl LedgerAccess for LedgerClient {
    async fn read_blocks(&self) -> Box<dyn Deref<Target = Blocks> + '_> {
        Box::new(self.blockchain.read().await)
    }

    async fn sync_blocks(&self, stopped: Arc<AtomicBool>) -> Result<(), ApiError> {
        if self.offline {
            return Err(ApiError::NotAvailableOffline(false, None));
        }
        let canister = self.canister_access.as_ref().unwrap();
        let TipOfChainRes {
            tip_index,
            certification,
        } = canister.query_tip().await?;
        let chain_length = tip_index + 1;

        if chain_length == 0 {
            return Ok(());
        }

        let mut blockchain = self.blockchain.write().await;

        let (mut last_block_hash, next_block_index) = match blockchain.synced_to() {
            Some((hash, index)) => (Some(hash), index + 1),
            None => (None, 0),
        };

        if next_block_index < chain_length {
            trace!(
                "Sync from: {}, chain_length: {}",
                next_block_index,
                chain_length
            );
        } else {
            if next_block_index > chain_length {
                trace!("Tip received from IC lower than what we already have (queried lagging replica?),
                 new chain length: {}, our {}", chain_length, next_block_index);
            }
            return Ok(());
        }

        let print_progress = if chain_length - next_block_index >= 1000 {
            info!(
                "Syncing {} blocks. New tip at {}",
                chain_length - next_block_index,
                chain_length - 1
            );
            true
        } else {
            false
        };

        let mut i = next_block_index;
        while i < chain_length {
            if stopped.load(Relaxed) {
                return Err(internal_error("Interrupted"));
            }

            let batch_len = 1000;
            let end = std::cmp::min(i + batch_len, chain_length);
            debug!("Asking for blocks {}-{}", i, end);

            let batch = canister.query_blocks(i, end).await?;

            debug!("Got batch of len: {}", batch.len());
            if batch.is_empty() {
                return Err(internal_error(
                    "Couldn't fetch new blocks (batch result empty)".to_string(),
                ));
            }

            for raw_block in batch {
                let block = raw_block
                    .decode()
                    .map_err(|err| internal_error(format!("Cannot decode block: {}", err)))?;
                if block.parent_hash != last_block_hash {
                    let err_msg = format!(
                        "Block at {}: parent hash mismatch. Expected: {:?}, got: {:?}",
                        i, last_block_hash, block.parent_hash
                    );
                    error!("{}", err_msg);
                    return Err(internal_error(err_msg));
                }
                let hb = HashedBlock::hash_block(raw_block, last_block_hash, i);
                blockchain.add_block(hb.clone())?;
                last_block_hash = Some(hb.hash);
                i += 1;
            }
            if print_progress && (i - next_block_index) % 10000 == 0 {
                info!("Synced up to {}", i - 1);
            }
        }
        if let Some(last_hash) = last_block_hash {
            verify_block_hash(certification, last_hash, &self.root_key, &self.canister_id)
                .map_err(internal_error)?;
            blockchain
                .block_store
                .mark_last_verified(chain_length - 1)?;
        }
        if next_block_index != chain_length {
            info!(
                "You are all caught up to block {}",
                blockchain.last()?.unwrap().index
            );
        }

        blockchain.try_prune(&self.store_max_blocks, PRUNE_DELAY)?;
        Ok(())
    }

    fn ledger_canister_id(&self) -> &CanisterId {
        &self.canister_id
    }

    fn governance_canister_id(&self) -> &CanisterId {
        &self.governance_canister_id
    }

    async fn submit(&self, envelopes: SignedTransaction) -> Result<Vec<SubmitResult>, ApiError> {
        if self.offline {
            return Err(ApiError::NotAvailableOffline(false, None));
        }

        // Exponential backoff from 100ms to 10s with a multiplier of 1.3.
        const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);
        const MAX_POLL_INTERVAL: Duration = Duration::from_secs(10);
        const POLL_INTERVAL_MULTIPLIER: f32 = 1.3;
        const TIMEOUT: Duration = Duration::from_secs(20);

        let start_time = Instant::now();
        let deadline = start_time + TIMEOUT;

        let http_client = reqwest::Client::new();

        let mut results = vec![];

        for (request_type, request) in envelopes {
            // Pick the update/read-start message that is currently valid.
            let now = ic_types::time::current_time();

            let EnvelopePair { update, read_state } = request
                .clone()
                .into_iter()
                .find(|EnvelopePair { update, .. }| {
                    let ingress_expiry = ic_types::Time::from_nanos_since_unix_epoch(
                        update.content.ingress_expiry(),
                    );
                    let ingress_start = ingress_expiry
                        - (ic_types::ingress::MAX_INGRESS_TTL - ic_types::ingress::PERMITTED_DRIFT);
                    ingress_start <= now && ingress_expiry > now
                })
                .ok_or(ApiError::TransactionExpired)?;

            let canister_id = match &update.content {
                HttpSubmitContent::Call { update } => {
                    CanisterId::try_from(update.canister_id.0.clone()).map_err(|e| {
                        internal_error(format!(
                            "Cannot parse canister ID found in submit call: {}",
                            e
                        ))
                    })?
                }
            };

            let request_id = MessageId::from(update.content.representation_independent_hash());
            let txn_id = transaction_id(request_type, &update)?;

            let http_body = SignedRequestBytes::try_from(update).map_err(|e| {
                internal_error(format!(
                    "Cannot serialize the submit request in CBOR format because of: {}",
                    e
                ))
            })?;

            let read_state_http_body = SignedRequestBytes::try_from(read_state).map_err(|e| {
                internal_error(format!(
                    "Cannot serialize the read state request in CBOR format because of: {}",
                    e
                ))
            })?;

            let url = self
                .ic_url
                .join(&ic_canister_client::update_path(canister_id))
                .expect("URL join failed");

            // Submit the update call (with retry).
            let mut poll_interval = MIN_POLL_INTERVAL;

            while Instant::now() + poll_interval < deadline {
                let wait_timeout = TIMEOUT - start_time.elapsed();

                match send_post_request(
                    &http_client,
                    url.as_str(),
                    http_body.clone().into(),
                    wait_timeout,
                )
                .await
                {
                    Err(err) => {
                        // Retry client-side errors.
                        error!("Error while submitting transaction: {}.", err);
                    }
                    Ok((body, status)) => {
                        if status.is_success() {
                            break;
                        }

                        // Retry on 5xx errors. We don't want to retry on
                        // e.g. authentication errors.
                        let body =
                            String::from_utf8(body).unwrap_or_else(|_| "<undecodable>".to_owned());
                        if status.is_server_error() {
                            error!(
                                "HTTP error {} while submitting transaction: {}.",
                                status, body
                            );
                        } else {
                            return Err(ic_error(status.as_u16(), body));
                        }
                    }
                }

                // Bump the poll interval and compute the next poll time (based on current wall
                // time, so we don't spin without delay after a slow poll).
                poll_interval = poll_interval
                    .mul_f32(POLL_INTERVAL_MULTIPLIER)
                    .min(MAX_POLL_INTERVAL);
            }

            // Do read-state calls until the result becomes available.
            let wait_for_result = || {
                async {
                    // Cut&paste from canister_client Agent.

                    let mut poll_interval = MIN_POLL_INTERVAL;

                    while Instant::now() + poll_interval < deadline {
                        debug!("Waiting {} ms for response", poll_interval.as_millis());
                        actix_rt::time::sleep(poll_interval).await;

                        let wait_timeout = TIMEOUT - start_time.elapsed();

                        let url = self
                            .ic_url
                            .join(&ic_canister_client::read_state_path(canister_id))
                            .expect("URL join failed");

                        match send_post_request(
                            &http_client,
                            url.as_str(),
                            read_state_http_body.clone().into(),
                            wait_timeout,
                        )
                        .await
                        {
                            Err(err) => {
                                // Retry client-side errors.
                                error!("Error while reading the IC state: {}.", err);
                            }
                            Ok((body, status)) => {
                                if status.is_success() {
                                    let cbor: serde_cbor::Value = serde_cbor::from_slice(&body)
                                        .map_err(|err| {
                                            format!("While parsing the status body: {}", err)
                                        })?;

                                    let status = ic_canister_client::parse_read_state_response(
                                        &request_id,
                                        cbor,
                                    )
                                    .map_err(|err| {
                                        format!("While parsing the read state response: {}", err)
                                    })?;

                                    debug!("Read state response: {:?}", status);

                                    match status.status.as_ref() {
                                        "replied" => match status.reply {
                                            Some(bytes) => match request_type {
                                                RequestType::Send => {
                                                    let block_index: BlockHeight =
                                                        ProtoBuf::from_bytes(bytes)
                                                        .map(|c| c.0)
                                                        .map_err(|err| {
                                                            format!(
                                                                "While parsing the reply of the send call: {}",
                                                                err
                                                            )
                                                        })?;
                                                    return Ok(Ok(Some(block_index)));
                                                }
                                                RequestType::CreateStake => {
                                                    let res: ClaimOrRefreshNeuronFromAccountResponse = candid::decode_one(&bytes)
                                                        .map_err(|err| {
                                                            format!(
                                                                "While parsing the reply of the stake creation call: {}",
                                                                err
                                                            )
                                                        })?;
                                                    match res.result.unwrap() {
                                                        ClaimOrRefreshResult::Error(err) => {
                                                            return Ok(Err(ApiError::TransactionRejected(
                                                                false,
                                                                into_error(format!("Could not claim neuron: {}", err)))));
                                                        }
                                                        ClaimOrRefreshResult::NeuronId(_) => {
                                                            // FIXME: return neuron ID
                                                            return Ok(Ok(None));
                                                        }
                                                    };
                                                }
                                            },
                                            None => {
                                                return Err(
                                                    "Send returned with no result.".to_owned()
                                                );
                                            }
                                        },
                                        "unknown" | "received" | "processing" => {}
                                        "rejected" => {
                                            return Ok(Err(ApiError::TransactionRejected(
                                                false,
                                                into_error(
                                                    status.reject_message.unwrap_or_else(|| {
                                                        "(no message)".to_owned()
                                                    }),
                                                ),
                                            )));
                                        }
                                        _ => {
                                            return Err(format!(
                                                "Send returned unexpected result: {:?} - {:?}",
                                                status.status, status.reject_message
                                            ))
                                        }
                                    }
                                } else {
                                    let body = String::from_utf8(body)
                                        .unwrap_or_else(|_| "<undecodable>".to_owned());
                                    let err = format!(
                                        "HTTP error {} while reading the IC state: {}.",
                                        status, body
                                    );
                                    if status.is_server_error() {
                                        // Retry on 5xx errors.
                                        error!("{}", err);
                                    } else {
                                        return Err(err);
                                    }
                                }
                            }
                        };

                        // Bump the poll interval and compute the next poll time (based on current
                        // wall time, so we don't spin without delay after a
                        // slow poll).
                        poll_interval = poll_interval
                            .mul_f32(POLL_INTERVAL_MULTIPLIER)
                            .min(MAX_POLL_INTERVAL);
                    }

                    // We didn't get a response in 30 seconds. Let the client handle it.
                    return Err(format!(
                        "Block submission took longer than {:?} to complete.",
                        TIMEOUT
                    ));
                }
            };

            /* Only return a non-200 result in case of an error from the
             * ledger canister. Otherwise just log the error and return a
             * 200 result with no block index. */
            match wait_for_result().await {
                // Success
                Ok(Ok(block_index)) => {
                    let res = SubmitResult {
                        transaction_identifier: txn_id,
                        block_index,
                    };
                    results.push(res);
                }
                // Error from ledger canister
                Ok(Err(err)) => return Err(err),
                // Some other error, transaction might still be processed by the IC
                Err(err) => {
                    error!("Error submitting transaction {:?}: {}.", txn_id, err);
                    // We can't continue with the next request since
                    // we don't know if the previous one succeeded.
                    let res = SubmitResult {
                        transaction_identifier: txn_id,
                        block_index: None,
                    };
                    results.push(res);
                    return Ok(results);
                }
            }
        }

        Ok(results)
    }
}

pub struct CanisterAccess {
    agent: Agent,
    canister_id: CanisterId,
}

impl CanisterAccess {
    pub fn new(url: Url, canister_id: CanisterId, client: HttpClient) -> Self {
        let agent = Agent::new_with_client(client, url, Sender::Anonymous);
        Self { agent, canister_id }
    }

    pub async fn query<'a, Payload: ToProto, Res: ToProto>(
        &self,
        method: &str,
        payload: Payload,
    ) -> Result<Res, String> {
        let arg = ProtoBuf(payload).into_bytes()?;
        let bytes = self
            .agent
            .execute_query(&self.canister_id, method, arg)
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        ProtoBuf::from_bytes(bytes).map(|c| c.0)
    }

    pub async fn query_canister<'a, Payload: ToProto, Res: ToProto>(
        &self,
        canister_id: CanisterId,
        method: &str,
        payload: Payload,
    ) -> Result<Res, String> {
        let arg = ProtoBuf(payload).into_bytes()?;
        let bytes = self
            .agent
            .execute_query(&canister_id, method, arg)
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        ProtoBuf::from_bytes(bytes).map(|c| c.0)
    }

    pub async fn query_tip(&self) -> Result<TipOfChainRes, ApiError> {
        self.query("tip_of_chain_pb", TipOfChainRequest {})
            .await
            .map_err(|e| internal_error(format!("In tip: {}", e)))
    }

    pub async fn query_raw_block(
        &self,
        height: BlockHeight,
    ) -> Result<Option<EncodedBlock>, ApiError> {
        let BlockRes(b) = self
            .query("block_pb", BlockArg(height))
            .await
            .map_err(|e| internal_error(format!("In block: {}", e)))?;
        match b {
            // block not found
            None => Ok(None),
            // block in the ledger
            Some(Ok(block)) => Ok(Some(block)),
            // block in the archive
            Some(Err(canister_id)) => {
                let BlockRes(b) = self
                    .query_canister(canister_id, "get_block_pb", BlockArg(height))
                    .await
                    .map_err(|e| internal_error(format!("In block: {}", e)))?;
                // get_block() on archive node will never return Ok(Err(canister_id))
                Ok(b.map(|x| x.unwrap()))
            }
        }
    }

    async fn call_query_blocks(
        &self,
        can_id: CanisterId,
        start: BlockHeight,
        end: BlockHeight,
    ) -> Result<Vec<EncodedBlock>, ApiError> {
        let blocks: GetBlocksRes = self
            .query_canister(
                can_id,
                "get_blocks_pb",
                GetBlocksArgs {
                    start,
                    length: (end - start) as usize,
                },
            )
            .await
            .map_err(|e| internal_error(format!("In blocks: {}", e)))?;

        blocks
            .0
            .map_err(|e| internal_error(format!("In blocks response: {}", e)))
    }

    pub async fn query_blocks(
        &self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> Result<Vec<EncodedBlock>, ApiError> {
        // asking for a low number of blocks means we are close to the tip
        // so we can try fetching from ledger without fetching the index
        // If that fails, we fetch the index and try with that
        if end - start < 500 {
            let blocks = self.call_query_blocks(self.canister_id, start, end).await;
            if blocks.is_ok() {
                return blocks;
            }
            debug!("Failed to get blocks from ledger.. querying for archives");
        }

        let index: ArchiveIndexResponse = self
            .query("get_archive_index_pb", ())
            .await
            .map_err(|e| internal_error(format!("In get archive index: {}", e)))?;
        let index = index.entries;

        trace!("query_blocks index: {:?}", index);

        let archive_idx_res = index.binary_search_by(|x| {
            if x.height_from <= start && start <= x.height_to {
                std::cmp::Ordering::Equal
            } else if x.height_from < start {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        let (can_id, can_end) = match archive_idx_res {
            Ok(i) => (
                index[i]
                    .canister_id
                    .map(|pid| CanisterId::try_from(pid).unwrap())
                    .unwrap_or(self.canister_id),
                index[i].height_to + 1,
            ),
            Err(_) => (self.canister_id, end),
        };
        let end = std::cmp::min(end, can_end);

        self.call_query_blocks(can_id, start, end).await
    }
}

pub struct Blocks {
    pub balance_book: BalanceBook,
    hash_location: HashMap<HashOf<EncodedBlock>, BlockHeight>,
    pub tx_hash_location: HashMap<HashOf<Transaction>, BlockHeight>,
    pub block_store: Box<dyn BlockStore + Send + Sync>,
    last_hash: Option<HashOf<EncodedBlock>>,
}

impl Default for Blocks {
    fn default() -> Self {
        Blocks::new_in_memory()
    }
}

impl Blocks {
    pub fn new(block_store: Box<dyn BlockStore + Send + Sync>) -> Self {
        Self {
            balance_book: BalanceBook::default(),
            hash_location: HashMap::default(),
            tx_hash_location: HashMap::default(),
            block_store,
            last_hash: None,
        }
    }

    pub fn new_in_memory() -> Self {
        Self::new(Box::new(InMemoryStore::new()))
    }

    pub fn new_on_disk(location: PathBuf, fsync: bool) -> Result<Self, BlockStoreError> {
        Ok(Self::new(Box::new(OnDiskStore::new(location, fsync)?)))
    }

    pub fn load_from_store(&mut self) -> Result<u64, ApiError> {
        assert!(self.last()?.is_none(), "Blocks is not empty");
        assert!(
            self.balance_book.store.acc_to_hist.is_empty(),
            "Blocks is not empty"
        );
        assert!(self.hash_location.is_empty(), "Blocks is not empty");
        assert!(self.tx_hash_location.is_empty(), "Blocks is not empty");

        if let Ok(genesis) = self.block_store.get_at(0) {
            self.process_block(genesis)?;
        } else {
            return Ok(0);
        }

        if let Some((first, balances_snapshot)) = self.block_store.first_snapshot().cloned() {
            self.balance_book = balances_snapshot;

            self.hash_location.insert(first.hash, first.index);

            let tx = first.block.decode().unwrap().transaction;
            self.tx_hash_location.insert(tx.hash(), first.index);
            self.last_hash = Some(first.hash);
        }

        let mut n = 0;
        let mut next_idx = self.last()?.map(|hb| hb.index + 1).unwrap();
        while let Ok(hb) = self.block_store.get_at(next_idx) {
            self.process_block(hb).map_err(|e| {
                error!(
                    "Processing block retrieved from store failed. Block idx: {}, error: {:?}",
                    next_idx, e
                );
                e
            })?;
            next_idx += 1;
            n += 1;
            if n % 30000 == 0 {
                info!("Loading... {} blocks processed", n);
            }
        }
        Ok(n)
    }

    fn get_at(&self, index: BlockHeight) -> Result<HashedBlock, ApiError> {
        Ok(self.block_store.get_at(index)?)
    }

    pub fn get_verified_at(&self, index: BlockHeight) -> Result<HashedBlock, ApiError> {
        let last_verified_idx = self
            .block_store
            .last_verified()
            .map(|x| x as i128)
            .unwrap_or(-1);
        if index as i128 > last_verified_idx {
            Err(BlockStoreError::NotFound(index).into())
        } else {
            self.get_at(index)
        }
    }

    pub fn get_balance(&self, acc: &AccountIdentifier, h: BlockHeight) -> Result<ICPTs, ApiError> {
        if let Ok(Some(b)) = self.first_verified() {
            if h < b.index {
                return Err(invalid_block_id(format!(
                    "Block at height: {} not available for query",
                    h
                )));
            }
        }
        let last_verified_idx = self
            .block_store
            .last_verified()
            .map(|x| x as i128)
            .unwrap_or(-1);
        if h as i128 > last_verified_idx {
            Err(invalid_block_id(format!(
                "Block not found at height: {}",
                h
            )))
        } else {
            self.balance_book.store.get_at(*acc, h)
        }
    }

    fn get(&self, hash: HashOf<EncodedBlock>) -> Result<HashedBlock, ApiError> {
        let index = *self
            .hash_location
            .get(&hash)
            .ok_or_else(|| invalid_block_id(format!("Block not found {}", hash)))?;
        self.get_at(index)
    }

    pub fn get_verified(&self, hash: HashOf<EncodedBlock>) -> Result<HashedBlock, ApiError> {
        let index = *self
            .hash_location
            .get(&hash)
            .ok_or_else(|| invalid_block_id(format!("Block not found {}", hash)))?;
        self.get_verified_at(index)
    }

    /// Add a block to the block_store data structure, the parent_hash must
    /// match the end of the chain
    pub fn add_block(&mut self, hb: HashedBlock) -> Result<(), ApiError> {
        self.block_store.push(hb.clone())?;
        self.process_block(hb)?;
        Ok(())
    }

    pub fn process_block(&mut self, hb: HashedBlock) -> Result<(), ApiError> {
        debug!("Process block: {} {}", hb.index, hb.hash);
        let HashedBlock {
            block,
            hash,
            parent_hash,
            index,
        } = hb.clone();
        let last = self.last()?;
        let last_hash = last.clone().map(|hb| hb.hash);
        let last_index = last.map(|hb| hb.index);
        assert_eq!(
            &parent_hash, &last_hash,
            "When adding a block the parent_hash must match the last added block"
        );

        let block = block.decode().unwrap();

        match last_index {
            Some(i) => assert_eq!(i + 1, index),
            None => assert_eq!(0, index),
        }

        let mut bb = &mut self.balance_book;
        bb.store.transaction_context = Some(index);
        bb.add_payment(&block.transaction.transfer);
        bb.store.transaction_context = None;

        self.hash_location.insert(hash, index);

        let tx = block.transaction;
        self.tx_hash_location.insert(tx.hash(), index);

        self.last_hash = Some(hb.hash);

        Ok(())
    }

    fn first(&self) -> Result<Option<HashedBlock>, ApiError> {
        Ok(self.block_store.first()?)
    }

    pub fn first_verified(&self) -> Result<Option<HashedBlock>, ApiError> {
        let last_verified_idx = self
            .block_store
            .last_verified()
            .map(|x| x as i128)
            .unwrap_or(-1);
        let first_block = self.block_store.first()?;
        if let Some(fb) = first_block.as_ref() {
            if fb.index as i128 > last_verified_idx {
                return Ok(None);
            }
        }
        Ok(first_block)
    }

    fn last(&self) -> Result<Option<HashedBlock>, ApiError> {
        match self.last_hash {
            Some(last_hash) => {
                let last = self.get(last_hash)?;
                Ok(Some(last))
            }
            None => Ok(None),
        }
    }

    pub fn last_verified(&self) -> Result<Option<HashedBlock>, ApiError> {
        match self.block_store.last_verified() {
            Some(h) => Ok(Some(self.block_store.get_at(h)?)),
            None => Ok(None),
        }
    }

    fn synced_to(&self) -> Option<(HashOf<EncodedBlock>, u64)> {
        self.last().ok().flatten().map(|hb| (hb.hash, hb.index))
    }

    pub fn try_prune(
        &mut self,
        max_blocks: &Option<u64>,
        prune_delay: u64,
    ) -> Result<(), ApiError> {
        if let Some(block_limit) = max_blocks {
            let first_idx = self.first()?.map(|hb| hb.index).unwrap_or(0);
            let last_idx = self.last()?.map(|hb| hb.index).unwrap_or(0);
            if first_idx + block_limit + prune_delay < last_idx {
                let new_first_idx = last_idx - block_limit;
                let hb = self.block_store.get_at(new_first_idx)?;
                self.balance_book.store.prune_at(hb.index);
                self.block_store
                    .prune(&hb, &self.balance_book)
                    .map_err(internal_error)?
            }
        }
        Ok(())
    }
}
