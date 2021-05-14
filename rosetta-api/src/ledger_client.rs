use crate::convert::{ic_error, internal_error, into_error, invalid_block_id, transaction_id};
use crate::models::{ApiError, Envelopes, TransactionIdentifier};
use crate::store::{BlockStore, BlockStoreError, HashedBlock, InMemoryStore, OnDiskStore};
use async_trait::async_trait;
use core::ops::Deref;
use dfn_protobuf::{ProtoBuf, ToProto};
use ic_canister_client::{Agent, HttpClient, Sender};
use ic_crypto_tree_hash::{Digest, LabeledTree, MixedHashTree};
use ic_crypto_utils_threshold_sig::verify_combined;
use ic_types::messages::{HttpSubmitContent, MessageId};
use ic_types::CanisterId;
use ic_types::{
    consensus::certification::CertificationContent,
    crypto::{threshold_sig::ThresholdSigPublicKey, CombinedThresholdSigOf, CryptoHash},
    messages::SignedRequestBytes,
    CryptoHashOfPartialState, Time,
};
use ledger_canister::protobuf::ArchiveIndexResponse;
use ledger_canister::{
    protobuf::TipOfChainRequest, AccountIdentifier, BalancesStore, BlockArg, BlockHeight, BlockRes,
    EncodedBlock, GetBlocksArgs, GetBlocksRes, HashOf, ICPTs, TipOfChainRes, Transaction,
};
use log::{debug, error, info, trace};
use on_wire::{FromWire, IntoWire};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tree_deserializer::{types::Leb128EncodedU64, LabeledTreeDeserializer};
use url::Url;

pub type Balances = ledger_canister::Balances<ChunkmapBalancesStore>;

#[async_trait]
pub trait LedgerAccess {
    // Maybe we should just return RwLockReadGuard explicitly and drop the Box
    async fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a>;
    async fn sync_blocks(&self, stopped: Arc<AtomicBool>) -> Result<(), ApiError>;
    fn ledger_canister_id(&self) -> &CanisterId;
    fn network_url(&self) -> &Url;
    async fn submit(
        &self,
        _envelopes: Envelopes,
    ) -> Result<(TransactionIdentifier, Option<BlockHeight>), ApiError>;
    async fn chain_length(&self) -> BlockHeight;
}

pub struct LedgerClient {
    blockchain: RwLock<Blocks>,
    canister_id: CanisterId,
    canister_access: Option<CanisterAccess>,
    network_url: Url,
    store_max_blocks: Option<u64>,
    offline: bool,
    root_key: Option<ThresholdSigPublicKey>,
}

pub enum StoreType {
    InMemory,
    OnDisk(PathBuf, bool),
}

impl LedgerClient {
    pub async fn create_on_disk(
        network_url: Url,
        canister_id: CanisterId,
        store_type: StoreType,
        store_max_blocks: Option<u64>,
        offline: bool,
        root_key: Option<ThresholdSigPublicKey>,
    ) -> Result<LedgerClient, ApiError> {
        let mut blocks = match store_type {
            StoreType::InMemory => Blocks::new_in_memory(),
            StoreType::OnDisk(store_location, fsync) => {
                let location = store_location.join("blocks");
                std::fs::create_dir_all(&location)
                    .map_err(|e| format!("{}", e))
                    .map_err(internal_error)?;

                Blocks::new_on_disk(location, fsync)?
            }
        };

        let canister_access = if offline {
            None
        } else {
            let http_client = HttpClient::new();
            let canister_access =
                CanisterAccess::new(network_url.clone(), canister_id, http_client);
            Self::verify_store(&blocks, &canister_access).await?;

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

        let prune_delay = 100;
        blocks.try_prune(&store_max_blocks, prune_delay)?;

        Ok(Self {
            blockchain: RwLock::new(blocks),
            canister_id,
            canister_access,
            network_url,
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
                if blocks.block_store.first_snapshot().is_some() {
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

        if let Some((first_block, _)) = blocks.block_store.first_snapshot() {
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

    fn verify_tip(
        &self,
        cert: ledger_canister::Certification,
        hash: HashOf<EncodedBlock>,
    ) -> Result<(), String> {
        match self.root_key {
            Some(root_key) => {
                let (from_cert, _) = check_certificate(
                    &self.canister_id,
                    &root_key,
                    &*cert.ok_or("verify tip failed: no data certificate present")?,
                )
                .map_err(|e| format!("Certification error: {:?}", e))?;
                if from_cert.as_bytes() != hash.into_bytes() {
                    Err("verify tip failed".to_string())
                } else {
                    Ok(())
                }
            }
            None => Ok(()),
        }
    }
}

#[derive(Debug)]
pub enum CertificationError {
    /// Failed to deserialize some part of the response.
    DeserError(String),
    /// The signature verification failed.
    InvalidSignature(String),
    /// The value at path "/canister/<cid>/certified_data" doesn't match the
    /// hash computed from the mixed hash tree with registry deltas.
    CertifiedDataMismatch { certified: Digest, computed: Digest },
    /// Parsing and signature verification was successful, but the list of
    /// deltas doesn't satisfy postconditions of the method.
    InvalidDeltas(String),
    /// The hash tree in the response was not well-formed.
    MalformedHashTree(String),
}

fn verify_combined_threshold_sig(
    msg: &CryptoHashOfPartialState,
    sig: &CombinedThresholdSigOf<CertificationContent>,
    root_key: &ThresholdSigPublicKey,
) -> Result<(), CertificationError> {
    verify_combined(&CertificationContent::new(msg.clone()), sig, root_key)
        .map_err(|e| CertificationError::InvalidSignature(e.to_string()))
}

fn check_certificate(
    canister_id: &CanisterId,
    nns_pk: &ThresholdSigPublicKey,
    encoded_certificate: &[u8],
) -> Result<(Digest, Time), CertificationError> {
    #[derive(Deserialize)]
    struct Certificate {
        tree: MixedHashTree,
        signature: CombinedThresholdSigOf<CertificationContent>,
    }

    #[derive(Deserialize)]
    struct CanisterView {
        certified_data: Digest,
    }

    #[derive(Deserialize)]
    struct ReplicaState {
        time: Leb128EncodedU64,
        canister: BTreeMap<CanisterId, CanisterView>,
    }

    let certificate: Certificate = serde_cbor::from_slice(encoded_certificate).map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to decode certificate from canister {}: {}",
            canister_id, err
        ))
    })?;

    let digest = CryptoHashOfPartialState::from(CryptoHash(certificate.tree.digest().to_vec()));

    verify_combined_threshold_sig(&digest, &certificate.signature, nns_pk).map_err(|err| {
        CertificationError::InvalidSignature(format!(
            "failed to verify threshold signature: root_hash={:?}, sig={:?}, pk={:?}, error={:?}",
            digest, certificate.signature, nns_pk, err
        ))
    })?;

    let replica_labeled_tree =
        LabeledTree::<Vec<u8>>::try_from(certificate.tree).map_err(|err| {
            CertificationError::MalformedHashTree(format!(
                "failed to convert hash tree to labeled tree: {:?}",
                err
            ))
        })?;

    let replica_state = ReplicaState::deserialize(LabeledTreeDeserializer::new(
        &replica_labeled_tree,
    ))
    .map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to unpack replica state from a labeled tree: {}",
            err
        ))
    })?;

    let time = Time::from_nanos_since_unix_epoch(replica_state.time.0);

    replica_state
        .canister
        .get(canister_id)
        .map(|canister| (canister.certified_data.clone(), time))
        .ok_or_else(|| {
            CertificationError::MalformedHashTree(format!(
                "cannot find certified_data for canister {} in the tree",
                canister_id
            ))
        })
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
        }
        if let Some(last_hash) = last_block_hash {
            self.verify_tip(certification, last_hash)
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

        let prune_delay = 100;
        blockchain.try_prune(&self.store_max_blocks, prune_delay)?;
        Ok(())
    }

    fn ledger_canister_id(&self) -> &CanisterId {
        &self.canister_id
    }

    fn network_url(&self) -> &Url {
        &self.network_url
    }

    async fn submit(
        &self,
        envelopes: Envelopes,
    ) -> Result<(TransactionIdentifier, Option<BlockHeight>), ApiError> {
        if self.offline {
            return Err(ApiError::NotAvailableOffline(false, None));
        }

        // Pick the update/read-start message that is currently valid.
        let now = ic_types::time::current_time();

        let (submit_request, read_state_request) = envelopes
            .into_iter()
            .find(|(submit_request, _)| {
                let ingress_expiry = ic_types::Time::from_nanos_since_unix_epoch(
                    submit_request.content.ingress_expiry(),
                );
                let ingress_start = ingress_expiry
                    - (ic_types::ingress::MAX_INGRESS_TTL - ic_types::ingress::PERMITTED_DRIFT);
                ingress_start <= now && ingress_expiry > now
            })
            .ok_or_else(|| ApiError::TransactionExpired)?;

        const TIMEOUT: Duration = Duration::from_secs(20);

        let start_time = Instant::now();
        let deadline = start_time + TIMEOUT;
        let canister_id = match &submit_request.content {
            HttpSubmitContent::Call { update } => {
                CanisterId::try_from(update.canister_id.0.clone()).map_err(|e| {
                    internal_error(format!(
                        "Cannot parse canister ID found in submit call: {}",
                        e
                    ))
                })?
            }
        };

        let request_id = MessageId::from(submit_request.content.representation_independent_hash());
        let txn_id = transaction_id(&submit_request)?;

        let http_body = SignedRequestBytes::try_from(submit_request).map_err(|e| {
            internal_error(format!(
                "Cannot serialize the submit request in CBOR format because of: {}",
                e
            ))
        })?;

        let read_state_http_body =
            SignedRequestBytes::try_from(read_state_request).map_err(|e| {
                internal_error(format!(
                    "Cannot serialize the read state request in CBOR format because of: {}",
                    e
                ))
            })?;

        let url = self
            .network_url
            .join(&ic_canister_client::update_path(canister_id))
            .expect("URL join failed");

        let http_client = reqwest::Client::new();

        // Exponential backoff from 100ms to 10s with a multiplier of 1.3.
        const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);
        const MAX_POLL_INTERVAL: Duration = Duration::from_secs(10);
        const POLL_INTERVAL_MULTIPLIER: f32 = 1.3;

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

        let wait_for_result = || {
            async {
                // Cut&paste from canister_client Agent.

                let mut poll_interval = MIN_POLL_INTERVAL;

                while Instant::now() + poll_interval < deadline {
                    debug!("Waiting {} ms for response", poll_interval.as_millis());
                    actix_rt::time::delay_for(poll_interval).await;

                    let wait_timeout = TIMEOUT - start_time.elapsed();

                    let url = self
                        .network_url
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
                                        Some(bytes) => {
                                            let block_index: BlockHeight =
                                                ProtoBuf::from_bytes(bytes).map(|c| c.0).map_err(
                                                    |err| {
                                                        format!(
                                                    "While parsing the reply of the send call: {}",
                                                    err
                                                )
                                                    },
                                                )?;
                                            return Ok(Ok(block_index));
                                        }
                                        None => {
                                            return Err("Send returned with no result.".to_owned());
                                        }
                                    },
                                    "unknown" | "received" | "processing" => {}
                                    "rejected" => {
                                        return Ok(Err(ApiError::TransactionRejected(
                                            false,
                                            into_error(
                                                status
                                                    .reject_message
                                                    .unwrap_or_else(|| "(no message)".to_owned()),
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

                    // Bump the poll interval and compute the next poll time (based on current wall
                    // time, so we don't spin without delay after a slow poll).
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
            Ok(Ok(block_index)) => Ok((txn_id, Some(block_index))),
            Ok(Err(err)) => Err(err),
            Err(err) => {
                error!("Error submitting transaction {:?}: {}.", txn_id, err);
                Ok((txn_id, None))
            }
        }
    }

    async fn chain_length(&self) -> BlockHeight {
        match self.blockchain.read().await.block_store.last_verified() {
            None => 0,
            Some(block_index) => block_index + 1,
        }
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

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ChunkmapBalancesStore(pub immutable_chunkmap::map::Map<AccountIdentifier, ICPTs>);

impl BalancesStore for ChunkmapBalancesStore {
    fn get_balance(&self, k: &AccountIdentifier) -> Option<&ICPTs> {
        self.0.get(k)
    }

    fn update<F>(&mut self, k: AccountIdentifier, mut f: F)
    where
        F: FnMut(Option<&ICPTs>) -> ICPTs,
    {
        let (m, _) = self
            .0
            .update(k, ICPTs::ZERO /* dummy param */, |_, _, prev| {
                let prev_v = prev.map(|x| x.1);
                let new_v = f(prev_v);
                if new_v != ICPTs::ZERO {
                    Some((k, new_v))
                } else {
                    None
                }
            });

        self.0 = m;
    }
}

pub struct Blocks {
    balances: HashMap<BlockHeight, Balances>,
    hash_location: HashMap<HashOf<EncodedBlock>, BlockHeight>,
    pub tx_hash_location: HashMap<HashOf<Transaction>, BlockHeight>,
    pub account_location: HashMap<AccountIdentifier, Vec<BlockHeight>>,
    pub block_store: Box<dyn BlockStore + Send + Sync>,
    last_hash: Option<HashOf<EncodedBlock>>,
}

impl Default for Blocks {
    fn default() -> Self {
        Blocks::new_in_memory()
    }
}

impl Blocks {
    pub fn new_in_memory() -> Self {
        Self {
            balances: HashMap::default(),
            hash_location: HashMap::default(),
            tx_hash_location: HashMap::default(),
            account_location: HashMap::default(),
            block_store: Box::new(InMemoryStore::new()),
            last_hash: None,
        }
    }

    pub fn new_on_disk(location: PathBuf, fsync: bool) -> Result<Self, BlockStoreError> {
        Ok(Blocks {
            balances: HashMap::default(),
            hash_location: HashMap::default(),
            block_store: Box::new(OnDiskStore::new(location, fsync)?),
            tx_hash_location: HashMap::default(),
            account_location: HashMap::default(),
            last_hash: None,
        })
    }

    pub fn load_from_store(&mut self) -> Result<u64, ApiError> {
        assert!(self.last()?.is_none(), "Blocks is not empty");
        assert!(self.balances.is_empty(), "Blocks is not empty");
        assert!(self.hash_location.is_empty(), "Blocks is not empty");
        assert!(self.tx_hash_location.is_empty(), "Blocks is not empty");
        assert!(self.account_location.is_empty(), "Blocks is not empty");

        if let Ok(genesis) = self.block_store.get_at(0) {
            self.process_block(genesis)?;
        } else {
            return Ok(0);
        }

        if let Some((first, balances)) = self.block_store.first_snapshot().cloned() {
            self.balances.insert(first.index, balances);
            self.hash_location.insert(first.hash, first.index);

            let tx = first.block.decode().unwrap().transaction;
            self.tx_hash_location.insert(tx.hash(), first.index);
            match tx.transfer {
                ledger_canister::Transfer::Burn { from, .. } => {
                    self.account_location
                        .entry(from)
                        .or_insert_with(Vec::new)
                        .push(first.index);
                }
                ledger_canister::Transfer::Mint { to, .. } => {
                    self.account_location
                        .entry(to)
                        .or_insert_with(Vec::new)
                        .push(first.index);
                }
                ledger_canister::Transfer::Send { from, to, .. } => {
                    self.account_location
                        .entry(from)
                        .or_insert_with(Vec::new)
                        .push(first.index);
                    self.account_location
                        .entry(to)
                        .or_insert_with(Vec::new)
                        .push(first.index);
                }
            };
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

    pub fn get_balances_at(&self, index: BlockHeight) -> Result<Balances, ApiError> {
        let last_verified_idx = self
            .block_store
            .last_verified()
            .map(|x| x as i128)
            .unwrap_or(-1);
        if index as i128 > last_verified_idx {
            Err(internal_error("Balances not found"))
        } else {
            self.balances
                .get(&index)
                .cloned()
                .ok_or_else(|| internal_error("Balances not found"))
        }
    }

    fn get(&self, hash: HashOf<EncodedBlock>) -> Result<HashedBlock, ApiError> {
        let index = *self
            .hash_location
            .get(&hash)
            .ok_or_else(|| invalid_block_id(format!("Block number out of bounds {}", hash)))?;
        self.get_at(index)
    }

    pub fn get_verified(&self, hash: HashOf<EncodedBlock>) -> Result<HashedBlock, ApiError> {
        let index = *self
            .hash_location
            .get(&hash)
            .ok_or_else(|| invalid_block_id(format!("Block number out of bounds {}", hash)))?;
        self.get_verified_at(index)
    }

    pub fn get_balances(&self, hash: HashOf<EncodedBlock>) -> Result<Balances, ApiError> {
        let index = *self
            .hash_location
            .get(&hash)
            .ok_or_else(|| invalid_block_id(format!("Block number out of bounds {}", hash)))?;
        self.get_balances_at(index)
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

        let mut new_balances = match last_index {
            // This is the first block being added
            None => Balances::default(),
            Some(i) => self
                .balances
                .get(&i)
                .ok_or_else(|| {
                    internal_error("Balances must be populated for all hashes in Blocks")
                })?
                .clone(),
        };

        new_balances.add_payment(&block.transaction.transfer);

        self.hash_location.insert(hash, index);

        let tx = block.transaction;
        self.tx_hash_location.insert(tx.hash(), index);
        match tx.transfer {
            ledger_canister::Transfer::Burn { from, .. } => {
                self.account_location
                    .entry(from)
                    .or_insert_with(Vec::new)
                    .push(index);
            }
            ledger_canister::Transfer::Mint { to, .. } => {
                self.account_location
                    .entry(to)
                    .or_insert_with(Vec::new)
                    .push(index);
            }
            ledger_canister::Transfer::Send { from, to, .. } => {
                self.account_location
                    .entry(from)
                    .or_insert_with(Vec::new)
                    .push(index);
                self.account_location
                    .entry(to)
                    .or_insert_with(Vec::new)
                    .push(index);
            }
        };

        self.balances.insert(index, new_balances);
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
                let balances = self
                    .balances
                    .get(&new_first_idx)
                    .cloned()
                    .ok_or_else(|| internal_error("Balances not found"))?;
                let hb = self.block_store.get_at(new_first_idx)?;
                self.block_store
                    .prune(&hb, &balances)
                    .map_err(internal_error)?
            }
        }
        Ok(())
    }
}
