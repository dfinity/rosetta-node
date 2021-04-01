use crate::convert::{ic_error, internal_error, into_error, invalid_block_id, transaction_id};
use crate::models::{ApiError, TransactionIdentifier};
use crate::store::{BlockStore, BlockStoreError, HashedBlock, InMemoryStore, OnDiskStore};
use async_trait::async_trait;
use core::ops::Deref;
use dfn_protobuf::{ProtoBuf, ToProto};
use ic_canister_client::{Agent, HttpClient, HttpContentType, RequestStub, Sender};
use ic_crypto_tree_hash::{Digest, LabeledTree, MixedHashTree};
use ic_crypto_utils_threshold_sig::verify_combined;
use ic_types::messages::{HttpReadContent, HttpRequestEnvelope, HttpSubmitContent, MessageId};
use ic_types::CanisterId;
use ic_types::{
    consensus::certification::CertificationContent,
    crypto::{threshold_sig::ThresholdSigPublicKey, CombinedThresholdSigOf, CryptoHash},
    CryptoHashOfPartialState,
};
use im::OrdMap;
use ledger_canister::{
    protobuf::TipOfChainRequest, AccountIdentifier, BalancesStore, BlockArg, BlockHeight, BlockRes,
    EncodedBlock, HashOf, ICPTs, TipOfChainRes,
};
use log::{debug, error, info, trace};
use on_wire::{FromWire, IntoWire};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tree_deserializer::LabeledTreeDeserializer;
use url::Url;

pub type Balances = ledger_canister::Balances<OrdMapBalancesStore>;

#[async_trait]
pub trait LedgerAccess {
    // Maybe we should just return RwLockReadGuard explicitly and drop the Box
    async fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a>;
    async fn sync_blocks(&self, stopped: Arc<AtomicBool>) -> Result<(), ApiError>;
    fn ledger_canister_id(&self) -> &CanisterId;
    fn agent_client(&self) -> &HttpClient;
    fn testnet_url(&self) -> &Url;
    async fn submit(
        &self,
        _submit_envelope: HttpRequestEnvelope<HttpSubmitContent>,
        _read_state_envelope: HttpRequestEnvelope<HttpReadContent>,
    ) -> Result<(TransactionIdentifier, Option<BlockHeight>), ApiError>;
    async fn chain_length(&self) -> BlockHeight;
}

pub struct LedgerClient {
    blockchain: RwLock<Blocks>,
    canister_id: CanisterId,
    agent_client: Option<HttpClient>,
    canister_access: Option<CanisterAccess>,
    testnet_url: Url,
    store_max_blocks: Option<u64>,
    offline: bool,
    public_key: Option<ThresholdSigPublicKey>,
}

impl LedgerClient {
    pub async fn create_on_disk(
        testnet_url: Url,
        canister_id: CanisterId,
        store_location: &Path,
        store_max_blocks: Option<u64>,
        offline: bool,
        public_key: Option<ThresholdSigPublicKey>,
    ) -> Result<LedgerClient, ApiError> {
        let location = store_location.join("blocks");
        std::fs::create_dir_all(&location)
            .map_err(|e| format!("{}", e))
            .map_err(internal_error)?;

        let mut blocks = Blocks::new_on_disk(location)?;

        let (agent_client, canister_access) = if offline {
            (None, None)
        } else {
            let agent_client = HttpClient::new();
            let canister_access =
                CanisterAccess::new(testnet_url.clone(), canister_id, agent_client.clone());
            Self::verify_store(&blocks, &canister_access).await?;

            (Some(agent_client), Some(canister_access))
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
            agent_client,
            canister_access,
            testnet_url,
            store_max_blocks,
            offline,
            public_key,
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
        match self.public_key {
            Some(public_key) => {
                let from_cert = check_certificate(
                    &self.canister_id,
                    &public_key,
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
    public_key: &ThresholdSigPublicKey,
) -> Result<(), CertificationError> {
    verify_combined(&CertificationContent::new(msg.clone()), sig, public_key)
        .map_err(|e| CertificationError::InvalidSignature(e.to_string()))
}

fn check_certificate(
    canister_id: &CanisterId,
    nns_public_key: &ThresholdSigPublicKey,
    encoded_certificate: &[u8],
) -> Result<Digest, CertificationError> {
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
        canister: BTreeMap<CanisterId, CanisterView>,
    }

    let certificate: Certificate = serde_cbor::from_slice(encoded_certificate).map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to decode certificate from canister {}: {}",
            canister_id, err
        ))
    })?;

    let digest = CryptoHashOfPartialState::from(CryptoHash(certificate.tree.digest().to_vec()));

    verify_combined_threshold_sig(&digest, &certificate.signature, nns_public_key).map_err(|err| {
        CertificationError::InvalidSignature(format!(
            "failed to verify threshold signature: root_hash={:?}, sig={:?}, public_key={:?}, error={:?}",
            digest, certificate.signature, nns_public_key, err
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

    replica_state
        .canister
        .get(canister_id)
        .map(|canister| canister.certified_data.clone())
        .ok_or_else(|| {
            CertificationError::MalformedHashTree(format!(
                "cannot find certified_data for canister {} in the tree",
                canister_id
            ))
        })
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
        }

        for i in next_block_index..chain_length {
            if stopped.load(Relaxed) {
                return Err(internal_error("Interrupted"));
            }
            debug!("Fetching block {}", i);
            let raw_block = canister.query_raw_block(i).await?.unwrap_or_else(|| {
                panic!(
                    "Block {} is missing when the tip of the chain is {}",
                    i, chain_length
                )
            });
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
        }
        if let Some(last_hash) = last_block_hash {
            self.verify_tip(certification, last_hash)
                .map_err(internal_error)?;
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

    fn agent_client(&self) -> &HttpClient {
        self.agent_client
            .as_ref()
            .expect("Agent client not present in offline mode")
    }

    fn testnet_url(&self) -> &Url {
        &self.testnet_url
    }

    async fn submit(
        &self,
        submit_request: HttpRequestEnvelope<HttpSubmitContent>,
        read_state_request: HttpRequestEnvelope<HttpReadContent>,
    ) -> Result<(TransactionIdentifier, Option<BlockHeight>), ApiError> {
        if self.offline {
            return Err(ApiError::NotAvailableOffline(false, None));
        }

        const TIMEOUT: Duration = Duration::from_secs(20);

        let start_time = Instant::now();
        let deadline = start_time + TIMEOUT;

        let http_body = ic_canister_client::cbor::to_self_describing_cbor(&submit_request)
            .map_err(|e| {
                internal_error(format!(
                    "Cannot serialize the submit request in CBOR format because of: {}",
                    e
                ))
            })?;

        let read_state_http_body = ic_canister_client::cbor::to_self_describing_cbor(
            &read_state_request,
        )
        .map_err(|e| {
            internal_error(format!(
                "Cannot serialize the read state request in CBOR format because of: {}",
                e
            ))
        })?;

        let request_id = MessageId::from(submit_request.content.representation_independent_hash());

        let url = self
            .testnet_url
            .join(ic_canister_client::UPDATE_PATH)
            .expect("URL join failed");

        let agent_client = HttpClient::new();
        let (body, status) = agent_client
            .send_post_request(
                url.as_str(),
                Some(HttpContentType::CBOR),
                Some(http_body),
                Some(TIMEOUT),
            )
            .await
            .map_err(internal_error)?;

        if !status.is_success() {
            let body = String::from_utf8(body).map_err(internal_error)?;
            return Err(ic_error(status.as_u16(), body));
        }

        // Cut&paste from canister_client Agent.

        // Exponential backoff from 100ms to 10s with a multiplier of 1.3.
        const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);
        const MAX_POLL_INTERVAL: Duration = Duration::from_secs(10);
        const POLL_INTERVAL_MULTIPLIER: f32 = 1.3;

        let mut poll_interval = MIN_POLL_INTERVAL;

        while Instant::now() + poll_interval < deadline {
            debug!("Waiting {} ms for response", poll_interval.as_millis());
            actix_rt::time::delay_for(poll_interval).await;

            let wait_timeout = TIMEOUT - start_time.elapsed();

            let url = self
                .testnet_url
                .join(ic_canister_client::QUERY_PATH)
                .expect("URL join failed");

            let (body, status) = agent_client
                .send_post_request(
                    url.as_str(),
                    Some(HttpContentType::CBOR),
                    Some(read_state_http_body.clone()),
                    Some(wait_timeout),
                )
                .await
                .map_err(internal_error)?;

            if status.is_success() {
                let cbor: serde_cbor::Value = serde_cbor::from_slice(&body).map_err(|err| {
                    internal_error(format!("While parsing the status body: {}", err))
                })?;

                let status = ic_canister_client::parse_read_state_response(&request_id, cbor)
                    .map_err(|err| {
                        internal_error(format!("While parsing the read state response: {}", err))
                    })?;

                debug!("Read state response: {:?}", status);

                match status.status.as_ref() {
                    "replied" => match status.reply {
                        Some(bytes) => {
                            let block_index: BlockHeight =
                                ProtoBuf::from_bytes(bytes).map(|c| c.0).map_err(|err| {
                                    internal_error(format!(
                                        "While parsing the reply of the send call: {}",
                                        err
                                    ))
                                })?;
                            return transaction_id(submit_request)
                                .map(|id| (id, Some(block_index)));
                        }
                        None => {
                            return Err(internal_error("Send returned with no result.".to_owned()));
                        }
                    },
                    "unknown" | "received" | "processing" => {}
                    "rejected" => {
                        return Err(ApiError::TransactionRejected(
                            false,
                            into_error(
                                status
                                    .reject_message
                                    .unwrap_or_else(|| "(no message)".to_owned()),
                            ),
                        ));
                    }
                    _ => {
                        return Err(internal_error(format!(
                            "Send returned unexpected result: {:?} - {:?}",
                            status.status, status.reject_message
                        )))
                    }
                }
            } else {
                let body = String::from_utf8(body).map_err(internal_error)?;
                error!(
                    "HTTP error {} while reading the IC state: {}.",
                    status, body
                );
            }

            // Bump the poll interval and compute the next poll time (based on current wall
            // time, so we don't spin without delay after a slow poll).
            poll_interval = poll_interval
                .mul_f32(POLL_INTERVAL_MULTIPLIER)
                .min(MAX_POLL_INTERVAL);
        }

        // We didn't get a response in 30 seconds. Let the client handle it.
        error!(
            "Block submission took longer than {:?} to complete.",
            TIMEOUT
        );

        transaction_id(submit_request).map(|id| (id, None))
    }

    async fn chain_length(&self) -> BlockHeight {
        match self.blockchain.read().await.synced_to() {
            None => 0,
            Some((_, block_index)) => block_index + 1,
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
            .execute_query(&self.canister_id, method, Some(arg))
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        ProtoBuf::from_bytes(bytes).map(|c| c.0)
    }

    pub async fn query_tip(&self) -> Result<TipOfChainRes, ApiError> {
        self.query("tip_of_chain", TipOfChainRequest {})
            .await
            .map_err(|e| internal_error(format!("In tip: {}", e)))
    }

    pub async fn query_raw_block(
        &self,
        height: BlockHeight,
    ) -> Result<Option<EncodedBlock>, ApiError> {
        let BlockRes(b) = self
            .query("block", BlockArg(height))
            .await
            .map_err(|e| internal_error(format!("In block: {}", e)))?;
        Ok(b)
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct OrdMapBalancesStore(pub OrdMap<AccountIdentifier, ICPTs>);

/// This is essencially copy-paste of BalancesStore for HashMap
impl BalancesStore for OrdMapBalancesStore {
    fn get_balance(&self, k: &AccountIdentifier) -> Option<&ICPTs> {
        self.0.get(k)
    }

    fn get_balance_mut(&mut self, k: &AccountIdentifier) -> Option<&mut ICPTs> {
        self.0.get_mut(k)
    }

    fn get_create_balance(&mut self, k: AccountIdentifier) -> &mut ICPTs {
        self.0.entry(k).or_insert(ICPTs::ZERO)
    }

    fn remove_account(&mut self, k: &AccountIdentifier) -> Option<ICPTs> {
        self.0.remove(k)
    }
}

pub struct Blocks {
    balances: HashMap<BlockHeight, Balances>,
    hash_location: HashMap<HashOf<EncodedBlock>, BlockHeight>,
    block_store: Box<dyn BlockStore + Send + Sync>,
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
            block_store: Box::new(InMemoryStore::new()),
            last_hash: None,
        }
    }

    pub fn new_on_disk(location: PathBuf) -> Result<Self, BlockStoreError> {
        Ok(Blocks {
            balances: HashMap::default(),
            hash_location: HashMap::default(),
            block_store: Box::new(OnDiskStore::new(location)?),
            last_hash: None,
        })
    }

    pub fn load_from_store(&mut self) -> Result<u64, ApiError> {
        assert!(self.last()?.is_none(), "Blocks is not empty");
        assert!(self.balances.is_empty(), "Blocks is not empty");
        assert!(self.hash_location.is_empty(), "Blocks is not empty");

        if let Ok(genesis) = self.block_store.get_at(0) {
            self.process_block(genesis)?;
        } else {
            return Ok(0);
        }

        if let Some((first, balances)) = self.block_store.first_snapshot().cloned() {
            self.balances.insert(first.index, balances);
            self.hash_location.insert(first.hash, first.index);
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

    pub fn get_at(&self, index: BlockHeight) -> Result<HashedBlock, ApiError> {
        Ok(self.block_store.get_at(index)?)
    }

    pub fn get_balances_at(&self, index: BlockHeight) -> Result<Balances, ApiError> {
        self.balances
            .get(&index)
            .cloned()
            .ok_or_else(|| internal_error("Balances not found"))
    }

    pub fn get(&self, hash: HashOf<EncodedBlock>) -> Result<HashedBlock, ApiError> {
        let index = *self
            .hash_location
            .get(&hash)
            .ok_or_else(|| invalid_block_id(format!("Block number out of bounds {}", hash)))?;
        self.get_at(index)
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
        self.balances.insert(index, new_balances);
        self.last_hash = Some(hb.hash);

        Ok(())
    }

    pub fn first(&self) -> Result<Option<HashedBlock>, ApiError> {
        Ok(self.block_store.first()?)
    }

    pub fn last(&self) -> Result<Option<HashedBlock>, ApiError> {
        match self.last_hash {
            Some(last_hash) => {
                let last = self.get(last_hash)?;
                Ok(Some(last))
            }
            None => Ok(None),
        }
    }

    pub fn synced_to(&self) -> Option<(HashOf<EncodedBlock>, u64)> {
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
                let balances = self.get_balances_at(new_first_idx)?;
                let hb = self.get_at(new_first_idx)?;
                self.block_store
                    .prune(&hb, &balances)
                    .map_err(internal_error)?
            }
        }
        Ok(())
    }
}
