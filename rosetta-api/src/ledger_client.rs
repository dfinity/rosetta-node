use crate::convert::{internal_error, invalid_block_id, transaction_id};
use crate::models::{ApiError, TransactionIdentifier};
use crate::store::{BlockStore, BlockStoreError, HashedBlock, InMemoryStore, OnDiskStore};
use async_trait::async_trait;
use core::ops::Deref;
use core::time::Duration;
use dfn_candid::{Candid, CandidOne};
use ic_canister_client::{Agent, Sender};
use ic_types::messages::{HttpRequestEnvelope, HttpSubmitContent};
use ic_types::{CanisterId, PrincipalId};
use im::OrdMap;
use ledger_canister::{
    Block, BlockHeight, Certification, HashOf, ICPTs, RawBlock, Serializable, Transfer,
};
use log::{debug, error, info, trace};
use on_wire::{FromWire, IntoWire};
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use tokio::sync::RwLock;

#[async_trait]
pub trait LedgerAccess {
    // Maybe we should just return RwLockReadGuard explicitly and drop the Box
    async fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a>;
    async fn sync_blocks(&self, stopped: Arc<AtomicBool>) -> Result<(), ApiError>;
    fn ledger_canister_id(&self) -> &CanisterId;
    fn reqwest_client(&self) -> &reqwest::Client;
    fn testnet_url(&self) -> &Url;
    async fn submit(
        &self,
        _envelope: HttpRequestEnvelope<HttpSubmitContent>,
    ) -> Result<TransactionIdentifier, ApiError>;
}

pub struct LedgerClient {
    blockchain: RwLock<Blocks>,
    canister_id: CanisterId,
    reqwest_client: Option<reqwest::Client>,
    canister_access: Option<CanisterAccess>,
    testnet_url: Url,
    store_max_blocks: Option<u64>,
    offline: bool,
}

impl LedgerClient {
    pub async fn create_on_disk(
        testnet_url: Url,
        canister_id: CanisterId,
        store_location: &Path,
        store_max_blocks: Option<u64>,
        offline: bool,
    ) -> Result<LedgerClient, ApiError> {
        let location = store_location.join("blocks");
        std::fs::create_dir_all(&location)
            .map_err(|e| format!("{}", e))
            .map_err(internal_error)?;

        let mut blocks = Blocks::new_on_disk(location)?;

        let (reqwest_client, canister_access) = if offline {
            (None, None)
        } else {
            let reqwest_client = reqwest::Client::new();
            let canister_access =
                CanisterAccess::new(testnet_url.clone(), canister_id, reqwest_client.clone());
            Self::verify_store(&blocks, &canister_access).await?;

            (Some(reqwest_client), Some(canister_access))
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
            reqwest_client,
            canister_access,
            testnet_url,
            store_max_blocks,
            offline,
        })
    }

    async fn verify_store(
        blocks: &Blocks,
        canister_access: &CanisterAccess,
    ) -> Result<(), ApiError> {
        debug!("Verifying store...");
        match blocks.block_store.get_at(0) {
            Ok(store_genesis) => {
                let genesis: Block = canister_access
                    .query_block(0)
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
            let queried_block = canister_access.query_block(first_block.index).await?;
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

    /// TODO actually verify the BLS signature
    fn verify_tip(_cert: Certification, _hash: Option<HashOf<Block>>) -> Result<(), String> {
        Ok(())
    }
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
        let (cert, tip) = canister.query_tip().await?;
        let chain_length = tip + 1;
        debug!("Chain length is {}", chain_length);

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
                break;
            }
            debug!("Fetching block {}", i);
            let b = canister.query_block(i).await?.unwrap_or_else(|| {
                panic!(
                    "Block {} is missing when the tip of the chain is {}",
                    i, chain_length
                )
            });
            let hb = HashedBlock::hash_block(b, last_block_hash, i);
            blockchain.add_block(hb.clone())?;
            last_block_hash = Some(hb.hash);
        }
        LedgerClient::verify_tip(cert, last_block_hash).map_err(internal_error)?;
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

    fn reqwest_client(&self) -> &reqwest::Client {
        self.reqwest_client
            .as_ref()
            .expect("Reqwest client not present in offline mode")
    }

    fn testnet_url(&self) -> &Url {
        &self.testnet_url
    }

    async fn submit(
        &self,
        submit_request: HttpRequestEnvelope<HttpSubmitContent>,
    ) -> Result<TransactionIdentifier, ApiError> {
        if self.offline {
            return Err(ApiError::NotAvailableOffline(false, None));
        }
        const UPDATE_PATH: &str = &"api/v1/submit";

        const INGRESS_TIMEOUT: Duration = Duration::from_secs(30);

        // TODO change all serde_json to serde_cbor to avoid this marshaling, but not
        // right now because JSON is easier to debug
        let http_body = serde_cbor::to_vec(&submit_request).map_err(|e| {
            internal_error(format!(
                "Cannot serialize the submit request in CBOR format because of: {}",
                e
            ))
        })?;

        let url = self.testnet_url.join(UPDATE_PATH).expect("URL join failed");

        let client = self.reqwest_client();

        let request = client
            .post(url)
            .header("Content-Type", "application/cbor")
            .body(http_body);

        let response = request
            .timeout(INGRESS_TIMEOUT)
            .send()
            .await
            .map_err(internal_error)?;

        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.map_err(internal_error)?;
            return Err(internal_error(format!(
                "IC returned HTTP error {}: {}",
                status, body
            )));
        }

        // If we need to debug the response
        //     .bytes()
        //     .await
        //     .map_err(internal_error)?;

        // let cbor = serde_cbor::from_slice(&bytes).map_err(|e| {
        //     internal_error(format!(
        //         "Failed to parse result from IC, got: {:?} - error {:?}",
        //         bytes, e
        //     ))
        // })?;

        transaction_id(submit_request)
    }
}

pub struct CanisterAccess {
    agent: Agent,
    canister_id: CanisterId,
}

impl CanisterAccess {
    pub fn new(url: Url, canister_id: CanisterId, client: reqwest::Client) -> Self {
        let agent = Agent::new_with_client(client, url, Sender::Anonymous);
        Self { agent, canister_id }
    }

    pub async fn query<'a, Payload: dfn_candid::ArgumentEncoder, Res: DeserializeOwned>(
        &self,
        method: &str,
        payload: Payload,
    ) -> Result<Res, String> {
        let arg = Candid(payload).into_bytes()?;
        let bytes = self
            .agent
            .execute_query(&self.canister_id, method, Some(arg))
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        CandidOne::from_bytes(bytes).map(|c| c.0)
    }

    pub async fn query_tip(&self) -> Result<(Certification, BlockHeight), ApiError> {
        self.query("tip_of_chain", ())
            .await
            .map_err(|e| internal_error(format!("In tip: {}", e)))
    }

    pub async fn query_block(&self, height: BlockHeight) -> Result<Option<Block>, ApiError> {
        let raw_block: Option<RawBlock> = self
            .query("block", (height,))
            .await
            .map_err(|e| internal_error(format!("In block: {}", e)))?;
        match raw_block {
            Some(raw_block) => {
                Ok(Some(Block::decode(&*raw_block).map_err(|err| {
                    internal_error(format!("While decoding block: {}", err))
                })?))
            }
            None => Ok(None),
        }
    }
}

/// describes the state of users accounts
/// This mirrors Balances in the canister code, but is immutable so it can be
/// more easily queried
#[must_use = "`Balances` are immutable, if you don't use it you'll lose your changes"]
#[derive(Clone, Serialize, Deserialize)]
pub struct Balances {
    pub inner: OrdMap<PrincipalId, ICPTs>,
}

// Annoyingly this is code duplication from Balances, I don't think rust can be
// polymorphic over mutability, so I think this is how it's going to have to be
// Perhaps I can break this up in the future to reduce duplication
impl Balances {
    pub fn account_balance(&self, account: &PrincipalId) -> ICPTs {
        self.inner.get(account).cloned().unwrap_or(ICPTs::ZERO)
    }

    pub fn add_payment(&mut self, payment: &Transfer) {
        match payment {
            Transfer::Send {
                from,
                to,
                amount,
                fee,
            } => {
                self.debit(from, (*amount + *fee).expect("amount + fee failed"));
                self.credit(to, *amount);
            }
            Transfer::Burn { from, amount, .. } => self.debit(from, *amount),
            Transfer::Mint { to, amount, .. } => self.credit(to, *amount),
        }
    }

    fn debit(&mut self, from: &PrincipalId, amount: ICPTs) {
        let balance = self
            .inner
            .get_mut(from)
            .expect("You tried to withdraw funds from an account that is empty");
        // This is technically redundant because Amount uses checked arithmetic, but
        // belt an braces
        assert!(
            *balance >= amount,
            "You have tried to spend more than the balance of your account"
        );
        *balance -= amount;

        // Remove an account whose balance reaches ZERO
        if *balance == ICPTs::ZERO {
            self.inner.remove(from);
        }
    }

    fn credit(&mut self, to: &PrincipalId, amount: ICPTs) {
        let balance = self.inner.entry(*to).or_insert(ICPTs::ZERO);
        *balance += amount;
    }
}

impl Default for Balances {
    fn default() -> Balances {
        Balances {
            inner: OrdMap::new(),
        }
    }
}

pub struct Blocks {
    balances: HashMap<BlockHeight, Balances>,
    hash_location: HashMap<HashOf<Block>, BlockHeight>,
    block_store: Box<dyn BlockStore + Send + Sync>,
    last_hash: Option<HashOf<Block>>,
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

    pub fn get(&self, hash: HashOf<Block>) -> Result<HashedBlock, ApiError> {
        let index = *self
            .hash_location
            .get(&hash)
            .ok_or_else(|| invalid_block_id(format!("Block number out of bounds {}", hash)))?;
        self.get_at(index)
    }

    pub fn get_balances(&self, hash: HashOf<Block>) -> Result<Balances, ApiError> {
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

        new_balances.add_payment(&block.transaction().transfer);

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

    pub fn synced_to(&self) -> Option<(HashOf<Block>, u64)> {
        self.last().ok().flatten().map(|hb| (hb.hash, hb.index))
    }

    fn try_prune(&mut self, max_blocks: &Option<u64>, prune_delay: u64) -> Result<(), ApiError> {
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
