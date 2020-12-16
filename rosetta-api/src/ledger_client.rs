use crate::convert::{internal_error, invalid_block_id, transaction_id};
use crate::models::{ApiError, TransactionIdentifier};
use crate::sync::{HashedBlock, LedgerCanister};
use async_trait::async_trait;
use core::ops::Deref;
use core::time::Duration;
use ic_types::messages::{HttpRequestEnvelope, HttpSubmitContent};
use ic_types::{CanisterId, PrincipalId};
use im::OrdMap;
use ledger_canister::{Block, BlockHeight, HashOf, ICPTs, Transfer};
use reqwest::Url;
use std::collections::HashMap;
use tokio::sync::RwLock;

#[async_trait]
pub trait LedgerAccess {
    // Maybe we should just return RwLockReadGuard explicitly and drop the Box
    async fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a>;
    async fn sync_blocks(&self) -> Result<(), ApiError>;
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
    reqwest_client: reqwest::Client,
    testnet_url: Url,
}

impl LedgerClient {
    pub async fn create(testnet_url: Url, canister_id: CanisterId) -> Result<Self, ApiError> {
        let in_memory = Blocks::default();

        let blockchain = RwLock::new(in_memory);

        let reqwest_client = reqwest::Client::new();

        Ok(Self {
            blockchain,
            canister_id,
            reqwest_client,
            testnet_url,
        })
    }

    pub async fn create_on_disk(
        testnet_url: Url,
        canister_id: CanisterId,
    ) -> Result<LedgerClient, ApiError> {
        let reqwest_client = reqwest::Client::new();

        let canister =
            LedgerCanister::new(reqwest_client.clone(), testnet_url.clone(), canister_id)
                .await
                .map_err(internal_error)?;

        let on_disk = Blocks::new_on_disk(canister);

        let blockchain = RwLock::new(on_disk);

        Ok(Self {
            blockchain,
            canister_id,
            reqwest_client,
            testnet_url,
        })
    }

    // #[cfg(test)]
    // pub fn create_with_sample_data(
    //     sample_data: Vec<HashedBlock>,
    //     testnet_url: Url,
    //     canister_id: CanisterId,
    // ) -> Result<Self, ApiError> {
    //     let mut bs = Blocks::default();
    //     for block in sample_data.into_iter() {
    //         bs.add_block(block)?;
    //     }
    //     Self::create_with_blocks(bs, testnet_url, canister_id)
    // }
}

#[async_trait]
impl LedgerAccess for LedgerClient {
    async fn read_blocks(&self) -> Box<dyn Deref<Target = Blocks> + '_> {
        Box::new(self.blockchain.read().await)
    }

    async fn sync_blocks(&self) -> Result<(), ApiError> {
        let mut locked = self.blockchain.write().await;
        locked.block_store.sync().await.map_err(internal_error)?;
        locked.sync().await
    }

    fn ledger_canister_id(&self) -> &CanisterId {
        &self.canister_id
    }

    fn reqwest_client(&self) -> &reqwest::Client {
        &self.reqwest_client
    }

    fn testnet_url(&self) -> &Url {
        &self.testnet_url
    }

    async fn submit(
        &self,
        submit_request: HttpRequestEnvelope<HttpSubmitContent>,
    ) -> Result<TransactionIdentifier, ApiError> {
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

        request
            .timeout(INGRESS_TIMEOUT)
            .send()
            .await
            .map_err(internal_error)?;

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

/// describes the state of users accounts
/// This mirrors Balances in the canister code, but is immutable so it can be
/// more easily queried
#[must_use = "`Balances` are immutable, if you don't use it you'll lose your changes"]
#[derive(Clone)]
pub struct Balances {
    pub inner: OrdMap<PrincipalId, ICPTs>,
}

// Annoyingly this is code duplication from Balances, I don't think rust can be
// polymorphic over mutability, so I think this is how it's going to have to be
// Perhaps I can break this up in the future to reduce duplication
impl Balances {
    pub fn get(&self, id: PrincipalId) -> ICPTs {
        self.inner.get(&id).cloned().unwrap_or_else(ICPTs::zero)
    }

    pub fn add_payment(&self, payment: &Transfer) -> Result<Self, String> {
        let res = match payment {
            Transfer::Send { from, to, amount } => self.debit(from, *amount)?.credit(to, *amount),
            Transfer::Burn { from, amount, .. } => self.debit(from, *amount)?,
            Transfer::Mint { to, amount, .. } => self.credit(to, *amount),
        };
        Ok(res)
    }

    fn debit(&self, from: &PrincipalId, amount: ICPTs) -> Result<Self, String> {
        let map = &self.inner;
        let balance = map.get(from).ok_or_else(|| {
            "You tried to withdraw funds from an account that doesn't exist".to_string()
        })?;
        if *balance < amount {
            return Err(
                "You have tried to spend more than the balance of your account".to_string(),
            );
        }
        let inner = map.update(*from, (*balance - amount)?);
        Ok(Balances { inner })
    }

    fn credit(&self, to: &PrincipalId, amount: ICPTs) -> Self {
        let inner = self
            .inner
            .clone()
            .update_with(*to, amount, |v, a| (v + a).unwrap());
        Balances { inner }
    }
}

impl Default for Balances {
    fn default() -> Balances {
        Balances {
            inner: OrdMap::new(),
        }
    }
}

// This is a crutch, we need to write some traits to dedup our code and simplify
// testing
enum BlockStore {
    OnDisk(LedgerCanister),
    InMemory(Vec<HashedBlock>),
}

impl BlockStore {
    fn last(&mut self) -> Result<Option<HashedBlock>, ApiError> {
        match self {
            BlockStore::OnDisk(lc) => lc.last().map_err(internal_error),
            BlockStore::InMemory(hbs) => Ok(hbs.last().cloned()),
        }
    }
    async fn sync(&mut self) -> Result<(), String> {
        if let BlockStore::OnDisk(lc) = self {
            lc.sync().await?;
        }
        Ok(())
    }
}

pub struct Blocks {
    balances: HashMap<BlockHeight, Balances>,
    hash_location: HashMap<HashOf<Block>, BlockHeight>,
    block_store: BlockStore,
    last_hash: Option<HashOf<Block>>,
}

impl Blocks {
    pub fn new_on_disk(ledger_canister: LedgerCanister) -> Self {
        Blocks {
            block_store: BlockStore::OnDisk(ledger_canister),
            ..Blocks::default()
        }
    }

    pub fn get_at(&self, index: BlockHeight) -> Result<HashedBlock, ApiError> {
        match &self.block_store {
            BlockStore::OnDisk(lc) => lc.read_cache(index).map_err(internal_error)?,
            BlockStore::InMemory(hm) => hm.get(index as usize).cloned(),
        }
        .ok_or_else(|| invalid_block_id(format!("Block not found: {:?}", index)))
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

        let parent_balances = match last_index {
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
        let new_balances = parent_balances
            .add_payment(&block.transaction.transfer)
            .map_err(internal_error)?;

        self.hash_location.insert(hash, index);
        self.balances.insert(index, new_balances);
        self.last_hash = Some(hb.hash);
        if let BlockStore::InMemory(hm) = &mut self.block_store {
            hm.push(hb);
        }
        Ok(())
    }

    /// Ensure that this data structure is updated to at least this height
    pub async fn sync(&mut self) -> Result<(), ApiError> {
        let height: BlockHeight = match self.block_store.last()? {
            Some(hb) => hb.index,
            None => return Ok(()),
        };
        let synced_until = match self.last()? {
            Some(hb) => hb.index + 1,
            None => 0,
        };
        for h in synced_until..=height {
            let hb = self.get_at(h)?;
            self.add_block(hb)?;
        }

        Ok(())
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
}

impl Default for Blocks {
    fn default() -> Self {
        Blocks {
            balances: HashMap::default(),
            hash_location: HashMap::default(),
            block_store: BlockStore::InMemory(Vec::new()),
            last_hash: None,
        }
    }
}
