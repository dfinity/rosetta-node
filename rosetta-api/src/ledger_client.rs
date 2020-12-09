use crate::convert::{internal_error, invalid_block_id, transaction_id};
use crate::models::{ApiError, TransactionIdentifier};
use crate::sync::{read_fs, LedgerCanister};
use async_trait::async_trait;
use core::ops::Deref;
use core::time::Duration;
use ic_types::messages::{HttpRequestEnvelope, HttpSubmitContent};
use ic_types::{CanisterId, PrincipalId};
use im::OrdMap;
use ledger_canister::{Block, HashOf, HashedBlock, ICPTs, Transfer};
use reqwest::Url;
use std::collections::HashMap;
use std::sync::RwLock;

#[async_trait]
pub trait LedgerAccess {
    // Maybe we should just return RwLockReadGuard explicitly and drop the Box
    fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a>;
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
    pub canister: LedgerCanister,
    reqwest_client: reqwest::Client,
    testnet_url: Url,
}

impl LedgerClient {
    pub fn create(testnet_url: Url, canister_id: CanisterId) -> Result<Self, ApiError> {
        let in_memory = Blocks::default();
        Self::create_with_blocks(in_memory, testnet_url, canister_id)
    }

    pub fn create_on_disk(testnet_url: Url, canister_id: CanisterId) -> Result<Self, ApiError> {
        let on_disk = Blocks::new_on_disk();
        Self::create_with_blocks(on_disk, testnet_url, canister_id)
    }

    #[cfg(test)]
    pub fn create_with_sample_data(
        sample_data: Vec<HashedBlock>,
        testnet_url: Url,
        canister_id: CanisterId,
    ) -> Result<Self, ApiError> {
        let mut bs = Blocks::default();
        for block in sample_data.into_iter() {
            bs.add_block(block)?;
        }
        Self::create_with_blocks(bs, testnet_url, canister_id)
    }

    pub fn create_with_blocks(
        bs: Blocks,
        testnet_url: Url,
        canister_id: CanisterId,
    ) -> Result<Self, ApiError> {
        let blockchain = RwLock::new(bs);

        let reqwest_client = reqwest::Client::new();

        let canister =
            LedgerCanister::new(reqwest_client.clone(), testnet_url.clone(), canister_id);

        Ok(Self {
            blockchain,
            canister_id,
            canister,
            reqwest_client,
            testnet_url,
        })
    }
}

#[async_trait]
impl LedgerAccess for LedgerClient {
    fn read_blocks(&self) -> Box<dyn Deref<Target = Blocks> + '_> {
        Box::new(self.blockchain.read().unwrap())
    }

    async fn sync_blocks(&self) -> Result<(), ApiError> {
        // First sync to disc
        let tip = self.canister.sync().await.map_err(|e| {
            internal_error(format!(
                "Error in reading blocks from the canister: {:?}",
                e
            ))
        })?;

        // Now sync to memory
        match tip {
            None => Ok(()),
            Some(tip) => {
                if let Err(err) = self.blockchain.write().unwrap().sync_to(tip) {
                    Err(internal_error(format!(
                        "Error in reading blocks from the file system: {:?}",
                        err
                    )))
                } else {
                    Ok(())
                }
            }
        }
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
    pub fn get(&self, id: PrincipalId) -> Option<ICPTs> {
        self.inner.get(&id).cloned()
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
    OnDisk,
    InMemory(HashMap<HashOf<Block>, HashedBlock>),
}

pub struct Blocks {
    balances: HashMap<HashOf<Block>, Balances>,
    block_order: Vec<HashOf<Block>>,
    block_store: BlockStore,
}

impl Blocks {
    pub fn new_on_disk() -> Blocks {
        Blocks {
            block_store: BlockStore::OnDisk,
            ..Blocks::default()
        }
    }

    pub fn get_at(&self, index: usize) -> Result<HashedBlock, ApiError> {
        let hash = *self
            .block_order
            .get(index)
            .ok_or_else(|| invalid_block_id(format!("Block number out of bounds {}", index)))?;
        self.get(hash)
    }

    pub fn get_balances_at(&self, index: usize) -> Result<Balances, ApiError> {
        let hash = *self
            .block_order
            .get(index)
            .ok_or_else(|| invalid_block_id(format!("Block number out of bounds {}", index)))?;
        self.get_balances(hash)
    }

    pub fn get(&self, hash: HashOf<Block>) -> Result<HashedBlock, ApiError> {
        match &self.block_store {
            BlockStore::OnDisk => read_fs(hash).map_err(internal_error)?,
            BlockStore::InMemory(hm) => hm.get(&hash).cloned(),
        }
        .ok_or_else(|| invalid_block_id(format!("Block not found: {:?}", hash)))
    }

    pub fn get_balances(&self, hash: HashOf<Block>) -> Result<Balances, ApiError> {
        self.balances
            .get(&hash)
            .cloned()
            .ok_or_else(|| internal_error("Balances not found"))
    }

    /// Add a block to the block_store data structure, the parent_hash must
    /// match the end of the chain
    pub fn add_block(&mut self, hb: HashedBlock) -> Result<(), ApiError> {
        let HashedBlock { block, hash, .. } = hb.clone();
        let last_hash = self.block_order.last();
        assert_eq!(
            block.parent_hash.as_ref(),
            last_hash,
            "When adding a block the parent_hash must match the last added block"
        );

        let parent_balances = match last_hash {
            // This is the first block being added
            None => Balances::default(),
            Some(hash) => self
                .balances
                .get(hash)
                .ok_or_else(|| {
                    internal_error("Balances must be populated for all hashes in Blocks")
                })?
                .clone(),
        };
        let new_balances = parent_balances
            .add_payment(&block.transaction.transfer)
            .map_err(internal_error)?;

        self.block_order.push(hash);
        self.balances.insert(hash, new_balances);
        if let BlockStore::InMemory(hm) = &mut self.block_store {
            hm.insert(hash, hb);
        }
        Ok(())
    }

    fn contains(&self, hash: &HashOf<Block>) -> bool {
        self.balances.contains_key(hash)
    }

    /// Ensure that this data structure is updated to at least this hash
    pub fn sync_to(&mut self, target: HashOf<Block>) -> Result<(), ApiError> {
        // List all the ancestors of the target that don't exist in this data structure
        // starting with the target
        let missing_values = itertools::unfold(Some(target), |mut_hash| {
            let current_hash = match mut_hash {
                // The last block was the genesis block so we're done
                None => return None,
                Some(x) => x,
            };
            if self.contains(current_hash) {
                // This block is inside Blocks so we're done
                None
            } else {
                let res = self
                    .get(*current_hash)
                    .map(|HashedBlock { hash, block, .. }| {
                        *mut_hash = block.parent_hash;
                        hash
                    });
                Some(res)
            }
        })
        .collect::<Result<Vec<HashOf<Block>>, ApiError>>()?;

        // Add the missing block_store starting with the oldest one
        for hash in missing_values.into_iter().rev() {
            let hb = self.get(hash)?;
            self.add_block(hb)?;
        }

        Ok(())
    }

    pub fn last(&self) -> Result<Option<HashedBlock>, ApiError> {
        match self.block_order.last().cloned() {
            Some(last_hash) => {
                let last = self.get(last_hash)?;
                Ok(Some(last))
            }
            None => Ok(None),
        }
    }
}

impl Default for Blocks {
    fn default() -> Blocks {
        Blocks {
            balances: HashMap::default(),
            block_order: Vec::default(),
            block_store: BlockStore::InMemory(HashMap::default()),
        }
    }
}
