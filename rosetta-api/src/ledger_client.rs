use crate::convert::{internal_error, invalid_block_id};
use crate::ledger_canister::{Amount, Hash, HashedBlock, Transaction, UserID};
use crate::models::ApiError;
use crate::sync::{read_fs, LedgerCanister};
use core::ops::Deref;
use ic_types::CanisterId;
use im::OrdMap;
use reqwest::Url;
use std::collections::HashMap;
use std::sync::RwLock;

pub trait LedgerAccess {
    // Maybe we should just return RwLockReadGuard explicitly and drop the Box
    fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a>;
    fn sync_blocks(&mut self, _tip: Option<Hash>) -> Result<(), ApiError>;
    fn ledger_canister_id(&self) -> &CanisterId;
    fn reqwest_client(&self) -> &reqwest::Client;
    fn testnet_url(&self) -> &Url;
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

impl LedgerAccess for LedgerClient {
    fn read_blocks(&self) -> Box<dyn Deref<Target = Blocks> + '_> {
        Box::new(self.blockchain.read().unwrap())
    }

    fn sync_blocks(&mut self, tip: Option<Hash>) -> Result<(), ApiError> {
        match tip {
            Some(tip) => self.blockchain.write().unwrap().sync_to(tip),
            None => Ok(()),
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
}

/// This is the entry point for the Rosetta API
#[cfg(test)]
fn read_ledger_transactions() -> Vec<HashedBlock> {
    use crate::test_utils::Scribe;
    let mut scribe = Scribe::new();
    let num_transactions = 3_000;
    let num_accounts = 100;

    scribe.gen_accounts(num_accounts, 1_000_000);
    for _i in 0..num_transactions {
        scribe.gen_transaction();
    }

    //scribe.buy(crate::test_utils::to_uid(0), 10);
    //scribe.sell(crate::test_utils::to_uid(1), 10);

    scribe.blockchain.into()
}

/// describes the state of users accounts
/// This mirrors Balances in the canister code, but is immutable so it can be
/// more easily queried
#[must_use = "`Balances` are immutable, if you don't use it you'll lose your changes"]
#[derive(Clone)]
pub struct Balances {
    pub inner: OrdMap<UserID, Amount>,
}

// Annoyingly this is code duplication from Balances, I don't think rust can be
// polymorphic over mutability, so I think this is how it's going to have to be
// Perhaps I can break this up in the future to reduce duplication
impl Balances {
    pub fn get(&self, id: UserID) -> Option<Amount> {
        self.inner.get(&id).cloned()
    }

    pub fn add_payment(&self, payment: &Transaction) -> Result<Self, String> {
        let res = match payment {
            Transaction::Send { from, to, amount } => {
                self.debit(from, *amount)?.credit(to, *amount)
            }
            Transaction::Burn { from, amount, .. } => self.debit(from, *amount)?,
            Transaction::Mint { to, amount, .. } => self.credit(to, *amount),
        };
        Ok(res)
    }

    fn debit(&self, from: &UserID, amount: Amount) -> Result<Self, String> {
        let map = &self.inner;
        let balance = map.get(from).ok_or_else(|| {
            "You tried to withdraw funds from an account that doesn't exist".to_string()
        })?;
        if *balance < amount {
            return Err(
                "You have tried to spend more than the balance of your account".to_string(),
            );
        }
        let inner = map.update(from.clone(), *balance - amount);
        Ok(Balances { inner })
    }

    fn credit(&self, to: &UserID, amount: Amount) -> Self {
        let inner = self
            .inner
            .clone()
            .update_with(to.clone(), amount, |v, a| v + a);
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
    InMemory(HashMap<Hash, HashedBlock>),
}

pub struct Blocks {
    balances: HashMap<Hash, Balances>,
    block_order: Vec<Hash>,
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

    pub fn get(&self, hash: Hash) -> Result<HashedBlock, ApiError> {
        match &self.block_store {
            BlockStore::OnDisk => read_fs(hash).map_err(internal_error)?,
            BlockStore::InMemory(hm) => hm.get(&hash).cloned(),
        }
        .ok_or_else(|| invalid_block_id(format!("Block not found: {:?}", hash)))
    }

    pub fn get_balances(&self, hash: Hash) -> Result<Balances, ApiError> {
        self.balances
            .get(&hash)
            .cloned()
            .ok_or_else(|| internal_error("Balances not found"))
    }

    /// Add a block to the block_store data structure, the parent_hash must
    /// match the end of the chain
    pub(crate) fn add_block(&mut self, hb: HashedBlock) -> Result<(), ApiError> {
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
            .add_payment(&block.payment)
            .map_err(internal_error)?;

        self.block_order.push(hash);
        self.balances.insert(hash, new_balances);
        if let BlockStore::InMemory(hm) = &mut self.block_store {
            hm.insert(hash, hb);
        }
        Ok(())
    }

    fn contains(&self, hash: &Hash) -> bool {
        self.balances.contains_key(hash)
    }

    /// Ensure that this data structure is updated to at least this hash
    pub fn sync_to(&mut self, target: Hash) -> Result<(), ApiError> {
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
        .collect::<Result<Vec<Hash>, ApiError>>()?;

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
