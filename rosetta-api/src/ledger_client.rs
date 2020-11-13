use crate::convert::into_error;
use crate::ledger_canister::Block;
use crate::ledger_canister::{Amount, Hash, HashedBlock, Transaction, UserID};
use crate::models::ApiError;

use std::collections::{HashMap, VecDeque};
use std::ops::Deref;
use std::sync::RwLock;

use im::OrdMap;

use ic_types::{CanisterId, PrincipalId};
use std::convert::TryFrom;

pub trait LedgerAccess {
    // Maybe we should just return RwLockReadGuard explicitly and drop the Box
    fn blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a>;
    fn ledger_canister_id(&self) -> &CanisterId;
    fn reqwest_client(&self) -> &reqwest::Client;
}

pub struct LedgerClient {
    blockchain: RwLock<Blocks>,
    canister_id: CanisterId,
    client: reqwest::Client,
}

impl LedgerClient {
    pub fn create() -> Result<Self, ApiError> {
        let client = reqwest::Client::new();
        // TODO plug in the real canister id here
        let canister_id =
            CanisterId::new(PrincipalId::try_from(&[0, 0, 0, 0, 0, 0, 4, 210][..]).unwrap())
                .unwrap();

        let bs = Blocks::default();

        // let ts = read_ledger_transactions();
        // for block in ts.into_iter() {
        //     bs.add_block(block)?;
        // }

        let blockchain = RwLock::new(bs);

        Ok(Self {
            blockchain,
            canister_id,
            client,
        })
    }
}

impl LedgerAccess for LedgerClient {
    fn blocks(&self) -> Box<dyn Deref<Target = Blocks> + '_> {
        Box::new(self.blockchain.read().unwrap())
    }

    fn ledger_canister_id(&self) -> &CanisterId {
        &self.canister_id
    }

    fn reqwest_client(&self) -> &reqwest::Client {
        &self.client
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
pub struct Balances {
    pub inner: OrdMap<UserID, Amount>,
}

// Annoyingly this is code duplication from Balances, I don't think rust can be
// polymorphic over mutability, so I think this is how it's going to have to be
// Perhaps I can break this up in the future to reduce duplication
impl Balances {
    pub fn get(&self, id: UserID) -> Option<&Amount> {
        self.inner.get(&id)
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

pub struct BlockInfo {
    pub balances: Balances,
    pub block: Block,
    pub hash: Hash,
    pub index: usize,
}

pub struct Blocks {
    blocks: VecDeque<BlockInfo>,
    index_map: HashMap<Hash, usize>,
}

impl Blocks {
    pub fn get_at(&self, index: usize) -> Option<&BlockInfo> {
        self.blocks.get(index)
    }

    pub fn get(&self, hash: Hash) -> Option<&BlockInfo> {
        self.index_map.get(&hash).and_then(|idx| self.get_at(*idx))
    }

    pub fn last(&self) -> Option<&BlockInfo> {
        self.blocks.back()
    }

    /// Blocks must be added starting from the genesis block, followed by the
    /// last blocks child
    pub fn add_block(&mut self, HashedBlock { hash, block }: HashedBlock) -> Result<(), ApiError> {
        let balances = match self.last() {
            Some(p) => p.balances.add_payment(&block.payment),
            None => Balances::default().add_payment(&block.payment),
        }
        .map_err(|e| ApiError::InvalidTransaction(false, into_error(e)))?;

        // TODO validate

        let index = self.blocks.len();
        let block_info = BlockInfo {
            balances,
            block,
            hash,
            index,
        };
        self.index_map.insert(block_info.hash, index);
        self.blocks.push_back(block_info);
        Ok(())
    }
}

impl Default for Blocks {
    fn default() -> Blocks {
        Blocks {
            blocks: VecDeque::default(),
            index_map: HashMap::default(),
        }
    }
}
