use candid::CandidType;
use ic_crypto_sha256::Sha256;
use ic_types::PrincipalId;
use lazy_static::lazy_static;
use phantom_newtype::Id;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::sync::RwLock;
use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

mod icpts;
pub use icpts::{ICPTs, DECIMAL_PLACES, ICP_SUBDIVIDABLE_BY};

#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HashOf<T> {
    inner: Id<T, [u8; 32]>,
}

impl<T: std::clone::Clone> Copy for HashOf<T> {}

impl<T> HashOf<T> {
    pub fn into_bytes(self) -> [u8; 32] {
        self.inner.get()
    }

    pub fn new(bs: [u8; 32]) -> Self {
        HashOf { inner: Id::new(bs) }
    }
}

impl<T> fmt::Display for HashOf<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let res = hex::encode(self.inner.get());
        write!(f, "{}", res)
    }
}

impl<T> FromStr for HashOf<T> {
    type Err = String;
    fn from_str(s: &str) -> Result<HashOf<T>, String> {
        let v = hex::decode(s).map_err(|e| e.to_string())?;
        let slice = v.as_slice();
        match slice.try_into() {
            Ok(ba) => Ok(HashOf::new(ba)),
            Err(_) => Err(format!(
                "Expected a Vec of length {} but it was {}",
                32,
                v.len(),
            )),
        }
    }
}

#[derive(
    Serialize, Deserialize, CandidType, Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Memo(pub u64);

impl Default for Memo {
    fn default() -> Memo {
        Memo(0)
    }
}

pub type BlockHeight = u64;

pub type SubmitArgs = (Memo, ICPTs, PrincipalId, Option<BlockHeight>);

// This type will change when we implement certification
pub type Certification = u64;

/// Describes the state of users accounts at the tip of the chain
#[derive(Default)]
pub struct Balances {
    // This uses a mutable map because we don't want to risk a space leak and we only require the
    // account balances at the tip of the chain
    pub inner: HashMap<PrincipalId, ICPTs>,
}

impl Balances {
    pub fn add_payment(&mut self, payment: &Transfer) {
        match payment {
            Transfer::Send { from, to, amount } => {
                self.debit(from, *amount);
                self.credit(to, *amount);
            }
            Transfer::Burn { from, amount, .. } => self.debit(from, *amount),
            Transfer::Mint { to, amount, .. } => self.credit(to, *amount),
        }
    }

    pub fn debit(&mut self, from: &PrincipalId, amount: ICPTs) {
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
    }

    pub fn credit(&mut self, to: &PrincipalId, amount: ICPTs) {
        let balance = self.inner.entry(*to).or_insert_with(ICPTs::zero);
        *balance += amount;
    }

    pub fn account_balance(&self, account: &PrincipalId) -> Option<ICPTs> {
        self.inner.get(account).cloned()
    }
}

/// An operation which modifies account balances
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Transfer {
    Burn {
        from: PrincipalId,
        amount: ICPTs,
    },
    Mint {
        to: PrincipalId,
        amount: ICPTs,
    },
    Send {
        from: PrincipalId,
        to: PrincipalId,
        amount: ICPTs,
    },
}

/// A transfer with the metadata the client generated attached to it
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Transaction {
    pub transfer: Transfer,
    pub memo: Memo,
    pub created_at: BlockHeight,
}

impl Transaction {
    pub fn new(
        from: PrincipalId,
        to: PrincipalId,
        amount: ICPTs,
        memo: Memo,
        created_at: BlockHeight,
    ) -> Self {
        let transfer = Transfer::Send { from, to, amount };
        Transaction {
            transfer,
            memo,
            created_at,
        }
    }

    /// This hash function gives us a globally unique identifier for each
    /// transaction. This hashes the transfer, the memo and the height the
    /// transaction was 'created_at'. A transaction is 'created' not when it is
    /// added to the ledger, but rather it is created at the height of the
    /// ledger last observed by the person signing the transaction.
    ///
    /// This means that if you create a transaction using a cold wallet, you can
    /// track that transactions identifier once it reaches the ledger.
    pub fn hash(&self) -> HashOf<Transaction> {
        let mut state = Sha256::new();
        let amount = match self.transfer {
            Transfer::Send { from, to, amount } => {
                state.write(from.as_slice());
                state.write(to.as_slice());
                amount
            }
            Transfer::Burn { from, amount } => {
                state.write(from.as_slice());
                amount
            }
            Transfer::Mint { to, amount } => {
                state.write(to.as_slice());
                amount
            }
        };
        state.write(&amount.get_doms().to_be_bytes());
        state.write(&self.memo.0.to_be_bytes());
        state.write(&self.created_at.to_be_bytes());
        let inner = state.finish();
        HashOf::new(inner)
    }
}

/// A transaction with the metadata the canister generated attached to it
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Block {
    pub transaction: Transaction,
    pub timestamp: SystemTime,
}

impl Block {
    pub fn new(transfer: Transfer, memo: Memo, created_at: BlockHeight) -> Result<Block, String> {
        let timestamp = dfn_core::api::now();
        let transaction = Transaction {
            transfer,
            memo,
            created_at,
        };
        Ok(Block {
            transaction,
            timestamp,
        })
    }

    /// This hash function exists so we can create a hash chain of blocks back
    /// to the genesis of this canister. It is a hash of the time this
    /// block was made, the transaction in this block and the previous blocks
    /// hash.
    pub fn hash(&self, parent_hash: Option<HashOf<Block>>) -> HashOf<Block> {
        let mut state = Sha256::new();
        let ns_since_epoch = self
            .timestamp
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos();
        state.write(&ns_since_epoch.to_be_bytes());
        state.write(&self.transaction.hash().into_bytes());
        if let Some(ph) = parent_hash {
            state.write(&ph.into_bytes());
        }
        HashOf::new(state.finish())
    }
}

/// Stores a chain of transactions with their metadata
#[derive(Default)]
pub struct BlockChain {
    pub inner: Vec<Block>,
    pub last_hash: Option<HashOf<Block>>,
}

impl BlockChain {
    pub fn add_payment(
        &mut self,
        message: Memo,
        payment: Transfer,
        created_at: Option<BlockHeight>,
    ) -> Result<BlockHeight, String> {
        // Either the caller specified the height that the block was created at, or we
        // assume it was created at the current height
        // TODO check created_at is between now and 24 hours in the past
        let created_at = created_at.unwrap_or_else(|| self.height());
        let block = Block::new(payment, message, created_at)?;
        let parent_hash = self.last_hash;
        self.last_hash = Some(block.hash(parent_hash));
        self.inner.push(block);
        Ok(self.height())
    }

    pub fn get(&self, height: BlockHeight) -> Option<&Block> {
        self.inner.get(usize::try_from(height).unwrap())
    }

    pub fn height(&self) -> BlockHeight {
        self.inner.len() as u64 - 1
    }

    pub fn last(&self) -> Option<&Block> {
        self.inner.last()
    }
}

#[derive(Default)]
pub struct State {
    pub balances: Balances,
    pub transactions: BlockChain,
}

impl State {
    pub fn add_payment(
        &mut self,
        message: Memo,
        payment: Transfer,
        created_at: Option<BlockHeight>,
    ) -> Result<BlockHeight, String> {
        self.balances.add_payment(&payment);
        self.transactions.add_payment(message, payment, created_at)
    }

    pub fn from_init(
        &mut self,
        initial_values: HashMap<PrincipalId, ICPTs>,
        minting_canister: PrincipalId,
    ) {
        self.add_payment(
            Memo::default(),
            Transfer::Mint {
                to: minting_canister,
                amount: ICPTs::MAX,
            },
            None,
        )
        .expect("Creating the minting canister account failed");
        for (to, amount) in initial_values.into_iter() {
            self.add_payment(
                Memo::default(),
                Transfer::Send {
                    from: minting_canister,
                    to,
                    amount,
                },
                None,
            )
            .expect(&format!("Creating account {:?} failed", to)[..]);
        }
    }
}

lazy_static! {
    pub static ref STATE: RwLock<State> = RwLock::new(State::default());
}

/// This is the only function that should write to state
pub fn add_payment(
    message: Memo,
    payment: Transfer,
    created_at: Option<BlockHeight>,
) -> BlockHeight {
    STATE
        .write()
        .unwrap()
        .add_payment(message, payment, created_at)
        .expect("Transfer failed")
}
