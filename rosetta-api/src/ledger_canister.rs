use dfn_core::api::call_with_funds;
use dfn_core::api::msg_funds_refunded;
use dfn_core::api::Funds;
use dfn_core::api::{caller, msg_funds_accept, msg_funds_available, TokenUnit};
use dfn_core::bytes;
use dfn_core::FutureResult;
use dfn_macro::{query, update};
use lazy_static::lazy_static;
use serde::{de::Error, Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::RwLock;
use std::time::SystemTime;

// #[derive(Serialize, Deserialize, Clone, Copy)]
// pub struct Hash {inner: [u8; 32]}
// TODO make this a proper hash (sha 256)
pub type Hash = u64;

pub type Amount = u64;

/// This can either be a person or a canister
#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Clone, PartialOrd, Ord, Debug)]
pub struct UserID(pub Vec<u8>);

impl UserID {
    fn caller() -> UserID {
        UserID(caller())
    }
}

// Remove this after the chron canister is merged
#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Clone, Debug)]
pub struct CanisterID(pub Vec<u8>);

impl CanisterID {
    fn caller() -> CanisterID {
        CanisterID(caller())
    }

    // TODO validate
    fn into_core(self) -> dfn_core::CanisterId {
        dfn_core::CanisterId::try_from(self.0).unwrap()
    }
}

pub type Certification = Hash;

/// Describes the state of users accounts at the tip of the chain
#[derive(Default)]
pub struct Balances {
    // This uses a mutable map because we don't want to risk a space leak and we only require the
    // account balances at the tip of the chain
    pub inner: HashMap<UserID, Amount>,
}

impl Balances {
    pub fn add_payment(&mut self, payment: &Transaction) {
        match payment {
            Transaction::Send { from, to, amount } => {
                self.debit(from, *amount);
                self.credit(to, *amount);
            }
            Transaction::Burn { from, amount, .. } => self.debit(from, *amount),
            Transaction::Mint { to, amount, .. } => self.credit(to, *amount),
        }
    }

    pub fn debit(&mut self, from: &UserID, amount: Amount) {
        let balance = self
            .inner
            .get_mut(from)
            .expect("You tried to withdraw funds from an account that doesn't exist");
        assert!(
            *balance >= amount,
            "You have tried to spend more than the balance of your account"
        );
        *balance -= amount;
    }

    pub fn credit(&mut self, to: &UserID, amount: Amount) {
        let balance = self.inner.entry(to.clone()).or_insert(0);
        *balance += amount;
    }
}

#[derive(Serialize, Deserialize, Hash, Debug, PartialEq, Eq, Clone)]
pub enum Transaction {
    Burn {
        from: UserID,
        to: CanisterID,
        amount: Amount,
    },
    Mint {
        from: CanisterID,
        to: UserID,
        amount: Amount,
    },
    Send {
        from: UserID,
        to: UserID,
        amount: Amount,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub payment: Transaction,
    pub timestamp: SystemTime,
    pub transaction_id: Hash,
    pub parent_hash: Option<Hash>,
    pub index: usize,
}

impl Block {
    fn new(
        payment: Transaction,
        transaction_id: Hash,
        parent_hash: Option<Hash>,
        index: usize,
    ) -> Block {
        let timestamp = dfn_core::api::now();
        Block {
            payment,
            timestamp,
            transaction_id,
            parent_hash,
            index,
        }
    }

    fn hash(&self) -> Hash {
        // TODO hash properly
        self.parent_hash.unwrap_or(0) + 1
    }
}

// We do this manually here because we want to prevent construction in the
// crate, whereas non_exhaustive only protects other crates from constructing
// things
#[allow(clippy::manual_non_exhaustive)]
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct HashedBlock {
    pub block: Block,
    pub hash: Hash,
    #[serde(skip_serializing)]
    __inner: (),
}

mod hidden {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct HashedBlock {
        pub block: super::Block,
        pub hash: super::Hash,
    }
}

impl HashedBlock {
    pub fn hash_block(block: Block) -> HashedBlock {
        HashedBlock {
            hash: block.hash(),
            block,
            __inner: (),
        }
    }
}

/// We have this custom implementation make sure that the HashedBlock is always
/// constructed correctly
impl<'de> Deserialize<'de> for HashedBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hidden::HashedBlock { block, hash } = Deserialize::deserialize(deserializer)?;
        if block.hash() != hash {
            return Err(Error::custom(
                "The block failed do deserialize, hash checking failed",
            ));
        }
        Ok(HashedBlock {
            block,
            hash,
            __inner: (),
        })
    }
}

/// Stores a chain of transactions with their metadata
#[derive(Default)]
pub struct BlockChain {
    pub inner: HashMap<Hash, Block>,
    pub last_hash: Option<Hash>,
}

impl BlockChain {
    pub fn add_payment(&mut self, transaction_id: Hash, payment: Transaction) {
        let parent_hash = self.last_block_hash();
        let this_index = match self.last_block() {
            Some(last_block) => last_block.block.index + 1,
            None => 0,
        };
        let block = Block::new(payment, transaction_id, parent_hash.cloned(), this_index);

        let block_hash = block.hash();
        self.last_hash = Some(block_hash);
        let res = self.inner.insert(block_hash, block);
        assert_eq!(res, None);
    }

    pub fn get(&self, hash: Hash) -> Option<HashedBlock> {
        let block = self.inner.get(&hash)?.clone();
        Some(HashedBlock {
            block,
            hash,
            __inner: (),
        })
    }

    pub fn last_block_hash(&self) -> Option<&Hash> {
        self.last_hash.as_ref()
    }

    pub fn last_block(&self) -> Option<HashedBlock> {
        let last = self.last_block_hash()?;
        self.get(*last)
    }
}

#[derive(Default)]
pub struct State {
    pub balances: Balances,
    pub transactions: BlockChain,
}

impl State {
    pub fn add_payment(&mut self, transaction_id: Hash, payment: Transaction) {
        self.balances.add_payment(&payment);
        self.transactions.add_payment(transaction_id, payment);
    }
}

lazy_static! {
    static ref STATE: RwLock<State> = RwLock::new(State::default());
}

/// This is the only function that should write to state
fn add_payment(transaction_id: Hash, payment: Transaction) {
    STATE.write().unwrap().add_payment(transaction_id, payment);
}

const TOKEN: TokenUnit = TokenUnit::ICP;

/// Endpoints:
/// Mint an amount of ICPT equivalent to the number of ICP deposited and place
/// it in the callers account
#[update]
fn deposit(transaction_id: Hash, to: UserID) {
    let amount = msg_funds_available(TOKEN);
    assert_ne!(amount, 0, "You must attach ICPTs to a deposit call");
    burn(transaction_id, to, amount);
}

/// Burn an amount of ICPT, if the callers account has it, and send an
/// equivalent amount of ICP to the receiver canister
/// Any amount refunded is re-added to the ledger
// TODO put limits on the payload before it gets loaded into memory
// TODO replace this completely when we have implemented the ERC-30
#[update]
async fn withdraw(
    transaction_id: Hash,
    amount: Amount,
    to: CanisterID,
    method: String,
    payload: Vec<u8>,
) {
    let from = UserID::caller();

    let payment = Transaction::Burn {
        from: from.clone(),
        to: to.clone(),
        amount,
    };
    // If this payment isn't possible this will panic and roll back
    add_payment(transaction_id, payment);

    // Succeed or fail we should add whatever is refunded back to the ledger
    let _: FutureResult<Vec<u8>> = call_with_funds(
        to.into_core(),
        &method,
        bytes,
        payload,
        Funds {
            icpts: amount,
            cycles: 0,
        },
    )
    .await;
    let refunded = msg_funds_refunded(TOKEN);
    // Use system entropy to generate a new ID
    let new_transaction_id = transaction_id + 1;
    burn(new_transaction_id, from, refunded);
}

/// Withdraw an amount of ICPT, if the callers account has it, and deposit it
/// in the receivers account on the same canister
#[update]
fn send(transaction_id: Hash, amount: Amount, to: UserID) {
    let from = UserID::caller();
    let payment = Transaction::Send { from, amount, to };
    add_payment(transaction_id, payment)
}

/// Certification isn't implemented yet
#[query]
fn tip_of_chain() -> Option<(Certification, Hash)> {
    let transactions = &STATE.read().unwrap().transactions;
    let hash = transactions.last_block_hash()?;
    Some((*hash, *hash))
}

#[query]
fn block(block_hash: Hash) -> Option<HashedBlock> {
    let transactions = &STATE.read().unwrap().transactions;
    transactions.get(block_hash)
}

fn burn(transaction_id: Hash, to: UserID, amount: Amount) {
    let payment = Transaction::Mint {
        to,
        amount,
        from: CanisterID::caller(),
    };
    add_payment(transaction_id, payment);
    // Do this right at the end so we can't keep funds then panic
    msg_funds_accept(TOKEN, amount);
}

pub fn main() {}
