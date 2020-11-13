use dfn_core::api::call_with_funds;
use dfn_core::api::msg_funds_refunded;
use dfn_core::api::Funds;
use dfn_core::api::{caller, msg_funds_accept, msg_funds_available, TokenUnit};
use dfn_core::bytes;
use dfn_core::FutureResult;
use dfn_macro::{query, update};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::RwLock;
use std::time::SystemTime;

type BlockIndex = usize;

// #[derive(Serialize, Deserialize, Clone, Copy)]
// pub struct Hash {inner: [u8; 32]}
// TODO make this a proper hash (sha 256)
pub type Hash = u64;

pub type Amount = u64;

/// This can either be a person or a canister
#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct UserID(pub Vec<u8>);

impl UserID {
    fn caller() -> UserID {
        UserID(caller())
    }
}

// Remove this after the chron canister is merged
#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Clone)]
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

type Certification = Hash;

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

#[derive(Serialize, Hash, Clone)]
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

#[derive(Serialize, Clone)]
pub struct Block {
    pub payment: Transaction,
    pub timestamp: SystemTime,
    pub transaction_id: Hash,
}

impl Block {
    // TODO This is not a hashing function
    pub fn hash(&self, parent_hash: Option<Hash>) -> Hash {
        parent_hash.unwrap_or(0) + 1
    }
}

#[derive(Serialize, Clone)]
pub struct HashedBlock {
    pub hash: Hash,
    pub block: Block,
}

impl HashedBlock {
    pub fn new(
        parent_block: Option<&HashedBlock>,
        transaction_id: Hash,
        payment: Transaction,
    ) -> HashedBlock {
        let timestamp = dfn_core::api::now();
        let block = Block {
            payment,
            timestamp,
            transaction_id,
        };
        let parent_hash = parent_block.map(|b| b.hash);
        let hash = block.hash(parent_hash);
        HashedBlock { block, hash }
    }
}

/// Stores a chain of transactions with their metadata
#[derive(Default)]
pub struct BlockChain {
    pub inner: Vec<HashedBlock>,
}

impl BlockChain {
    pub fn add_payment(&mut self, transaction_id: Hash, payment: Transaction) {
        let last = self.last_block();
        let block = HashedBlock::new(last, transaction_id, payment);
        self.inner.push(block)
    }

    pub fn get(&self, index: BlockIndex) -> Option<&HashedBlock> {
        self.inner.get(index)
    }

    pub fn last_block_index(&self) -> Option<BlockIndex> {
        if self.inner.is_empty() {
            None
        } else {
            Some(self.inner.len() - 1)
        }
    }

    pub fn last_block(&self) -> Option<&HashedBlock> {
        self.inner.last()
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
fn tip_of_chain() -> Option<(Certification, BlockIndex)> {
    let transactions = &STATE.read().unwrap().transactions;
    let ind = transactions.last_block_index()?;
    let hash = transactions.last_block()?.hash;
    Some((hash, ind))
}

#[query]
fn block(block_index: BlockIndex) -> Option<HashedBlock> {
    let transactions = &STATE.read().unwrap().transactions;
    transactions.get(block_index).cloned()
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
