use candid::CandidType;
use ic_types::PrincipalId;
use lazy_static::lazy_static;
use serde::{de::Error, Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::RwLock;
use std::time::SystemTime;

mod icpts;
pub use icpts::{ICPTs, DECIMAL_PLACES, ICP_SUBDIVIDABLE_BY};

// pub struct Hash {inner: [u8; 32]}
// TODO make this a proper hash (sha 256)
pub type Hash = u64;

#[derive(
    Serialize, Deserialize, CandidType, Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Message(pub u64);

impl Default for Message {
    fn default() -> Message {
        Message(0)
    }
}

#[derive(
    Serialize, Deserialize, CandidType, Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct BlockHeight(pub u64);

pub type SubmitArgs = (Message, ICPTs, PrincipalId, Option<BlockHeight>);

pub type Certification = Hash;

/// Describes the state of users accounts at the tip of the chain
#[derive(Default)]
pub struct Balances {
    // This uses a mutable map because we don't want to risk a space leak and we only require the
    // account balances at the tip of the chain
    pub inner: HashMap<PrincipalId, ICPTs>,
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

#[derive(CandidType, Serialize, Deserialize, Hash, Debug, PartialEq, Eq, Clone)]
pub enum Transaction {
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub payment: Transaction,
    pub timestamp: SystemTime,
    pub message: Message,
    pub parent_hash: Option<Hash>,
    pub index: usize,
    pub created_at_offset: u32,
}

impl Block {
    pub fn new(
        payment: Transaction,
        message: Message,
        parent_hash: Option<Hash>,
        index: usize,
        created_at: Option<BlockHeight>,
    ) -> Result<Block, String> {
        let timestamp = dfn_core::api::now();
        // TODO check created_at is between now and 24 hours in the past
        let created_at_offset: u32 = match created_at {
            Some(ca) => u32::try_from((index as u64) - ca.0).map_err(|e| e.to_string())?,
            None => 1,
        };
        Ok(Block {
            payment,
            timestamp,
            message,
            parent_hash,
            index,
            created_at_offset,
        })
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
#[derive(CandidType, Serialize, Clone, Debug, PartialEq, Eq)]
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
    pub fn add_payment(
        &mut self,
        message: Message,
        payment: Transaction,
        created_at: Option<BlockHeight>,
    ) -> Result<usize, String> {
        // Either the caller specified the height that the block was created at, or we
        // assume it was created at the current height
        let parent_hash = self.last_block_hash();
        let this_index = match self.last_block() {
            Some(last_block) => last_block.block.index + 1,
            None => 0,
        };
        let block = Block::new(
            payment,
            message,
            parent_hash.cloned(),
            this_index,
            created_at,
        )?;

        let block_hash = block.hash();
        self.last_hash = Some(block_hash);
        let res = self.inner.insert(block_hash, block);
        assert_eq!(res, None);
        Ok(this_index)
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

    pub fn height(&self) -> BlockHeight {
        BlockHeight(self.inner.len() as u64)
    }

    // At what blockheight was the block at the specified height created at
    // pub fn created_at_height(&self, height: BlockHeight) -> BlockHeight {
    //     let height = height.0 + (self.offset as u64);
    //     BlockHeight(height)
    // }
}

#[derive(Default)]
pub struct State {
    pub balances: Balances,
    pub transactions: BlockChain,
}

impl State {
    pub fn add_payment(
        &mut self,
        message: Message,
        payment: Transaction,
        created_at: Option<BlockHeight>,
    ) -> Result<usize, String> {
        self.balances.add_payment(&payment);
        self.transactions.add_payment(message, payment, created_at)
    }

    pub fn from_init(
        &mut self,
        initial_values: HashMap<PrincipalId, ICPTs>,
        minting_canister: PrincipalId,
    ) {
        self.add_payment(
            Message::default(),
            Transaction::Mint {
                to: minting_canister,
                amount: ICPTs::MAX,
            },
            None,
        )
        .expect("Creating the minting canister account failed");
        for (to, amount) in initial_values.into_iter() {
            self.add_payment(
                Message::default(),
                Transaction::Send {
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
    message: Message,
    payment: Transaction,
    created_at: Option<BlockHeight>,
) -> usize {
    STATE
        .write()
        .unwrap()
        .add_payment(message, payment, created_at)
        .expect("Transaction failed")
}
