use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use candid::CandidType;
use dfn_candid::CandidOne;
use dfn_protobuf::ProtoBuf;
use ic_crypto_sha256::Sha256;
use ic_types::{CanisterId, PrincipalId};
use intmap::IntMap;
use lazy_static::lazy_static;
use on_wire::{FromWire, IntoWire, NewType};
use phantom_newtype::Id;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::io::{Seek, SeekFrom};
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::RwLock;

mod account_identifier;
mod icpts;
#[path = "../gen/ic_ledger.pb.types.v1.rs"]
#[rustfmt::skip]
pub mod protobuf;
mod timestamp;
mod validate_endpoints;

pub mod spawn;
pub use account_identifier::{AccountIdentifier, Subaccount};
pub use icpts::{ICPTs, DECIMAL_PLACES, ICP_SUBDIVIDABLE_BY, MIN_BURN_AMOUNT, TRANSACTION_FEE};
pub use timestamp::Timestamp;

pub const HASH_LENGTH: usize = 32;

#[derive(CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HashOf<T> {
    inner: Id<T, [u8; HASH_LENGTH]>,
}

impl<T: std::clone::Clone> Copy for HashOf<T> {}

impl<T> HashOf<T> {
    pub fn into_bytes(self) -> [u8; HASH_LENGTH] {
        self.inner.get()
    }

    pub fn new(bs: [u8; HASH_LENGTH]) -> Self {
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
                HASH_LENGTH,
                v.len(),
            )),
        }
    }
}

impl<T> Serialize for HashOf<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(self.inner.get_ref())
        }
    }
}

impl<'de, T> Deserialize<'de> for HashOf<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct HashOfVisitor<T> {
            phantom: PhantomData<T>,
        }

        impl<'de, T> serde::de::Visitor<'de> for HashOfVisitor<T> {
            type Value = HashOf<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "a hash of type {}: a blob with at most {} bytes",
                    std::any::type_name::<T>(),
                    HASH_LENGTH
                )
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(HashOf::new(
                    v.try_into().expect("hash does not have correct length"),
                ))
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                HashOf::from_str(s).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(HashOfVisitor {
                phantom: PhantomData,
            })
        } else {
            deserializer.deserialize_bytes(HashOfVisitor {
                phantom: PhantomData,
            })
        }
    }
}

#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct EncodedBlock(pub Box<[u8]>);

impl From<Box<[u8]>> for EncodedBlock {
    fn from(bytes: Box<[u8]>) -> Self {
        Self(bytes)
    }
}

impl EncodedBlock {
    pub fn hash(&self) -> HashOf<Self> {
        let mut state = Sha256::new();
        state.write(&self.0);
        HashOf::new(state.finish())
    }

    pub fn decode(&self) -> Result<Block, String> {
        let bytes = self.0.to_vec();
        Ok(ProtoBuf::from_bytes(bytes)?.get())
    }

    pub fn size_bytes(&self) -> usize {
        self.0.len()
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

/// Position of a block in the chain. The first block has position 0.
pub type BlockHeight = u64;

pub type Certification = Option<Vec<u8>>;

pub type LedgerBalances = Balances<HashMap<AccountIdentifier, ICPTs>>;

pub trait BalancesStore {
    fn get_balance(&self, k: &AccountIdentifier) -> Option<&ICPTs>;
    fn get_balance_mut(&mut self, k: &AccountIdentifier) -> Option<&mut ICPTs>;
    fn get_create_balance(&mut self, k: AccountIdentifier) -> &mut ICPTs;
    fn remove_account(&mut self, k: &AccountIdentifier) -> Option<ICPTs>;
}

impl BalancesStore for HashMap<AccountIdentifier, ICPTs> {
    fn get_balance(&self, k: &AccountIdentifier) -> Option<&ICPTs> {
        self.get(k)
    }

    fn get_balance_mut(&mut self, k: &AccountIdentifier) -> Option<&mut ICPTs> {
        self.get_mut(k)
    }

    fn get_create_balance(&mut self, k: AccountIdentifier) -> &mut ICPTs {
        self.entry(k).or_insert(ICPTs::ZERO)
    }

    fn remove_account(&mut self, k: &AccountIdentifier) -> Option<ICPTs> {
        self.remove(k)
    }
}

/// Describes the state of users accounts at the tip of the chain
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Balances<S: BalancesStore> {
    // This uses a mutable map because we don't want to risk a space leak and we only require the
    // account balances at the tip of the chain
    pub store: S,
    pub icpt_pool: ICPTs,
}

impl<S: Default + BalancesStore> Default for Balances<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Default + BalancesStore> Balances<S> {
    pub fn new() -> Self {
        Self {
            store: S::default(),
            icpt_pool: ICPTs::MAX,
        }
    }

    pub fn add_payment(&mut self, payment: &Transfer) {
        match payment {
            Transfer::Send {
                from,
                to,
                amount,
                fee,
            } => {
                let debit_amount = (*amount + *fee).expect("amount + fee failed");
                self.debit(from, debit_amount);
                self.credit(to, *amount);
                self.icpt_pool += *fee;
            }
            Transfer::Burn { from, amount, .. } => {
                self.debit(from, *amount);
                self.icpt_pool += *amount;
            }
            Transfer::Mint { to, amount, .. } => {
                self.credit(to, *amount);
                self.icpt_pool -= *amount;
            }
        }
    }

    // Debiting an account will automatically remove it from the `inner`
    // HashMap if the balance reaches zero.
    pub fn debit(&mut self, from: &AccountIdentifier, amount: ICPTs) {
        let balance = self
            .store
            .get_balance_mut(from)
            .unwrap_or_else(|| panic!("You tried to withdraw funds from empty account {}", from));
        // This is technically redundant because Amount uses checked arithmetic, but
        // belt an braces
        assert!(
            *balance >= amount,
            "You have tried to spend more than the balance of your account"
        );
        *balance -= amount;

        // Remove an account whose balance reaches ZERO
        if *balance == ICPTs::ZERO {
            self.store.remove_account(from);
        }
    }

    // Crediting an account will automatically add it to the `inner` HashMap if
    // not already present.
    pub fn credit(&mut self, to: &AccountIdentifier, amount: ICPTs) {
        let balance = self.store.get_create_balance(*to);
        *balance += amount;
    }

    pub fn account_balance(&self, account: &AccountIdentifier) -> ICPTs {
        self.store
            .get_balance(account)
            .cloned()
            .unwrap_or(ICPTs::ZERO)
    }

    /// Returns the total quantity of ICPs that are "in existence" -- that
    /// is, excluding un-minted "potential" ICPs.
    pub fn total_supply(&self) -> ICPTs {
        (ICPTs::MAX - self.icpt_pool).unwrap_or_else(|e| {
            panic!(
                "It is expected that the icpt_pool is always smaller than \
            or equal to ICPTs::MAX, yet subtracting it lead to the following error: {}",
                e
            )
        })
    }
}

impl LedgerBalances {
    // Find the specified number of accounts with lowest balances so that their
    // balances can be reclaimed.
    fn select_accounts_to_trim(&mut self, num_accounts: usize) -> Vec<(ICPTs, AccountIdentifier)> {
        let mut to_trim: std::collections::BinaryHeap<(ICPTs, AccountIdentifier)> =
            std::collections::BinaryHeap::new();

        let mut iter = self.store.iter();

        // Accumulate up to `trim_quantity` accounts
        for (account, balance) in iter.by_ref().take(num_accounts) {
            to_trim.push((*balance, *account));
        }

        for (account, balance) in iter {
            // If any account's balance is lower than the maximum in our set,
            // include that account, and remove the current maximum
            if let Some((greatest_balance, _)) = to_trim.peek() {
                if balance < greatest_balance {
                    to_trim.push((*balance, *account));
                    to_trim.pop();
                }
            }
        }

        to_trim.into_vec()
    }
}

/// An operation which modifies account balances
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Transfer {
    Burn {
        from: AccountIdentifier,
        amount: ICPTs,
    },
    Mint {
        to: AccountIdentifier,
        amount: ICPTs,
    },
    Send {
        from: AccountIdentifier,
        to: AccountIdentifier,
        amount: ICPTs,
        fee: ICPTs,
    },
}

/// A transfer with the metadata the client generated attached to it
///
/// Note that hash() gives us a globally unique identifier for each
/// transaction. This hashes the transfer, the memo and the height the
/// transaction was 'created_at'. A transaction is 'created' not when
/// it is added to the ledger, but rather it is created at the height
/// of the ledger last observed by the person signing the transaction.
///
/// This means that if you create a transaction using a cold wallet, you can
/// track that transactions identifier once it reaches the ledger.
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Transaction {
    pub transfer: Transfer,
    pub memo: Memo,
    pub created_at: BlockHeight,
}

impl Transaction {
    pub fn new(
        from: AccountIdentifier,
        to: AccountIdentifier,
        amount: ICPTs,
        fee: ICPTs,
        memo: Memo,
        created_at: BlockHeight,
    ) -> Self {
        let transfer = Transfer::Send {
            from,
            to,
            amount,
            fee,
        };
        Transaction {
            transfer,
            memo,
            created_at,
        }
    }

    pub fn hash(&self) -> HashOf<Self> {
        let mut state = Sha256::new();
        state.write(&serde_cbor::ser::to_vec_packed(&self).unwrap());
        HashOf::new(state.finish())
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub parent_hash: Option<HashOf<EncodedBlock>>,
    pub transaction: Transaction,
    /// Nanoseconds since the Unix epoch.
    pub timestamp: Timestamp,
}

impl Block {
    pub fn new(
        parent_hash: Option<HashOf<EncodedBlock>>,
        transfer: Transfer,
        memo: Memo,
        created_at: BlockHeight,
        timestamp: Timestamp,
    ) -> Result<Self, String> {
        let transaction = Transaction {
            transfer,
            memo,
            created_at,
        };
        Ok(Self::new_from_transaction(
            parent_hash,
            transaction,
            timestamp,
        ))
    }

    pub fn new_from_transaction(
        parent_hash: Option<HashOf<EncodedBlock>>,
        transaction: Transaction,
        timestamp: Timestamp,
    ) -> Self {
        Self {
            parent_hash,
            transaction,
            timestamp,
        }
    }

    pub fn encode(self) -> Result<EncodedBlock, String> {
        let slice = ProtoBuf::new(self).into_bytes()?.into_boxed_slice();
        Ok(EncodedBlock(slice))
    }

    pub fn parent_hash(&self) -> Option<HashOf<EncodedBlock>> {
        self.parent_hash
    }

    pub fn transaction(&self) -> Cow<Transaction> {
        Cow::Borrowed(&self.transaction)
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }
}

/// Stores a chain of transactions with their metadata
#[derive(Default)]
pub struct BlockChain {
    pub inner: Vec<EncodedBlock>,
    pub last_hash: Option<HashOf<EncodedBlock>>,
}

impl BlockChain {
    pub fn add_payment(
        &mut self,
        message: Memo,
        payment: Transfer,
        created_at: Option<BlockHeight>,
        timestamp: Timestamp,
    ) -> Result<BlockHeight, String> {
        // Either the caller specified the height that the block was created at, or we
        // assume it was created at the current height
        // TODO check created_at is between now and 24 hours in the past
        let created_at = created_at.unwrap_or_else(|| {
            // There is no last block at genesis
            if self.inner.is_empty() {
                0
            } else {
                self.last_block_index()
            }
        });
        let block = Block::new(self.last_hash, payment, message, created_at, timestamp)?;
        self.add_block(block)
    }

    pub fn add_block(&mut self, block: Block) -> Result<BlockHeight, String> {
        let raw_block = block.clone().encode()?;
        self.add_block_with_encoded(block, raw_block)
    }

    pub fn add_block_with_encoded(
        &mut self,
        block: Block,
        encoded_block: EncodedBlock,
    ) -> Result<BlockHeight, String> {
        if block.parent_hash != self.last_hash {
            return Err("Cannot apply block because its parent hash doesn't match.".to_string());
        }
        self.last_hash = Some(encoded_block.hash());
        self.inner.push(encoded_block);
        Ok(self.last_block_index())
    }

    pub fn get(&self, height: BlockHeight) -> Option<&EncodedBlock> {
        self.inner.get(usize::try_from(height).unwrap())
    }

    pub fn last_block_index(&self) -> BlockHeight {
        self.inner.len() as u64 - 1
    }

    pub fn last(&self) -> Option<&EncodedBlock> {
        self.inner.last()
    }

    /// Serialize the entire chain by concatenating the serialization
    /// of the blocks.
    pub fn encode(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        writer.write_u64::<LittleEndian>(self.inner.len() as u64)?;
        for block in &self.inner {
            writer.write_u64::<LittleEndian>(block.size_bytes() as u64)?;
            writer.write_all(&block.0)?;
        }
        Ok(())
    }
}

pub struct State {
    pub balances: LedgerBalances,
    pub blocks: BlockChain,
    // A cap on the maximum number of accounts
    maximum_number_of_accounts: usize,
    // When maximum number of accounts is exceeded, a specified number of
    // accounts with lowest balances are removed
    accounts_overflow_trim_quantity: usize,
    pub minting_account_id: Option<AccountIdentifier>,
    // This is a set of blockheights that have been notified
    pub blocks_notified: IntMap<()>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            balances: LedgerBalances::default(),
            blocks: BlockChain::default(),
            maximum_number_of_accounts: 50_000_000,
            accounts_overflow_trim_quantity: 100_000,
            minting_account_id: None,
            blocks_notified: IntMap::new(),
        }
    }
}

impl State {
    /// This creates a block and adds it to the ledger
    pub fn add_payment(
        &mut self,
        message: Memo,
        payment: Transfer,
        created_at: Option<BlockHeight>,
        timestamp: Timestamp,
    ) -> Result<(BlockHeight, HashOf<EncodedBlock>), String> {
        self.balances.add_payment(&payment);
        let result = self
            .blocks
            .add_payment(message, payment, created_at, timestamp);
        let to_trim = if self.balances.store.len() > self.maximum_number_of_accounts {
            self.balances
                .select_accounts_to_trim(self.accounts_overflow_trim_quantity)
        } else {
            vec![]
        };

        for (balance, account) in to_trim {
            let payment = Transfer::Burn {
                from: account,
                amount: balance,
            };
            self.balances.add_payment(&payment);
            self.blocks
                .add_payment(message, payment, created_at, timestamp)
                .unwrap();
        }

        result.map(|height| (height, self.blocks.last_hash.unwrap()))
    }

    /// This adds a pre created block to the ledger. This should only be used
    /// during canister migration or upgrade
    pub fn add_block(&mut self, block: Block) -> Result<BlockHeight, String> {
        self.balances.add_payment(&block.transaction.transfer);
        self.blocks.add_block(block)
    }

    pub fn add_block_with_raw(
        &mut self,
        block: Block,
        raw_block: EncodedBlock,
    ) -> Result<BlockHeight, String> {
        self.balances.add_payment(&block.transaction.transfer);
        self.blocks.add_block_with_encoded(block, raw_block)
    }

    pub fn from_init(
        &mut self,
        initial_values: HashMap<AccountIdentifier, ICPTs>,
        minting_account: AccountIdentifier,
        timestamp: Timestamp,
    ) {
        self.balances.icpt_pool = ICPTs::MAX;
        self.minting_account_id = Some(minting_account);

        for (to, amount) in initial_values.into_iter() {
            self.add_payment(
                Memo::default(),
                Transfer::Mint { to, amount },
                None,
                timestamp,
            )
            .expect(&format!("Creating account {:?} failed", to)[..]);
        }
    }

    const VERSION: u32 = 1;

    /// Serialize the state. This is just all the blocks, their notification
    /// state and a version field to accomodate canister upgrades.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.write_u32::<LittleEndian>(Self::VERSION).unwrap();
        self.blocks.encode(&mut bytes).unwrap();
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut rdr = std::io::Cursor::new(bytes);
        let version = rdr.read_u32::<LittleEndian>().unwrap();

        match version {
            Self::VERSION => {
                let mut state = State::default();

                // FIXME: bit ugly to do this here rather than in
                // BlockChain, but we need to apply the blocks to our
                // state...
                let nr_blocks = rdr.read_u64::<LittleEndian>().unwrap();

                for _ in 0..nr_blocks {
                    let block_size = rdr.read_u64::<LittleEndian>().unwrap();
                    let contents: &[u8] = &rdr.get_ref()
                        [rdr.position() as usize..(rdr.position() + block_size) as usize];
                    let block = ProtoBuf::from_bytes(contents.to_vec())?.get();
                    let raw_block = contents.to_vec().into_boxed_slice().into();
                    state.add_block_with_raw(block, raw_block)?;
                    rdr.seek(SeekFrom::Current(block_size as i64)).unwrap();
                }

                Ok(state)
            }

            _ => Err(format!(
                "Cannot decode state from unknown version {}.",
                version
            )),
        }
    }

    pub fn change_notification_state(
        &mut self,
        height: BlockHeight,
        new_state: bool,
    ) -> Result<(), String> {
        let is_notified = self.blocks_notified.get(height).is_some();

        match (is_notified, new_state) {
            (true, true) | (false, false) => {
                Err(format!("The notification state is already {}", is_notified))
            }
            (true, false) => {
                self.blocks_notified.remove(height);
                Ok(())
            }
            (false, true) => {
                self.blocks_notified.insert(height, ());
                Ok(())
            }
        }
    }
}

lazy_static! {
    pub static ref STATE: RwLock<State> = RwLock::new(State::default());
    pub static ref ARCHIVE_CANISTER: RwLock<Option<CanisterId>> = RwLock::new(None);
    // Maximum inter-canister message size in bytes
    pub static ref MAX_MESSAGE_SIZE_BYTES: RwLock<usize> = RwLock::new(2 * (1024^2));
}

pub fn add_payment(
    message: Memo,
    payment: Transfer,
    created_at: Option<BlockHeight>,
) -> (BlockHeight, HashOf<EncodedBlock>) {
    STATE
        .write()
        .unwrap()
        .add_payment(message, payment, created_at, dfn_core::api::now().into())
        .expect("Transfer failed")
}

pub fn change_notification_state(height: BlockHeight, new_state: bool) -> Result<(), String> {
    STATE
        .write()
        .unwrap()
        .change_notification_state(height, new_state)
}

pub fn split_off_older_than(split_off_age: std::time::Duration) -> Vec<EncodedBlock> {
    let mut state = STATE.write().unwrap();

    // Find the index of the first block older than specified duration
    let now = dfn_core::api::now();
    let mut split_off_ix = None;
    for (ix, block) in state.blocks.inner.iter().enumerate() {
        let elapsed: std::time::Duration = now
            .duration_since(block.decode().unwrap().timestamp.into())
            .unwrap();
        dfn_core::api::print(format!("block {} elapsed {:?}", ix, elapsed));
        if elapsed > split_off_age {
            split_off_ix = Some(ix);
            break;
        }
    }

    // Split off elements older than specified.
    // Note: Vec::split_off copies the elements. We may want something more
    // efficient in the future
    split_off_ix
        .map(|ix| state.blocks.inner.split_off(ix))
        .unwrap_or_default()
}

// This is how we pass arguments to 'init' in main.rs
#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct LedgerCanisterInitPayload {
    pub minting_account: AccountIdentifier,
    pub initial_values: HashMap<AccountIdentifier, ICPTs>,
    pub archive_canister: Option<CanisterId>,
    pub max_message_size_bytes: Option<usize>,
}

impl LedgerCanisterInitPayload {
    pub fn new(
        minting_account: AccountIdentifier,
        initial_values: HashMap<AccountIdentifier, ICPTs>,
        archive_canister: Option<CanisterId>,
        max_message_size_bytes: Option<usize>,
    ) -> Self {
        // verify ledger's invariant about the maximum amount
        let _can_sum = initial_values.values().fold(ICPTs::ZERO, |acc, x| {
            (acc + *x).expect("Summation overflowing?")
        });

        // Don't allow self-transfers of the minting canister
        assert!(initial_values.get(&minting_account).is_none());

        Self {
            minting_account,
            initial_values,
            archive_canister,
            max_message_size_bytes,
        }
    }
}

#[derive(Clone, Debug, Deserialize, CandidType)]
pub struct ArchiveCanisterInitPayload {
    pub node_max_memory_size_bytes: Option<usize>,
    pub max_message_size_bytes: Option<usize>,
}

impl ArchiveCanisterInitPayload {
    pub fn new(
        node_max_memory_size_bytes: Option<usize>,
        max_message_size_bytes: Option<usize>,
    ) -> Self {
        Self {
            node_max_memory_size_bytes,
            max_message_size_bytes,
        }
    }
}

/// Pop blocks off the start of the vector `blocks` as long as the
/// total size of the blocks is less than `max_size`. FIXME: need to
/// decide what to do if the first block is greater than max_size.
pub fn get_chain_prefix(
    blocks: &mut VecDeque<EncodedBlock>,
    mut max_size: usize,
) -> Vec<EncodedBlock> {
    let mut result = vec![];
    while let Some(last) = blocks.front() {
        if last.size_bytes() > max_size {
            break;
        }
        max_size -= last.size_bytes();
        result.push(blocks.pop_front().unwrap());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn balances_overflow() {
        let balances = LedgerBalances::new();
        let mut state = State {
            balances,
            blocks: BlockChain::default(),
            maximum_number_of_accounts: 8,
            accounts_overflow_trim_quantity: 2,
            minting_account_id: Some(PrincipalId::new_user_test_id(137).into()),
            blocks_notified: IntMap::new(),
        };
        assert_eq!(state.balances.icpt_pool, ICPTs::MAX);
        println!(
            "minting canister initial balance: {}",
            state.balances.icpt_pool
        );
        let mut credited = ICPTs::ZERO;
        for i in 0..10 {
            let amount = ICPTs::new(i, 0).unwrap();
            state
                .add_payment(
                    Memo::default(),
                    Transfer::Mint {
                        to: PrincipalId::new_user_test_id(i).into(),
                        amount,
                    },
                    None,
                    Timestamp::new(1234, 456),
                )
                .unwrap();
            credited += amount
        }
        println!("amount credited to accounts: {}", credited);

        println!("balances: {:?}", state.balances);

        // The two accounts with lowest balances, 0 and 1 respectively, have been
        // removed
        assert!(state.balances.store.len() == 8);
        assert_eq!(
            state
                .balances
                .account_balance(&PrincipalId::new_user_test_id(0).into()),
            ICPTs::ZERO
        );
        assert_eq!(
            state
                .balances
                .account_balance(&PrincipalId::new_user_test_id(1).into()),
            ICPTs::ZERO
        );
        // We have credited 45 ICPTs to vairous accounts but the two accounts
        // with lowest balances, 0 and 1, should have been removed and their
        // balance returned to the minting canister
        let expected_minting_canister_balance =
            ((ICPTs::MAX - credited).unwrap() + ICPTs::new(1, 0).unwrap()).unwrap();
        assert_eq!(state.balances.icpt_pool, expected_minting_canister_balance);
    }

    #[test]
    fn balances_remove_accounts_with_zero_balance() {
        let mut b = LedgerBalances::new();
        let canister = CanisterId::from_u64(7).get().into();
        let target_canister = CanisterId::from_u64(13).into();
        b.add_payment(&Transfer::Mint {
            to: canister,
            amount: ICPTs::from_doms(1000),
        });
        // verify that an account entry exists for the `canister`
        assert_eq!(b.store.get(&canister), Some(&ICPTs::from_doms(1000)));
        // make 2 transfers that empty the account
        for _ in 0..2 {
            b.add_payment(&Transfer::Send {
                from: canister,
                to: target_canister,
                amount: ICPTs::from_doms(400),
                fee: ICPTs::from_doms(100),
            });
        }
        // target canister's balance adds up
        assert_eq!(b.store.get(&target_canister), Some(&ICPTs::from_doms(800)));
        // source canister has been removed
        assert_eq!(b.store.get(&canister), None);
        assert_eq!(b.account_balance(&canister), ICPTs::ZERO);
    }

    #[test]
    fn balances_fee() {
        let mut b = LedgerBalances::new();
        let pool_start_balance = b.icpt_pool.get_doms();
        let uid0 = PrincipalId::new_user_test_id(1000).into();
        let uid1 = PrincipalId::new_user_test_id(1007).into();
        let mint_amount = 1000000;
        let send_amount = 10000;
        let send_fee = 100;

        b.add_payment(&Transfer::Mint {
            to: uid0,
            amount: ICPTs::from_doms(mint_amount),
        });
        assert_eq!(b.icpt_pool.get_doms(), pool_start_balance - mint_amount);
        assert_eq!(b.account_balance(&uid0).get_doms(), mint_amount);

        b.add_payment(&Transfer::Send {
            from: uid0,
            to: uid1,
            amount: ICPTs::from_doms(send_amount),
            fee: ICPTs::from_doms(send_fee),
        });

        assert_eq!(
            b.icpt_pool.get_doms(),
            pool_start_balance - mint_amount + send_fee
        );
        assert_eq!(
            b.account_balance(&uid0).get_doms(),
            mint_amount - send_amount - send_fee
        );
        assert_eq!(b.account_balance(&uid1).get_doms(), send_amount);
    }

    #[test]
    fn serialize() {
        let mut state = State::default();

        state.from_init(
            vec![(
                PrincipalId::new_user_test_id(0).into(),
                ICPTs::new(2000000, 0).unwrap(),
            )]
            .into_iter()
            .collect(),
            PrincipalId::new_user_test_id(1000).into(),
            SystemTime::UNIX_EPOCH.into(),
        );

        let txn = Transaction::new(
            PrincipalId::new_user_test_id(0).into(),
            PrincipalId::new_user_test_id(1).into(),
            ICPTs::new(10000, 50).unwrap(),
            TRANSACTION_FEE,
            Memo(456),
            789,
        );

        let txn_hash = txn.hash();
        println!("txn hash = {}", txn_hash);

        let block = Block {
            parent_hash: state.blocks.last_hash,
            transaction: txn,
            timestamp: (SystemTime::UNIX_EPOCH + Duration::new(2000000000, 123456789)).into(),
        };

        let block_bytes = block.clone().encode().unwrap();
        println!("block bytes = {:02x?}", block_bytes.0);
        let block_hash = block_bytes.hash();
        println!("block hash = {}", block_hash);
        let block_decoded = block_bytes.decode().unwrap();
        println!("block decoded = {:#?}", block_decoded);

        let block_decoded = block_bytes.decode().unwrap();
        assert_eq!(block, block_decoded);

        state.add_block(block).unwrap();

        let txn2 = Transaction::new(
            PrincipalId::new_user_test_id(0).into(),
            PrincipalId::new_user_test_id(200).into(),
            ICPTs::new(30000, 10000).unwrap(),
            TRANSACTION_FEE,
            Memo(0),
            321,
        );

        let block2 = Block {
            parent_hash: Some(block_hash),
            transaction: txn2,
            timestamp: (SystemTime::UNIX_EPOCH + Duration::from_nanos(200000000)).into(),
        };

        state.add_block(block2).unwrap();

        let state_bytes = state.encode();

        let state_decoded = State::decode(&state_bytes).unwrap();

        assert_eq!(
            state.blocks.last_block_index(),
            state_decoded.blocks.last_block_index()
        );
        assert_eq!(state.blocks.last_hash, state_decoded.blocks.last_hash);
        assert_eq!(state.blocks.inner.len(), state_decoded.blocks.inner.len());
        assert_eq!(state.balances.store, state_decoded.balances.store);
    }
}

/// Argument taken by the send endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct SendArgs {
    pub memo: Memo,
    pub amount: ICPTs,
    pub fee: ICPTs,
    pub from_subaccount: Option<Subaccount>,
    pub to: AccountIdentifier,
    // TODO rename this to created_at
    pub block_height: Option<BlockHeight>,
}

/// Struct sent by the ledger canister when it notifies a recipient of a payment
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct TransactionNotification {
    pub from: PrincipalId,
    pub from_subaccount: Option<Subaccount>,
    pub to: CanisterId,
    pub to_subaccount: Option<Subaccount>,
    pub block_height: BlockHeight,
    pub amount: ICPTs,
    pub memo: Memo,
}

/// A Candid-encoded value returned by transaction notification, limited to
/// MAX_LENGTH bytes.
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransactionNotificationResult(Vec<u8>);

impl TransactionNotificationResult {
    pub const MAX_LENGTH: usize = 1024;

    pub fn encode<T: CandidType>(x: T) -> Result<Self, String> {
        let res = Self(CandidOne(x).into_bytes()?);
        res.check_size()?;
        Ok(res)
    }

    pub fn decode<T: CandidType + DeserializeOwned>(self) -> Result<T, String> {
        Ok(CandidOne::from_bytes(self.0)?.into_inner())
    }

    pub fn check_size(&self) -> Result<(), String> {
        if self.0.len() > Self::MAX_LENGTH {
            return Err(format!(
                "TransactionNotificationResult is too long ({} bytes)",
                self.0.len()
            ));
        }
        Ok(())
    }
}

/// Argument taken by the notification endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct NotifyCanisterArgs {
    pub block_height: BlockHeight,
    pub max_fee: ICPTs,
    pub from_subaccount: Option<Subaccount>,
    pub to_canister: CanisterId,
    pub to_subaccount: Option<Subaccount>,
}

impl NotifyCanisterArgs {
    /// Construct a `notify` call to notify a canister about the
    /// transaction created by a previous `send` call. `block_height`
    /// is the index of the block returned by `send`.
    pub fn new_from_send(
        send_args: &SendArgs,
        block_height: BlockHeight,
        to_canister: CanisterId,
        to_subaccount: Option<Subaccount>,
    ) -> Result<Self, String> {
        if AccountIdentifier::new(to_canister.get(), to_subaccount) != send_args.to {
            Err("Account identifier does not match canister args".to_string())
        } else {
            Ok(NotifyCanisterArgs {
                block_height,
                max_fee: send_args.fee,
                from_subaccount: send_args.from_subaccount,
                to_canister,
                to_subaccount,
            })
        }
    }
}

/// Argument taken by the account_balance endpoint
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct AccountBalanceArgs {
    pub account: AccountIdentifier,
}

impl AccountBalanceArgs {
    pub fn new(account: AccountIdentifier) -> Self {
        AccountBalanceArgs { account }
    }
}

/// Argument taken by the total_supply endpoint
///
/// The reason it is a struct is so that it can be extended -- e.g., to be able
/// to query past values. Requiring 1 candid value instead of zero is a
/// non-backward compatible change. But adding optional fields to a struct taken
/// as input is backward-compatible.
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct TotalSupplyArgs {}

/// Argument returned by the tip_of_chain endpoint
pub struct TipOfChainRes {
    pub certification: Option<Vec<u8>>,
    pub tip_index: BlockHeight,
}

pub struct GetBlocksArgs {
    pub start: usize,
    pub length: usize,
}

impl GetBlocksArgs {
    pub fn new(start: usize, length: usize) -> Self {
        GetBlocksArgs { start, length }
    }
}

pub struct GetBlocksRes(pub Vec<EncodedBlock>);

// These is going away soon
pub struct BlockArg(pub BlockHeight);
pub struct BlockRes(pub Option<EncodedBlock>);
