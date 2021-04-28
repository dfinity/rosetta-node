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
use serde::{
    de::{DeserializeOwned, Deserializer, MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Serialize, Serializer,
};
use std::borrow::Cow;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::hash::Hash;
use std::io::{Seek, SeekFrom};
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

mod account_identifier;
mod icpts;
#[path = "../gen/ic_ledger.pb.v1.rs"]
#[rustfmt::skip]
pub mod protobuf;
mod timestamp;
mod validate_endpoints;

pub mod archive;

use archive::Archive;

pub mod spawn;
pub use account_identifier::{AccountIdentifier, Subaccount};
pub use icpts::{ICPTs, DECIMAL_PLACES, ICP_SUBDIVIDABLE_BY, MIN_BURN_AMOUNT, TRANSACTION_FEE};
pub use protobuf::TimeStamp;

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
        S: Serializer,
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
        D: Deserializer<'de>,
    {
        struct HashOfVisitor<T> {
            phantom: PhantomData<T>,
        }

        impl<'de, T> Visitor<'de> for HashOfVisitor<T> {
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
    // Update balance for an account using function f.
    // Its arg is previous balance or None if not found and
    // return value is the new balance.
    fn update<F>(&mut self, acc: AccountIdentifier, action_on_acc: F)
    where
        F: FnMut(Option<&ICPTs>) -> ICPTs;
}

impl BalancesStore for HashMap<AccountIdentifier, ICPTs> {
    fn get_balance(&self, k: &AccountIdentifier) -> Option<&ICPTs> {
        self.get(k)
    }

    fn update<F>(&mut self, k: AccountIdentifier, mut f: F)
    where
        F: FnMut(Option<&ICPTs>) -> ICPTs,
    {
        match self.entry(k) {
            Occupied(mut entry) => {
                let new_v = f(Some(entry.get()));
                if new_v != ICPTs::ZERO {
                    *entry.get_mut() = new_v;
                } else {
                    entry.remove_entry();
                }
            }
            Vacant(entry) => {
                let new_v = f(None);
                if new_v != ICPTs::ZERO {
                    entry.insert(new_v);
                }
            }
        };
    }
}

/// Describes the state of users accounts at the tip of the chain
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
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
        self.store.update(*from, |prev| {
            let mut balance = match prev {
                Some(x) => *x,
                None => panic!("You tried to withdraw funds from empty account {}", from),
            };
            // This is technically redundant because Amount uses checked arithmetic, but
            // belt an braces
            assert!(
                balance >= amount,
                "You have tried to spend more than the balance of your account"
            );
            balance -= amount;
            balance
        });
    }

    // Crediting an account will automatically add it to the `inner` HashMap if
    // not already present.
    pub fn credit(&mut self, to: &AccountIdentifier, amount: ICPTs) {
        self.store.update(*to, |prev| {
            let mut balance = match prev {
                Some(x) => *x,
                None => ICPTs::ZERO,
            };
            balance += amount;
            balance
        });
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
#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Transaction {
    pub transfer: Transfer,
    pub memo: Memo,

    /// The time this transaction was created.
    pub created_at_time: TimeStamp,
}

impl Transaction {
    pub fn new(
        from: AccountIdentifier,
        to: AccountIdentifier,
        amount: ICPTs,
        fee: ICPTs,
        memo: Memo,
        created_at_time: TimeStamp,
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
            created_at_time,
        }
    }

    pub fn hash(&self) -> HashOf<Self> {
        let mut state = Sha256::new();
        state.write(&serde_cbor::ser::to_vec_packed(&self).unwrap());
        HashOf::new(state.finish())
    }
}

/// A transaction with the metadata the canister generated attached to it
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub parent_hash: Option<HashOf<EncodedBlock>>,
    pub transaction: Transaction,
    /// Nanoseconds since the Unix epoch.
    pub timestamp: TimeStamp,
}

impl Block {
    pub fn new(
        parent_hash: Option<HashOf<EncodedBlock>>,
        transfer: Transfer,
        memo: Memo,
        created_at_time: TimeStamp, // transaction timestamp
        timestamp: TimeStamp,       // block timestamp
    ) -> Result<Self, String> {
        let transaction = Transaction {
            transfer,
            memo,
            created_at_time,
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
        timestamp: TimeStamp,
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

    pub fn timestamp(&self) -> TimeStamp {
        self.timestamp
    }
}

/// Stores a chain of transactions with their metadata
#[derive(Serialize, Deserialize, Debug)]
pub struct Blockchain {
    pub blocks: Vec<EncodedBlock>,
    pub last_hash: Option<HashOf<EncodedBlock>>,

    /// The timestamp of the most recent block. Must be monotonically
    /// non-decreasing.
    pub last_timestamp: TimeStamp,
    pub archive: Option<Archive>,
}

impl Default for Blockchain {
    fn default() -> Self {
        Self {
            blocks: vec![],
            last_hash: None,
            last_timestamp: SystemTime::UNIX_EPOCH.into(),
            archive: None,
        }
    }
}

impl Blockchain {
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
        if block.timestamp < self.last_timestamp {
            return Err(
                "Cannot apply block because its timestamp is older than the previous tip."
                    .to_owned(),
            );
        }
        self.last_hash = Some(encoded_block.hash());
        self.last_timestamp = block.timestamp;
        self.blocks.push(encoded_block);
        Ok(self.chain_length().checked_sub(1).unwrap())
    }

    pub fn get(&self, height: BlockHeight) -> Option<&EncodedBlock> {
        if height < self.num_archived_blocks() {
            None
        } else {
            self.blocks
                .get(usize::try_from(height - self.num_archived_blocks()).unwrap())
        }
    }

    pub fn last(&self) -> Option<&EncodedBlock> {
        self.blocks.last()
    }

    /// Serialize the entire chain by concatenating the serialization
    /// of the blocks.
    pub fn encode(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        writer.write_u64::<LittleEndian>(self.blocks.len() as u64)?;
        for block in &self.blocks {
            writer.write_u64::<LittleEndian>(block.size_bytes() as u64)?;
            writer.write_all(&block.0)?;
        }
        Ok(())
    }

    pub fn num_archived_blocks(&self) -> u64 {
        self.archive
            .as_ref()
            .map(|archive| archive.num_archived_blocks())
            .unwrap_or(0)
    }

    pub fn num_unarchived_blocks(&self) -> u64 {
        self.blocks.len().try_into().unwrap()
    }

    pub fn chain_length(&self) -> BlockHeight {
        self.num_archived_blocks() + self.num_unarchived_blocks() as BlockHeight
    }
}

/// Similar to Vec::split_off. Splits the Vec into two at the given index. `vec`
/// contains elements [at, len), and the returned Vec contains elements [0, at).
fn split_off_front(vec: &mut Vec<EncodedBlock>, at: usize) -> Vec<EncodedBlock> {
    let len = vec.len();
    assert!(at <= len, "`at` out of bounds");

    let returned = vec[0..at].to_vec();
    *vec = vec[at..].to_vec();
    returned
}

fn serialize_int_map<S>(im: &IntMap<()>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = serializer.serialize_map(Some(im.len()))?;
    for (k, v) in im.iter() {
        map.serialize_entry(k, v)?;
    }
    map.end()
}

struct IntMapVisitor<V> {
    marker: PhantomData<fn() -> IntMap<V>>,
}

impl<V> IntMapVisitor<V> {
    fn new() -> Self {
        IntMapVisitor {
            marker: PhantomData,
        }
    }
}

impl<'de, V> Visitor<'de> for IntMapVisitor<V>
where
    V: Deserialize<'de>,
{
    type Value = IntMap<V>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a very special map")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = IntMap::with_capacity(access.size_hint().unwrap_or(0));

        while let Some((key, value)) = access.next_entry()? {
            map.insert(key, value);
        }

        Ok(map)
    }
}

fn deserialize_int_map<'de, D>(deserializer: D) -> Result<IntMap<()>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(IntMapVisitor::new())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ledger {
    pub balances: LedgerBalances,
    #[serde(skip)]
    pub blockchain: Blockchain,
    // A cap on the maximum number of accounts
    maximum_number_of_accounts: usize,
    // When maximum number of accounts is exceeded, a specified number of
    // accounts with lowest balances are removed
    accounts_overflow_trim_quantity: usize,
    pub minting_account_id: Option<AccountIdentifier>,
    // This is a set of blockheights that have been notified
    #[serde(
        serialize_with = "serialize_int_map",
        deserialize_with = "deserialize_int_map",
        default = "IntMap::new"
    )]
    pub blocks_notified: IntMap<()>,
    /// How long transactions are remembered to detect duplicates.
    pub transaction_window: Duration,
    /// For each transaction, record the block in which the
    /// transaction was created. This only contains transactions from
    /// the last `transaction_window` period.
    transactions_by_hash: BTreeMap<HashOf<Transaction>, BlockHeight>,
    /// The transactions in the transaction window, sorted by block
    /// index / block timestamp. (Block timestamps are monotonically
    /// non-decreasing, so this is the same.)
    transactions_by_height: VecDeque<TransactionInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
struct TransactionInfo {
    block_timestamp: TimeStamp,
    transaction_hash: HashOf<Transaction>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            balances: LedgerBalances::default(),
            blockchain: Blockchain::default(),
            maximum_number_of_accounts: 50_000_000,
            accounts_overflow_trim_quantity: 100_000,
            minting_account_id: None,
            blocks_notified: IntMap::new(),
            transaction_window: Duration::from_secs(24 * 60 * 60),
            transactions_by_hash: BTreeMap::new(),
            transactions_by_height: VecDeque::new(),
        }
    }
}

impl Ledger {
    /// This creates a block and adds it to the ledger
    pub fn add_payment(
        &mut self,
        memo: Memo,
        payment: Transfer,
        created_at_time: Option<TimeStamp>,
    ) -> Result<(BlockHeight, HashOf<EncodedBlock>), String> {
        self.add_payment_with_timestamp(memo, payment, created_at_time, dfn_core::api::now().into())
    }

    /// Internal version of `add_payment` that takes a timestamp, for
    /// testing.
    fn add_payment_with_timestamp(
        &mut self,
        memo: Memo,
        payment: Transfer,
        created_at_time: Option<TimeStamp>,
        now: TimeStamp,
    ) -> Result<(BlockHeight, HashOf<EncodedBlock>), String> {
        self.purge_old_transactions(now);

        let created_at_time = created_at_time.unwrap_or(now);

        if created_at_time + self.transaction_window < now {
            return Err("Rejecting expired transaction.".to_owned());
        }

        if created_at_time > now + ic_types::ingress::PERMITTED_DRIFT {
            return Err("Rejecting transaction with timestamp in the future.".to_owned());
        }

        let transaction = Transaction {
            transfer: payment.clone(),
            memo,
            created_at_time,
        };

        let transaction_hash = transaction.hash();

        if self.transactions_by_hash.contains_key(&transaction_hash) {
            return Err("Transaction already exists on chain.".to_owned());
        }

        let block = Block::new_from_transaction(self.blockchain.last_hash, transaction, now);
        let block_timestamp = block.timestamp;

        self.balances.add_payment(&payment);

        let height = self.blockchain.add_block(block)?;

        self.transactions_by_hash.insert(transaction_hash, height);
        self.transactions_by_height.push_back(TransactionInfo {
            block_timestamp,
            transaction_hash,
        });

        let to_trim = if self.balances.store.len()
            >= self.maximum_number_of_accounts + self.accounts_overflow_trim_quantity
        {
            self.balances
                .select_accounts_to_trim(self.accounts_overflow_trim_quantity)
        } else {
            vec![]
        };

        for (balance, account) in to_trim {
            let transfer = Transfer::Burn {
                from: account,
                amount: balance,
            };
            self.balances.add_payment(&transfer);
            self.blockchain
                .add_block(Block::new_from_transaction(
                    self.blockchain.last_hash,
                    Transaction {
                        transfer,
                        memo: Memo::default(),
                        created_at_time: now,
                    },
                    now,
                ))
                .unwrap();
        }

        Ok((height, self.blockchain.last_hash.unwrap()))
    }

    /// Remove transactions older than `transaction_window`.
    fn purge_old_transactions(&mut self, now: TimeStamp) {
        while let Some(TransactionInfo {
            block_timestamp,
            transaction_hash,
        }) = self.transactions_by_height.front()
        {
            if *block_timestamp + self.transaction_window > now {
                // Stop at a sufficiently recent block.
                break;
            }
            let removed = self.transactions_by_hash.remove(&transaction_hash);
            assert!(removed.is_some());
            self.transactions_by_height.pop_front();
        }
    }

    /// This adds a pre created block to the ledger. This should only be used
    /// during canister migration or upgrade
    pub fn add_block(&mut self, block: Block) -> Result<BlockHeight, String> {
        self.balances.add_payment(&block.transaction.transfer);
        self.blockchain.add_block(block)
    }

    pub fn from_init(
        &mut self,
        initial_values: HashMap<AccountIdentifier, ICPTs>,
        minting_account: AccountIdentifier,
        timestamp: TimeStamp,
        transaction_window: Option<Duration>,
    ) {
        self.balances.icpt_pool = ICPTs::MAX;
        self.minting_account_id = Some(minting_account);
        if let Some(t) = transaction_window {
            self.transaction_window = t;
        }

        for (to, amount) in initial_values.into_iter() {
            self.add_payment_with_timestamp(
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
        self.blockchain.encode(&mut bytes).unwrap();
        let serialized = bincode::serialize(&self).unwrap();
        bytes.extend_from_slice(&serialized);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut rdr = std::io::Cursor::new(bytes);
        let version = rdr.read_u32::<LittleEndian>().unwrap();

        match version {
            Self::VERSION => {
                // FIXME: bit ugly to do this here rather than in
                // Blockchain, but we need to apply the blocks to our
                // state...
                let nr_blocks = rdr.read_u64::<LittleEndian>().unwrap();
                let mut blocks = Vec::with_capacity(nr_blocks as usize);

                for _ in 0..nr_blocks {
                    let block_size = rdr.read_u64::<LittleEndian>().unwrap();
                    let contents: &[u8] = &rdr.get_ref()
                        [rdr.position() as usize..(rdr.position() + block_size) as usize];
                    let block = ProtoBuf::from_bytes(contents.to_vec())?.get();
                    let raw_block = contents.to_vec().into_boxed_slice().into();
                    blocks.push((block, raw_block));
                    rdr.seek(SeekFrom::Current(block_size as i64)).unwrap();
                }

                let mut state: Ledger =
                    bincode::deserialize(&bytes[rdr.position() as usize..]).unwrap();

                for (block, raw_block) in blocks.into_iter() {
                    state.blockchain.add_block_with_encoded(block, raw_block)?;
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

    pub fn find_block_in_archive(&self, block_height: u64) -> Option<CanisterId> {
        let index = self
            .blockchain
            .archive
            .as_ref()
            .expect("archiving not enabled")
            .index();
        let result = index.binary_search_by(|((from, to), _)| {
            // If within the range we've found the right node
            if *from <= block_height && block_height <= *to {
                std::cmp::Ordering::Equal
            } else if *from < block_height {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        match result {
            Ok(i) => Some(index[i].1),
            Err(_) => None,
        }
    }

    pub fn split_off_blocks_to_archive(&mut self, at: usize) -> VecDeque<EncodedBlock> {
        if self.blockchain.archive.is_none() {
            VecDeque::new()
        } else {
            VecDeque::from(split_off_front(&mut self.blockchain.blocks, at))
        }
    }
}

lazy_static! {
    pub static ref LEDGER: RwLock<Ledger> = RwLock::new(Ledger::default());
    // Maximum inter-canister message size in bytes
    pub static ref MAX_MESSAGE_SIZE_BYTES: RwLock<usize> = RwLock::new(2 * (1024^2));
}

pub fn add_payment(
    memo: Memo,
    payment: Transfer,
    created_at_time: Option<TimeStamp>,
) -> (BlockHeight, HashOf<EncodedBlock>) {
    LEDGER
        .write()
        .unwrap()
        .add_payment(memo, payment, created_at_time)
        .expect("Transfer failed")
}

pub fn change_notification_state(height: BlockHeight, new_state: bool) -> Result<(), String> {
    LEDGER
        .write()
        .unwrap()
        .change_notification_state(height, new_state)
}

// This is how we pass arguments to 'init' in main.rs
#[derive(Serialize, Deserialize, CandidType, Clone, Debug, PartialEq, Eq)]
pub struct LedgerCanisterInitPayload {
    pub minting_account: AccountIdentifier,
    pub initial_values: HashMap<AccountIdentifier, ICPTs>,
    pub max_message_size_bytes: Option<usize>,
    pub transaction_window: Option<Duration>,
    pub archive_options: Option<ArchiveOptions>,
}

impl LedgerCanisterInitPayload {
    pub fn new(
        minting_account: AccountIdentifier,
        initial_values: HashMap<AccountIdentifier, ICPTs>,
        archive_options: Option<ArchiveOptions>,
        max_message_size_bytes: Option<usize>,
        transaction_window: Option<Duration>,
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
            max_message_size_bytes,
            transaction_window,
            archive_options,
        }
    }
}

#[derive(Serialize, Deserialize, CandidType, Clone, Debug, Default, PartialEq, Eq)]
pub struct ArchiveOptions {
    pub node_max_memory_size_bytes: Option<usize>,
    pub max_message_size_bytes: Option<usize>,
}

impl ArchiveOptions {
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
    fn test_split_off_front() {
        fn make_block(timestamp: TimeStamp) -> Block {
            let transaction = Transaction::new(
                AccountIdentifier::new(CanisterId::from_u64(1).get(), None),
                AccountIdentifier::new(CanisterId::from_u64(2).get(), None),
                ICPTs::new(10000, 50).unwrap(),
                TRANSACTION_FEE,
                Memo(456),
                TimeStamp::new(1, 0),
            );
            Block::new_from_transaction(None, transaction, timestamp)
        }
        let start_t: std::time::SystemTime = dfn_core::api::now();

        let mut blocks: Vec<EncodedBlock> = vec![];
        // blocks[0] is the oldest
        for i in 0..10 {
            blocks.push(
                make_block(TimeStamp::from(start_t + std::time::Duration::new(i, 0)))
                    .encode()
                    .unwrap(),
            )
        }
        let all_blocks = blocks.clone();
        println!("[test] blocks: {:?}", blocks);

        // we will split off the first 7 blocks with indices [0..=6]; this
        // should leave blocks [7..=9] in the vector
        println!("[test] splitting off first 7 blocks");
        assert!(blocks.len() == 10);
        let split = split_off_front(&mut blocks, 7);
        println!("[test] blocks left after split: {:?}", blocks);
        assert!(blocks.len() == 3);
        println!("[test] blocks which have been split off: {:?}", split);
        assert!(split.len() == 7);
        // block[9] is the youngest so blocks [7..=9] should be left in the vector
        assert!(all_blocks[7..=9] == blocks[..]);
        // block[0] is the oldest so blocks [0..=6] should be split off
        assert!(all_blocks[0..=6] == split[..]);
    }

    #[test]
    fn balances_overflow() {
        let balances = LedgerBalances::new();
        let mut state = Ledger::default();
        state.balances = balances;
        state.maximum_number_of_accounts = 8;
        state.accounts_overflow_trim_quantity = 2;
        state.minting_account_id = Some(PrincipalId::new_user_test_id(137).into());
        assert_eq!(state.balances.icpt_pool, ICPTs::MAX);
        println!(
            "minting canister initial balance: {}",
            state.balances.icpt_pool
        );
        let mut credited = ICPTs::ZERO;

        // 11 accounts. The one with 0 will not be added
        // The rest will be added and trigger a trim of 2 once
        // the total number reaches 8 + 2
        // the number of active accounts won't go below 8 after trimming
        for i in 0..11 {
            let amount = ICPTs::new(i, 0).unwrap();
            state
                .add_payment(
                    Memo::default(),
                    Transfer::Mint {
                        to: PrincipalId::new_user_test_id(i).into(),
                        amount,
                    },
                    None,
                )
                .unwrap();
            credited += amount
        }
        println!("amount credited to accounts: {}", credited);

        println!("balances: {:?}", state.balances);

        // The two accounts with lowest balances, 0 and 1 respectively, have been
        // removed
        assert_eq!(state.balances.store.len(), 8);
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
        // We have credited 55 ICPTs to various accounts but the three accounts
        // with lowest balances, 0, 1 and 2, should have been removed and their
        // balance returned to the minting canister
        let expected_minting_canister_balance =
            ((ICPTs::MAX - credited).unwrap() + ICPTs::new(1 + 2, 0).unwrap()).unwrap();
        assert_eq!(state.balances.icpt_pool, expected_minting_canister_balance);
    }

    #[test]
    fn balances_remove_accounts_with_zero_balance() {
        let mut b = LedgerBalances::new();
        let canister = CanisterId::from_u64(7).get().into();
        let target_canister = CanisterId::from_u64(13).into();
        b.add_payment(&Transfer::Mint {
            to: canister,
            amount: ICPTs::from_e8s(1000),
        });
        // verify that an account entry exists for the `canister`
        assert_eq!(b.store.get(&canister), Some(&ICPTs::from_e8s(1000)));
        // make 2 transfers that empty the account
        for _ in 0..2 {
            b.add_payment(&Transfer::Send {
                from: canister,
                to: target_canister,
                amount: ICPTs::from_e8s(400),
                fee: ICPTs::from_e8s(100),
            });
        }
        // target canister's balance adds up
        assert_eq!(b.store.get(&target_canister), Some(&ICPTs::from_e8s(800)));
        // source canister has been removed
        assert_eq!(b.store.get(&canister), None);
        assert_eq!(b.account_balance(&canister), ICPTs::ZERO);

        // one account left in the store
        assert_eq!(b.store.len(), 1);

        b.add_payment(&Transfer::Send {
            from: target_canister,
            to: canister,
            amount: ICPTs::from_e8s(0),
            fee: ICPTs::from_e8s(100),
        });
        // No new account should have been created
        assert_eq!(b.store.len(), 1);
        // and the fee should have been taken from sender
        assert_eq!(b.store.get(&target_canister), Some(&ICPTs::from_e8s(700)));

        b.add_payment(&Transfer::Mint {
            to: canister,
            amount: ICPTs::from_e8s(0),
        });

        // No new account should have been created
        assert_eq!(b.store.len(), 1);

        b.add_payment(&Transfer::Burn {
            from: target_canister,
            amount: ICPTs::from_e8s(700),
        });

        // And burn should have exhausted the target_canister
        assert_eq!(b.store.len(), 0);
    }

    #[test]
    fn balances_fee() {
        let mut b = LedgerBalances::new();
        let pool_start_balance = b.icpt_pool.get_e8s();
        let uid0 = PrincipalId::new_user_test_id(1000).into();
        let uid1 = PrincipalId::new_user_test_id(1007).into();
        let mint_amount = 1000000;
        let send_amount = 10000;
        let send_fee = 100;

        b.add_payment(&Transfer::Mint {
            to: uid0,
            amount: ICPTs::from_e8s(mint_amount),
        });
        assert_eq!(b.icpt_pool.get_e8s(), pool_start_balance - mint_amount);
        assert_eq!(b.account_balance(&uid0).get_e8s(), mint_amount);

        b.add_payment(&Transfer::Send {
            from: uid0,
            to: uid1,
            amount: ICPTs::from_e8s(send_amount),
            fee: ICPTs::from_e8s(send_fee),
        });

        assert_eq!(
            b.icpt_pool.get_e8s(),
            pool_start_balance - mint_amount + send_fee
        );
        assert_eq!(
            b.account_balance(&uid0).get_e8s(),
            mint_amount - send_amount - send_fee
        );
        assert_eq!(b.account_balance(&uid1).get_e8s(), send_amount);
    }

    #[test]
    fn serialize() {
        let mut state = Ledger::default();

        state.from_init(
            vec![(
                PrincipalId::new_user_test_id(0).into(),
                ICPTs::new(2000000, 0).unwrap(),
            )]
            .into_iter()
            .collect(),
            PrincipalId::new_user_test_id(1000).into(),
            SystemTime::UNIX_EPOCH.into(),
            None,
        );

        let txn = Transaction::new(
            PrincipalId::new_user_test_id(0).into(),
            PrincipalId::new_user_test_id(1).into(),
            ICPTs::new(10000, 50).unwrap(),
            TRANSACTION_FEE,
            Memo(456),
            TimeStamp::new(1, 0),
        );

        let block = Block {
            parent_hash: state.blockchain.last_hash,
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
            TimeStamp::new(1, 100),
        );

        let block2 = Block {
            parent_hash: Some(block_hash),
            transaction: txn2,
            timestamp: (SystemTime::UNIX_EPOCH + Duration::new(2000000000, 123456790)).into(),
        };

        state.add_block(block2).unwrap();

        let state_bytes = state.encode();

        let state_decoded = Ledger::decode(&state_bytes).unwrap();

        assert_eq!(
            state.blockchain.chain_length(),
            state_decoded.blockchain.chain_length()
        );
        assert_eq!(
            state.blockchain.last_hash,
            state_decoded.blockchain.last_hash
        );
        assert_eq!(
            state.blockchain.blocks.len(),
            state_decoded.blockchain.blocks.len()
        );
        assert_eq!(state.balances.store, state_decoded.balances.store);
    }

    /// Check that 'created_at_time' is not too far in the past or
    /// future.
    #[test]
    fn bad_created_at_time() {
        let mut state = Ledger::default();

        let user1 = PrincipalId::new_user_test_id(1).into();

        let transfer = Transfer::Mint {
            to: user1,
            amount: ICPTs::from_e8s(1000),
        };

        let now = dfn_core::api::now().into();

        assert!(state
            .add_payment(
                Memo(1),
                transfer.clone(),
                Some(now - state.transaction_window - Duration::from_secs(1))
            )
            .unwrap_err()
            .contains("expired transaction"));

        state
            .add_payment(
                Memo(2),
                transfer.clone(),
                Some(now - Duration::from_secs(1)),
            )
            .unwrap();

        assert!(state
            .add_payment(
                Memo(3),
                transfer.clone(),
                Some(now + Duration::from_secs(120))
            )
            .unwrap_err()
            .contains("in the future"));

        state.add_payment(Memo(4), transfer, Some(now)).unwrap();
    }

    /// Check that block timestamps don't go backwards.
    #[test]
    fn monotonic_timestamps() {
        let mut state = Ledger::default();

        let user1 = PrincipalId::new_user_test_id(1).into();

        let transfer = Transfer::Mint {
            to: user1,
            amount: ICPTs::from_e8s(1000),
        };

        state.add_payment(Memo(1), transfer.clone(), None).unwrap();

        state.add_payment(Memo(2), transfer.clone(), None).unwrap();

        assert!(state
            .add_payment_with_timestamp(
                Memo(2),
                transfer,
                None,
                state.blockchain.last_timestamp - Duration::from_secs(1),
            )
            .unwrap_err()
            .contains("timestamp is older"));
    }

    /// Check that duplicate transactions during transaction_window
    /// are rejected.
    #[test]
    fn duplicate_txns() {
        let mut state = Ledger::default();
        state.blockchain.archive = Some(archive::Archive::new(ArchiveOptions::default()));

        let user1 = PrincipalId::new_user_test_id(1).into();

        let transfer = Transfer::Mint {
            to: user1,
            amount: ICPTs::from_e8s(1000),
        };

        let now = dfn_core::api::now().into();

        assert_eq!(
            state
                .add_payment(Memo::default(), transfer.clone(), Some(now))
                .unwrap()
                .0,
            0
        );

        assert_eq!(
            state
                .add_payment(Memo(123), transfer.clone(), Some(now))
                .unwrap()
                .0,
            1
        );

        assert_eq!(
            state
                .add_payment(
                    Memo::default(),
                    transfer.clone(),
                    Some(now - Duration::from_secs(1))
                )
                .unwrap()
                .0,
            2
        );

        assert_eq!(
            state
                .add_payment_with_timestamp(
                    Memo::default(),
                    transfer.clone(),
                    Some(now - Duration::from_secs(2)),
                    state.blockchain.last_timestamp + Duration::from_secs(10000)
                )
                .unwrap()
                .0,
            3
        );

        assert!(state
            .add_payment(Memo::default(), transfer.clone(), Some(now))
            .unwrap_err()
            .contains("Transaction already exists on chain"));

        // A day later we should have forgotten about these transactions.
        let t = state.blockchain.last_timestamp + Duration::from_secs(1);
        assert_eq!(
            state
                .add_payment_with_timestamp(
                    Memo::default(),
                    transfer.clone(),
                    Some(t),
                    state.blockchain.last_timestamp + state.transaction_window
                )
                .unwrap()
                .0,
            4
        );

        assert!(state
            .add_payment_with_timestamp(
                Memo::default(),
                transfer,
                Some(t),
                state.blockchain.last_timestamp + Duration::from_secs(1),
            )
            .unwrap_err()
            .contains("Transaction already exists on chain"));
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
    pub created_at_time: Option<TimeStamp>,
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
    pub start: BlockHeight,
    pub length: usize,
}

impl GetBlocksArgs {
    pub fn new(start: BlockHeight, length: usize) -> Self {
        GetBlocksArgs { start, length }
    }
}

pub struct GetBlocksRes(pub Result<Vec<EncodedBlock>, String>);

pub struct IterBlocksArgs {
    pub start: usize,
    pub length: usize,
}

impl IterBlocksArgs {
    pub fn new(start: usize, length: usize) -> Self {
        IterBlocksArgs { start, length }
    }
}

pub struct IterBlocksRes(pub Vec<EncodedBlock>);

// These is going away soon
pub struct BlockArg(pub BlockHeight);
pub struct BlockRes(pub Option<Result<EncodedBlock, CanisterId>>);

// A helper function for ledger/get_blocks and archive_node/get_blocks endpoints
pub fn get_blocks(
    blocks: &[EncodedBlock],
    range_from_offset: BlockHeight,
    range_from: BlockHeight,
    length: usize,
) -> GetBlocksRes {
    // Inclusive end of the range of *requested* blocks
    let requested_range_to = range_from as usize + length - 1;
    // Inclusive end of the range of *available* blocks
    let range_to = range_from_offset as usize + blocks.len() - 1;
    // Example: If the Node stores 10 blocks beginning at BlockHeight 100, i.e.
    // [100 .. 109] then requesting blocks at BlockHeight < 100 or BlockHeight
    // > 109 is an error
    if range_from < range_from_offset || requested_range_to > range_to {
        return GetBlocksRes(Err(format!("Requested blocks outside the range stored in the archive node. Requested [{} .. {}]. Available [{} .. {}].",
            range_from, requested_range_to, range_from_offset, range_to)));
    }
    // Example: If the node stores blocks [100 .. 109] then BLOCK_HEIGHT_OFFSET
    // is 100 and the Block with BlockHeight 100 is at index 0
    let offset = (range_from - range_from_offset) as usize;
    GetBlocksRes(Ok(blocks[offset..offset + length].to_vec()))
}

// A helper function for ledger/iter_blocks and archive_node/iter_blocks
// endpoints
pub fn iter_blocks(blocks: &[EncodedBlock], offset: usize, length: usize) -> IterBlocksRes {
    let start = std::cmp::min(offset, blocks.len());
    let end = std::cmp::min(start + length, blocks.len());
    let blocks = blocks[start..end].to_vec();
    IterBlocksRes(blocks)
}
