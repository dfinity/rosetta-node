use crate::balance_book::BalanceBook;
use crate::convert::{internal_error, invalid_block_id};
use crate::models::ApiError;

use ledger_canister::{AccountIdentifier, BlockHeight, EncodedBlock, HashOf, ICPTs};
use log::{debug, error, trace};
use serde::{Deserialize, Serialize};

use std::collections::VecDeque;
use std::convert::TryInto;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(candid::CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HashedBlock {
    pub block: EncodedBlock,
    pub hash: HashOf<EncodedBlock>,
    pub parent_hash: Option<HashOf<EncodedBlock>>,
    pub index: u64,
}

impl HashedBlock {
    pub fn hash_block(
        block: EncodedBlock,
        parent_hash: Option<HashOf<EncodedBlock>>,
        index: BlockHeight,
    ) -> HashedBlock {
        HashedBlock {
            hash: block.hash(),
            block,
            parent_hash,
            index,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum BlockStoreError {
    NotFound(BlockHeight),
    NotAvailable(BlockHeight),
    Other(String),
}

impl From<BlockStoreError> for ApiError {
    fn from(e: BlockStoreError) -> Self {
        match e {
            BlockStoreError::NotFound(idx) => invalid_block_id(format!("Block not found: {}", idx)),
            // TODO Add a new error type (ApiError::BlockPruned or something like that)
            BlockStoreError::NotAvailable(idx) => {
                internal_error(format!("Block not available for query: {}", idx))
            }
            BlockStoreError::Other(msg) => internal_error(msg),
        }
    }
}

pub trait BlockStore {
    fn get_at(&self, index: BlockHeight) -> Result<HashedBlock, BlockStoreError>;
    fn push(&mut self, block: HashedBlock) -> Result<(), BlockStoreError>;
    fn prune(&mut self, hb: &HashedBlock, balances: &BalanceBook) -> Result<(), String>;
    fn first_snapshot(&self) -> Option<&(HashedBlock, BalanceBook)>;
    fn first(&self) -> Result<Option<HashedBlock>, BlockStoreError>;
    fn last_verified(&self) -> Option<BlockHeight>;
    fn mark_last_verified(&mut self, h: BlockHeight) -> Result<(), BlockStoreError>;
}

pub struct SQLiteStore {
    connection: Mutex<rusqlite::Connection>,
    base_idx: u64,
    balances_snapshot: BalancesSnapshot,
    first_block_snapshot: Option<(HashedBlock, BalanceBook)>,
    last_verified_idx: Option<BlockHeight>,
}

impl SQLiteStore {
    pub fn new(
        location: PathBuf,
        connection: rusqlite::Connection,
    ) -> Result<Self, BlockStoreError> {
        let balances_snapshot = BalancesSnapshot::new(location);
        let mut store = Self {
            connection: Mutex::new(connection),
            base_idx: 0,
            balances_snapshot,
            first_block_snapshot: None,
            last_verified_idx: None,
        };
        store.create_tables().map_err(|e| {
            BlockStoreError::Other(format!("Failed to initialize SQLite database: {}", e))
        })?;
        store.first_block_snapshot = store
            .read_oldest_block_snapshot()
            .map_err(BlockStoreError::Other)?;

        if let Some((first_block, _)) = &store.first_block_snapshot {
            store.base_idx = first_block.index;
            store.get_at(first_block.index).and_then(|b| {
                if *first_block != b {
                    Err(BlockStoreError::Other("Corrupted snapshot".to_string()))
                } else {
                    Ok(())
                }
            })?;
        }

        {
            let connection = store.connection.lock().unwrap();
            let mut stmt = connection
                .prepare("SELECT idx FROM blocks WHERE verified = TRUE ORDER BY idx DESC LIMIT 1")
                .map_err(|e| BlockStoreError::Other(e.to_string()))?;
            let mut rows = stmt
                .query([])
                .map_err(|e| BlockStoreError::Other(e.to_string()))?;
            store.last_verified_idx = rows
                .next()
                .map_err(|e| BlockStoreError::Other(e.to_string()))?
                .map(|row| row.get(0).unwrap());
        }
        Ok(store)
    }

    pub fn create_tables(&self) -> Result<(), rusqlite::Error> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            r#"CREATE TABLE IF NOT EXISTS blocks (
      hash BLOB NOT NULL,
      block BLOB NOT NULL,
      parent_hash BLOB,
      idx INTEGER NOT NULL PRIMARY KEY,
      verified BOOLEAN)"#,
            [],
        )?;
        Ok(())
    }

    fn read_oldest_block_snapshot(&self) -> Result<Option<(HashedBlock, BalanceBook)>, String> {
        self.balances_snapshot.read_oldest_block_snapshot()
    }

    fn write_oldest_block_snapshot(
        &mut self,
        hb: &HashedBlock,
        balances: &BalanceBook,
    ) -> Result<(), String> {
        if let Ok(Some(b)) = self.first() {
            // this check is made in upper levels, but for readability:
            assert!(
                b.index <= hb.index,
                "Oldest: {}, new oldest: {}",
                b.index,
                hb.index
            );
        }
        self.first_block_snapshot = self
            .balances_snapshot
            .write_oldest_block_snapshot(hb, balances)?;
        Ok(())
    }
}

fn vec_into_array(v: Vec<u8>) -> [u8; 32] {
    let ba: Box<[u8; 32]> = match v.into_boxed_slice().try_into() {
        Ok(ba) => ba,
        Err(v) => panic!("Expected a Vec of length 32 but it was {}", v.len()),
    };
    *ba
}

impl BlockStore for SQLiteStore {
    fn get_at(&self, index: BlockHeight) -> Result<HashedBlock, BlockStoreError> {
        if 0 < index && index < self.base_idx {
            return Err(BlockStoreError::NotAvailable(index));
        }

        let connection = self.connection.lock().unwrap();
        let mut stmt = connection
            .prepare("SELECT hash, block, parent_hash, idx FROM blocks WHERE idx = ?")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut blocks = stmt
            .query_map(rusqlite::params![index], |row| {
                Ok(HashedBlock {
                    hash: row.get(0).map(|bytes| HashOf::new(vec_into_array(bytes)))?,
                    block: row
                        .get(1)
                        .map(|bytes: Vec<u8>| EncodedBlock::from(bytes.into_boxed_slice()))?,
                    parent_hash: row.get(2).map(|opt_bytes: Option<Vec<u8>>| {
                        opt_bytes.map(|bytes| HashOf::new(vec_into_array(bytes)))
                    })?,
                    index: row.get(3)?,
                })
            })
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        blocks
            .next()
            .ok_or(BlockStoreError::NotFound(index))
            .map(|block| block.unwrap())
    }

    fn push(&mut self, hb: HashedBlock) -> Result<(), BlockStoreError> {
        let hash = hb.hash.into_bytes().to_vec();
        let parent_hash = hb.parent_hash.map(|ph| ph.into_bytes().to_vec());
        let connection = self.connection.lock().unwrap();
        connection
            .execute(
                "INSERT INTO blocks (hash, block, parent_hash, idx, verified) VALUES (?1, ?2, ?3, ?4, FALSE)",
                rusqlite::params![hash, hb.block.0, parent_hash, hb.index],
            )
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        Ok(())
    }

    // FIXME: Make `prune` return `BlockStoreError` on error
    fn prune(&mut self, hb: &HashedBlock, balances: &BalanceBook) -> Result<(), String> {
        self.write_oldest_block_snapshot(hb, balances)?;
        let connection = self.connection.lock().unwrap();
        connection
            .execute(
                "DELETE FROM blocks WHERE idx > 0 AND idx < ?",
                rusqlite::params![hb.index],
            )
            .map_err(|e| e.to_string())?;
        self.base_idx = hb.index;
        Ok(())
    }

    fn first_snapshot(&self) -> Option<&(HashedBlock, BalanceBook)> {
        self.first_block_snapshot.as_ref()
    }

    fn first(&self) -> Result<Option<HashedBlock>, BlockStoreError> {
        if let Some((first_block, _)) = self.first_block_snapshot.as_ref() {
            Ok(Some(first_block.clone()))
        } else {
            match self.get_at(0) {
                Ok(x) => Ok(Some(x)),
                Err(BlockStoreError::NotFound(_)) => Ok(None),
                Err(e) => Err(e),
            }
        }
    }

    fn last_verified(&self) -> Option<BlockHeight> {
        self.last_verified_idx
    }

    fn mark_last_verified(&mut self, block_height: BlockHeight) -> Result<(), BlockStoreError> {
        if let Some(hh) = self.last_verified_idx {
            if block_height < hh {
                panic!(
                    "New last verified index lower than the old one. New: {}, old: {}",
                    block_height, hh
                );
            }
            if block_height == hh {
                return Ok(());
            }
        }

        let connection = self.connection.lock().unwrap();
        let mut stmt = connection
            .prepare("UPDATE blocks SET verified = TRUE WHERE idx >= ? AND idx <= ?")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        stmt.execute(rusqlite::params![
            self.last_verified_idx.map(|x| x + 1).unwrap_or(0),
            block_height
        ])
        .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        self.last_verified_idx = Some(block_height);
        Ok(())
    }
}

pub struct InMemoryStore {
    inner: VecDeque<HashedBlock>,
    base_idx: u64,
    genesis: Option<HashedBlock>,
    last_verified_idx: Option<BlockHeight>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            inner: VecDeque::new(),
            base_idx: 0,
            genesis: None,
            last_verified_idx: None,
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockStore for InMemoryStore {
    fn get_at(&self, index: u64) -> Result<HashedBlock, BlockStoreError> {
        if index < self.base_idx {
            if index == 0 {
                return self.genesis.clone().ok_or(BlockStoreError::NotFound(0));
            }
            return Err(BlockStoreError::NotAvailable(index));
        }
        self.inner
            .get((index - self.base_idx) as usize)
            .cloned()
            .ok_or(BlockStoreError::NotFound(index))
    }

    fn push(&mut self, block: HashedBlock) -> Result<(), BlockStoreError> {
        self.inner.push_back(block);
        Ok(())
    }

    fn prune(&mut self, hb: &HashedBlock, _balances: &BalanceBook) -> Result<(), String> {
        if self.genesis.is_none() {
            self.genesis = self.inner.front().cloned();
        }
        while self.base_idx < hb.index {
            self.inner.pop_front();
            self.base_idx += 1;
        }
        Ok(())
    }

    fn first_snapshot(&self) -> Option<&(HashedBlock, BalanceBook)> {
        None
    }

    fn first(&self) -> Result<Option<HashedBlock>, BlockStoreError> {
        Ok(self.inner.front().cloned())
    }

    fn last_verified(&self) -> Option<BlockHeight> {
        self.last_verified_idx
    }

    fn mark_last_verified(&mut self, h: BlockHeight) -> Result<(), BlockStoreError> {
        if let Some(hh) = self.last_verified_idx {
            if h < hh {
                panic!("New last verified index lower than the old one");
            }
        }
        self.last_verified_idx = Some(h);
        Ok(())
    }
}

pub struct OnDiskStore {
    location: PathBuf,
    balances_snapshot: BalancesSnapshot,
    first_block_snapshot: Option<(HashedBlock, BalanceBook)>,
    last_verified_idx: Option<BlockHeight>,
    fsync: bool,
}

impl OnDiskStore {
    pub fn new(location: PathBuf, fsync: bool) -> Result<Self, BlockStoreError> {
        let balances_snapshot = BalancesSnapshot::new(location.clone());
        let mut store = Self {
            location,
            balances_snapshot,
            first_block_snapshot: None,
            last_verified_idx: None,
            fsync,
        };
        store.first_block_snapshot = store
            .read_oldest_block_snapshot()
            .map_err(BlockStoreError::Other)?;
        if let Some((first_block, _)) = &store.first_block_snapshot {
            store.get_at(first_block.index).and_then(|b| {
                if *first_block != b {
                    Err(BlockStoreError::Other("Corrupted snapshot".to_string()))
                } else {
                    Ok(())
                }
            })?;
        }
        store.last_verified_idx = store.read_last_verified().map_err(BlockStoreError::Other)?;
        Ok(store)
    }

    pub fn block_file_name(&self, height: BlockHeight) -> Box<Path> {
        self.location.join(format!("{}.json", height)).into()
    }

    fn last_verified_idx_file_name(&self) -> Box<Path> {
        self.location.join("last_verified_idx.json").into()
    }

    fn read_last_verified(&self) -> Result<Option<BlockHeight>, String> {
        let file_name = self.last_verified_idx_file_name();
        let file = OpenOptions::new().read(true).open(file_name);
        match file.map_err(|e| e.kind()) {
            Ok(f) => {
                debug!("Loading last verified idx");
                let h: BlockHeight = serde_json::from_reader(f).map_err(|e| e.to_string())?;
                Ok(Some(h))
            }
            Err(std::io::ErrorKind::NotFound) => Ok(None),
            Err(e) => Err(format!(
                "Reading file failed ({}): {:?}",
                self.last_verified_idx_file_name().to_string_lossy(),
                e
            )),
        }
    }

    fn read_oldest_block_snapshot(&self) -> Result<Option<(HashedBlock, BalanceBook)>, String> {
        self.balances_snapshot.read_oldest_block_snapshot()
    }

    fn write_oldest_block_snapshot(
        &mut self,
        hb: &HashedBlock,
        balances: &BalanceBook,
    ) -> Result<(), String> {
        if let Ok(Some(b)) = self.first() {
            // this check is made in upper levels, but for readability:
            assert!(b.index <= hb.index);
        }
        self.first_block_snapshot = self
            .balances_snapshot
            .write_oldest_block_snapshot(hb, balances)?;
        Ok(())
    }
}

impl BlockStore for OnDiskStore {
    fn get_at(&self, index: u64) -> Result<HashedBlock, BlockStoreError> {
        let file_name = self.block_file_name(index);
        let file = OpenOptions::new().read(true).open(file_name);
        match file.map_err(|e| e.kind()) {
            Ok(f) => serde_json::from_reader(f).map_err(|e| BlockStoreError::Other(e.to_string())),
            Err(std::io::ErrorKind::NotFound) => {
                let first_idx = self
                    .first_block_snapshot
                    .as_ref()
                    .map(|(hb, _)| hb.index)
                    .unwrap_or(0);
                if index < first_idx {
                    Err(BlockStoreError::NotAvailable(index))
                } else {
                    Err(BlockStoreError::NotFound(index))
                }
            }
            Err(e) => Err(BlockStoreError::Other(format!(
                "Reading file failed ({}): {:?}",
                self.block_file_name(index).to_string_lossy(),
                e
            ))),
        }
    }

    fn push(&mut self, block: HashedBlock) -> Result<(), BlockStoreError> {
        debug!("Writing block to the store. Block height: {}", block.index);
        let file_name = self.block_file_name(block.index);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_name)
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;

        serde_json::to_writer(&file, &block).map_err(|e| BlockStoreError::Other(e.to_string()))?;

        if self.fsync {
            file.sync_all().map_err(|e| {
                let msg = format!("Syncing file after write failed: {:?}", e);
                error!("{}", msg);
                BlockStoreError::Other(msg)
            })?;
        }

        Ok(())
    }

    fn prune(&mut self, hb: &HashedBlock, balances: &BalanceBook) -> Result<(), String> {
        let prune_start_idx = self
            .first_block_snapshot
            .as_ref()
            .map(|(first_block, _)| first_block.index)
            .unwrap_or(1);

        debug!("Prune store from {} to {}", prune_start_idx, hb.index);
        if prune_start_idx >= hb.index {
            return Ok(());
        }

        self.write_oldest_block_snapshot(hb, balances)?;

        for i in prune_start_idx..hb.index {
            let _ = std::fs::remove_file(self.block_file_name(i));
        }

        Ok(())
    }

    fn first_snapshot(&self) -> Option<&(HashedBlock, BalanceBook)> {
        self.first_block_snapshot.as_ref()
    }

    fn first(&self) -> Result<Option<HashedBlock>, BlockStoreError> {
        if let Some((first_block, _)) = self.first_block_snapshot.as_ref() {
            Ok(Some(first_block.clone()))
        } else {
            match self.get_at(0) {
                Ok(x) => Ok(Some(x)),
                Err(BlockStoreError::NotFound(_)) => Ok(None),
                Err(e) => Err(e),
            }
        }
    }

    fn last_verified(&self) -> Option<BlockHeight> {
        self.last_verified_idx
    }

    fn mark_last_verified(&mut self, h: BlockHeight) -> Result<(), BlockStoreError> {
        if let Some(hh) = self.last_verified_idx {
            if h < hh {
                panic!(
                    "New last verified index lower than the old one. New: {}, old: {}",
                    h, hh
                );
            }
            if h == hh {
                return Ok(());
            }
        }

        trace!("Writing last verified idx. Block height: {}", h);
        let file_name = self.last_verified_idx_file_name();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_name)
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;

        serde_json::to_writer(&file, &h).map_err(|e| BlockStoreError::Other(e.to_string()))?;

        if self.fsync {
            file.sync_all().map_err(|e| {
                let msg = format!("Syncing last verified idx file after write failed: {:?}", e);
                error!("{}", msg);
                BlockStoreError::Other(msg)
            })?;
        }

        self.last_verified_idx = Some(h);
        Ok(())
    }
}

struct BalancesSnapshot {
    location: PathBuf,
}

impl BalancesSnapshot {
    fn new(location: PathBuf) -> Self {
        Self { location }
    }

    fn oldest_block_snapshot_file_name(&self) -> Box<Path> {
        self.location.join("oldest_block_snapshot.json").into()
    }

    fn read_oldest_block_snapshot(&self) -> Result<Option<(HashedBlock, BalanceBook)>, String> {
        let file_name = self.oldest_block_snapshot_file_name();
        let file = OpenOptions::new().read(true).open(file_name);
        match file.map_err(|e| e.kind()) {
            Ok(f) => {
                debug!("Loading oldest block snapshot");
                let (hb, bal, icpt_pool): (
                    HashedBlock,
                    Vec<(AccountIdentifier, usize, ICPTs)>,
                    ICPTs,
                ) = serde_json::from_reader(f).map_err(|e| {
                    format!(
                        "Loading balances snapshot failed with error: {}. \
                    Possibly the snapshot format changed and a full resync \
                    on a clean block store is required.",
                        e.to_string()
                    )
                })?;
                let mut balance_book = BalanceBook::default();
                for (acc, num_pruned, amount) in &bal {
                    balance_book.store.insert(*acc, hb.index, *amount);
                    balance_book
                        .store
                        .acc_to_hist
                        .get_mut(acc)
                        .unwrap()
                        .num_pruned_transactions = *num_pruned;
                }
                balance_book.icpt_pool = icpt_pool;

                // sanity check
                let mut sum_icpt = ICPTs::ZERO;
                for acc in balance_book.store.acc_to_hist.keys() {
                    sum_icpt += balance_book.account_balance(acc);
                }
                let expected_icpt_pool = (ICPTs::MAX - sum_icpt).unwrap();
                if expected_icpt_pool != balance_book.icpt_pool {
                    return Err(format!(
                        "Incorrect ICPT pool value in the snapshot (expected: {}, got: {})",
                        expected_icpt_pool, balance_book.icpt_pool
                    ));
                }

                Ok(Some((hb, balance_book)))
            }
            Err(std::io::ErrorKind::NotFound) => {
                debug!("No oldest block snapshot present");
                Ok(None)
            }
            Err(e) => Err(format!(
                "Reading file failed ({}): {:?}",
                self.oldest_block_snapshot_file_name().to_string_lossy(),
                e
            )),
        }
    }

    fn write_oldest_block_snapshot(
        &mut self,
        hb: &HashedBlock,
        balances: &BalanceBook,
    ) -> Result<Option<(HashedBlock, BalanceBook)>, String> {
        debug!("Writing oldest block snapshot. Block height: {}", hb.index);
        let file_name = self.oldest_block_snapshot_file_name();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_name)
            .map_err(|e| e.to_string())?;

        let mut balances_snapshot = BalanceBook::default();
        let bal: Vec<_> = balances
            .store
            .acc_to_hist
            .iter()
            .map(|(acc, hist)| {
                let amount = hist.get_at(hb.index).unwrap(); //won't fail if first.idx <= hb.idx
                balances_snapshot.icpt_pool -= amount;
                balances_snapshot.store.insert(*acc, hb.index, amount);
                (acc, hist.num_pruned_transactions, amount)
            })
            .collect();
        serde_json::to_writer(&file, &(hb, bal, balances_snapshot.icpt_pool))
            .map_err(|e| e.to_string())?;

        file.sync_all().map_err(|e| {
            let msg = format!(
                "Syncing oldest block snapshot file after write failed: {:?}",
                e
            );
            error!("{}", msg);
            msg
        })?;

        Ok(Some((hb.clone(), balances_snapshot)))
    }
}
