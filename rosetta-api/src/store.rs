use crate::convert::{internal_error, invalid_block_id};
use crate::ledger_client::Balances;
use crate::models::ApiError;

use ledger_canister::{AccountIdentifier, BlockHeight, EncodedBlock, HashOf, ICPTs};
use log::{debug, error, trace};
use serde::{Deserialize, Serialize};

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

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
    fn prune(&mut self, hb: &HashedBlock, balances: &Balances) -> Result<(), String>;
    fn first_snapshot(&self) -> Option<&(HashedBlock, Balances)>;
    fn first(&self) -> Result<Option<HashedBlock>, BlockStoreError>;
    fn last_verified(&self) -> Option<BlockHeight>;
    fn mark_last_verified(&mut self, h: BlockHeight) -> Result<(), BlockStoreError>;
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
                return self
                    .genesis
                    .clone()
                    .ok_or_else(|| BlockStoreError::NotFound(0));
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

    fn prune(&mut self, hb: &HashedBlock, _balances: &Balances) -> Result<(), String> {
        if self.genesis.is_none() {
            self.genesis = self.inner.front().cloned();
        }
        while self.base_idx < hb.index {
            self.inner.pop_front();
            self.base_idx += 1;
        }
        Ok(())
    }

    fn first_snapshot(&self) -> Option<&(HashedBlock, Balances)> {
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
    first_block_snapshot: Option<(HashedBlock, Balances)>,
    last_verified_idx: Option<BlockHeight>,
    fsync: bool,
}

impl OnDiskStore {
    pub fn new(location: PathBuf, fsync: bool) -> Result<Self, BlockStoreError> {
        let mut store = Self {
            location,
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

    fn oldest_block_snapshot_file_name(&self) -> Box<Path> {
        self.location.join("oldest_block_snapshot.json").into()
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
            Err(e) => Err(format!("Reading file failed: {:?}", e)),
        }
    }

    fn read_oldest_block_snapshot(&self) -> Result<Option<(HashedBlock, Balances)>, String> {
        let file_name = self.oldest_block_snapshot_file_name();
        let file = OpenOptions::new().read(true).open(file_name);
        match file.map_err(|e| e.kind()) {
            Ok(f) => {
                debug!("Loading oldest block snapshot");
                let (hb, bal, icpt_pool): (HashedBlock, Vec<(AccountIdentifier, ICPTs)>, ICPTs) =
                    serde_json::from_reader(f).map_err(|e| e.to_string())?;
                let mut balances = Balances::default();
                balances.icpt_pool = icpt_pool;
                balances.store.0 = immutable_chunkmap::map::Map::new()
                    .insert_many(bal.iter().map(|(k, v)| (*k, *v)));
                Ok(Some((hb, balances)))
            }
            Err(std::io::ErrorKind::NotFound) => {
                debug!("No oldest block snapshot present");
                Ok(None)
            }
            Err(e) => Err(format!("Reading file failed: {:?}", e)),
        }
    }

    fn write_oldest_block_snapshot(
        &mut self,
        hb: &HashedBlock,
        balances: &Balances,
    ) -> Result<(), String> {
        debug!("Writing oldest block snapshot. Block height: {}", hb.index);
        let file_name = self.oldest_block_snapshot_file_name();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_name)
            .map_err(|e| e.to_string())?;

        // TODO implement Serialize for Balances
        let b = balances.store.0.clone();
        let bal: Vec<_> = b.into_iter().collect();
        serde_json::to_writer(&file, &(hb, bal, balances.icpt_pool)).map_err(|e| e.to_string())?;

        if self.fsync {
            file.sync_data().map_err(|e| {
                let msg = format!(
                    "Syncing oldest block snapshot file after write failed: {:?}",
                    e
                );
                error!("{}", msg);
                msg
            })?;
        }

        self.first_block_snapshot = Some((hb.clone(), balances.clone()));
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
                "Reading file failed: {:?}",
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
            file.sync_data().map_err(|e| {
                let msg = format!("Syncing file after write failed: {:?}", e);
                error!("{}", msg);
                BlockStoreError::Other(msg)
            })?;
        }

        Ok(())
    }

    fn prune(&mut self, hb: &HashedBlock, balances: &Balances) -> Result<(), String> {
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

    fn first_snapshot(&self) -> Option<&(HashedBlock, Balances)> {
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
            file.sync_data().map_err(|e| {
                let msg = format!("Syncing last verified idx file after write failed: {:?}", e);
                error!("{}", msg);
                BlockStoreError::Other(msg)
            })?;
        }

        self.last_verified_idx = Some(h);
        Ok(())
    }
}
