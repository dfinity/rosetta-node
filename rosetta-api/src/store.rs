use crate::convert::{internal_error, invalid_block_id};
use crate::ledger_client::Balances;
use crate::models::ApiError;

use ic_types::PrincipalId;
use ledger_canister::{Block, BlockHeight, HashOf, ICPTs, Serializable};
use log::{debug, error};
use serde::{Deserialize, Serialize};

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

#[derive(candid::CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HashedBlock {
    pub block: Block,
    pub hash: HashOf<Block>,
    pub parent_hash: Option<HashOf<Block>>,
    pub index: u64,
}

impl HashedBlock {
    pub fn hash_block(
        block: Block,
        parent_hash: Option<HashOf<Block>>,
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
}

pub struct InMemoryStore {
    inner: VecDeque<HashedBlock>,
    base_idx: u64,
    genesis: Option<HashedBlock>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            inner: VecDeque::new(),
            base_idx: 0,
            genesis: None,
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
}

pub struct OnDiskStore {
    location: PathBuf,
    first_block_snapshot: Option<(HashedBlock, Balances)>,
}

impl OnDiskStore {
    pub fn new(location: PathBuf) -> Result<Self, BlockStoreError> {
        let mut store = Self {
            location,
            first_block_snapshot: None,
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
        Ok(store)
    }

    pub fn block_file_name(&self, height: BlockHeight) -> Box<Path> {
        self.location.join(format!("{}.json", height)).into()
    }

    fn oldest_block_snapshot_file_name(&self) -> Box<Path> {
        self.location.join("oldest_block_snapshot.json").into()
    }

    fn read_oldest_block_snapshot(&self) -> Result<Option<(HashedBlock, Balances)>, String> {
        let file_name = self.oldest_block_snapshot_file_name();
        let file = OpenOptions::new().read(true).open(file_name);
        match file.map_err(|e| e.kind()) {
            Ok(f) => {
                debug!("Loading oldest block snapshot");
                let (hb, bal, icpt_pool): (HashedBlock, Vec<(PrincipalId, ICPTs)>, ICPTs) =
                    serde_json::from_reader(f).map_err(|e| e.to_string())?;
                let mut balances = Balances::default();
                balances.icpt_pool = icpt_pool;
                for (k, v) in bal {
                    balances.store.0.insert(k, v);
                }
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
        let bal: Vec<_> = balances.store.0.iter().collect(); //this is a vec of refs
        serde_json::to_writer(&file, &(hb, bal, balances.icpt_pool)).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| {
            let msg = format!(
                "Syncing oldest block snapshot file after write failed: {:?}",
                e
            );
            error!("{}", msg);
            msg
        })?;

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
        file.sync_all().map_err(|e| {
            let msg = format!("Syncing file after write failed: {:?}", e);
            error!("{}", msg);
            BlockStoreError::Other(msg)
        })?;
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
}
