// This pulls down ICPT transactions from the ledger canister, verifies them
// then saves them to disk
use candid::CandidType;
use dfn_candid::{Candid, CandidOne};
use ic_canister_client::{Agent, Sender};
use ic_types::CanisterId;
use ledger_canister::{Block, BlockHeight, Certification, HashOf};
use on_wire::{FromWire, IntoWire};
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, OpenOptions};
use std::io::ErrorKind;
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct LedgerCanister {
    pub agent: Agent,
    pub canister_id: CanisterId,
    pub synced_to: Option<(HashOf<Block>, BlockHeight)>,
    pub verified_until: BlockHeight,
    init_time: Option<SystemTime>,
}

impl LedgerCanister {
    pub async fn new(
        client: reqwest::Client,
        url: Url,
        canister_id: CanisterId,
    ) -> Result<LedgerCanister, String> {
        let mut lc = LedgerCanister {
            agent: Agent::new_with_client(client, url, Sender::Anonymous),
            canister_id,
            synced_to: None,
            verified_until: 0,
            init_time: None,
        };
        let genesis_block: Block = lc
            .block(0)
            .await?
            .expect("Every blockchain should have a genesis block");

        lc.init_time = Some(genesis_block.timestamp);
        let mut genesis_path = lc.block_file_name(0).as_ref().to_path_buf();
        genesis_path.pop();
        // ensure the store directory is created
        create_dir_all(&genesis_path).map_err(|e| format!("{}", e))?;
        Ok(lc)
    }

    pub async fn query<'a, Payload: dfn_candid::ArgumentEncoder, Res: DeserializeOwned>(
        &self,
        method: &str,
        payload: Payload,
    ) -> Result<Res, String> {
        let arg = Candid(payload).into_bytes()?;
        let bytes = self
            .agent
            .execute_query(&self.canister_id, method, Some(arg))
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        CandidOne::from_bytes(bytes).map(|c| c.0)
    }

    async fn populate_cache(
        &self,
        height: BlockHeight,
        parent_hash: Option<HashOf<Block>>,
    ) -> Result<Option<HashedBlock>, String> {
        match self.read_cache(height)? {
            None => match self
                .query::<_, Option<Block>>("block", (height,))
                .await
                .map_err(|e| format!("In populate cache: {}", e))?
            {
                None => Ok(None),
                Some(b) => {
                    let hb = HashedBlock::hash_block(b, parent_hash, height);
                    // Don't write before init
                    self.write_cache(hb.clone())?;
                    Ok(Some(hb))
                }
            },
            Some(cached_value) => Ok(Some(cached_value)),
        }
    }

    async fn tip(&self) -> Result<(Certification, BlockHeight), String> {
        self.query("tip_of_chain", ())
            .await
            .map_err(|e| format!("In tip: {}", e))
    }

    async fn block(&self, height: BlockHeight) -> Result<Option<Block>, String> {
        self.query("block", (height,))
            .await
            .map_err(|e| format!("In block: {}", e))
    }

    /// Returns the tip of the blockheight having written all the blocks to the
    /// fs
    pub async fn sync(&mut self) -> Result<BlockHeight, String> {
        let (cert, ledger_height) = self.tip().await?;

        let (mut synced_hash, synced_height) = match self.synced_to {
            Some((hash, height)) => (Some(hash), height),
            None => (None, 0),
        };

        for i in synced_height..=ledger_height {
            let hb = self
                .populate_cache(i, synced_hash)
                .await?
                .unwrap_or_else(|| {
                    panic!(
                        "Block {} is missing when the tip of the chain is {}",
                        i, ledger_height
                    )
                });
            self.synced_to = Some((hb.hash, hb.index));
            synced_hash = Some(hb.hash);
        }

        verify_tip(cert, synced_hash)?;

        if synced_height != ledger_height {
            println!("You are all caught up to block height {}", ledger_height);
        }

        self.verified_until = synced_height;
        Ok(synced_height)
    }

    pub fn read_cache(&self, height: BlockHeight) -> Result<Option<HashedBlock>, String> {
        let file_name = self.block_file_name(height);
        let file = OpenOptions::new().read(true).open(file_name);
        match file.map_err(|e| e.kind()) {
            Ok(f) => serde_json::from_reader(f).map_err(|e| e.to_string()),
            Err(ErrorKind::NotFound) => Ok(None),
            Err(e) => Err(format!("Reading file failed: {:?}", e)),
        }
    }

    pub fn last(&self) -> Result<Option<HashedBlock>, String> {
        match self.verified_until {
            0 => Ok(None),
            n => self.read_cache(n - 1),
        }
    }

    fn write_cache(&self, hashed: HashedBlock) -> Result<(), String> {
        let file_name = self.block_file_name(hashed.index);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_name)
            .map_err(|e| e.to_string())?;

        serde_json::to_writer(&file, &hashed).map_err(|e| e.to_string())
    }

    fn block_file_name(&self, height: BlockHeight) -> Box<Path> {
        self.chain_id()
            // TODO put this somewhere more sensible
            .store_location(PathBuf::new())
            .join(format!("{}.json", height))
            .into_boxed_path()
    }

    fn chain_id(&self) -> ChainIdentifier {
        let init_time = self.init_time.expect("This should not fail after init");
        ChainIdentifier {
            canister_id: self.canister_id,
            init_time,
            url: self.agent.url.clone(),
        }
    }
}

/// TODO actually verify the BLS signature
fn verify_tip(_cert: Certification, _hash: Option<HashOf<Block>>) -> Result<(), String> {
    Ok(())
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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
            hash: block.hash(parent_hash),
            block,
            parent_hash,
            index,
        }
    }
}

struct ChainIdentifier {
    canister_id: CanisterId,
    init_time: SystemTime,
    url: Url,
}

impl ChainIdentifier {
    fn store_location(&self, base: PathBuf) -> PathBuf {
        let time_ns = self
            .init_time
            .duration_since(UNIX_EPOCH)
            .expect("Invalid time stamp")
            .as_nanos();
        base.join(&self.url.to_string())
            .join(&self.canister_id.to_string())
            .join(&format!("{}", time_ns))
    }
}
