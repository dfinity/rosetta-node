use dfn_candid::{Candid, CandidOne};
use ic_canister_client::{Agent, Sender};
use ic_types::CanisterId;
use ledger_canister::{Certification, Hash, HashedBlock};
use on_wire::{FromWire, IntoWire};
use reqwest::Url;
use serde::de::DeserializeOwned;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::Path;

type BlockResult = Result<Option<HashedBlock>, String>;

pub fn read_fs(hash: Hash) -> BlockResult {
    let file_name = hash_file_name(&hash);
    let file = OpenOptions::new().read(true).open(file_name);
    let hb = match file.map_err(|e| e.kind()) {
        Ok(f) => serde_json::from_reader(f).map_err(|e| e.to_string())?,
        Err(ErrorKind::NotFound) => return Ok(None),
        Err(e) => return Err(format!("Reading file failed: {:?}", e)),
    };
    Ok(Some(hb))
}

fn write_fs(hashed: &HashedBlock) -> Result<(), String> {
    let file_name = hash_file_name(&hashed.hash);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&file_name)
        .map_err(|e| e.to_string())?;

    serde_json::to_writer(&file, &hashed).map_err(|e| e.to_string())
}

fn exists_fs(hash: Hash) -> bool {
    Path::new(&hash_file_name(&hash)).exists()
}

fn hash_file_name(hash: &Hash) -> String {
    format!("{}.json", hex::encode(hash.to_be_bytes()))
}

pub struct LedgerCanister {
    pub agent: Agent,
    pub canister_id: CanisterId,
}

impl LedgerCanister {
    pub fn new(client: reqwest::Client, url: Url, canister_id: CanisterId) -> Self {
        LedgerCanister {
            agent: Agent::new_with_client(client, url, Sender::Anonymous),
            canister_id,
        }
    }

    async fn query<'a, Payload: dfn_candid::encode::EncodeArguments, Res: DeserializeOwned>(
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

    async fn read(&self, hash: &Hash) -> Result<Option<HashedBlock>, String> {
        self.query("block", (hash,)).await
    }

    async fn tip(&self) -> Result<(Certification, Hash), String> {
        self.query("tip_of_chain", ()).await
    }

    /// Returns the tip of the chain having verified and written all the other
    /// blocks to disk
    pub async fn sync(&self) -> Result<Option<Hash>, String> {
        let (cert, hash) = self.tip().await?;

        let mut to_fetch = Some(verify_tip(cert, hash)?);

        while let Some((tip, false)) = to_fetch.map(|tip| (tip, exists_fs(tip))) {
            match self.read(&tip).await? {
                Some(hb) => {
                    let hash = hb.hash;
                    if Some(hash) == to_fetch {
                        write_fs(&hb)?;
                        to_fetch = hb.block.parent_hash;
                    } else {
                        return Err(format!(
                            "Hash verification failed Expected {:?}, Found {:?}",
                            &to_fetch, &hash
                        ));
                    }
                }
                None => return Err(format!("Hash {:?} not found", &to_fetch)),
            }
        }

        Ok(Some(hash))
    }
}

/// TODO actually verify the BLS signature
fn verify_tip(cert: Certification, hash: Hash) -> Result<Hash, String> {
    if hash == cert {
        Ok(hash)
    } else {
        Err("Ceritifaction failed".to_string())
    }
}
