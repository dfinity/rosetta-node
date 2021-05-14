mod basic_tests;
mod rosetta_cli_tests;
mod store_tests;

use lazy_static::lazy_static;
use url::Url;

use ic_rosetta_api::models::{
    AccountBalanceRequest, AccountBalanceResponse, ApiError, Envelopes, NetworkListResponse,
    NetworkRequest, PartialBlockIdentifier, TransactionIdentifier,
};
use ledger_canister::{self, AccountIdentifier, Block, BlockHeight, ICPTs, SendArgs, Transfer};
use tokio::sync::RwLock;

// TODO remove after disconnecting tests
use async_trait::async_trait;
use dfn_core::CanisterId;
#[allow(unused_imports)]
use ic_rosetta_api::convert::{
    from_arg, from_hash, from_hex, from_model_account_identifier, from_public_key, internal_error,
    operations, to_arg, to_hash, to_hex, to_model_account_identifier, transaction_id,
    transaction_identifier,
};
use ic_rosetta_api::ledger_client::{Balances, Blocks, ChunkmapBalancesStore, LedgerAccess};
use ic_rosetta_api::rosetta_server::RosettaApiServer;
use ic_rosetta_api::{store::HashedBlock, RosettaRequestHandler};
use ic_types::{
    messages::{HttpCanisterUpdate, HttpSubmitContent},
    PrincipalId,
};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::ops::Deref;
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use ic_rosetta_test_utils::acc_id;
use ic_rosetta_test_utils::sample_data::Scribe;

fn init_test_logger() {
    // Unfortunately cargo test doesn't capture stdout properly
    // so we set the level to warn (so we don't spam).
    // I tried to use env logger here, which is supposed to work,
    // and sure, cargo test captures it's output on MacOS, but it
    // doesn't on linux.
    log4rs::init_file("log_config_tests.yml", Default::default()).ok();
}

fn create_tmp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("test_tmp_")
        .tempdir_in(".")
        .unwrap()
}

lazy_static! {
    static ref DUMMY_CAN_ID: CanisterId = {
        CanisterId::new(PrincipalId::try_from(&[0, 0, 0, 0, 0, 0, 4, 210][..]).unwrap()).unwrap()
    };
}

pub struct TestLedger {
    blockchain: RwLock<Blocks>,
    canister_id: CanisterId,
    submit_queue: RwLock<Vec<HashedBlock>>,
}

impl TestLedger {
    pub fn new() -> Self {
        Self {
            blockchain: RwLock::new(Blocks::default()),
            canister_id: CanisterId::new(
                PrincipalId::from_str("5v3p4-iyaaa-aaaaa-qaaaa-cai").unwrap(),
            )
            .unwrap(),
            submit_queue: RwLock::new(Vec::new()),
        }
    }

    async fn last_submitted(&self) -> Result<Option<HashedBlock>, ApiError> {
        match self.submit_queue.read().await.last() {
            Some(b) => Ok(Some(b.clone())),
            None => self.read_blocks().await.last_verified(),
        }
    }

    async fn add_block(&self, hb: HashedBlock) -> Result<(), ApiError> {
        let mut blockchain = self.blockchain.write().await;
        blockchain.block_store.mark_last_verified(hb.index)?;
        blockchain.add_block(hb)
    }
}

impl Default for TestLedger {
    fn default() -> Self {
        Self::new()
    }
}

async fn post_json_request(
    http_client: &reqwest::Client,
    url: &str,
    body: Vec<u8>,
) -> Result<(Vec<u8>, reqwest::StatusCode), String> {
    let resp = http_client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .map_err(|err| format!("sending post request failed with {}: ", err))?;
    let resp_status = resp.status();
    let resp_body = resp
        .bytes()
        .await
        .map_err(|err| format!("receive post response failed with {}: ", err))?
        .to_vec();
    Ok((resp_body, resp_status))
}

#[async_trait]
impl LedgerAccess for TestLedger {
    async fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a> {
        Box::new(self.blockchain.read().await)
    }

    async fn sync_blocks(&self, _stopped: Arc<AtomicBool>) -> Result<(), ApiError> {
        let mut queue = self.submit_queue.write().await;

        {
            let mut blockchain = self.blockchain.write().await;
            for hb in queue.iter() {
                blockchain.block_store.mark_last_verified(hb.index)?;
                blockchain.add_block(hb.clone())?;
            }
        }

        *queue = Vec::new();

        Ok(())
    }

    fn ledger_canister_id(&self) -> &CanisterId {
        &self.canister_id
    }

    fn network_url(&self) -> &Url {
        panic!("Network url not available");
    }

    async fn submit(
        &self,
        envelopes: Envelopes,
    ) -> Result<(TransactionIdentifier, Option<BlockHeight>), ApiError> {
        let (submit_request, _read_state_request) = &envelopes[0];

        let HttpCanisterUpdate { arg, sender, .. } = match submit_request.content.clone() {
            HttpSubmitContent::Call { update } => update,
        };

        let from = PrincipalId::try_from(sender.0).map_err(internal_error)?;

        let SendArgs {
            memo,
            amount,
            fee,
            from_subaccount,
            to,
            created_at_time,
        } = from_arg(arg.0).unwrap();
        let created_at_time = created_at_time.unwrap();

        let from = ledger_canister::AccountIdentifier::new(from, from_subaccount);

        let transaction = Transfer::Send {
            from,
            to,
            amount,
            fee,
        };

        let (parent_hash, index) = match self.last_submitted().await? {
            None => (None, 0),
            Some(hb) => (Some(hb.hash), hb.index + 1),
        };

        let block = Block::new(
            None, /* FIXME */
            transaction,
            memo,
            created_at_time,
            dfn_core::api::now().into(),
        )
        .map_err(internal_error)?;

        let raw_block = block.clone().encode().map_err(internal_error)?;

        let hb = HashedBlock::hash_block(raw_block, parent_hash, index);

        self.submit_queue.write().await.push(hb.clone());

        Ok((transaction_identifier(&block.transaction().hash()), None))
    }

    async fn chain_length(&self) -> BlockHeight {
        match self.blockchain.read().await.last_verified().unwrap() {
            None => 0,
            Some(hb) => hb.index + 1,
        }
    }
}

pub(crate) fn to_balances(b: BTreeMap<AccountIdentifier, ICPTs>) -> Balances {
    use std::iter::FromIterator;
    let mut balances = Balances::default();
    let x = immutable_chunkmap::map::Map::<AccountIdentifier, ICPTs>::from_iter(b.into_iter());
    balances.store = ChunkmapBalancesStore(x);
    balances
}

pub async fn get_balance(
    req_handler: &RosettaRequestHandler,
    height: Option<usize>,
    acc: AccountIdentifier,
) -> Result<ICPTs, ApiError> {
    let block_id = height.map(|h| PartialBlockIdentifier {
        index: Some(h as i64),
        hash: None,
    });
    let mut msg = AccountBalanceRequest::new(
        req_handler.network_id(),
        ic_rosetta_api::convert::to_model_account_identifier(&acc),
    );
    msg.block_identifier = block_id;
    let resp = req_handler.account_balance(msg).await?;
    Ok(ICPTs::from_e8s(resp.balances[0].value.parse().unwrap()))
}

#[actix_rt::test]
async fn smoke_test_with_server() {
    init_test_logger();

    let addr = "127.0.0.1:8090".to_string();

    let mut scribe = Scribe::new();
    let num_transactions = 1000;
    let num_accounts = 100;

    scribe.gen_accounts(num_accounts, 1_000_000);
    for _i in 0..num_transactions {
        scribe.gen_transaction();
    }

    let ledger = Arc::new(TestLedger::new());
    let req_handler = RosettaRequestHandler::new(ledger.clone());
    for b in &scribe.blockchain {
        ledger.add_block(b.clone()).await.ok();
    }

    let serv_ledger = ledger.clone();
    let serv_req_handler = req_handler.clone();

    let serv =
        Arc::new(RosettaApiServer::new(serv_ledger, serv_req_handler, addr.clone()).unwrap());
    let serv_run = serv.clone();
    actix_rt::spawn(async move {
        log::info!("Spawning server");
        serv_run.run(false, false).await.unwrap();
        log::info!("Server thread done");
    });

    let http_client = reqwest::Client::new();

    let msg = NetworkRequest::new(req_handler.network_id());
    let http_body = serde_json::to_vec(&msg).unwrap();
    let (res, _) = post_json_request(
        &http_client,
        &format!("http://{}/network/list", addr),
        http_body,
    )
    .await
    .unwrap();
    let resp: NetworkListResponse = serde_json::from_slice(&res).unwrap();

    assert_eq!(resp.network_identifiers[0], req_handler.network_id());

    let msg = AccountBalanceRequest::new(
        req_handler.network_id(),
        ic_rosetta_api::convert::to_model_account_identifier(&acc_id(0)),
    );

    let http_body = serde_json::to_vec(&msg).unwrap();
    let (res, _) = post_json_request(
        &http_client,
        &format!("http://{}/account/balance", addr),
        http_body,
    )
    .await
    .unwrap();
    let res: AccountBalanceResponse = serde_json::from_slice(&res).unwrap();

    assert_eq!(
        res.block_identifier.index,
        (num_transactions + num_accounts - 1) as i64
    );
    assert_eq!(
        ICPTs::from_e8s(u64::from_str(&res.balances[0].value).unwrap()),
        *scribe.balance_book.get(&acc_id(0)).unwrap()
    );

    serv.stop().await;
}
