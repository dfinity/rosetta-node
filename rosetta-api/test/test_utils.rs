mod basic_tests;
mod rosetta_cli_tests;

use lazy_static::lazy_static;
use reqwest::Url;

use ic_rosetta_api::models::*;
use ic_types::{CanisterId, PrincipalId};
use ledger_canister::{self, Block, Hash, HashedBlock, ICPTs, Message, Transaction};
use std::sync::RwLock;

use rand::{rngs::StdRng, RngCore, SeedableRng};
use rand_distr::Distribution;
use thread_local::ThreadLocal;

// TODO remove after disconnecting tests
use async_trait::async_trait;
#[allow(unused_imports)]
use ic_rosetta_api::convert::{from_arg, from_hash, internal_error, to_hash};
use ic_rosetta_api::ledger_client::{Blocks, LedgerAccess};
use ic_rosetta_api::rosetta_server::RosettaApiServer;
use ic_rosetta_api::RosettaRequestHandler;
use ic_scenario_tests::{
    api::system::builder::Subnet, api::system::handle::IcHandle, system_test::InternetComputer,
};
use ic_types::messages::{HttpCanisterUpdate, HttpRequestEnvelope, HttpSubmitContent};
use std::collections::{BTreeMap, VecDeque};
use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};
use std::process::Command;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

const SEED: u64 = 137;

lazy_static! {
    static ref RNG: ThreadLocal<Mutex<StdRng>> = ThreadLocal::new();
}

fn rng() -> impl DerefMut<Target = impl rand::RngCore> {
    RNG.get_or(|| Mutex::new(StdRng::seed_from_u64(SEED)))
        .lock()
        .unwrap()
}

fn rand_val(val: u64, dev: f64) -> u64 {
    let gen = rand_distr::Normal::new(val as f64, val as f64 * dev).unwrap();
    let ret = gen.sample(&mut *rng()).max(0.0);
    ret as u64
}

fn dice_num(n: u64) -> u64 {
    rng().next_u64() % n
}

pub fn to_uid(id: u64) -> PrincipalId {
    PrincipalId::try_from(id.to_be_bytes().to_vec()).unwrap()
}

lazy_static! {
    static ref DUMMY_CAN_ID: CanisterId = {
        CanisterId::new(PrincipalId::try_from(&[0, 0, 0, 0, 0, 0, 4, 210][..]).unwrap()).unwrap()
    };
}

pub struct TestLedger {
    blockchain: RwLock<Blocks>,
    canister_id: CanisterId,
    ic: Option<Arc<IcHandle>>,
    submit_queue: RwLock<Vec<HashedBlock>>,
}

impl TestLedger {
    pub fn new() -> Self {
        Self {
            blockchain: RwLock::new(Blocks::default()),
            canister_id: CanisterId::new(
                PrincipalId::try_from(&[0, 0, 0, 0, 0, 0, 4, 210][..]).unwrap(),
            )
            .unwrap(),
            ic: None,
            submit_queue: RwLock::new(Vec::new()),
        }
    }

    pub fn with_ic(mut self, ic: Arc<IcHandle>) -> Self {
        self.ic = Some(ic);
        self
    }

    fn last_submitted(&self) -> Result<Option<HashedBlock>, ApiError> {
        match self.submit_queue.read().unwrap().last() {
            Some(b) => Ok(Some(b.clone())),
            None => self.read_blocks().last(),
        }
    }

    fn add_block(&self, hb: HashedBlock) -> Result<(), ApiError> {
        self.blockchain.write().unwrap().add_block(hb)
    }
}

impl Default for TestLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LedgerAccess for TestLedger {
    fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a> {
        Box::new(self.blockchain.read().unwrap())
    }

    async fn sync_blocks(&self) -> Result<(), ApiError> {
        let mut queue = self.submit_queue.write().unwrap();

        {
            let mut blockchain = self.blockchain.write().unwrap();
            for hb in queue.iter() {
                blockchain.add_block(hb.clone())?;
            }
        }

        *queue = Vec::new();

        Ok(())
    }

    fn ledger_canister_id(&self) -> &CanisterId {
        &self.canister_id
    }

    fn reqwest_client(&self) -> &reqwest::Client {
        if let Some(ref ic) = self.ic {
            ic.reqwest_client()
        } else {
            panic!("Reqwest client not available");
        }
    }

    fn testnet_url(&self) -> &Url {
        panic!("Testnet url not available");
    }

    async fn submit(
        &self,
        submit_request: HttpRequestEnvelope<HttpSubmitContent>,
    ) -> Result<Hash, ApiError> {
        let HttpCanisterUpdate { arg, sender, .. } = match submit_request.content {
            HttpSubmitContent::Call { update } => update,
        };

        let from = PrincipalId::try_from(sender.0).map_err(internal_error)?;

        let (message, amount, to, _) = from_arg(arg.0).unwrap();

        let transaction = Transaction::Send { from, to, amount };

        let (parent_hash, index) = match self.last_submitted()? {
            None => (None, 0),
            Some(hb) => (Some(hb.hash), hb.block.index + 1),
        };

        let block =
            Block::new(transaction, message, parent_hash, index, None).map_err(internal_error)?;

        let hb = HashedBlock::hash_block(block);

        self.submit_queue.write().unwrap().push(hb.clone());

        Ok(hb.hash)
    }
}

enum Trans {
    Buy(PrincipalId, ICPTs),
    Sell(PrincipalId, ICPTs),
    Transfer(PrincipalId, PrincipalId, ICPTs),
}

pub struct Scribe {
    balance_book: BTreeMap<PrincipalId, ICPTs>,
    pub blockchain: VecDeque<HashedBlock>,
    transactions: VecDeque<Trans>,
    balance_history: VecDeque<BTreeMap<PrincipalId, ICPTs>>,
}

impl Scribe {
    pub fn new() -> Self {
        Self {
            balance_book: BTreeMap::new(),
            blockchain: VecDeque::new(),
            transactions: VecDeque::new(),
            balance_history: VecDeque::new(),
        }
    }

    pub fn num_accounts(&self) -> u64 {
        self.balance_book.len() as u64
    }

    fn time(&self) -> SystemTime {
        //2010.01.01 1:0:0 + int
        std::time::UNIX_EPOCH
            + std::time::Duration::from_millis(1262307600000 + self.blockchain.len() as u64)
    }

    fn next_message(&self) -> Message {
        Message(self.next_index() as u64)
    }

    fn next_index(&self) -> usize {
        self.blockchain.len()
    }

    pub fn gen_accounts(&mut self, num: u64, balance: u64) {
        let num_accounts = self.balance_book.len() as u64;
        for i in num_accounts..num_accounts + num {
            let amount = rand_val(balance, 0.1);
            self.balance_book.insert(to_uid(i), ICPTs::zero());
            self.buy(to_uid(i), amount);
        }
    }

    pub fn add_block(&mut self, block: Block) {
        self.blockchain.push_back(HashedBlock::hash_block(block));
    }

    pub fn buy(&mut self, uid: PrincipalId, amount: u64) {
        let amount = ICPTs::from_icpts(amount).unwrap();
        self.transactions.push_back(Trans::Buy(uid, amount));
        *self.balance_book.get_mut(&uid).unwrap() += amount;
        let block = Block {
            payment: Transaction::Mint { to: uid, amount },
            timestamp: self.time(),
            message: self.next_message(),
            index: self.next_index() as usize,
            parent_hash: self.blockchain.back().map(|hb| hb.hash),
            created_at_offset: 1,
        };
        self.balance_history.push_back(self.balance_book.clone());
        self.add_block(block);
    }

    pub fn sell(&mut self, uid: PrincipalId, amount: u64) {
        let amount = ICPTs::from_icpts(amount).unwrap();
        self.transactions.push_back(Trans::Sell(uid, amount));
        *self.balance_book.get_mut(&uid).unwrap() -= amount;
        let block = Block {
            payment: Transaction::Burn { from: uid, amount },
            timestamp: self.time(),
            message: self.next_message(),
            index: self.next_index() as usize,
            parent_hash: self.blockchain.back().map(|hb| hb.hash),
            created_at_offset: 1,
        };
        self.balance_history.push_back(self.balance_book.clone());
        self.add_block(block);
    }

    pub fn transfer(&mut self, src: PrincipalId, dst: PrincipalId, amount: u64) {
        let amount = ICPTs::from_icpts(amount).unwrap();
        self.transactions
            .push_back(Trans::Transfer(src, dst, amount));
        *self.balance_book.get_mut(&src).unwrap() -= amount;
        *self.balance_book.get_mut(&dst).unwrap() += amount;

        let block = Block {
            payment: Transaction::Send {
                from: src,
                to: dst,
                amount,
            },
            timestamp: self.time(),
            message: self.next_message(),
            index: self.next_index() as usize,
            parent_hash: self.blockchain.back().map(|hb| hb.hash),
            created_at_offset: 1,
        };
        self.balance_history.push_back(self.balance_book.clone());
        self.add_block(block);
    }

    pub fn gen_transaction(&mut self) {
        let account1 = to_uid(dice_num(self.num_accounts()));
        let amount = rand_val((1 + dice_num(3)) * 100, 0.1);
        let amount_ = ICPTs::from_doms(amount);
        match dice_num(4) {
            0 => self.buy(account1, amount),
            1 => {
                if *self.balance_book.get(&account1).unwrap() >= amount_ {
                    self.sell(account1, amount);
                } else {
                    self.buy(account1, amount);
                }
            }
            _ => {
                if *self.balance_book.get(&account1).unwrap() >= amount_ {
                    let mut account2 = to_uid(dice_num(self.num_accounts()));
                    while account1 == account2 {
                        account2 = to_uid(dice_num(self.num_accounts()));
                    }
                    self.transfer(account1, account2, amount)
                } else {
                    self.buy(account1, amount);
                }
            }
        };
    }
}

impl Default for Scribe {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn get_balance(
    req_handler: &RosettaRequestHandler,
    height: Option<usize>,
    uid: u64,
) -> Result<ICPTs, ApiError> {
    let block_id = height.map(|h| PartialBlockIdentifier {
        index: Some(h as i64),
        hash: None,
    });
    let mut msg = AccountBalanceRequest::new(
        req_handler.network_id(),
        ic_rosetta_api::convert::account_identifier(&to_uid(uid)),
    );
    msg.block_identifier = block_id;
    let resp = req_handler.account_balance(msg).await?;
    Ok(ICPTs::from_doms(resp.balances[0].value.parse().unwrap()))
}

#[actix_rt::test]
async fn smoke_test_with_server() {
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
        ledger.add_block(b.clone()).ok();
    }

    let serv_ledger = ledger.clone();
    let serv_req_handler = req_handler.clone();

    let serv =
        Arc::new(RosettaApiServer::new(serv_ledger, serv_req_handler, addr.clone()).unwrap());
    let serv_run = serv.clone();
    actix_rt::spawn(async move {
        println!("Spawning server");
        serv_run.run().await.unwrap();
        println!("Server thread done");
    });

    let reqwest_client = reqwest::Client::new();

    let msg = NetworkRequest::new(req_handler.network_id());
    let http_body = serde_json::to_vec(&msg).unwrap();
    let request = reqwest_client
        .post(&format!("http://{}/network/list", addr))
        .header("Content-Type", "application/json")
        .body(http_body);

    let res = request.send().await.unwrap();
    let resp: NetworkListResponse = serde_json::from_str(&res.text().await.unwrap()).unwrap();

    assert_eq!(resp.network_identifiers[0], req_handler.network_id());

    let msg = AccountBalanceRequest::new(
        req_handler.network_id(),
        ic_rosetta_api::convert::account_identifier(&to_uid(0)),
    );

    let http_body = serde_json::to_vec(&msg).unwrap();
    let request = reqwest_client
        .post(&format!("http://{}/account/balance", addr))
        .header("Content-Type", "application/json")
        .body(http_body);

    let res = request.send().await.unwrap();
    let res: AccountBalanceResponse = serde_json::from_str(&res.text().await.unwrap()).unwrap();

    assert_eq!(
        res.block_identifier.index,
        (num_transactions + num_accounts - 1) as i64
    );
    assert_eq!(
        ICPTs::from_doms(u64::from_str(&res.balances[0].value).unwrap()),
        *scribe.balance_book.get(&to_uid(0)).unwrap()
    );

    serv.stop().await;
}

#[ignore] // ICSUP-133 work in progress.
#[actix_rt::test]
async fn simple_ic_test() {
    let ic = InternetComputer::new()
        .with_subnet(Subnet::new().add_nodes(5))
        .start()
        .await;
    let ic = ic.ready().await.expect("Not ready yet");
    let _ledger = TestLedger::new().with_ic(ic);
}
