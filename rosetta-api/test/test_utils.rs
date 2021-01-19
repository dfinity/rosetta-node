mod basic_tests;
mod rosetta_cli_tests;

use lazy_static::lazy_static;
use reqwest::Url;

use ic_rosetta_api::models::*;
use ic_rosetta_api::sync::HashedBlock;
use ic_types::{CanisterId, PrincipalId};
use ledger_canister::{self, Block, BlockHeight, ICPTs, Memo, Transaction, Transfer};
use tokio::sync::RwLock;

use rand::{
    rngs::{OsRng, StdRng},
    RngCore, SeedableRng,
};
use rand_distr::Distribution;
use thread_local::ThreadLocal;

// TODO remove after disconnecting tests
use async_std::task::sleep;
use async_trait::async_trait;
use dfn_candid::Candid;
#[allow(unused_imports)]
use ic_rosetta_api::convert::{
    account_identifier, from_arg, from_hash, from_hex, internal_error, operations, principal_id,
    to_hash, to_hex, transaction_id, transaction_identifier,
};
use ic_rosetta_api::ledger_client::{self, Blocks, LedgerAccess};
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
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

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

    async fn last_submitted(&self) -> Result<Option<HashedBlock>, ApiError> {
        match self.submit_queue.read().await.last() {
            Some(b) => Ok(Some(b.clone())),
            None => self.read_blocks().await.last(),
        }
    }

    async fn add_block(&self, hb: HashedBlock) -> Result<(), ApiError> {
        self.blockchain.write().await.add_block(hb)
    }
}

impl Default for TestLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LedgerAccess for TestLedger {
    async fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a> {
        Box::new(self.blockchain.read().await)
    }

    async fn sync_blocks(&self) -> Result<(), ApiError> {
        let mut queue = self.submit_queue.write().await;

        {
            let mut blockchain = self.blockchain.write().await;
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
    ) -> Result<TransactionIdentifier, ApiError> {
        let HttpCanisterUpdate { arg, sender, .. } = match submit_request.content {
            HttpSubmitContent::Call { update } => update,
        };

        let from = PrincipalId::try_from(sender.0).map_err(internal_error)?;

        let (memo, amount, to, created_at) = from_arg(arg.0).unwrap();
        let created_at = created_at.unwrap();

        let transaction = Transfer::Send { from, to, amount };

        let (parent_hash, index) = match self.last_submitted().await? {
            None => (None, 0),
            Some(hb) => (Some(hb.hash), hb.index + 1),
        };

        let block = Block::new(transaction, memo, created_at).map_err(internal_error)?;

        let hb = HashedBlock::hash_block(block, parent_hash, index);

        self.submit_queue.write().await.push(hb.clone());

        Ok(transaction_identifier(&hb.block.transaction.hash()))
    }
}

enum Trans {
    Buy(PrincipalId, ICPTs),
    Sell(PrincipalId, ICPTs),
    Transfer(PrincipalId, PrincipalId, ICPTs),
}

pub struct Scribe {
    accounts: VecDeque<PrincipalId>,
    balance_book: BTreeMap<PrincipalId, ICPTs>,
    pub blockchain: VecDeque<HashedBlock>,
    transactions: VecDeque<Trans>,
    balance_history: VecDeque<BTreeMap<PrincipalId, ICPTs>>,
}

impl Scribe {
    pub fn new() -> Self {
        Self {
            accounts: VecDeque::new(),
            balance_book: BTreeMap::new(),
            blockchain: VecDeque::new(),
            transactions: VecDeque::new(),
            balance_history: VecDeque::new(),
        }
    }

    pub fn num_accounts(&self) -> u64 {
        self.accounts.len() as u64
    }

    fn time(&self) -> SystemTime {
        //2010.01.01 1:0:0 + int
        std::time::UNIX_EPOCH
            + std::time::Duration::from_millis(1262307600000 + self.blockchain.len() as u64)
        //std::time::SystemTime::now()
    }

    fn next_message(&self) -> Memo {
        Memo(self.next_index() as u64)
    }

    fn next_index(&self) -> BlockHeight {
        self.blockchain.len() as u64
    }

    pub fn gen_accounts(&mut self, num: u64, balance: u64) {
        let num_accounts = self.num_accounts();
        for i in num_accounts..num_accounts + num {
            let amount = rand_val(balance, 0.1);
            self.accounts.push_back(to_uid(i));
            self.balance_book.insert(to_uid(i), ICPTs::zero());
            self.buy(to_uid(i), amount);
        }
    }

    pub fn add_account(&mut self, address: &str, balance: u64) {
        let address =
            PrincipalId::try_from(hex::decode(address).expect("The address should be hex"))
                .expect("Hex was not valid pid");
        self.accounts.push_back(address);
        self.balance_book.insert(address, ICPTs::zero());
        self.buy(address, balance);
    }

    pub fn add_block(&mut self, block: Block) {
        let parent_hash = self.blockchain.back().map(|hb| hb.hash);
        let index = self.next_index();
        self.blockchain
            .push_back(HashedBlock::hash_block(block, parent_hash, index));
    }

    pub fn buy(&mut self, uid: PrincipalId, amount: u64) {
        let amount = ICPTs::from_icpts(amount).unwrap();
        self.transactions.push_back(Trans::Buy(uid, amount));
        *self.balance_book.get_mut(&uid).unwrap() += amount;
        let transaction = Transaction {
            transfer: Transfer::Mint { to: uid, amount },
            memo: self.next_message(),
            created_at: 1,
        };
        let block = Block {
            transaction,
            timestamp: self.time(),
        };
        self.balance_history.push_back(self.balance_book.clone());
        self.add_block(block);
    }

    pub fn sell(&mut self, uid: PrincipalId, amount: u64) {
        let amount = ICPTs::from_icpts(amount).unwrap();
        self.transactions.push_back(Trans::Sell(uid, amount));
        *self.balance_book.get_mut(&uid).unwrap() -= amount;
        let transaction = Transaction {
            transfer: Transfer::Burn { from: uid, amount },
            memo: self.next_message(),
            created_at: 1,
        };
        let block = Block {
            transaction,
            timestamp: self.time(),
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

        let transaction = Transaction {
            transfer: Transfer::Send {
                from: src,
                to: dst,
                amount,
            },
            memo: self.next_message(),
            created_at: 1,
        };
        let block = Block {
            transaction,
            timestamp: self.time(),
        };
        self.balance_history.push_back(self.balance_book.clone());
        self.add_block(block);
    }

    pub fn gen_transaction(&mut self) {
        let account1 = self.accounts[dice_num(self.num_accounts()) as usize];
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
                    let mut account2 = self.accounts[dice_num(self.num_accounts()) as usize];
                    while account1 == account2 {
                        account2 = self.accounts[dice_num(self.num_accounts()) as usize];
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
        ledger.add_block(b.clone()).await.ok();
    }

    let serv_ledger = ledger.clone();
    let serv_req_handler = req_handler.clone();

    let serv =
        Arc::new(RosettaApiServer::new(serv_ledger, serv_req_handler, addr.clone()).unwrap());
    let serv_run = serv.clone();
    actix_rt::spawn(async move {
        println!("Spawning server");
        serv_run.run(false).await.unwrap();
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

// ignored because this takes 30 seconds
// TODO put it somewhere where it can run slowly
#[ignore]
#[actix_rt::test]
async fn simple_ic_test() -> Result<(), String> {
    use canister_test::*;

    let ic = InternetComputer::new()
        .with_subnet(Subnet::new().add_nodes(1))
        .start()
        .await
        .ready()
        .await
        .expect("Not ready");
    let a_subnet_id = ic.subnet_ids().into_iter().next().unwrap();
    let a_subnet = ic.subnet(a_subnet_id);
    let a_node_id = a_subnet.node_ids().into_iter().next().unwrap();
    let a_node = a_subnet.node(a_node_id);
    let url = a_node.api_url();

    let r = a_node.api();

    let path = PathBuf::new()
        .join(env!("CARGO_MANIFEST_DIR"))
        .join("canister");
    let proj = Project::new(path);

    let keypair = {
        let mut rng = OsRng::default(); // use `ChaChaRng::seed_from_u64` for deterministic keys
        ed25519_dalek::Keypair::generate(&mut rng)
    };

    // Generate an arbitrary public key
    let public_key = PublicKey {
        hex_bytes: to_hex(&keypair.public.to_bytes()),
        // This is a guess
        curve_type: CurveType::EDWARDS25519,
    };

    let tester = PrincipalId::new_self_authenticating(&keypair.public.to_bytes()[..]);

    // Install the ledger canister with one account owned by the arbitrary public
    // key

    let recipients: Vec<(PrincipalId, ICPTs)> = Vec::new();

    let canister = proj
        .cargo_bin("ledger-canister")
        .install_(&r, Candid((tester, recipients)))
        .await?;

    // Setup the ledger + request handler
    let client = ledger_client::LedgerClient::create_on_disk(
        url,
        canister.canister_id(),
        Path::new("./data"),
    )
    .await
    .expect("Failed to initialize ledger client");

    let ledger = Arc::new(client);
    let req_handler = RosettaRequestHandler::new(ledger.clone());

    let network_identifier = req_handler.network_id();

    let public_keys = None;

    // A nice to have if you want to get information about a private key
    // let address = req_handler
    //     .construction_derive(ConstructionDeriveRequest {
    //         network_identifier: network_identifier.clone(),
    //         public_key: public_key.clone(),
    //         metadata: None,
    //     })
    //     .await
    //     .unwrap();

    // println!("Pid: {}", tester);
    // println!("Public Key: {}", hex::encode(&keypair.public.to_bytes()));
    // println!("Private Key: {}", hex::encode(&keypair.secret.to_bytes()));
    // println!("Address: {}", address.account_identifier.unwrap().address);

    // Go through the submit workflow
    let metadata = req_handler
        .construction_metadata(ConstructionMetadataRequest {
            network_identifier: network_identifier.clone(),
            options: None,
            public_keys: public_keys.clone(),
        })
        .await
        .unwrap()
        .metadata;

    let operations = operations(
        &Transfer::Send {
            from: tester,
            to: CanisterId::ic_00().get(),
            amount: ICPTs::from_doms(100),
        },
        false,
    )
    .unwrap();

    let ConstructionPayloadsResponse {
        unsigned_transaction,
        payloads,
    } = req_handler
        .construction_payloads(ConstructionPayloadsRequest {
            network_identifier: network_identifier.clone(),
            metadata: Some(metadata),
            operations,
            public_keys: public_keys.clone(),
        })
        .await
        .unwrap();

    // Sign the transactions using the public key
    let signatures = payloads
        .into_iter()
        .map(|p| {
            let bytes = from_hex(p.hex_bytes.clone()).unwrap();
            let signature_bytes = keypair.sign(&bytes).to_bytes();
            let hex_bytes = to_hex(&signature_bytes);
            Signature {
                signing_payload: p,
                public_key: public_key.clone(),
                signature_type: SignatureType::ED25519,
                hex_bytes,
            }
        })
        .collect();

    let signed_transaction = req_handler
        .construction_combine(ConstructionCombineRequest {
            network_identifier: network_identifier.clone(),
            signatures,
            unsigned_transaction,
        })
        .await
        .unwrap()
        .signed_transaction;

    let sent_tid = req_handler
        .construction_submit(ConstructionSubmitRequest {
            network_identifier: network_identifier.clone(),
            signed_transaction,
        })
        .await
        .unwrap()
        .transaction_identifier;

    // Wait for the block to arrive on the ledger
    sleep(Duration::from_secs(5)).await;
    ledger.sync_blocks().await.unwrap();

    // Check the block has arrived on the ledger
    let block = req_handler
        .block(BlockRequest {
            network_identifier,
            block_identifier: PartialBlockIdentifier {
                index: Some(1),
                hash: None,
            },
        })
        .await
        .unwrap()
        .block
        .unwrap();

    let recieved_tid = &block.transactions.first().unwrap().transaction_identifier;

    // Check the transaction hash is the same off and on the ledger
    assert_eq!(&sent_tid, recieved_tid);

    Ok(())
}
