mod basic_tests;
mod rosetta_cli_tests;
mod store_tests;

use lazy_static::lazy_static;
use reqwest::Url;

use ic_rosetta_api::models::*;
use ic_rosetta_api::store::HashedBlock;
use ic_types::{CanisterId, PrincipalId};
use ledger_canister::{
    self, Block, BlockHeight, ICPTs, LedgerCanisterInitPayload, Memo, SendArgs, Serializable,
    Transaction, Transfer, TRANSACTION_FEE,
};
use tokio::sync::RwLock;

use rand::{
    rngs::{OsRng, StdRng},
    RngCore, SeedableRng,
};
use rand_distr::Distribution;
use thread_local::ThreadLocal;

// TODO remove after disconnecting tests
use async_trait::async_trait;
use dfn_candid::CandidOne;
#[allow(unused_imports)]
use ic_rosetta_api::convert::{
    account_identifier, from_arg, from_hash, from_hex, from_public_key, internal_error, operations,
    principal_id, to_hash, to_hex, transaction_id, transaction_identifier,
};
use ic_rosetta_api::ledger_client::{self, Balances, Blocks, LedgerAccess, OrdMapBalancesStore};
use ic_rosetta_api::rosetta_server::RosettaApiServer;
use ic_rosetta_api::RosettaRequestHandler;
use ic_scenario_tests::{
    api::system::builder::Subnet, api::system::handle::IcHandle, system_test::InternetComputer,
};
use ic_types::messages::{HttpCanisterUpdate, HttpRequestEnvelope, HttpSubmitContent};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::{path::PathBuf, time::Duration, time::SystemTime};

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
                PrincipalId::from_str("5v3p4-iyaaa-aaaaa-qaaaa-cai").unwrap(),
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

    async fn sync_blocks(&self, _stopped: Arc<AtomicBool>) -> Result<(), ApiError> {
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

        let SendArgs {
            memo,
            amount,
            fee,
            from_subaccount,
            to,
            to_subaccount,
            block_height,
        } = from_arg(arg.0).unwrap();
        let block_height = block_height.unwrap();

        let from =
            ledger_canister::account_identifier(from, from_subaccount).map_err(internal_error)?;
        let to = ledger_canister::account_identifier(to, to_subaccount).map_err(internal_error)?;

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
            block_height,
            dfn_core::api::now().into(),
        )
        .map_err(internal_error)?;

        let hb = HashedBlock::hash_block(block, parent_hash, index);

        self.submit_queue.write().await.push(hb.clone());

        Ok(transaction_identifier(&hb.block.transaction().hash()))
    }

    async fn chain_length(&self) -> BlockHeight {
        match self.blockchain.read().await.synced_to() {
            None => 0,
            Some((_, block_index)) => block_index + 1,
        }
    }
}

pub(crate) fn to_balances(b: BTreeMap<PrincipalId, ICPTs>) -> Balances {
    let mut balances = Balances::default();
    balances.store = OrdMapBalancesStore(b.into());
    balances
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

    pub fn new_with_sample_data(num_accounts: u64, num_transactions: u64) -> Self {
        let mut scribe = Scribe::new();

        scribe.gen_accounts(num_accounts, 1_000_000);
        for _i in 0..num_transactions {
            scribe.gen_transaction();
        }
        scribe
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
            self.balance_book.insert(to_uid(i), ICPTs::ZERO);
            self.buy(to_uid(i), amount);
        }
    }

    pub fn add_account(&mut self, address: &str, balance: u64) {
        let address =
            PrincipalId::try_from(hex::decode(address).expect("The address should be hex"))
                .expect("Hex was not valid pid");
        self.accounts.push_back(address);
        self.balance_book.insert(address, ICPTs::ZERO);
        self.buy(address, balance);
    }

    pub fn add_block(&mut self, block: Block) {
        let parent_hash = self.blockchain.back().map(|hb| hb.hash);
        let index = self.next_index();
        self.blockchain
            .push_back(HashedBlock::hash_block(block, parent_hash, index));
    }

    pub fn buy(&mut self, uid: PrincipalId, amount: u64) {
        let amount = ICPTs::from_doms(amount);
        self.transactions.push_back(Trans::Buy(uid, amount));
        *self.balance_book.get_mut(&uid).unwrap() += amount;
        let transaction = Transaction {
            transfer: Transfer::Mint { to: uid, amount },
            memo: self.next_message(),
            created_at: 1,
        };
        let block = Block::new_from_transaction(
            None, // FIXME
            transaction,
            self.time().into(),
        );
        self.balance_history.push_back(self.balance_book.clone());
        self.add_block(block);
    }

    pub fn sell(&mut self, uid: PrincipalId, amount: u64) {
        let amount = ICPTs::from_doms(amount);
        self.transactions.push_back(Trans::Sell(uid, amount));
        *self.balance_book.get_mut(&uid).unwrap() -= amount;
        let transaction = Transaction {
            transfer: Transfer::Burn { from: uid, amount },
            memo: self.next_message(),
            created_at: 1,
        };
        let block = Block::new_from_transaction(
            None, // FIXME
            transaction,
            self.time().into(),
        );
        self.balance_history.push_back(self.balance_book.clone());

        self.add_block(block);
    }

    pub fn transfer(&mut self, src: PrincipalId, dst: PrincipalId, amount: u64) {
        let amount = ICPTs::from_doms(amount);
        self.transactions
            .push_back(Trans::Transfer(src, dst, amount));
        *self.balance_book.get_mut(&src).unwrap() -= (amount + TRANSACTION_FEE).unwrap();
        *self.balance_book.get_mut(&dst).unwrap() += amount;

        let transaction = Transaction {
            transfer: Transfer::Send {
                from: src,
                to: dst,
                amount,
                fee: TRANSACTION_FEE,
            },
            memo: self.next_message(),
            created_at: 1,
        };
        let block = Block::new_from_transaction(
            None, // FIXME
            transaction,
            self.time().into(),
        );
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
                if *self.balance_book.get(&account1).unwrap()
                    >= (amount_ + TRANSACTION_FEE).unwrap()
                {
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

fn make_user() -> (PrincipalId, ed25519_dalek::Keypair, PublicKey) {
    let mut rng = OsRng::default(); // use `ChaChaRng::seed_from_u64` for deterministic keys

    let keypair = ed25519_dalek::Keypair::generate(&mut rng);

    let public_key = PublicKey {
        hex_bytes: to_hex(&keypair.public.to_bytes()),
        // This is a guess
        curve_type: CurveType::EDWARDS25519,
    };

    let public_key_der =
        ic_canister_client::ed25519_public_key_to_der(keypair.public.to_bytes().to_vec());

    assert_eq!(
        from_public_key(&public_key).unwrap(),
        keypair.public.to_bytes()
    );

    let user_id = PrincipalId::new_self_authenticating(&public_key_der);

    println!("[test] created user {}", user_id);

    (user_id, keypair, public_key)
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

async fn start_ic() -> Result<
    (
        Arc<IcHandle>,
        Url,
        CanisterId,
        PrincipalId,
        ed25519_dalek::Keypair,
        PublicKey,
    ),
    String,
> {
    use canister_test::*;

    println!("[test] starting IC");

    let ic = InternetComputer::new()
        .with_subnet(Subnet::new().add_nodes(1))
        .with_actix_hack()
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

    // Generate an arbitrary public key
    let (minting_id, _minting_keypair, _minting_public_key) = make_user();

    // Install the ledger canister with one account owned by the arbitrary public
    // key

    println!(
        "[test] installing ledger-canister {} {:?}",
        minting_id, proj.cargo_manifest_dir
    );

    let (user0, user0_keypair, user0_public_key) = make_user();

    let mut initial_values = HashMap::new();
    initial_values.insert(user0, ICPTs::from_icpts(10000).unwrap());

    let canister = proj
        .cargo_bin("ledger-canister")
        .install_(
            &r,
            CandidOne(LedgerCanisterInitPayload {
                minting_account: minting_id,
                initial_values,
                archive_canister: None,
                max_message_size_bytes: None,
            }),
        )
        .await?;

    Ok((
        ic,
        url,
        canister.canister_id(),
        user0,
        user0_keypair,
        user0_public_key,
    ))
}

struct TestState {
    req_handler: RosettaRequestHandler,
    reqwest_client: reqwest::Client,
    rosetta_addr: String,
    _tmpdir: tempfile::TempDir,
    ledger_client: Arc<ledger_client::LedgerClient>,
    api_server: Arc<RosettaApiServer>,
    arbiter: actix_rt::Arbiter,
}

impl TestState {
    async fn stop(mut self) {
        self.api_server.stop().await;
        self.arbiter.stop();
        self.arbiter.join().unwrap();
    }
}

async fn start_rosetta_server(
    url: Url,
    canister_id: CanisterId,
    rosetta_port: u16,
) -> Result<TestState, String> {
    let tmpdir = create_tmp_dir();
    println!("[test] using {} for storage", tmpdir.path().display());

    // Setup the ledger + request handler
    println!("[test] starting rosetta server");

    let ledger_client = Arc::new(
        ledger_client::LedgerClient::create_on_disk(url, canister_id, tmpdir.path(), None, false)
            .await
            .expect("Failed to initialize ledger client"),
    );

    let req_handler = RosettaRequestHandler::new(ledger_client.clone());

    // FIXME: select unused port (use TcpPortAllocator)
    let rosetta_addr = format!("127.0.0.1:{}", rosetta_port);

    let api_server = Arc::new(
        RosettaApiServer::new(
            ledger_client.clone(),
            req_handler.clone(),
            rosetta_addr.clone(),
        )
        .unwrap(),
    );

    let api_server_run = api_server.clone();

    let arbiter = actix_rt::Arbiter::new();
    arbiter.send(Box::pin(async move {
        log::info!("Spawning server");
        api_server_run.run(false, false).await.unwrap();
        log::info!("Server thread done");
    }));

    let reqwest_client = reqwest::Client::new();

    Ok(TestState {
        req_handler,
        reqwest_client,
        rosetta_addr,
        _tmpdir: tmpdir,
        ledger_client,
        api_server,
        arbiter,
    })
}

async fn prepare_txn(
    state: &TestState,
    transfer: Transfer,
) -> Result<(String, Vec<ic_rosetta_api::models::SigningPayload>), String> {
    let public_keys = None;

    // Go through the submit workflow
    println!("[test] getting metadata");
    let metadata = state
        .req_handler
        .construction_metadata(ConstructionMetadataRequest {
            network_identifier: state.req_handler.network_id(),
            options: None,
            public_keys: public_keys.clone(),
        })
        .await
        .unwrap()
        .metadata;

    println!("[test] constructing payloads");
    let operations = operations(&transfer, false).unwrap();

    let ConstructionPayloadsResponse {
        unsigned_transaction,
        payloads,
    } = state
        .req_handler
        .construction_payloads(ConstructionPayloadsRequest {
            network_identifier: state.req_handler.network_id(),
            metadata: Some(metadata),
            operations,
            public_keys: public_keys.clone(),
        })
        .await
        .unwrap();

    Ok((unsigned_transaction, payloads))
}

async fn sign_txn(
    state: &TestState,
    payloads: Vec<ic_rosetta_api::models::SigningPayload>,
    keypair: &ed25519_dalek::Keypair,
    public_key: &PublicKey,
    unsigned_transaction: String,
) -> Result<String, String> {
    let signatures = payloads
        .into_iter()
        .map(|p| {
            let bytes = from_hex(&p.hex_bytes).unwrap();
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

    let signed_transaction = state
        .req_handler
        .construction_combine(ConstructionCombineRequest {
            network_identifier: state.req_handler.network_id(),
            signatures,
            unsigned_transaction,
        })
        .await
        .unwrap()
        .signed_transaction;

    Ok(signed_transaction)
}

fn assert_ic_error(err: &str, code: u32, ic_http_status: u64, text: &str) {
    let err: Error = serde_json::from_str(&err).unwrap();
    assert_eq!(err.code, code);
    let details = err.details.unwrap();
    assert_eq!(
        details.get("ic_http_status").unwrap().as_u64().unwrap(),
        ic_http_status
    );
    assert!(details
        .get("error_message")
        .unwrap()
        .as_str()
        .unwrap()
        .contains(text));
}

async fn submit_txn(
    state: &TestState,
    signed_transaction: String,
) -> Result<TransactionIdentifier, String> {
    let req = ConstructionSubmitRequest {
        network_identifier: state.req_handler.network_id(),
        signed_transaction,
    };

    let request = state
        .reqwest_client
        .post(&format!(
            "http://{}/construction/submit",
            state.rosetta_addr
        ))
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&req).unwrap());

    let res = request.send().await.unwrap();

    let status = res.status();

    if !status.is_success() {
        let body = res.text().await.unwrap();
        println!("[test] HTTP error {}: {}", status, body);
        return Err(body);
    }

    let res: ConstructionSubmitResponse = serde_json::from_str(&res.text().await.unwrap()).unwrap();

    println!("[test] tid = {:?}", res.transaction_identifier);

    Ok(res.transaction_identifier)
}

async fn do_txn(
    state: &TestState,
    keypair: &ed25519_dalek::Keypair,
    public_key: &PublicKey,
    transfer: Transfer,
) -> Result<TransactionIdentifier, String> {
    let (unsigned_transaction, payloads) = prepare_txn(state, transfer).await?;

    let signed_transaction =
        sign_txn(state, payloads, &keypair, &public_key, unsigned_transaction).await?;

    Ok(submit_txn(state, signed_transaction).await?)
}

// ignored because this takes 30 seconds
// TODO put it somewhere where it can run slowly
#[ignore]
#[actix_rt::test]
async fn ic_test_simple() -> Result<(), String> {
    let (_ic, url, canister_id, user0, user0_keypair, user0_public_key) = start_ic().await?;

    let state = start_rosetta_server(url, canister_id, 8110).await?;

    // A nice to have if you want to get information about a private key
    // let address = req_handler
    //     .construction_derive(ConstructionDeriveRequest {
    //         network_identifier: network_identifier.clone(),
    //         public_key: public_key.clone(),
    //         metadata: None,
    //     })
    //     .await
    //     .unwrap();

    // println!("Pid: {}", minting_id);
    // println!("Public Key: {}", hex::encode(&keypair.public.to_bytes()));
    // println!("Private Key: {}", hex::encode(&keypair.secret.to_bytes()));
    // println!("Address: {}", address.account_identifier.unwrap().address);

    let (unsigned_transaction, payloads) = prepare_txn(
        &state,
        Transfer::Send {
            from: user0,
            to: to_uid(1),
            amount: ICPTs::from_doms(100),
            fee: TRANSACTION_FEE,
        },
    )
    .await?;

    // Sign the transactions using the correct public key
    println!("[test] signing transaction");
    let signed_transaction = sign_txn(
        &state,
        payloads,
        &user0_keypair,
        &user0_public_key,
        unsigned_transaction,
    )
    .await?;

    println!("[test] submitting transaction {:?}", signed_transaction);
    let sent_tid = submit_txn(&state, signed_transaction).await?;

    // Check the block has arrived on the ledger
    println!("[test] checking for block on ledger");
    state
        .req_handler
        .wait_for_transaction(&sent_tid, 0, SystemTime::now() + Duration::from_secs(30))
        .await
        .unwrap();

    let block = state
        .req_handler
        .block(BlockRequest {
            network_identifier: state.req_handler.network_id(),
            block_identifier: PartialBlockIdentifier {
                index: Some(1),
                hash: None,
            },
        })
        .await
        .unwrap()
        .block
        .unwrap();

    let received_tid = &block.transactions.first().unwrap().transaction_identifier;

    // Check the transaction hash is the same off and on the ledger
    assert_eq!(&sent_tid, received_tid);

    state.stop().await;

    Ok(())
}

#[ignore]
#[actix_rt::test]
async fn ic_test_wrong_key() -> Result<(), String> {
    let (_ic, url, canister_id, user0, _user0_keypair, _user0_public_key) = start_ic().await?;

    let state = start_rosetta_server(url, canister_id, 8111).await?;

    let (unsigned_transaction, payloads) = prepare_txn(
        &state,
        Transfer::Send {
            from: user0,
            to: to_uid(1),
            amount: ICPTs::from_doms(100),
            fee: TRANSACTION_FEE,
        },
    )
    .await?;

    println!("[test] signing transaction (wrong key)");
    let (_wrong_uid, wrong_keypair, wrong_public_key) = make_user();
    let signed_transaction = sign_txn(
        &state,
        payloads.clone(),
        &wrong_keypair,
        &wrong_public_key,
        unsigned_transaction.clone(),
    )
    .await?;

    println!(
        "[test] submitting transaction (wrong key) {:?}",
        signed_transaction
    );
    let err = submit_txn(&state, signed_transaction).await.unwrap_err();
    assert_ic_error(&err, 740, 403, "does not match the public key");

    state.stop().await;

    Ok(())
}

#[ignore]
#[actix_rt::test]
async fn ic_test_wrong_canister_id() -> Result<(), String> {
    let (_ic, url, _canister_id, user0, user0_keypair, user0_public_key) = start_ic().await?;

    let wrong_canister_id = *DUMMY_CAN_ID;

    let state = start_rosetta_server(url, wrong_canister_id, 8112).await?;

    let (unsigned_transaction, payloads) = prepare_txn(
        &state,
        Transfer::Send {
            from: user0,
            to: to_uid(1),
            amount: ICPTs::from_doms(100),
            fee: TRANSACTION_FEE,
        },
    )
    .await?;

    // sign the transactions using the correct public key
    println!("[test] signing transaction");
    let signed_transaction = sign_txn(
        &state,
        payloads,
        &user0_keypair,
        &user0_public_key,
        unsigned_transaction,
    )
    .await?;

    println!(
        "[test] submitting transaction {:?} to wrong canister",
        signed_transaction
    );

    let err = submit_txn(&state, signed_transaction).await.unwrap_err();
    assert_ic_error(&err, 740, 404, "Requested canister does not exist");

    state.stop().await;

    Ok(())
}

#[ignore]
#[actix_rt::test]
async fn ic_test_no_funds() -> Result<(), String> {
    let (_ic, url, canister_id, user0, user0_keypair, user0_public_key) = start_ic().await?;

    let state = start_rosetta_server(url, canister_id, 8113).await?;

    let user2 = to_uid(2);

    let (user1, user1_keypair, user1_public_key) = make_user();

    // Transfer some funds to user1
    do_txn(
        &state,
        &user0_keypair,
        &user0_public_key,
        Transfer::Send {
            from: user0,
            to: user1,
            amount: ICPTs::from_doms(137 * 2 + 100),
            fee: TRANSACTION_FEE,
        },
    )
    .await?;

    // Transfer some funds from user1 to user2
    let txn2 = do_txn(
        &state,
        &user1_keypair,
        &user1_public_key,
        Transfer::Send {
            from: user1,
            to: user2,
            amount: ICPTs::from_doms(90),
            fee: TRANSACTION_FEE,
        },
    )
    .await?;

    // Sync.
    state
        .req_handler
        .wait_for_transaction(&txn2, 0, SystemTime::now() + Duration::from_secs(30))
        .await
        .unwrap();

    let prev_chain_length = state.ledger_client.chain_length().await;
    assert_eq!(prev_chain_length, 3);

    // Try to transfer more. This block should not appear: the
    // canister will not apply the block, but since we can't get error
    // messages from the canister, we have no way to tell.
    let txn3 = do_txn(
        &state,
        &user1_keypair,
        &user1_public_key,
        Transfer::Send {
            from: user1,
            to: user2,
            amount: ICPTs::from_doms(11),
            fee: TRANSACTION_FEE,
        },
    )
    .await?;

    assert_eq!(
        state
            .req_handler
            .wait_for_transaction(
                &txn3,
                prev_chain_length,
                SystemTime::now() + Duration::from_secs(10)
            )
            .await
            .unwrap(),
        None
    );

    let new_chain_length = state.ledger_client.chain_length().await;

    assert_eq!(prev_chain_length, new_chain_length);

    state.stop().await;

    Ok(())
}
