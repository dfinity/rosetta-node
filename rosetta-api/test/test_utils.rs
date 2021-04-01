mod basic_tests;
mod rosetta_cli_tests;
mod store_tests;

use lazy_static::lazy_static;
use url::Url;

use cycles_minting_canister::{CyclesCanisterInitPayload, CREATE_CANISTER_REFUND_FEE};
use ic_canister_client::{Agent, HttpClient, HttpContentType, RequestStub, Sender};
use ic_nns_common::registry::encode_or_panic;
use ic_protobuf::registry::conversion_rate::v1::IcpXdrConversionRateRecord;
use ic_registry_transport::pb::v1::RegistryMutation;
use ic_rosetta_api::models::{
    AccountBalanceRequest, AccountBalanceResponse, ApiError, BlockRequest,
    ConstructionCombineRequest, ConstructionCombineResponse, ConstructionMetadataRequest,
    ConstructionPayloadsRequest, ConstructionPayloadsResponse, ConstructionSubmitRequest,
    ConstructionSubmitResponse, CurveType, Error, NetworkListResponse, NetworkRequest,
    PartialBlockIdentifier, PublicKey, Signature, SignatureType, TransactionIdentifier,
};
use ledger_canister::{
    self, AccountIdentifier, Block, BlockArg, BlockHeight, BlockRes, EncodedBlock, ICPTs,
    LedgerCanisterInitPayload, Memo, SendArgs, Transaction, Transfer, TRANSACTION_FEE,
};
use on_wire::{FromWire, IntoWire};
use tokio::sync::RwLock;

use rand::{rngs::StdRng, RngCore, SeedableRng};
use rand_distr::Distribution;
use thread_local::ThreadLocal;

// TODO remove after disconnecting tests
use async_trait::async_trait;
use dfn_candid::CandidOne;
use dfn_core::CanisterId;
use dfn_protobuf::ProtoBuf;
#[allow(unused_imports)]
use ic_rosetta_api::convert::{
    from_arg, from_hash, from_hex, from_model_account_identifier, from_public_key, internal_error,
    operations, to_arg, to_hash, to_hex, to_model_account_identifier, transaction_id,
    transaction_identifier,
};
use ic_rosetta_api::ledger_client::{self, Balances, Blocks, LedgerAccess, OrdMapBalancesStore};
use ic_rosetta_api::rosetta_server::RosettaApiServer;
use ic_rosetta_api::{store::HashedBlock, RosettaRequestHandler};
use ic_scenario_tests::{
    api::system::builder::Subnet, api::system::handle::IcHandle, system_test::InternetComputer,
};
use ic_types::{
    messages::{HttpCanisterUpdate, HttpReadContent, HttpRequestEnvelope, HttpSubmitContent},
    PrincipalId,
};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::{
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

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

fn rng() -> impl DerefMut<Target = StdRng> {
    RNG.get_or(|| Mutex::new(StdRng::seed_from_u64(SEED)))
        .lock()
        .unwrap()
}

fn rng_set_seed(seed: u64) {
    *RNG.get_or(|| Mutex::new(StdRng::seed_from_u64(seed)))
        .lock()
        .unwrap() = StdRng::seed_from_u64(seed);
}

fn rand_val(val: u64, dev: f64) -> u64 {
    let gen = rand_distr::Normal::new(val as f64, val as f64 * dev).unwrap();
    let ret = gen.sample(&mut *rng()).max(0.0);
    ret as u64
}

fn dice_num(n: u64) -> u64 {
    rng().next_u64() % n
}

pub fn to_uid(id: u64) -> AccountIdentifier {
    PrincipalId::try_from(id.to_be_bytes().to_vec())
        .unwrap()
        .into()
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

    fn agent_client(&self) -> &HttpClient {
        if let Some(ref ic) = self.ic {
            ic.agent_client()
        } else {
            panic!("Agent client not available");
        }
    }

    fn testnet_url(&self) -> &Url {
        panic!("Testnet url not available");
    }

    async fn submit(
        &self,
        submit_request: HttpRequestEnvelope<HttpSubmitContent>,
        _read_state_request: HttpRequestEnvelope<HttpReadContent>,
    ) -> Result<(TransactionIdentifier, Option<BlockHeight>), ApiError> {
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
            block_height,
        } = from_arg(arg.0).unwrap();
        let block_height = block_height.unwrap();

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
            block_height,
            dfn_core::api::now().into(),
        )
        .map_err(internal_error)?;

        let raw_block = block.clone().encode().map_err(internal_error)?;

        let hb = HashedBlock::hash_block(raw_block, parent_hash, index);

        self.submit_queue.write().await.push(hb.clone());

        Ok((transaction_identifier(&block.transaction().hash()), None))
    }

    async fn chain_length(&self) -> BlockHeight {
        match self.blockchain.read().await.synced_to() {
            None => 0,
            Some((_, block_index)) => block_index + 1,
        }
    }
}

pub(crate) fn to_balances(b: BTreeMap<AccountIdentifier, ICPTs>) -> Balances {
    let mut balances = Balances::default();
    balances.store = OrdMapBalancesStore(b.into());
    balances
}

enum Trans {
    Buy(AccountIdentifier, ICPTs),
    Sell(AccountIdentifier, ICPTs),
    Transfer(AccountIdentifier, AccountIdentifier, ICPTs),
}

pub struct Scribe {
    accounts: VecDeque<AccountIdentifier>,
    balance_book: BTreeMap<AccountIdentifier, ICPTs>,
    pub blockchain: VecDeque<HashedBlock>,
    transactions: VecDeque<Trans>,
    balance_history: VecDeque<BTreeMap<AccountIdentifier, ICPTs>>,
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
            AccountIdentifier::from_hex(address).expect("Hex was not valid account identifier");
        self.accounts.push_back(address);
        self.balance_book.insert(address, ICPTs::ZERO);
        self.buy(address, balance);
    }

    pub fn add_block(&mut self, block: EncodedBlock) {
        let parent_hash = self.blockchain.back().map(|hb| hb.hash);
        let index = self.next_index();
        self.blockchain
            .push_back(HashedBlock::hash_block(block, parent_hash, index));
    }

    pub fn buy(&mut self, uid: AccountIdentifier, amount: u64) {
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
        self.add_block(block.encode().unwrap());
    }

    pub fn sell(&mut self, uid: AccountIdentifier, amount: u64) {
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

        self.add_block(block.encode().unwrap());
    }

    pub fn transfer(&mut self, src: AccountIdentifier, dst: AccountIdentifier, amount: u64) {
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
        self.add_block(block.encode().unwrap());
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
        ic_rosetta_api::convert::to_model_account_identifier(&to_uid(uid)),
    );
    msg.block_identifier = block_id;
    let resp = req_handler.account_balance(msg).await?;
    Ok(ICPTs::from_doms(resp.balances[0].value.parse().unwrap()))
}

fn make_user(
    seed: u64,
) -> (
    AccountIdentifier,
    ed25519_dalek::Keypair,
    PublicKey,
    PrincipalId,
) {
    let mut rng = StdRng::seed_from_u64(seed);
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

    let pid = PrincipalId::new_self_authenticating(&public_key_der);
    let user_id: AccountIdentifier = pid.into();

    println!("[test] created user {}", user_id);

    (user_id, keypair, public_key, pid)
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

    let agent_client = HttpClient::new();

    let msg = NetworkRequest::new(req_handler.network_id());
    let http_body = serde_json::to_vec(&msg).unwrap();
    let (res, _) = agent_client
        .send_post_request(
            &format!("http://{}/network/list", addr),
            Some(HttpContentType::JSON),
            Some(http_body),
            None,
        )
        .await
        .unwrap();
    let resp: NetworkListResponse = serde_json::from_slice(&res).unwrap();

    assert_eq!(resp.network_identifiers[0], req_handler.network_id());

    let msg = AccountBalanceRequest::new(
        req_handler.network_id(),
        ic_rosetta_api::convert::to_model_account_identifier(&to_uid(0)),
    );

    let http_body = serde_json::to_vec(&msg).unwrap();
    let (res, _) = agent_client
        .send_post_request(
            &format!("http://{}/account/balance", addr),
            Some(HttpContentType::JSON),
            Some(http_body),
            None,
        )
        .await
        .unwrap();
    let res: AccountBalanceResponse = serde_json::from_slice(&res).unwrap();

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

struct IcState {
    _ic: Arc<IcHandle>,
    url: Url,
    ledger_canister_id: CanisterId,
    user0_id: AccountIdentifier,
    user0_keypair: ed25519_dalek::Keypair,
    user0_public_key: PublicKey,
    cycles_canister_id: Option<CanisterId>,
    //extra_subnet_id: Option<SubnetId>,
}

async fn start_ic(
    with_cycles_canister: bool,
    with_nns_subnet: bool,
    with_extra_subnet: bool,
) -> Result<IcState, String> {
    use canister_test::*;

    println!("[test] starting IC");

    let mut ic_args = InternetComputer::new().with_actix_hack();
    if with_nns_subnet {
        ic_args = ic_args
            .with_nns_subnet(Subnet::new().add_nodes(1))
            .with_initial_mutation(RegistryMutation {
                mutation_type: 0,
                key: ic_registry_keys::XDR_PER_ICP_KEY.as_bytes().to_vec(),
                value: encode_or_panic::<IcpXdrConversionRateRecord>(&IcpXdrConversionRateRecord {
                    timestamp_seconds: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    xdr_permyriad_per_icp: 5_000, // = 0.5 XDR/ICP
                }),
            });
    }
    if with_extra_subnet {
        ic_args = ic_args.with_subnet(Subnet::new().add_nodes(1));
    }
    let ic = ic_args.start().await.ready().await.expect("Not ready");

    let subnet0_id = ic.subnet_ids()[0];
    let subnet0 = ic.subnet(subnet0_id);
    let node_id = subnet0.node_ids().into_iter().next().unwrap();
    let node = subnet0.node(node_id);
    let url = node.api_url();

    let node_api = node.api();

    let path = PathBuf::new()
        .join(env!("CARGO_MANIFEST_DIR"))
        .join("canister");
    let proj = Project::new(path);

    // Generate the minting user
    let (minting_user_id, _minting_user_keypair, _minting_user_public_key, _) = make_user(88);

    // Install the ledger canister with one account owned by the arbitrary public
    // key

    println!(
        "[test] installing ledger-canister {} {:?}",
        minting_user_id, proj.cargo_manifest_dir
    );

    let (user0_id, user0_keypair, user0_public_key, _) = make_user(0);

    let mut initial_values = HashMap::new();
    initial_values.insert(user0_id, ICPTs::from_icpts(10000).unwrap());

    let ledger_canister = proj
        .cargo_bin("ledger-canister")
        .install_(
            &node_api,
            CandidOne(LedgerCanisterInitPayload {
                minting_account: minting_user_id,
                initial_values,
                archive_canister: None,
                max_message_size_bytes: None,
            }),
        )
        .await?;

    let ledger_canister_id = ledger_canister.canister_id();

    println!("[test] installed ledger-canister {}", ledger_canister_id);

    let mut cycles_canister_id = None;

    if with_cycles_canister {
        let path = PathBuf::new()
            .join(env!("CARGO_MANIFEST_DIR"))
            .join("cycles_minting_canister");
        let proj = Project::new(path);

        println!(
            "[test] installing cycles_minting_canister {:?}",
            proj.cargo_manifest_dir
        );

        let cycles_canister = proj
            .cargo_bin("cycles_minting_canister")
            .install_(
                &node_api,
                CyclesCanisterInitPayload {
                    ledger_canister_id,
                    minting_account_id: Some(minting_user_id),
                    nns_subnet_id: subnet0_id,
                },
            )
            .await?;

        cycles_canister_id = Some(cycles_canister.canister_id());

        println!(
            "[test] installed cycles-canister {}",
            cycles_canister_id.unwrap()
        );
    }

    Ok(IcState {
        //extra_subnet_id: ic.subnet_ids().get(1).map(|x| *x),
        _ic: ic,
        url,
        ledger_canister_id,
        user0_id,
        user0_keypair,
        user0_public_key,
        cycles_canister_id,
    })
}

struct TestState {
    req_handler: RosettaRequestHandler,
    agent_client: HttpClient,
    rosetta_addr: String,
    _tmpdir: tempfile::TempDir,
    _ledger_client: Arc<ledger_client::LedgerClient>,
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
        ledger_client::LedgerClient::create_on_disk(
            url,
            canister_id,
            tmpdir.path(),
            None,
            false,
            None,
        )
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

    let agent_client = HttpClient::new();

    Ok(TestState {
        req_handler,
        agent_client,
        rosetta_addr,
        _tmpdir: tmpdir,
        _ledger_client: ledger_client,
        api_server,
        arbiter,
    })
}

async fn prepare_txn(
    state: &TestState,
    transfer: Transfer,
    sender_public_key: PublicKey,
) -> Result<ConstructionPayloadsResponse, String> {
    // Go through the submit workflow
    println!("[test] getting metadata");
    let metadata = state
        .req_handler
        .construction_metadata(ConstructionMetadataRequest {
            network_identifier: state.req_handler.network_id(),
            options: None,
            public_keys: None,
        })
        .await
        .unwrap()
        .metadata;

    println!("[test] constructing payloads");
    let operations = operations(&transfer, false).unwrap();

    let resp: ConstructionPayloadsResponse = state
        .req_handler
        .construction_payloads(ConstructionPayloadsRequest {
            network_identifier: state.req_handler.network_id(),
            metadata: Some(metadata),
            operations,
            public_keys: Some(vec![sender_public_key]),
        })
        .await
        .unwrap();

    Ok(resp)
}

async fn sign_txn(
    state: &TestState,
    keypair: &ed25519_dalek::Keypair,
    public_key: &PublicKey,
    payloads: ConstructionPayloadsResponse,
) -> Result<ConstructionCombineResponse, String> {
    use ed25519_dalek::Signer;
    let signatures = payloads
        .payloads
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

    let resp = state
        .req_handler
        .construction_combine(ConstructionCombineRequest {
            network_identifier: state.req_handler.network_id(),
            signatures,
            unsigned_transaction: payloads.unsigned_transaction,
        })
        .await
        .unwrap();

    Ok(resp)
}

fn assert_canister_error(err: &str, code: u32, text: &str) {
    let err: Error = serde_json::from_str(&err).unwrap();
    assert_eq!(err.code, code);
    let details = err.details.unwrap();
    assert!(details
        .get("error_message")
        .unwrap()
        .as_str()
        .unwrap()
        .contains(text));
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
    signed: ConstructionCombineResponse,
) -> Result<(TransactionIdentifier, Option<BlockHeight>), String> {
    let req = ConstructionSubmitRequest {
        network_identifier: state.req_handler.network_id(),
        signed_transaction: signed.signed_transaction,
    };

    let (body, status) = state
        .agent_client
        .send_post_request(
            &format!("http://{}/construction/submit", state.rosetta_addr),
            Some(HttpContentType::JSON),
            Some(serde_json::to_vec(&req).unwrap()),
            None,
        )
        .await
        .unwrap();

    if !status.is_success() {
        let body = String::from_utf8(body).unwrap();
        println!("[test] HTTP error {}: {}", status, body);
        return Err(body);
    }

    let res: ConstructionSubmitResponse = serde_json::from_slice(&body).unwrap();

    println!("[test] tid = {:?}", res.transaction_identifier);

    Ok((res.transaction_identifier, res.block_index))
}

async fn do_txn(
    state: &TestState,
    keypair: &ed25519_dalek::Keypair,
    public_key: &PublicKey,
    transfer: Transfer,
) -> Result<(TransactionIdentifier, Option<BlockHeight>), String> {
    let payloads = prepare_txn(state, transfer, public_key.clone()).await?;

    let signed = sign_txn(state, &keypair, &public_key, payloads).await?;

    Ok(submit_txn(state, signed).await?)
}

fn have_nodemanager() -> bool {
    which::which("nodemanager").is_ok()
}

#[actix_rt::test]
async fn ic_test_simple() -> Result<(), String> {
    if !have_nodemanager() {
        return Ok(());
    }

    let ic_state = start_ic(false, false, true).await?;

    let state = start_rosetta_server(ic_state.url, ic_state.ledger_canister_id, 8110).await?;

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

    let payloads = prepare_txn(
        &state,
        Transfer::Send {
            from: ic_state.user0_id,
            to: to_uid(1),
            amount: ICPTs::from_doms(100),
            fee: TRANSACTION_FEE,
        },
        ic_state.user0_public_key.clone(),
    )
    .await?;

    // Sign the transactions using the correct public key
    println!("[test] signing transaction");
    let signed = sign_txn(
        &state,
        &ic_state.user0_keypair,
        &ic_state.user0_public_key,
        payloads,
    )
    .await?;

    println!(
        "[test] submitting transaction {:?}",
        signed.signed_transaction
    );
    let (sent_tid, block_index) = submit_txn(&state, signed).await?;

    assert_eq!(block_index, Some(1));

    // Check the block has arrived on the ledger
    println!("[test] checking for block on ledger");
    state
        .req_handler
        .wait_for_transaction(&sent_tid, 0, Instant::now() + Duration::from_secs(30))
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

#[actix_rt::test]
async fn ic_test_wrong_key() -> Result<(), String> {
    if !have_nodemanager() {
        return Ok(());
    }

    let ic_state = start_ic(false, false, true).await?;

    let state = start_rosetta_server(ic_state.url, ic_state.ledger_canister_id, 8111).await?;

    let payloads = prepare_txn(
        &state,
        Transfer::Send {
            from: ic_state.user0_id,
            to: to_uid(1),
            amount: ICPTs::from_doms(100),
            fee: TRANSACTION_FEE,
        },
        ic_state.user0_public_key.clone(),
    )
    .await?;

    println!("[test] signing transaction (wrong key)");
    let (_wrong_uid, wrong_keypair, wrong_public_key, _) = make_user(13);
    let signed = sign_txn(&state, &wrong_keypair, &wrong_public_key, payloads).await?;

    println!(
        "[test] submitting transaction (wrong key) {:?}",
        signed.signed_transaction
    );
    let err = submit_txn(&state, signed).await.unwrap_err();
    assert_ic_error(&err, 740, 403, "does not match the public key");

    state.stop().await;

    Ok(())
}

#[actix_rt::test]
async fn ic_test_wrong_canister_id() -> Result<(), String> {
    if !have_nodemanager() {
        return Ok(());
    }

    let ic_state = start_ic(false, false, true).await?;

    let wrong_canister_id = *DUMMY_CAN_ID;

    let state = start_rosetta_server(ic_state.url, wrong_canister_id, 8112).await?;

    let payloads = prepare_txn(
        &state,
        Transfer::Send {
            from: ic_state.user0_id,
            to: to_uid(1),
            amount: ICPTs::from_doms(100),
            fee: TRANSACTION_FEE,
        },
        ic_state.user0_public_key.clone(),
    )
    .await?;

    // sign the transactions using the correct public key
    println!("[test] signing transaction");
    let signed = sign_txn(
        &state,
        &ic_state.user0_keypair,
        &ic_state.user0_public_key,
        payloads,
    )
    .await?;

    println!(
        "[test] submitting transaction {:?} to wrong canister",
        signed.signed_transaction
    );

    let err = submit_txn(&state, signed).await.unwrap_err();
    assert_ic_error(&err, 740, 404, "Requested canister does not exist");

    state.stop().await;

    Ok(())
}

#[actix_rt::test]
async fn ic_test_no_funds() -> Result<(), String> {
    if !have_nodemanager() {
        return Ok(());
    }

    let ic_state = start_ic(false, false, true).await?;

    let state = start_rosetta_server(ic_state.url, ic_state.ledger_canister_id, 8113).await?;

    let user2 = to_uid(2);

    let (user1, user1_keypair, user1_public_key, _) = make_user(1);

    // Transfer some funds to user1
    do_txn(
        &state,
        &ic_state.user0_keypair,
        &ic_state.user0_public_key,
        Transfer::Send {
            from: ic_state.user0_id,
            to: user1,
            amount: ICPTs::from_doms(137 * 2 + 100),
            fee: TRANSACTION_FEE,
        },
    )
    .await?;

    // Transfer some funds from user1 to user2
    let (_, block2) = do_txn(
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

    assert_eq!(block2, Some(2));

    // Try to transfer more. This should fail with an error from the canister.
    let err = do_txn(
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
    .await
    .unwrap_err();

    assert_canister_error(
        &err,
        750,
        "tried to spend more than the balance of your account",
    );

    state.stop().await;

    Ok(())
}

async fn get_block(
    ic_state: &IcState,
    agent_client: &HttpClient,
    block_index: BlockHeight,
) -> Result<Option<Block>, String> {
    let ledger_agent = Agent::new_with_client(
        agent_client.clone(),
        ic_state.url.clone(),
        Sender::Anonymous,
    );

    let bytes = ledger_agent
        .execute_query(
            &ic_state.ledger_canister_id,
            &"block",
            Some(ProtoBuf(BlockArg(block_index)).into_bytes()?),
        )
        .await?
        .unwrap();
    let resp: Result<BlockRes, String> = ProtoBuf::from_bytes(bytes).map(|c| c.0);

    Ok(resp?.0.map(|b| b.decode().unwrap()))
}

#[actix_rt::test]
async fn ic_test_cycles_canister() -> Result<(), String> {
    if !have_nodemanager() {
        return Ok(());
    }

    let ic_state = start_ic(true, true, true).await?;

    let agent_client = HttpClient::new();

    let (controller_user_id, _controller_user_keypair, _controller_user_public_key, controller_pid) =
        make_user(7);

    println!("[test] controller = {}", controller_user_id);

    println!("[test] creating canister");

    let initial_amount = ICPTs::new(2, 0).unwrap();

    let new_canister_id = cycles_minting_client::CreateCanister {
        client: agent_client.clone(),
        ic_url: ic_state.url.clone(),
        ledger_canister_id: &ic_state.ledger_canister_id,
        cycles_canister_id: &ic_state.cycles_canister_id.unwrap(),
        sender_keypair: &ic_state.user0_keypair,
        sender_subaccount: None,
        amount: initial_amount,
        controller_id: &controller_pid,
    }
    .execute()
    .await
    .unwrap();

    // TODO: check that controller_user_id owns the canister

    /* Check that the funds for the canister creation attempt are burned. */
    let block = get_block(&ic_state, &agent_client, 3).await?.unwrap();

    let txn = block.transaction();

    match txn.transfer {
        Transfer::Burn { amount, .. } => {
            assert_eq!((amount + TRANSACTION_FEE).unwrap(), initial_amount);
        }
        _ => panic!("unexpected block {:?}", txn),
    }

    println!("[test] topping up");

    let top_up_amount = ICPTs::new(4, 0).unwrap();

    cycles_minting_client::TopUpCanister {
        client: agent_client.clone(),
        ic_url: ic_state.url.clone(),
        ledger_canister_id: &ic_state.ledger_canister_id,
        cycles_canister_id: &ic_state.cycles_canister_id.unwrap(),
        sender_keypair: &ic_state.user0_keypair,
        sender_subaccount: None,
        amount: top_up_amount,
        target_canister_id: &new_canister_id,
    }
    .execute()
    .await
    .unwrap();

    /* Check that the funds for the canister top up attempt are burned. */
    let block = get_block(&ic_state, &agent_client, 6).await?.unwrap();

    let txn = block.transaction();

    match txn.transfer {
        Transfer::Burn { amount, .. } => {
            assert_eq!((amount + TRANSACTION_FEE).unwrap(), top_up_amount);
        }
        _ => panic!("unexpected block {:?}", txn),
    }

    println!("[test] done");

    Ok(())
}

#[actix_rt::test]
async fn ic_test_no_subnets() -> Result<(), String> {
    if !have_nodemanager() {
        return Ok(());
    }

    let ic_state = start_ic(true, true, false).await?;

    let agent_client = HttpClient::new();

    let (controller_user_id, _controller_user_keypair, _controller_user_public_key, controller_pid) =
        make_user(7);

    println!("[test] controller = {}", controller_user_id);

    println!("[test] creating canister");

    let send_amount = ICPTs::new(2, 0).unwrap();

    let (err, refund_block) = cycles_minting_client::CreateCanister {
        client: agent_client.clone(),
        ic_url: ic_state.url.clone(),
        ledger_canister_id: &ic_state.ledger_canister_id,
        cycles_canister_id: &ic_state.cycles_canister_id.unwrap(),
        sender_keypair: &ic_state.user0_keypair,
        sender_subaccount: None,
        amount: send_amount,
        controller_id: &controller_pid,
    }
    .execute()
    .await
    .unwrap_err();

    println!("[test] error: {}", err);
    assert!(err.contains("No subnets in which to create a canister"));

    /* Check that the funds for the failed creation attempt are returned to use
     * (minus the fees). */
    let block = get_block(&ic_state, &agent_client, refund_block.unwrap())
        .await?
        .unwrap();

    let txn = block.transaction();

    match txn.transfer {
        Transfer::Send { amount, to, .. } => {
            assert_eq!(
                ((amount + TRANSACTION_FEE).unwrap() + CREATE_CANISTER_REFUND_FEE).unwrap(),
                send_amount
            );
            assert_eq!(to, ic_state.user0_id);
        }
        _ => panic!("unexpected block {:?}", txn),
    }

    let block = get_block(&ic_state, &agent_client, 4).await?.unwrap();

    let txn = block.transaction();

    match txn.transfer {
        Transfer::Burn { amount, .. } => {
            assert_eq!(CREATE_CANISTER_REFUND_FEE, amount);
        }
        _ => panic!("unexpected block {:?}", txn),
    }

    println!("[test] done");

    Ok(())
}
