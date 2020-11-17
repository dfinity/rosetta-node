use lazy_static::lazy_static;
use reqwest::Url;

use crate::ledger_canister::{self, Block, CanisterID, Hash, HashedBlock, Transaction, UserID};
use crate::models::*;
use ic_types::{CanisterId, PrincipalId};

use rand::{rngs::StdRng, RngCore, SeedableRng};
use rand_distr::Distribution;
use thread_local::ThreadLocal;

// TODO remove after disconnecting tests
#[allow(unused_imports)]
use crate::convert::{from_hash, to_hash};
use crate::ledger_client::{Blocks, LedgerAccess};
use std::collections::{BTreeMap, VecDeque};
use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

// TODO remove after disconnecting tests
#[allow(unused_imports)]
use ic_scenario_tests::{
    api::system::builder::Subnet, api::system::handle::IcHandle, system_test::InternetComputer,
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

pub fn to_uid(id: u64) -> UserID {
    UserID(id.to_be_bytes().to_vec())
}

fn network_id(ledger: &impl LedgerAccess) -> NetworkIdentifier {
    let net_id = hex::encode(ledger.ledger_canister_id().get().into_vec());
    NetworkIdentifier::new("Internet Computer".to_string(), net_id)
}

lazy_static! {
    static ref DUMMY_CAN_ID: CanisterID = {
        CanisterID(vec![1,2,3])
        //CanisterId::new(PrincipalId::try_from(&[0, 0, 0, 0, 0, 0, 4, 210][..]).unwrap()).unwrap()
    };
}

pub struct TestLedger {
    blockchain: Blocks,
    canister_id: CanisterId,
    ic: Option<Arc<IcHandle>>,
}

impl TestLedger {
    pub fn new() -> Self {
        Self {
            blockchain: Blocks::default(),
            canister_id: CanisterId::new(
                PrincipalId::try_from(&[0, 0, 0, 0, 0, 0, 4, 210][..]).unwrap(),
            )
            .unwrap(),
            ic: None,
        }
    }

    pub fn with_ic(mut self, ic: Arc<IcHandle>) -> Self {
        self.ic = Some(ic);
        self
    }
}

impl Default for TestLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl LedgerAccess for TestLedger {
    fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a> {
        Box::new(&self.blockchain)
    }

    fn sync_blocks(&mut self, _tip: Option<Hash>) -> Result<(), ApiError> {
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
}

enum Trans {
    Buy(UserID, u64),
    Sell(UserID, u64),
    Transfer(UserID, UserID, u64),
}

pub struct Scribe {
    balance_book: BTreeMap<UserID, u64>,
    pub blockchain: VecDeque<HashedBlock>,
    transactions: VecDeque<Trans>,
    balance_history: VecDeque<BTreeMap<UserID, u64>>,
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

    fn next_transaction_id(&self) -> ledger_canister::Hash {
        self.blockchain.len() as u64
    }

    pub fn gen_accounts(&mut self, num: u64, balance: u64) {
        let num_accounts = self.balance_book.len() as u64;
        for i in num_accounts..num_accounts + num {
            let amount = rand_val(balance, 0.1);
            self.balance_book.insert(to_uid(i), 0);
            self.buy(to_uid(i), amount);
        }
    }

    pub fn add_block(&mut self, block: Block) {
        self.blockchain.push_back(HashedBlock::hash_block(block));
    }

    pub fn buy(&mut self, uid: UserID, amount: u64) {
        self.transactions.push_back(Trans::Buy(uid.clone(), amount));
        *self.balance_book.get_mut(&uid).unwrap() += amount;
        let block = Block {
            payment: Transaction::Mint {
                from: DUMMY_CAN_ID.clone(),
                to: uid,
                amount,
            },
            timestamp: self.time(),
            transaction_id: self.next_transaction_id(),
            index: self.next_transaction_id() as usize,
            parent_hash: self.blockchain.back().map(|hb| hb.hash),
        };
        self.balance_history.push_back(self.balance_book.clone());
        self.add_block(block);
    }

    pub fn sell(&mut self, uid: UserID, amount: u64) {
        self.transactions
            .push_back(Trans::Sell(uid.clone(), amount));
        *self.balance_book.get_mut(&uid).unwrap() -= amount;
        let block = Block {
            payment: Transaction::Burn {
                from: uid,
                to: DUMMY_CAN_ID.clone(),
                amount,
            },
            timestamp: self.time(),
            transaction_id: self.next_transaction_id(),
            index: self.next_transaction_id() as usize,
            parent_hash: self.blockchain.back().map(|hb| hb.hash),
        };
        self.balance_history.push_back(self.balance_book.clone());
        self.add_block(block);
    }

    pub fn transfer(&mut self, src: UserID, dst: UserID, amount: u64) {
        self.transactions
            .push_back(Trans::Transfer(src.clone(), dst.clone(), amount));
        *self.balance_book.get_mut(&src).unwrap() -= amount;
        *self.balance_book.get_mut(&dst).unwrap() += amount;

        let block = Block {
            payment: Transaction::Send {
                from: src,
                to: dst,
                amount,
            },
            timestamp: self.time(),
            transaction_id: self.next_transaction_id(),
            index: self.next_transaction_id() as usize,
            parent_hash: self.blockchain.back().map(|hb| hb.hash),
        };
        self.balance_history.push_back(self.balance_book.clone());
        self.add_block(block);
    }

    pub fn gen_transaction(&mut self) {
        let account1 = to_uid(dice_num(self.num_accounts()));
        let amount = rand_val((1 + dice_num(3)) * 100, 0.1);
        match dice_num(4) {
            0 => self.buy(account1, amount),
            1 => {
                if *self.balance_book.get(&account1).unwrap() >= amount {
                    self.sell(account1, amount);
                } else {
                    self.buy(account1, amount);
                }
            }
            _ => {
                if *self.balance_book.get(&account1).unwrap() >= amount {
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
    ledger: &mut impl LedgerAccess,
    height: Option<usize>,
    uid: u64,
) -> Result<u64, ApiError> {
    let block_id = height.map(|h| PartialBlockIdentifier {
        index: Some(h as i64),
        hash: None,
    });
    let mut msg = AccountBalanceRequest::new(
        network_id(ledger),
        crate::convert::account_identifier(&to_uid(uid)),
    );
    msg.block_identifier = block_id;
    let resp = crate::account_balance(msg, ledger).await?;
    Ok(resp.balances[0].value.parse().unwrap())
}

#[actix_rt::test]
async fn balances_test() {
    let mut ledger = TestLedger::new();
    let mut scribe = Scribe::new();

    scribe.gen_accounts(2, 1_000_000);
    for b in &scribe.blockchain {
        ledger.blockchain.add_block(b.clone()).ok();
    }

    assert_eq!(
        get_balance(&mut ledger, None, 0).await.unwrap(),
        *scribe.balance_book.get(&to_uid(0)).unwrap()
    );
    assert_eq!(
        get_balance(&mut ledger, None, 1).await.unwrap(),
        *scribe.balance_book.get(&to_uid(1)).unwrap()
    );

    scribe.buy(to_uid(0), 10);
    ledger
        .blockchain
        .add_block(scribe.blockchain.back().unwrap().clone())
        .ok();
    assert_eq!(
        get_balance(&mut ledger, None, 0).await.unwrap(),
        *scribe.balance_book.get(&to_uid(0)).unwrap()
    );
    assert_eq!(
        get_balance(&mut ledger, None, 1).await.unwrap(),
        *scribe.balance_book.get(&to_uid(1)).unwrap()
    );

    let after_buy_balance = *scribe.balance_book.get(&to_uid(0)).unwrap();

    scribe.sell(to_uid(0), 100);
    ledger
        .blockchain
        .add_block(scribe.blockchain.back().unwrap().clone())
        .ok();
    assert_eq!(
        get_balance(&mut ledger, None, 0).await.unwrap(),
        *scribe.balance_book.get(&to_uid(0)).unwrap()
    );
    assert_eq!(
        get_balance(&mut ledger, None, 1).await.unwrap(),
        *scribe.balance_book.get(&to_uid(1)).unwrap()
    );

    scribe.transfer(to_uid(0), to_uid(1), 1000);
    ledger
        .blockchain
        .add_block(scribe.blockchain.back().unwrap().clone())
        .ok();
    assert_eq!(
        get_balance(&mut ledger, None, 0).await.unwrap(),
        *scribe.balance_book.get(&to_uid(0)).unwrap()
    );
    assert_eq!(
        get_balance(&mut ledger, None, 1).await.unwrap(),
        *scribe.balance_book.get(&to_uid(1)).unwrap()
    );

    // and test if we can access arbitrary block
    assert_eq!(
        get_balance(&mut ledger, Some(2), 0).await.unwrap(),
        after_buy_balance
    );
}

#[actix_rt::test]
async fn blocks_test() {
    let mut ledger = TestLedger::new();
    let mut scribe = Scribe::new();
    let num_transactions: usize = 100;
    let num_accounts = 10;

    scribe.gen_accounts(num_accounts, 1_000_000);
    for _i in 0..num_transactions {
        scribe.gen_transaction();
    }

    for b in &scribe.blockchain {
        ledger.blockchain.add_block(b.clone()).ok();
    }

    let h = num_accounts as usize + 17;
    for i in 0..num_accounts {
        assert_eq!(
            get_balance(&mut ledger, Some(h), i).await.unwrap(),
            *scribe.balance_history[h].get(&to_uid(i)).unwrap()
        );
    }

    // fetch by index
    let block_id = PartialBlockIdentifier {
        index: Some(h as i64),
        hash: None,
    };
    let msg = BlockRequest::new(network_id(&ledger), block_id);
    let resp = crate::block(msg, &ledger).await.unwrap();

    let block = resp.block.unwrap();
    assert_eq!(
        to_hash(&block.block_identifier.hash).unwrap(),
        scribe.blockchain[h].hash
    );

    // fetch by hash
    let block_id = PartialBlockIdentifier {
        index: None,
        hash: Some(from_hash(&scribe.blockchain[h].hash)),
    };
    let msg = BlockRequest::new(network_id(&ledger), block_id);
    let resp = crate::block(msg, &ledger).await.unwrap();
    let block = resp.block.unwrap();

    assert_eq!(block.block_identifier.index, h as i64);
    assert_eq!(block.parent_block_identifier.index, h as i64 - 1);
    assert_eq!(
        to_hash(&block.parent_block_identifier.hash).unwrap(),
        scribe.blockchain[h - 1].hash
    );

    // now fetch a transaction
    let trans = block.transactions[0].clone();

    let block_id = BlockIdentifier {
        index: h as i64,
        hash: from_hash(&scribe.blockchain[h].hash),
    };
    let msg = BlockTransactionRequest::new(
        network_id(&ledger),
        block_id,
        trans.transaction_identifier.clone(),
    );
    let resp = crate::block_transaction(msg, &ledger).await.unwrap();

    assert_eq!(
        trans.transaction_identifier.hash,
        resp.transaction.transaction_identifier.hash
    );
}

// TODO
#[ignore]
#[actix_rt::test]
async fn simple_ic_test() {
    let ic = InternetComputer::new()
        .with_subnet(Subnet::new().add_nodes(5))
        .start()
        .await;
    let ic = ic.ready().await.expect("Not ready yet");
    let _ledger = TestLedger::new().with_ic(ic);
}

#[actix_rt::test]
async fn hello_world() {
    let mut scribe = Scribe::new();
    let num_transactions: usize = 1000;
    let num_accounts = 100;

    scribe.gen_accounts(num_accounts, 1_000_000);
    for _i in 0..num_transactions {
        scribe.gen_transaction();
    }

    let mut ledger = TestLedger::new();
    for b in &scribe.blockchain {
        ledger.blockchain.add_block(b.clone()).ok();
    }

    assert_eq!(
        scribe.blockchain.len(),
        ledger.blockchain.last().unwrap().unwrap().block.index + 1
    );

    for i in 0..num_accounts {
        assert_eq!(
            get_balance(&mut ledger, None, i).await.unwrap(),
            *scribe.balance_book.get(&to_uid(i)).unwrap()
        );
    }

    let msg = NetworkRequest::new(network_id(&ledger));
    let res = crate::network_status(msg, &ledger).await;
    println!("Network status: {:?}", res);

    //let msg = MetadataRequest::new();
    //let resp = crate::network_list(msg,)

    let msg = NetworkRequest::new(network_id(&ledger));
    let res = crate::network_options(msg, &ledger).await;
    println!("Network options: {:?}", res);

    let msg = NetworkRequest::new(network_id(&ledger));
    let res = crate::mempool(msg, &ledger).await;
    println!("Mempool : {:?}", res);

    let msg = MempoolTransactionRequest::new(
        network_id(&ledger),
        TransactionIdentifier::new("hello there".to_string()),
    );
    let res = crate::mempool_transaction(msg, &ledger).await;
    println!("Mempool transaction : {:?}", res);

    let msg = AccountBalanceRequest::new(
        network_id(&ledger),
        crate::convert::account_identifier(&to_uid(0)),
    );
    let res = crate::account_balance(msg, &ledger).await;
    println!("Account balance : {:?}", res);
    println!(
        "From balance book: {}",
        scribe.balance_book.get(&to_uid(0)).unwrap()
    );
}
