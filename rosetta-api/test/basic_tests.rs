use super::*;

use ic_rosetta_api::models::*;

use ic_rosetta_api::convert::{from_hash, to_hash};
use ic_rosetta_api::ledger_client::LedgerAccess;
use ic_rosetta_api::RosettaRequestHandler;

use std::sync::Arc;

#[actix_rt::test]
async fn smoke_test() {
    let mut scribe = Scribe::new();
    let num_transactions: usize = 1000;
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

    assert_eq!(
        scribe.blockchain.len() as u64,
        ledger.read_blocks().last().unwrap().unwrap().block.index + 1
    );

    for i in 0..num_accounts {
        assert_eq!(
            get_balance(&req_handler, None, i).await.unwrap(),
            *scribe.balance_book.get(&to_uid(i)).unwrap()
        );
    }

    let msg = NetworkRequest::new(req_handler.network_id());
    let res = req_handler.network_status(msg).await;
    println!("Network status: {:?}", res);

    //let msg = MetadataRequest::new();
    //let resp = ic_rosetta_api::network_list(msg,)

    let msg = NetworkRequest::new(req_handler.network_id());
    let res = req_handler.network_options(msg).await;
    println!("Network options: {:?}", res);

    let msg = NetworkRequest::new(req_handler.network_id());
    let res = req_handler.mempool(msg).await;
    println!("Mempool : {:?}", res);

    let msg = MempoolTransactionRequest::new(
        req_handler.network_id(),
        TransactionIdentifier::new("hello there".to_string()),
    );
    let res = req_handler.mempool_transaction(msg).await;
    println!("Mempool transaction : {:?}", res);

    let msg = AccountBalanceRequest::new(
        req_handler.network_id(),
        ic_rosetta_api::convert::account_identifier(&to_uid(0)),
    );
    let res = req_handler.account_balance(msg).await;
    println!("Account balance : {:?}", res);
    println!(
        "From balance book: {}",
        scribe.balance_book.get(&to_uid(0)).unwrap()
    );
}

#[actix_rt::test]
async fn blocks_test() {
    let ledger = Arc::new(TestLedger::new());
    let req_handler = RosettaRequestHandler::new(ledger.clone());
    let mut scribe = Scribe::new();
    let num_transactions: usize = 100;
    let num_accounts = 10;

    scribe.gen_accounts(num_accounts, 1_000_000);
    for _i in 0..num_transactions {
        scribe.gen_transaction();
    }

    for b in &scribe.blockchain {
        ledger.add_block(b.clone()).ok();
    }

    let h = num_accounts as usize + 17;
    for i in 0..num_accounts {
        assert_eq!(
            get_balance(&req_handler, Some(h), i).await.unwrap(),
            *scribe.balance_history[h].get(&to_uid(i)).unwrap()
        );
    }

    // fetch by index
    let block_id = PartialBlockIdentifier {
        index: Some(h as i64),
        hash: None,
    };
    let msg = BlockRequest::new(req_handler.network_id(), block_id);
    let resp = req_handler.block(msg).await.unwrap();

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
    let msg = BlockRequest::new(req_handler.network_id(), block_id);
    let resp = req_handler.block(msg).await.unwrap();
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
        req_handler.network_id(),
        block_id,
        trans.transaction_identifier.clone(),
    );
    let resp = req_handler.block_transaction(msg).await.unwrap();

    assert_eq!(
        trans.transaction_identifier.hash,
        resp.transaction.transaction_identifier.hash
    );
}

#[actix_rt::test]
async fn balances_test() {
    let ledger = Arc::new(TestLedger::new());
    let req_handler = RosettaRequestHandler::new(ledger.clone());
    let mut scribe = Scribe::new();

    scribe.gen_accounts(2, 1_000_000);
    for b in &scribe.blockchain {
        ledger.add_block(b.clone()).ok();
    }

    assert_eq!(
        get_balance(&req_handler, None, 0).await.unwrap(),
        *scribe.balance_book.get(&to_uid(0)).unwrap()
    );
    assert_eq!(
        get_balance(&req_handler, None, 1).await.unwrap(),
        *scribe.balance_book.get(&to_uid(1)).unwrap()
    );

    scribe.buy(to_uid(0), 10);
    ledger
        .add_block(scribe.blockchain.back().unwrap().clone())
        .ok();
    assert_eq!(
        get_balance(&req_handler, None, 0).await.unwrap(),
        *scribe.balance_book.get(&to_uid(0)).unwrap()
    );
    assert_eq!(
        get_balance(&req_handler, None, 1).await.unwrap(),
        *scribe.balance_book.get(&to_uid(1)).unwrap()
    );

    let after_buy_balance = *scribe.balance_book.get(&to_uid(0)).unwrap();

    scribe.sell(to_uid(0), 100);
    ledger
        .add_block(scribe.blockchain.back().unwrap().clone())
        .ok();
    assert_eq!(
        get_balance(&req_handler, None, 0).await.unwrap(),
        *scribe.balance_book.get(&to_uid(0)).unwrap()
    );
    assert_eq!(
        get_balance(&req_handler, None, 1).await.unwrap(),
        *scribe.balance_book.get(&to_uid(1)).unwrap()
    );

    scribe.transfer(to_uid(0), to_uid(1), 1000);
    ledger
        .add_block(scribe.blockchain.back().unwrap().clone())
        .ok();
    assert_eq!(
        get_balance(&req_handler, None, 0).await.unwrap(),
        *scribe.balance_book.get(&to_uid(0)).unwrap()
    );
    assert_eq!(
        get_balance(&req_handler, None, 1).await.unwrap(),
        *scribe.balance_book.get(&to_uid(1)).unwrap()
    );

    // and test if we can access arbitrary block
    assert_eq!(
        get_balance(&req_handler, Some(2), 0).await.unwrap(),
        after_buy_balance
    );
}
