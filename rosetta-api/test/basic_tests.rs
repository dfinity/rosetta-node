use super::*;

use ic_rosetta_api::models::*;

use ic_rosetta_api::convert::{amount_, block_id, from_hash, timestamp, to_hash};
use ic_rosetta_api::ledger_client::LedgerAccess;
use ic_rosetta_api::{RosettaRequestHandler, API_VERSION, MIDDLEWARE_VERSION, NODE_VERSION};

use serde_json::map::Map;
use std::sync::Arc;

#[actix_rt::test]
async fn smoke_test() {
    init_test_logger();

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
        ledger.add_block(b.clone()).await.ok();
    }

    assert_eq!(
        scribe.blockchain.len() as u64,
        ledger.read_blocks().await.last().unwrap().unwrap().index + 1
    );

    for i in 0..num_accounts {
        assert_eq!(
            get_balance(&req_handler, None, i).await.unwrap(),
            *scribe.balance_book.get(&to_uid(i)).unwrap()
        );
    }

    let msg = NetworkRequest::new(req_handler.network_id());
    let res = req_handler.network_status(msg).await;
    assert_eq!(
        res,
        Ok(NetworkStatusResponse::new(
            block_id(&scribe.blockchain.back().unwrap()).unwrap(),
            timestamp(scribe.blockchain.back().unwrap().block.timestamp().into()).unwrap(),
            block_id(&scribe.blockchain.front().unwrap()).unwrap(),
            Some(block_id(&scribe.blockchain.front().unwrap()).unwrap()),
            SyncStatus::new(scribe.blockchain.back().unwrap().index as i64, None),
            vec![]
        ))
    );

    let msg = MetadataRequest::new();
    let res = req_handler.network_list(msg).await;
    assert_eq!(
        res,
        Ok(NetworkListResponse::new(vec![req_handler.network_id()]))
    );

    let msg = NetworkRequest::new(req_handler.network_id());
    let res = req_handler.network_options(msg).await;
    assert_eq!(
        res,
        Ok(NetworkOptionsResponse::new(
            Version::new(
                API_VERSION.to_string(),
                NODE_VERSION.to_string(),
                Some(MIDDLEWARE_VERSION.to_string()),
                Some(Map::new())
            ),
            Allow::new(
                vec![OperationStatus::new("COMPLETED".to_string(), true)],
                vec![
                    "BURN".to_string(),
                    "MINT".to_string(),
                    "TRANSACTION".to_string()
                ],
                vec![
                    Error::new(&ApiError::InternalError(true, None)),
                    Error::new(&ApiError::InvalidRequest(false, None)),
                    Error::new(&ApiError::InvalidNetworkId(false, None)),
                    Error::new(&ApiError::InvalidAccountId(false, None)),
                    Error::new(&ApiError::InvalidBlockId(false, None)),
                    Error::new(&ApiError::MempoolTransactionMissing(false, None)),
                    Error::new(&ApiError::BlockchainEmpty(false, None)),
                    Error::new(&ApiError::InvalidTransaction(false, None)),
                ],
                true
            )
        ))
    );

    let msg = NetworkRequest::new(req_handler.network_id());
    let res = req_handler.mempool(msg).await;
    assert_eq!(res, Ok(MempoolResponse::new(vec![])));

    let msg = MempoolTransactionRequest::new(
        req_handler.network_id(),
        TransactionIdentifier::new("hello there".to_string()),
    );
    let res = req_handler.mempool_transaction(msg).await;
    assert_eq!(res, Err(ApiError::MempoolTransactionMissing(false, None)));

    let msg = AccountBalanceRequest::new(
        req_handler.network_id(),
        ic_rosetta_api::convert::account_identifier(&to_uid(0)),
    );
    let res = req_handler.account_balance(msg).await;
    assert_eq!(
        res,
        Ok(AccountBalanceResponse::new(
            block_id(&scribe.blockchain.back().unwrap()).unwrap(),
            vec![amount_(*scribe.balance_book.get(&to_uid(0)).unwrap()).unwrap()]
        ))
    );
}

#[actix_rt::test]
async fn blocks_test() {
    init_test_logger();

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
        ledger.add_block(b.clone()).await.ok();
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
    init_test_logger();

    let ledger = Arc::new(TestLedger::new());
    let req_handler = RosettaRequestHandler::new(ledger.clone());
    let mut scribe = Scribe::new();

    scribe.gen_accounts(2, 1_000_000);
    for b in &scribe.blockchain {
        ledger.add_block(b.clone()).await.ok();
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
        .await
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
        .await
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
        .await
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

#[actix_rt::test]
async fn load_from_store_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();

    let scribe = Scribe::new_with_sample_data(10, 100);

    let mut blocks = Blocks::new_on_disk(tmpdir.path().into()).unwrap();
    for hb in &scribe.blockchain {
        blocks.add_block(hb.clone()).unwrap();
    }
    drop(blocks);

    let mut blocks = Blocks::new_on_disk(tmpdir.path().into()).unwrap();
    blocks.load_from_store().unwrap();

    for hb in &scribe.blockchain {
        assert_eq!(*hb, blocks.get_at(hb.index).unwrap());
        assert_eq!(*hb, blocks.get(hb.hash).unwrap());
        assert!(blocks.get_balances_at(hb.index).is_ok());
        for (account, amount) in scribe.balance_history.get(hb.index as usize).unwrap() {
            assert_eq!(
                blocks
                    .get_balances_at(hb.index)
                    .unwrap()
                    .account_balance(account),
                *amount
            );
        }
    }
}
