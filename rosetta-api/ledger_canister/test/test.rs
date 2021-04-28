use canister_test::*;
use dfn_candid::{candid, CandidOne};
use dfn_protobuf::protobuf;
use ic_canister_client::Sender;
use ic_types::{CanisterId, PrincipalId};
use ledger_canister::{
    AccountBalanceArgs, AccountIdentifier, ArchiveOptions, Block, BlockArg, BlockHeight, BlockRes,
    EncodedBlock, GetBlocksArgs, GetBlocksRes, ICPTs, IterBlocksArgs, IterBlocksRes,
    LedgerCanisterInitPayload, Memo, NotifyCanisterArgs, SendArgs, Subaccount, TimeStamp,
    TotalSupplyArgs, Transaction, TransactionNotificationResult, Transfer, MIN_BURN_AMOUNT,
    TRANSACTION_FEE,
};
use on_wire::IntoWire;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::time::Duration;

fn create_sender(i: u64) -> ic_canister_client::Sender {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    let keypair = {
        let mut rng = ChaChaRng::seed_from_u64(i);
        ed25519_dalek::Keypair::generate(&mut rng)
    };
    ic_canister_client::Sender::from_keypair(&keypair)
}

// So we can get the size of EncodedBlock
fn example_block() -> Block {
    let transaction = Transaction::new(
        AccountIdentifier::new(CanisterId::from_u64(1).get(), None),
        AccountIdentifier::new(CanisterId::from_u64(2).get(), None),
        ICPTs::new(10000, 50).unwrap(),
        TRANSACTION_FEE,
        Memo(456),
        TimeStamp::new(2_000_000_000, 123_456_789),
    );
    Block::new_from_transaction(None, transaction, TimeStamp::new(1, 1))
}

async fn simple_send(
    ledger: &Canister<'_>,
    to: &Sender,
    from: &Sender,
    amount_e8s: u64,
    fee_e8s: u64,
) -> Result<BlockHeight, String> {
    ledger
        .update_from_sender(
            "send_pb",
            protobuf,
            SendArgs {
                memo: Memo::default(),
                amount: ICPTs::from_e8s(amount_e8s),
                fee: ICPTs::from_e8s(fee_e8s),
                from_subaccount: None,
                to: to.get_principal_id().into(),
                created_at_time: None,
            },
            &from,
        )
        .await
}

async fn query_balance(ledger: &Canister<'_>, acc: &Sender) -> Result<ICPTs, String> {
    ledger
        .query_(
            "account_balance_pb",
            protobuf,
            AccountBalanceArgs {
                account: acc.get_principal_id().into(),
            },
        )
        .await
}

fn make_accounts(num_accounts: u64, num_subaccounts: u8) -> HashMap<AccountIdentifier, ICPTs> {
    (1..=num_accounts)
        .flat_map(|i| {
            let pid = CanisterId::from_u64(i).get();
            (1..=num_subaccounts).map(move |j| {
                let subaccount: [u8; 32] = [j; 32];
                (
                    AccountIdentifier::new(pid, Some(Subaccount(subaccount))),
                    ICPTs::from_e8s(i * j as u64),
                )
            })
        })
        .collect()
}

#[test]
fn upgrade_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let accounts = make_accounts(5, 4);

        let mut ledger = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload {
                    minting_account: CanisterId::from_u64(0).into(),
                    initial_values: accounts,
                    max_message_size_bytes: None,
                    transaction_window: None,
                    archive_options: None,
                }),
            )
            .await?;

        let GetBlocksRes(blocks_before) = ledger
            .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(0u64, 20usize))
            .await?;
        let blocks_before = blocks_before.unwrap();

        ledger.upgrade_to_self_binary(Vec::new()).await?;

        let GetBlocksRes(blocks_after) = ledger
            .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(0u64, 20usize))
            .await?;
        let blocks_after = blocks_after.unwrap();

        assert_eq!(blocks_before, blocks_after);
        Ok(())
    })
}

#[test]
fn archive_blocks_small_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        // 12 blocks
        let accounts = make_accounts(4, 3);
        println!("[test] accounts: {:?}", accounts);

        println!("[test] installing archive canister");
        // For this test we will use a tiny node size. This is because
        // we want multiple archive nodes to be created
        let blocks_per_archive_node = 2;
        println!(
            "[test] blocks per archive node: {}",
            blocks_per_archive_node
        );
        // The tiny maximum message size will force archiving one block at a
        // time
        let max_message_size_bytes = 192;
        let node_max_memory_size_bytes =
            example_block().encode().unwrap().size_bytes() * blocks_per_archive_node;
        let archive_options = Some(ArchiveOptions {
            node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
            max_message_size_bytes: Some(max_message_size_bytes),
        });

        println!("[test] installing ledger canister");
        let ledger: canister_test::Canister = {
            let payload = LedgerCanisterInitPayload {
                minting_account: CanisterId::from_u64(0).into(),
                initial_values: accounts,
                max_message_size_bytes: Some(max_message_size_bytes),
                transaction_window: None,
                archive_options,
            };
            let mut install = proj.cargo_bin("ledger-canister").install(&r);
            install.memory_allocation = Some(128 * 1024 * 1024);
            install.bytes(CandidOne(payload).into_bytes()?).await?
        };
        println!("[test] ledger canister id: {}", ledger.canister_id());

        // We will archive all Blocks from the ledger. Retrieving a copy to
        // compare with archive contents
        let IterBlocksRes(blocks) = ledger
            .query_(
                "iter_blocks_pb",
                protobuf,
                IterBlocksArgs::new(0usize, 128usize),
            )
            .await?;
        println!("[test] retrieved {} blocks", blocks.len());
        assert!(blocks.len() == 12);

        // Since we're archiving all Blocks the ledger should be empty after
        // this call
        println!("[test] calling archive_blocks on the ledger canister");
        let () = ledger
            .update_("archive_blocks", dfn_candid::candid, (0usize, 12usize))
            .await?;

        // First we get the CanisterId of each archive node that has been
        // created
        println!("[test] retrieving nodes");
        let nodes: Vec<CanisterId> = ledger.query_("get_nodes", dfn_candid::candid, ()).await?;
        // 12 blocks, 2 blocks per archive node = 6 archive nodes
        assert_eq!(nodes.len(), 6, "expected 6 archive nodes");
        println!("[test] retrieved {} nodes: {:?}", nodes.len(), nodes);

        // Then loop over these nodes and fetch all blocks
        let mut blocks_from_archive = vec![];
        for n in nodes {
            println!("[test] retrieving blocks from {}. calling iter_blocks()", n);
            let node = Canister::new(&r, n);
            let IterBlocksRes(mut blocks) = node
                .query_(
                    "iter_blocks_pb",
                    protobuf,
                    IterBlocksArgs::new(0usize, 128usize),
                )
                .await?;
            // Because blocks is emptied by append we need the length for the log message
            let blocks_len = blocks.len();
            blocks_from_archive.append(&mut blocks);
            println!(
                "[test] retrieved {} blocks from node {}. total blocks so far: {}",
                blocks_len,
                n,
                blocks_from_archive.len()
            );
        }

        // Finally check that we retrieved what we have expected
        assert_eq!(blocks_from_archive, blocks);

        Ok(())
    })
}

#[test]
fn archive_blocks_large_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        // 4096 blocks
        let accounts = make_accounts(64, 64);

        println!("[test] installing archive canister");
        let blocks_per_archive_node: usize = 32768;

        // 1 MiB
        let max_message_size_bytes: usize = 1024 * 1024;
        let node_max_memory_size_bytes: usize =
            example_block().encode().unwrap().size_bytes() * blocks_per_archive_node;
        let archive_options = Some(ArchiveOptions {
            node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
            max_message_size_bytes: Some(max_message_size_bytes),
        });

        println!("[test] installing ledger canister");
        let ledger: canister_test::Canister = {
            let payload = LedgerCanisterInitPayload {
                minting_account: CanisterId::from_u64(0).into(),
                initial_values: accounts,
                max_message_size_bytes: Some(max_message_size_bytes),
                transaction_window: None,
                archive_options,
            };
            let mut install = proj.cargo_bin("ledger-canister").install(&r);
            install.memory_allocation = Some(128 * 1024 * 1024);
            install.bytes(CandidOne(payload).into_bytes()?).await?
        };
        println!("[test] ledger canister id: {}", ledger.canister_id());

        // We will archive all Blocks from the ledger. Retrieving a copy to
        // compare with archive contents
        let blocks = {
            let mut blocks = vec![];
            // Need to make multiple queries due to query message size limit
            let blocks_per_query: usize = 8192;
            for i in 0usize..blocks_per_archive_node / blocks_per_query {
                let offset = i * blocks_per_query;
                println!(
                    "[test] retrieving blocks[{}..{}] from the ledger",
                    offset,
                    offset + blocks_per_query
                );
                let IterBlocksRes(mut result) = ledger
                    .query_(
                        "iter_blocks_pb",
                        protobuf,
                        IterBlocksArgs::new(offset, blocks_per_query),
                    )
                    .await?;
                blocks.append(&mut result);
            }
            println!("[test] retrieved {} blocks", blocks.len());
            blocks
        };
        assert_eq!(blocks.len(), 4096, "Expected 4096 blocks.");

        // Since we're archiving all Blocks the ledger should be empty after
        // this call
        println!("[test] calling archive_blocks on the ledger canister");
        let () = ledger
            .update_("archive_blocks", dfn_candid::candid, (0usize, 4096usize))
            .await?;

        // First we get the CanisterId of each archive node that has been
        // created
        println!("[test] retrieving nodes");
        let nodes: Vec<CanisterId> = ledger.query_("get_nodes", dfn_candid::candid, ()).await?;
        assert_eq!(nodes.len(), 1, "expected 1 archive node");
        println!("[test] retrieved {} nodes: {:?}", nodes.len(), nodes);

        // Then loop over these nodes and fetch all blocks
        let mut blocks_from_archive = vec![];
        for n in nodes {
            println!("[test] retrieving blocks from {}. calling iter_blocks()", n);
            let node = Canister::new(&r, n);

            let mut blocks = {
                let mut blocks = vec![];
                // Need to make multiple queries due to query message size limit
                let blocks_per_query: usize = 8192;
                for i in 0usize..blocks_per_archive_node / blocks_per_query {
                    let offset = i * blocks_per_query;
                    println!(
                        "[test] retrieving blocks[{}..{}]",
                        offset,
                        offset + blocks_per_query
                    );
                    let IterBlocksRes(mut result) = node
                        .query_(
                            "iter_blocks_pb",
                            protobuf,
                            IterBlocksArgs::new(offset, blocks_per_query),
                        )
                        .await?;
                    blocks.append(&mut result);
                }
                println!("[test] retrieved {} blocks", blocks.len());
                blocks
            };

            blocks_from_archive.append(&mut blocks);
            println!(
                "[test] blocks retrieved so far from all of the nodes: {}",
                blocks_from_archive.len()
            );
        }

        // Finally check that we retrieved what we have expected
        assert_eq!(blocks_from_archive, blocks);

        Ok(())
    })
}

#[test]
fn notify_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));
        let mut accounts = HashMap::new();
        accounts.insert(
            PrincipalId::new_anonymous().into(),
            ICPTs::from_icpts(100).unwrap(),
        );

        let test_canister = proj
            .cargo_bin("test-notified")
            .install_(&r, Vec::new())
            .await?;

        let minting_account = create_sender(0);

        let ledger_canister = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload {
                    minting_account: CanisterId::try_from(minting_account.get_principal_id())
                        .unwrap()
                        .into(),
                    initial_values: accounts,
                    max_message_size_bytes: None,
                    transaction_window: None,
                    archive_options: None,
                }),
            )
            .await?;

        let block_height: BlockHeight = ledger_canister
            .update_(
                "send_pb",
                protobuf,
                SendArgs {
                    from_subaccount: None,
                    to: test_canister.canister_id().into(),
                    amount: ICPTs::from_icpts(1).unwrap(),
                    fee: TRANSACTION_FEE,
                    memo: Memo(0),
                    created_at_time: None,
                },
            )
            .await?;

        let notify = NotifyCanisterArgs {
            block_height,
            max_fee: TRANSACTION_FEE,
            from_subaccount: None,
            to_canister: test_canister.canister_id(),
            to_subaccount: None,
        };

        let r1: Result<TransactionNotificationResult, String> = ledger_canister
            .update_("notify_pb", protobuf, notify.clone())
            .await;

        let r2: Result<TransactionNotificationResult, String> = ledger_canister
            .update_("notify_pb", protobuf, notify.clone())
            .await;

        let r3: Result<TransactionNotificationResult, String> = ledger_canister
            .update_("notify_pb", protobuf, notify.clone())
            .await;

        let count: u32 = test_canister.query_("check_counter", candid, ()).await?;

        assert_eq!(
            Err(
                "Canister rejected with message: Notification failed with message \'Rejected\'"
                    .to_string()
            ),
            r1
        );

        assert_eq!(r2.unwrap().decode::<()>(), Ok(()));

        // This is vague because it contains stuff like src spans as it's a panic
        assert!(r3
            .unwrap_err()
            .contains("There is already an outstanding notification"));

        assert_eq!(2, count);

        Ok(())
    });
}

#[test]
fn sub_account_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let mut initial_values = HashMap::new();

        let sub_account = |x| Some(Subaccount([x; 32]));

        // The principal ID of the test runner
        let us = PrincipalId::new_anonymous();

        initial_values.insert(
            AccountIdentifier::new(us, sub_account(1)),
            ICPTs::from_icpts(10).unwrap(),
        );

        let ledger_canister = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload {
                    minting_account: CanisterId::from_u64(0).into(),
                    initial_values,
                    max_message_size_bytes: None,
                    transaction_window: None,
                    archive_options: None,
                }),
            )
            .await?;

        // Send a payment to yourself on a different sub_account
        let _: BlockHeight = ledger_canister
            .update_(
                "send_pb",
                protobuf,
                SendArgs {
                    from_subaccount: sub_account(1),
                    to: AccountIdentifier::new(us, sub_account(2)),
                    amount: ICPTs::from_icpts(1).unwrap(),
                    fee: TRANSACTION_FEE,
                    memo: Memo(0),
                    created_at_time: None,
                },
            )
            .await?;

        let balance_1 = ledger_canister
            .query_(
                "account_balance_pb",
                protobuf,
                AccountBalanceArgs {
                    account: AccountIdentifier::new(us, sub_account(1)),
                },
            )
            .await?;

        let balance_2 = ledger_canister
            .query_(
                "account_balance_pb",
                protobuf,
                AccountBalanceArgs {
                    account: AccountIdentifier::new(us, sub_account(2)),
                },
            )
            .await?;

        // Transaction fees are a pain so we're easy going with equality
        fn is_roughly(a: ICPTs, b: ICPTs) {
            let one_tenth = ICPTs::from_e8s(10_000_000);
            assert!((a + one_tenth).unwrap() > b);
            assert!((a - one_tenth).unwrap() < b);
        }

        is_roughly(balance_1, ICPTs::from_icpts(9).unwrap());

        is_roughly(balance_2, ICPTs::from_icpts(1).unwrap());

        Ok(())
    })
}

#[test]
fn transaction_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let minting_account = create_sender(0);
        let acc1 = create_sender(1);
        let acc2 = create_sender(2);

        let acc1_start_amount = 1000;
        let acc2_start_amount = 2000;

        let mut accounts = HashMap::new();
        accounts.insert(
            acc1.get_principal_id().into(),
            ICPTs::from_e8s(acc1_start_amount),
        );
        accounts.insert(
            acc2.get_principal_id().into(),
            ICPTs::from_e8s(acc2_start_amount),
        );

        let ledger = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload {
                    minting_account: CanisterId::try_from(minting_account.get_principal_id())
                        .unwrap()
                        .into(),
                    initial_values: accounts,
                    max_message_size_bytes: None,
                    transaction_window: None,
                    archive_options: None,
                }),
            )
            .await?;

        let acc1_balance = query_balance(&ledger, &acc1).await?;
        assert_eq!(acc1_balance.get_e8s(), acc1_start_amount);

        let acc2_balance = query_balance(&ledger, &acc2).await?;
        assert_eq!(acc2_balance.get_e8s(), acc2_start_amount);

        let supply: ICPTs = ledger
            .query_("total_supply_pb", protobuf, TotalSupplyArgs {})
            .await?;
        assert_eq!(supply.get_e8s(), acc1_start_amount + acc2_start_amount);

        // perform a mint
        let mint_amount = 100;
        simple_send(&ledger, &acc1, &minting_account, mint_amount, 0).await?;

        let acc1_balance = query_balance(&ledger, &acc1).await?;
        assert_eq!(acc1_balance.get_e8s(), acc1_start_amount + mint_amount);

        let supply: ICPTs = ledger
            .query_("total_supply_pb", protobuf, TotalSupplyArgs {})
            .await?;
        assert_eq!(
            supply.get_e8s(),
            acc1_start_amount + acc2_start_amount + mint_amount
        );

        // perform a send
        let send_amount = 500;
        let send_fee = TRANSACTION_FEE.get_e8s();
        simple_send(&ledger, &acc2, &acc1, send_amount, send_fee).await?;

        let acc1_balance = query_balance(&ledger, &acc1).await?;
        assert_eq!(
            acc1_balance.get_e8s(),
            acc1_start_amount + mint_amount - send_amount - send_fee
        );

        let acc2_balance = query_balance(&ledger, &acc2).await?;
        assert_eq!(acc2_balance.get_e8s(), acc2_start_amount + send_amount);

        // perform a burn
        let burn_amount = MIN_BURN_AMOUNT.get_e8s();
        simple_send(&ledger, &minting_account, &acc2, burn_amount, 0).await?;

        let acc2_balance = query_balance(&ledger, &acc2).await?;
        assert_eq!(
            acc2_balance.get_e8s(),
            acc2_start_amount + send_amount - burn_amount
        );

        // invalid transaction
        let invalid_transaction_res =
            simple_send(&ledger, &minting_account, &minting_account, burn_amount, 0).await;
        assert!(invalid_transaction_res.is_err());

        // invalid burn (too little)
        let invalid_burn_res = simple_send(&ledger, &minting_account, &acc2, 3, 0).await;
        assert!(invalid_burn_res.is_err());

        // invalid burn (too much)
        let invalid_burn_res = simple_send(&ledger, &minting_account, &acc2, 3000, 0).await;
        assert!(invalid_burn_res.is_err());

        // invalid send (too much)
        let invalid_send_res = simple_send(&ledger, &acc2, &acc1, 3000, send_fee).await;
        assert!(invalid_send_res.is_err());

        // invalid send (invalid fee)
        let invalid_send_res = simple_send(&ledger, &acc2, &acc1, 1, 0).await;
        assert!(invalid_send_res.is_err());

        let minting_canister_balance = query_balance(&ledger, &minting_account).await?;
        assert_eq!(minting_canister_balance.get_e8s(), 0);

        let blocks: Vec<Block> = {
            let IterBlocksRes(blocks) = ledger
                .query_(
                    "iter_blocks_pb",
                    protobuf,
                    IterBlocksArgs::new(0usize, 100usize),
                )
                .await?;
            blocks.iter().map(|rb| rb.decode().unwrap()).collect()
        };

        let mint_transaction = blocks
            .get(blocks.len() - 3)
            .unwrap()
            .transaction()
            .into_owned()
            .transfer;
        let send_transaction = blocks
            .get(blocks.len() - 2)
            .unwrap()
            .transaction()
            .into_owned()
            .transfer;
        let burn_transaction = blocks.last().unwrap().transaction().into_owned().transfer;

        assert_eq!(
            mint_transaction,
            Transfer::Mint {
                to: acc1.get_principal_id().into(),
                amount: ICPTs::from_e8s(mint_amount)
            }
        );

        assert_eq!(
            send_transaction,
            Transfer::Send {
                from: acc1.get_principal_id().into(),
                to: acc2.get_principal_id().into(),
                amount: ICPTs::from_e8s(send_amount),
                fee: ICPTs::from_e8s(send_fee)
            }
        );

        assert_eq!(
            burn_transaction,
            Transfer::Burn {
                from: acc2.get_principal_id().into(),
                amount: ICPTs::from_e8s(burn_amount)
            }
        );

        Ok(())
    })
}

// Verify that block() can fetch blocks regardless of whether they are stored
// in the ledger itself, or in the archive. To do this we create 32 blocks,
// fetch them all from the ledger using repeated calls to block(), then archive
// all of them, and then fetch the blocks again, this time from the archive,
// using the same repeated block() calls. The results before and after
// archiving should be identical. Futhermore, multiple archive nodes should be
// created during this test.
#[test]
fn get_block_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        // For printing and comparing blocks since they're now hidden behind a
        // trait
        let blk = |b: &ledger_canister::Block| (b.transaction().into_owned(), b.timestamp());

        let minting_account = create_sender(0);

        // This is how many blocks we want to generate for this test.
        // Generating blocks is done by proxy, that is, by creating multiple
        // accounts (since each account will generate a Mint transaction).
        let num_blocks = 32u64;

        let accounts = make_accounts(num_blocks, 1);

        println!("[test] installing archive canister");
        // With 32 accounts and 8 blocks per archive we should generate
        // multiple archive nodes
        let blocks_per_archive_node: usize = 8;

        let max_message_size_bytes: usize = 1024 * 1024;
        let node_max_memory_size_bytes: usize = {
            let e = example_block().encode().unwrap();
            println!("[test] encoded block size: {}", e.size_bytes());
            e.size_bytes() * blocks_per_archive_node
        };
        let archive_init_args = ArchiveOptions {
            node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
            max_message_size_bytes: Some(max_message_size_bytes),
        };

        println!(
            "[test] installing ledger canister with {} accounts",
            accounts.len()
        );
        let ledger: canister_test::Canister = {
            let payload = LedgerCanisterInitPayload {
                minting_account: CanisterId::try_from(minting_account.get_principal_id())
                    .unwrap()
                    .into(),
                initial_values: accounts,
                max_message_size_bytes: Some(max_message_size_bytes),
                transaction_window: None,
                archive_options: Some(archive_init_args),
            };
            let mut install = proj.cargo_bin("ledger-canister").install(&r);
            install.memory_allocation = Some(128 * 1024 * 1024);
            install.bytes(CandidOne(payload).into_bytes()?).await?
        };
        println!("[test] ledger canister id: {}", ledger.canister_id());

        // Fetch some blocks using block() while they're still inside Ledger.
        // Later on we will archive them all and then block() has to
        // fetch them from Archive
        let mut blocks_from_ledger_before_archive = vec![];
        for i in 0..num_blocks {
            let BlockRes(block) = ledger.query_("block_pb", protobuf, i).await?;
            // Since blocks are still in the Ledger we should get Some(Ok(block))
            let block = block
                .unwrap()
                .unwrap()
                .decode()
                .expect("unable to decode block");
            blocks_from_ledger_before_archive.push(blk(&block))
        }

        // Since we're archiving all Blocks the ledger should be empty after
        // this call
        println!("[test] calling archive_blocks on the ledger canister");
        let () = ledger
            .update_("archive_blocks", dfn_candid::candid, (0usize, num_blocks))
            .await?;

        // Assert that we have created multiple nodes. We want to make sure
        // ledger.block() seamlessly fetches Blocks from any node
        {
            let nodes: Vec<CanisterId> = ledger
                .update_("get_nodes", dfn_candid::candid_one, Duration::from_secs(0))
                .await?;
            println!("[test] created {} archive nodes", nodes.len());
            assert_eq!(nodes.len(), 4);
        }

        // Make sure Ledger is empty after archiving blocks
        {
            let IterBlocksRes(blocks_from_ledger) = ledger
                .query_(
                    "iter_blocks_pb",
                    protobuf,
                    IterBlocksArgs::new(0usize, 512usize),
                )
                .await?;
            assert!(blocks_from_ledger.is_empty());
        }

        let mut blocks_from_archive: Vec<(Transaction, TimeStamp)> = vec![];
        for i in 0..num_blocks {
            let block = {
                let BlockRes(result) = ledger.query_("block_pb", protobuf, BlockArg(i)).await?;
                // Since blocks are now in the archive we should get Some(Err(canister_id))
                let canister_id: CanisterId = result.unwrap().unwrap_err();
                let node: Canister = Canister::new(&r, canister_id);
                let BlockRes(block) = node.query_("get_block_pb", protobuf, BlockArg(i)).await?;
                // We should get Some(Ok(block))
                let block = block.expect("block not found in the archive node").unwrap();
                block.decode().unwrap()
            };
            println!("[test] retrieved block: {:?}", blk(&block));
            blocks_from_archive.push(blk(&block))
        }

        assert_eq!(blocks_from_archive, blocks_from_ledger_before_archive);

        // Generate another block
        println!("[test] generating an additional block");
        let acc1 = create_sender(1001);
        simple_send(&ledger, &acc1, &minting_account, 9999, 0).await?;

        // And fetch it from the ledger
        let block_index: u64 = num_blocks;
        let BlockRes(block_from_ledger) = ledger
            .query_("block_pb", protobuf, BlockArg(block_index))
            .await?;
        let block_from_ledger = block_from_ledger.unwrap().unwrap().decode().unwrap();
        println!(
            "[test] retrieved block [{}]: {:?}",
            block_index,
            blk(&block_from_ledger)
        );

        // Then archive it
        println!("[test] calling archive_blocks on the ledger canister");
        let () = ledger
            .update_("archive_blocks", dfn_candid::candid, (0usize, 1usize))
            .await?;

        // Again, make sure Ledger is empty after archiving blocks
        {
            let IterBlocksRes(blocks_from_ledger) = ledger
                .query_(
                    "iter_blocks_pb",
                    protobuf,
                    IterBlocksArgs::new(0usize, 512usize),
                )
                .await?;
            assert!(blocks_from_ledger.is_empty());
        }

        // And fetch the block again, at the same index, this time from the
        // archive
        let block_from_archive: EncodedBlock = {
            let BlockRes(result) = ledger
                .query_("block_pb", protobuf, BlockArg(block_index))
                .await?;
            // Since the block is now in the archive we should get Some(Err(canister_id))
            let canister_id: CanisterId = result.unwrap().unwrap_err();
            // So we need to fetch it from archive canister directly
            let node: Canister = Canister::new(&r, canister_id);
            let BlockRes(block) = node
                .query_("get_block_pb", protobuf, BlockArg(block_index))
                .await?;
            block.unwrap().unwrap()
        };
        let block_from_archive = block_from_archive.decode().unwrap();
        println!(
            "[test] retrieved block [{}]: {:?}",
            block_index,
            blk(&block_from_archive)
        );

        assert_eq!(blk(&block_from_ledger), blk(&block_from_archive));

        let ledger_canister::protobuf::ArchiveIndexResponse { entries } =
            ledger.query_("get_archive_index_pb", protobuf, ()).await?;
        println!("[test] archive_index: {:?}", entries);

        Ok(())
    })
}

#[test]
fn get_multiple_blocks_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let minting_account = create_sender(0);

        // This is how many blocks we want to generate for this test.
        // Generating blocks is done by proxy, that is, by creating multiple
        // accounts (since each account will generate a Mint transaction).
        let num_blocks = 14u64;

        let accounts = make_accounts(num_blocks, 1);

        println!("[test] installing archive canister");

        // For this test we only need two archive nodes to check the range
        // queries. We will start with 14 blocks, so the first archive node
        // will be filled and then some space will be left in the second. Note
        // that the number here is **approximate**
        let blocks_per_archive_node: usize = 8;

        let max_message_size_bytes: usize = 1024 * 1024;
        let node_max_memory_size_bytes: usize = {
            let e = example_block().encode().unwrap();
            println!("[test] encoded block size: {}", e.size_bytes());
            e.size_bytes() * blocks_per_archive_node
        };
        let archive_options = Some(ArchiveOptions {
            node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
            max_message_size_bytes: Some(max_message_size_bytes),
        });

        println!(
            "[test] installing ledger canister with {} accounts",
            accounts.len()
        );
        let ledger: canister_test::Canister = {
            let payload = LedgerCanisterInitPayload {
                minting_account: CanisterId::try_from(minting_account.get_principal_id())
                    .unwrap()
                    .into(),
                initial_values: accounts,
                max_message_size_bytes: Some(max_message_size_bytes),
                transaction_window: None,
                archive_options,
            };
            let mut install = proj.cargo_bin("ledger-canister").install(&r);
            install.memory_allocation = Some(128 * 1024 * 1024);
            install.bytes(CandidOne(payload).into_bytes()?).await?
        };
        println!("[test] ledger canister id: {}", ledger.canister_id());

        let node: Canister = {
            // Archive all blocks
            println!("[test] calling archive_blocks on the ledger canister");
            let () = ledger
                .update_("archive_blocks", dfn_candid::candid, (0usize, num_blocks))
                .await?;

            // Make sure Ledger is empty after archiving blocks
            let IterBlocksRes(blocks_from_ledger) = ledger
                .query_(
                    "iter_blocks_pb",
                    protobuf,
                    IterBlocksArgs::new(0usize, 512usize),
                )
                .await?;
            assert!(blocks_from_ledger.is_empty());

            let nodes: Vec<CanisterId> = ledger
                .update_("get_nodes", dfn_candid::candid_one, Duration::from_secs(0))
                .await?;

            // There should be two nodes
            assert!(nodes.len() == 2);

            // We are interested in the second node which still has some empty
            // space
            Canister::new(&r, nodes[1])
        };

        // Blocks [0 .. 8] (inclusive) are stored in node [0]. Remaining five
        // blocks in node [1] are those with BlockHeights 9, 10, 11, 12 and 13

        // Query Blocks 10 and 11
        {
            println!("[test] querying blocks 10 and 11");
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(10u64, 2usize))
                .await?;

            let blocks_from_node: Vec<EncodedBlock> = blocks_from_node.unwrap();
            assert!(blocks_from_node.len() == 2);
        }

        // Query Blocks 11 and 12
        {
            println!("[test] querying blocks 11 and 12");
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(11u64, 2usize))
                .await?;

            let blocks_from_node: Vec<EncodedBlock> = blocks_from_node.unwrap();
            assert!(blocks_from_node.len() == 2);
        }

        // Query Blocks 12 and 13
        {
            println!("[test] querying blocks 12 and 13");
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(11u64, 2usize))
                .await?;

            let blocks_from_node: Vec<EncodedBlock> = blocks_from_node.unwrap();
            assert!(blocks_from_node.len() == 2);
        }

        // Query all blocks
        {
            println!("[test] querying all blocks");
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(9u64, 5usize))
                .await?;

            let blocks_from_node: Vec<EncodedBlock> = blocks_from_node.unwrap();
            assert!(blocks_from_node.len() == 5);
        }

        // And some invalid queries
        println!("[test] testing invalid queries to the archive node");
        {
            // outside range left
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(8u64, 2usize))
                .await?;
            assert!(blocks_from_node.is_err());

            // outside range right
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(10u64, 5usize))
                .await?;
            assert!(blocks_from_node.is_err());

            // outside range both sides
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(8u64, 6usize))
                .await?;
            assert!(blocks_from_node.is_err());
        }

        println!("[test] generating additional blocks in the ledger");
        // Generate additional blocks. These should have heights 14 and 15
        let acc1 = create_sender(1001);
        simple_send(&ledger, &acc1, &minting_account, 9999, 0).await?;
        let acc2 = create_sender(1002);
        simple_send(&ledger, &acc2, &minting_account, 8888, 0).await?;

        {
            println!("[test] querying blocks from the ledger");
            // Fetch 2 blocks beginning at BlockHeight 14 from the ledger
            let GetBlocksRes(blocks_from_ledger) = ledger
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(14u64, 2usize))
                .await?;
            let blocks_from_ledger = blocks_from_ledger.unwrap();
            assert!(
                blocks_from_ledger.len() == 2,
                "Expected Blocks 14 and 15 to be in the Ledger"
            );

            println!("[test] testing invalid queries to the ledger");
            // And some invalid queries
            let GetBlocksRes(blocks_from_ledger) = ledger
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(10u64, 2usize))
                .await?;
            assert!(blocks_from_ledger.is_err());

            let GetBlocksRes(blocks_from_ledger) = ledger
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(14u64, 3usize))
                .await?;
            assert!(blocks_from_ledger.is_err());

            let GetBlocksRes(blocks_from_ledger) = ledger
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(13u64, 2usize))
                .await?;
            assert!(blocks_from_ledger.is_err());

            let GetBlocksRes(blocks_from_ledger) = ledger
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(13u64, 7usize))
                .await?;
            assert!(blocks_from_ledger.is_err());
        }

        Ok(())
    })
}

#[test]
fn only_ledger_can_append_blocks_to_archive_nodes() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let minting_account = create_sender(0);

        let num_blocks = 8u64;

        let accounts = make_accounts(num_blocks, 1);

        println!("[test] installing archive canister");

        let blocks_per_archive_node: usize = 128;

        let max_message_size_bytes: usize = 1024 * 1024;
        let node_max_memory_size_bytes: usize = {
            let e = example_block().encode().unwrap();
            println!("[test] encoded block size: {}", e.size_bytes());
            e.size_bytes() * blocks_per_archive_node
        };
        let archive_options = Some(ArchiveOptions {
            node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
            max_message_size_bytes: Some(max_message_size_bytes),
        });

        println!(
            "[test] installing ledger canister with {} accounts",
            accounts.len()
        );
        let ledger: canister_test::Canister = {
            let payload = LedgerCanisterInitPayload {
                minting_account: CanisterId::try_from(minting_account.get_principal_id())
                    .unwrap()
                    .into(),
                initial_values: accounts,
                max_message_size_bytes: Some(max_message_size_bytes),
                transaction_window: None,
                archive_options,
            };
            let mut install = proj.cargo_bin("ledger-canister").install(&r);
            install.memory_allocation = Some(128 * 1024 * 1024);
            install.bytes(CandidOne(payload).into_bytes()?).await?
        };
        println!("[test] ledger canister id: {}", ledger.canister_id());

        // Archive all blocks
        println!("[test] calling archive_blocks on the ledger canister");
        let () = ledger
            .update_("archive_blocks", dfn_candid::candid, (0usize, num_blocks))
            .await?;

        // Check that only the Archive Canister can append blocks to a Node
        // canister
        {
            println!(
                "[test] checking that only ledger canister can append blocks to a node canister"
            );

            // Create a non-ledger sender
            let sender = create_sender(1234);

            let ledger_canister::protobuf::ArchiveIndexResponse { entries } =
                ledger.query_("get_archive_index_pb", protobuf, ()).await?;

            let node_canister_id = CanisterId::try_from(entries[0].canister_id.unwrap()).unwrap();
            let node: Canister = Canister::new(&r, node_canister_id);

            // Try appending blocks. We don't need any blocks (empty vector is
            // fine). Just need to send the message.
            let result: Result<(), String> = node
                .update_from_sender(
                    "append_blocks",
                    dfn_candid::candid_one,
                    Vec::<EncodedBlock>::new(),
                    &sender,
                )
                .await;

            // It should've failed
            assert!(
                result.is_err(),
                "Appending blocks from non-Ledger sender should not have succeeded"
            );
        }

        Ok(())
    })
}
