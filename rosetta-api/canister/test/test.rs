use canister_test::*;
use dfn_candid::{candid, candid_one, CandidOne};
use ic_canister_client::Sender;
use ic_types::{CanisterId, PrincipalId};
use ledger_canister::{
    account_identifier, AccountBalanceArgs, ArchiveCanisterInitPayload, Block, BlockHeight, ICPTs,
    LedgerCanisterInitPayload, Memo, NotifyCanisterArgs, RawBlock, SendArgs, Serializable,
    TotalSupplyArgs, Transfer, MIN_BURN_AMOUNT, TRANSACTION_FEE,
};
use on_wire::IntoWire;
use std::collections::HashMap;
use std::convert::TryFrom;

fn create_sender(i: u64) -> ic_canister_client::Sender {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    let keypair = {
        let mut rng = ChaChaRng::seed_from_u64(i);
        ed25519_dalek::Keypair::generate(&mut rng)
    };
    ic_canister_client::Sender::from_keypair(&keypair)
}

async fn simple_send(
    ledger: &Canister<'_>,
    to: &Sender,
    from: &Sender,
    amount_doms: u64,
    fee_doms: u64,
) -> Result<BlockHeight, String> {
    ledger
        .update_from_sender(
            "send",
            candid_one,
            SendArgs {
                memo: Memo::default(),
                amount: ICPTs::from_doms(amount_doms),
                fee: ICPTs::from_doms(fee_doms),
                from_subaccount: None,
                to: to.get_principal_id(),
                to_subaccount: None,
                block_height: None,
            },
            &from,
        )
        .await
}

async fn query_balance(ledger: &Canister<'_>, acc: &Sender) -> Result<ICPTs, String> {
    ledger
        .query_(
            "account_balance",
            candid_one,
            AccountBalanceArgs {
                account: acc.get_principal_id(),
                sub_account: None,
            },
        )
        .await
}

#[test]
fn upgrade_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let accounts: std::collections::HashMap<PrincipalId, ICPTs> = (1..5)
            .map(|i| (CanisterId::from_u64(i).get(), ICPTs::from_doms(i)))
            .collect();

        let mut ledger = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload {
                    minting_account: CanisterId::from_u64(0).get(),
                    initial_values: accounts,
                    archive_canister: None,
                    max_message_size_bytes: None,
                }),
            )
            .await?;

        let blocks_before: Vec<RawBlock> = ledger
            .query_("get_blocks", dfn_candid::candid, (0usize, 128usize))
            .await?;

        ledger.upgrade_to_self_binary(Vec::new()).await?;

        let blocks_after: Vec<RawBlock> = ledger
            .query_("get_blocks", dfn_candid::candid, (0usize, 128usize))
            .await?;

        assert_eq!(blocks_before, blocks_after);
        Ok(())
    })
}

#[test]
fn archive_blocks_small_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let accounts: std::collections::HashMap<PrincipalId, ICPTs> = (1..8)
            .map(|i| (CanisterId::from_u64(i).get(), ICPTs::from_doms(i)))
            .collect();
        println!("[test] accounts: {:?}", accounts);

        println!("[test] installing archive canister");
        // For this test we will use a tiny node size. This is because
        // we want multiple archive nodes to be created
        let blocks_per_archive_node = 2;
        println!(
            "[test] blocks per archive node: {}",
            blocks_per_archive_node
        );
        let max_message_size_bytes = 192;
        let node_max_memory_size_bytes = 256;
        let archive_init_args = ArchiveCanisterInitPayload {
            node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
            max_message_size_bytes: Some(max_message_size_bytes),
        };
        let archive: canister_test::Canister = proj
            .cargo_bin("ledger-archive-canister")
            .install_(&r, CandidOne(archive_init_args))
            .await?;
        println!("[test] archive canister id: {}", archive.canister_id());

        println!("[test] installing ledger canister");
        let ledger: canister_test::Canister = {
            let payload = LedgerCanisterInitPayload {
                minting_account: CanisterId::from_u64(0).get(),
                initial_values: accounts,
                archive_canister: Some(archive.canister_id()),
                max_message_size_bytes: Some(max_message_size_bytes),
            };
            let mut install = proj.cargo_bin("ledger-canister").install(&r);
            install.memory_allocation = Some(128 * 1024 * 1024);
            install.bytes(CandidOne(payload).into_bytes()?).await?
        };
        println!("[test] ledger canister id: {}", ledger.canister_id());

        // We will archive all Blocks from the ledger. Retrieving a copy to
        // compare with archive contents
        let blocks: Vec<RawBlock> = ledger
            .query_("get_blocks", dfn_candid::candid, (0usize, 128usize))
            .await?;
        println!("[test] retrieved {} blocks", blocks.len());

        // Since we're archiving Blocks from the age >= 0, the ledger should be
        // empty after this call
        println!("[test] calling archive_blocks on the ledger canister");
        let () = ledger
            .update_(
                "archive_blocks",
                dfn_candid::candid_one,
                std::time::Duration::from_secs(0),
            )
            .await?;

        // First we get the CanisterId of each archive node that has been
        // created
        println!("[test] retrieving nodes from archive");
        let nodes: Vec<CanisterId> = archive.query_("get_nodes", dfn_candid::candid, ()).await?;
        assert_eq!(nodes.len(), 3, "expected 3 archive nodes");
        println!("[test] retrieved {} nodes: {:?}", nodes.len(), nodes);

        // Then loop over these nodes and fetch all blocks
        let mut blocks_from_archive = vec![];
        for n in nodes {
            println!("[test] retrieving blocks from {}. calling get_blocks()", n);
            let node = Canister::new(&r, n);
            let mut blocks: Vec<RawBlock> = node
                .query_("get_blocks", dfn_candid::candid, (0usize, 128usize))
                .await?;
            blocks_from_archive.append(&mut blocks);
            println!(
                "[test] retrieved {} blocks. total blocks so far: {}",
                blocks.len(),
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

        // Generate around 4 MiB of Blocks
        let accounts: std::collections::HashMap<PrincipalId, ICPTs> = (1..32768)
            .map(|i| (CanisterId::from_u64(i).get(), ICPTs::from_doms(i)))
            .collect();

        println!("[test] installing archive canister");
        let blocks_per_archive_node: usize = 32768;
        println!(
            "[test] blocks per archive node: {}",
            blocks_per_archive_node * 256
        );

        // 1 MiB or 8192 Blocks of size 128
        let max_message_size_bytes: usize = 1024 * 1024;
        // Block size on the Wasm side is 128 which is different than 136
        // reported by size_of here. Hence, using a hard-coded value
        let node_max_memory_size_bytes: usize = 128 * blocks_per_archive_node;
        let archive_init_args = ArchiveCanisterInitPayload {
            node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
            max_message_size_bytes: Some(max_message_size_bytes),
        };
        let archive: canister_test::Canister = proj
            .cargo_bin("ledger-archive-canister")
            .install_(&r, CandidOne(archive_init_args))
            .await?;
        println!("[test] archive canister id: {}", archive.canister_id());

        println!("[test] installing ledger canister");
        let ledger: canister_test::Canister = {
            let payload = LedgerCanisterInitPayload {
                minting_account: CanisterId::from_u64(0).get(),
                initial_values: accounts,
                archive_canister: Some(archive.canister_id()),
                max_message_size_bytes: Some(max_message_size_bytes),
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
                let mut result: Vec<RawBlock> = ledger
                    .query_("get_blocks", dfn_candid::candid, (offset, blocks_per_query))
                    .await?;
                blocks.append(&mut result);
            }
            println!("[test] retrieved {} blocks", blocks.len());
            blocks
        };

        // Since we're archiving Blocks from the age >= 0, the ledger should be
        // empty after this call
        println!("[test] calling archive_blocks on the ledger canister");
        let () = ledger
            .update_(
                "archive_blocks",
                dfn_candid::candid_one,
                std::time::Duration::from_secs(0),
            )
            .await?;

        // First we get the CanisterId of each archive node that has been
        // created
        println!("[test] retrieving nodes from archive");
        let nodes: Vec<CanisterId> = archive.query_("get_nodes", dfn_candid::candid, ()).await?;
        assert_eq!(nodes.len(), 1, "expected 1 archive node");
        println!("[test] retrieved {} nodes: {:?}", nodes.len(), nodes);

        // Then loop over these nodes and fetch all blocks
        let mut blocks_from_archive = vec![];
        for n in nodes {
            println!("[test] retrieving blocks from {}. calling get_blocks()", n);
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
                    let mut result: Vec<RawBlock> = node
                        .query_("get_blocks", dfn_candid::candid, (offset, blocks_per_query))
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
            PrincipalId::new_anonymous(),
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
                        .get(),
                    initial_values: accounts,
                    archive_canister: None,
                    max_message_size_bytes: None,
                }),
            )
            .await?;

        let block_height: BlockHeight = ledger_canister
            .update_(
                "send",
                candid_one,
                SendArgs {
                    from_subaccount: None,
                    to: test_canister.canister_id().get(),
                    to_subaccount: None,
                    amount: ICPTs::from_icpts(1).unwrap(),
                    fee: TRANSACTION_FEE,
                    memo: Memo(0),
                    block_height: None,
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

        let r1: Result<(), String> = ledger_canister
            .update_("notify", candid_one, notify.clone())
            .await;

        let r2: Result<(), String> = ledger_canister
            .update_("notify", candid_one, notify.clone())
            .await;

        let r3: Result<(), String> = ledger_canister
            .update_("notify", candid_one, notify.clone())
            .await;

        let count: u32 = test_canister.query_("check_counter", candid, ()).await?;

        assert_eq!(
            Err(
                "Canister rejected with message: Notification failed with message \'Rejected\'"
                    .to_string()
            ),
            r1
        );
        assert_eq!(Ok(()), r2);

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

        let sub_account = |x| Some([x; 32]);

        // The principal ID of the test runner
        let us = PrincipalId::new_anonymous();

        initial_values.insert(
            account_identifier(us, sub_account(1)).unwrap(),
            ICPTs::from_icpts(10).unwrap(),
        );

        let ledger_canister = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload {
                    minting_account: CanisterId::from_u64(0).get(),
                    initial_values,
                    archive_canister: None,
                    max_message_size_bytes: None,
                }),
            )
            .await?;

        // Send a payment to yourself on a different sub_account
        let _: BlockHeight = ledger_canister
            .update_(
                "send",
                candid_one,
                SendArgs {
                    from_subaccount: sub_account(1),
                    to: us,
                    to_subaccount: sub_account(2),
                    amount: ICPTs::from_icpts(1).unwrap(),
                    fee: TRANSACTION_FEE,
                    memo: Memo(0),
                    block_height: None,
                },
            )
            .await?;

        let balance_1 = ledger_canister
            .query_(
                "account_balance",
                candid_one,
                AccountBalanceArgs {
                    account: us,
                    sub_account: sub_account(1),
                },
            )
            .await?;

        let balance_2 = ledger_canister
            .query_(
                "account_balance",
                candid_one,
                AccountBalanceArgs {
                    account: us,
                    sub_account: sub_account(2),
                },
            )
            .await?;

        // Transaction fees are a pain so we're easy going with equality
        fn is_roughly(a: ICPTs, b: ICPTs) {
            let one_tenth = ICPTs::from_doms(10_000_000);
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
        accounts.insert(acc1.get_principal_id(), ICPTs::from_doms(acc1_start_amount));
        accounts.insert(acc2.get_principal_id(), ICPTs::from_doms(acc2_start_amount));

        let ledger = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload {
                    minting_account: CanisterId::try_from(minting_account.get_principal_id())
                        .unwrap()
                        .get(),
                    initial_values: accounts,
                    archive_canister: None,
                    max_message_size_bytes: None,
                }),
            )
            .await?;

        let acc1_balance = query_balance(&ledger, &acc1).await?;
        assert_eq!(acc1_balance.get_doms(), acc1_start_amount);

        let acc2_balance = query_balance(&ledger, &acc2).await?;
        assert_eq!(acc2_balance.get_doms(), acc2_start_amount);

        let supply: ICPTs = ledger
            .query_("total_supply", candid_one, TotalSupplyArgs {})
            .await?;
        assert_eq!(supply.get_doms(), acc1_start_amount + acc2_start_amount);

        // perform a mint
        let mint_amount = 100;
        simple_send(&ledger, &acc1, &minting_account, mint_amount, 0).await?;

        let acc1_balance = query_balance(&ledger, &acc1).await?;
        assert_eq!(acc1_balance.get_doms(), acc1_start_amount + mint_amount);

        let supply: ICPTs = ledger
            .query_("total_supply", candid_one, TotalSupplyArgs {})
            .await?;
        assert_eq!(
            supply.get_doms(),
            acc1_start_amount + acc2_start_amount + mint_amount
        );

        // perform a send
        let send_amount = 500;
        let send_fee = TRANSACTION_FEE.get_doms();
        simple_send(&ledger, &acc2, &acc1, send_amount, send_fee).await?;

        let acc1_balance = query_balance(&ledger, &acc1).await?;
        assert_eq!(
            acc1_balance.get_doms(),
            acc1_start_amount + mint_amount - send_amount - send_fee
        );

        let acc2_balance = query_balance(&ledger, &acc2).await?;
        assert_eq!(acc2_balance.get_doms(), acc2_start_amount + send_amount);

        // perform a burn
        let burn_amount = MIN_BURN_AMOUNT.get_doms();
        simple_send(&ledger, &minting_account, &acc2, burn_amount, 0).await?;

        let acc2_balance = query_balance(&ledger, &acc2).await?;
        assert_eq!(
            acc2_balance.get_doms(),
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
        assert_eq!(minting_canister_balance.get_doms(), 0);

        let raw_blocks: Vec<RawBlock> = ledger
            .query_("get_blocks", dfn_candid::candid, (0usize, 100usize))
            .await?;

        let blocks: Vec<Block> = raw_blocks
            .iter()
            .map(|rb| Block::decode(&rb).unwrap())
            .collect();

        let mint_transaction = match blocks.get(blocks.len() - 3).unwrap() {
            Block::V0(b) => b.transaction.transfer.clone(),
        };
        let send_transaction = match blocks.get(blocks.len() - 2).unwrap() {
            Block::V0(b) => b.transaction.transfer.clone(),
        };
        let burn_transaction = match blocks.last().unwrap() {
            Block::V0(b) => b.transaction.transfer.clone(),
        };

        assert_eq!(
            mint_transaction,
            Transfer::Mint {
                to: acc1.get_principal_id(),
                amount: ICPTs::from_doms(mint_amount)
            }
        );

        assert_eq!(
            send_transaction,
            Transfer::Send {
                from: acc1.get_principal_id(),
                to: acc2.get_principal_id(),
                amount: ICPTs::from_doms(send_amount),
                fee: ICPTs::from_doms(send_fee)
            }
        );

        assert_eq!(
            burn_transaction,
            Transfer::Burn {
                from: acc2.get_principal_id(),
                amount: ICPTs::from_doms(burn_amount)
            }
        );

        Ok(())
    })
}
