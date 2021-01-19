use super::*;

#[actix_rt::test]
async fn rosetta_cli_data_test() {
    let addr = "127.0.0.1:8091".to_string();

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
    let mut arbiter = actix_rt::Arbiter::new();
    arbiter.send(Box::pin(async move {
        println!("Spawning server");
        serv_run.run(false).await.unwrap();
        println!("Server thread done");
    }));

    let output = Command::new("rosetta-cli")
        .args(&[
            "check:data",
            "--configuration-file",
            "test/rosetta-cli_data_test.json",
        ])
        .output()
        .expect("failed to execute rosetta-cli");

    assert!(
        output.status.success(),
        format!(
            "rosetta-cli did not finish successfully: {},/\
             \n\n--------------------------\nstdout: {}, \
             \n\n--------------------------\nstderr: {}",
            output.status,
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap()
        )
    );

    serv.stop().await;
    arbiter.stop();
    arbiter.join().unwrap();
}

#[actix_rt::test]
async fn rosetta_cli_construction_create_account_test() {
    let addr = "127.0.0.1:8092".to_string();

    let mut scribe = Scribe::new();
    let num_transactions = 10;

    scribe.add_account(
        "46ed0873face9d8d0cc332bf834034f885a5e983372db0a0f0bd608f02",
        1_000_000_001,
    );
    scribe.add_account(
        "7c7ec16552f5fcb2e9e61aeb2141cde19f0800bee00a6ee8672d448202",
        1_000_000_001,
    );
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
    let mut arbiter = actix_rt::Arbiter::new();
    arbiter.send(Box::pin(async move {
        println!("Spawning server");
        serv_run.run(false).await.unwrap();
        println!("Server thread done");
    }));

    let output = Command::new("rosetta-cli")
        .args(&[
            "check:construction",
            "--configuration-file",
            "test/rosetta-cli_construction_create_account_test.json",
        ])
        .output()
        .expect("failed to execute rosetta-cli");

    assert!(
        output.status.success(),
        format!(
            "rosetta-cli did not finish successfully: {},/\
             \n\n--------------------------\nstdout: {}, \
             \n\n--------------------------\nstderr: {}",
            output.status,
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap()
        )
    );

    serv.stop().await;
    arbiter.stop();
    arbiter.join().unwrap();
}

#[ignore] //WIP
#[actix_rt::test]
async fn rosetta_cli_construction_test() {
    let addr = "127.0.0.1:8093".to_string();

    let mut scribe = Scribe::new();
    let num_accounts = 2;

    scribe.gen_accounts(num_accounts, 1_000 * 100_000_000);

    scribe.add_account(
        "7c7ec16552f5fcb2e9e61aeb2141cde19f0800bee00a6ee8672d448202",
        100_000_000_001,
    );
    scribe.add_account(
        "46ed0873face9d8d0cc332bf834034f885a5e983372db0a0f0bd608f02",
        100_000_000_001,
    );

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
    let mut arbiter = actix_rt::Arbiter::new();
    arbiter.send(Box::pin(async move {
        println!("Spawning server");
        serv_run.run(false).await.unwrap();
        println!("Server thread done");
    }));

    let output = Command::new("rosetta-cli")
        .args(&[
            "check:construction",
            "--configuration-file",
            "test/rosetta-cli_construction_test.json",
        ])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output()
        .expect("failed to execute rosetta-cli");

    assert!(
        output.status.success(),
        format!(
            "rosetta-cli did not finish successfully: {},/\
             \n\n--------------------------\nstdout: {}, \
             \n\n--------------------------\nstderr: {}",
            output.status,
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap()
        )
    );

    serv.stop().await;
    arbiter.stop();
    arbiter.join().unwrap();
}
