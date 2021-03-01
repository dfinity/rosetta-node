use super::*;

use log::debug;

#[actix_rt::test]
async fn rosetta_cli_data_test() {
    init_test_logger();

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
        debug!("Spawning server");
        serv_run.run(false, false).await.unwrap();
        debug!("Server thread done");
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
    init_test_logger();

    let addr = "127.0.0.1:8092".to_string();

    let mut scribe = Scribe::new();
    let num_transactions = 10;

    scribe.add_account(
        "536b6209f79889378cafe5f0342cac176f261cca3d182da95c3bfd6302",
        1_000_000_001,
    );
    scribe.add_account(
        "fe82b6784eb4a61a1261941f3010066f3df813154cc3e6ced3d3b63202",
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
        debug!("Spawning server");
        serv_run.run(false, false).await.unwrap();
        debug!("Server thread done");
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

#[actix_rt::test]
async fn rosetta_cli_construction_test() {
    init_test_logger();

    let addr = "127.0.0.1:8093".to_string();

    let mut scribe = Scribe::new();
    let num_accounts = 2;

    scribe.gen_accounts(num_accounts, 1_000 * 100_000_000);

    scribe.add_account(
        "fe82b6784eb4a61a1261941f3010066f3df813154cc3e6ced3d3b63202",
        100_000_000_001,
    );
    scribe.add_account(
        "536b6209f79889378cafe5f0342cac176f261cca3d182da95c3bfd6302",
        100_000_000_002,
    );
    scribe.add_account(
        "df86247a1456860419c51c432faffc05fc6d0e405c21cb31b36a772d02",
        100_000_000_003,
    );
    scribe.add_account(
        "5360a4ac7ecf4495b764cfe9ca9ef050d3686d43fd5ae0ec7517de8c02",
        100_000_000_004,
    );
    scribe.add_account(
        "edcfc2ed66a7cfbd688f064afe6d3d9dfb1155b66e8de062ab13ef0202",
        100_000_000_005,
    );
    scribe.add_account(
        "1a513246f54ea1e2374187222ffb84624896961f513353811d468c7802",
        100_000_000_006,
    );
    scribe.add_account(
        "47dc99f3bc06aeaa3f175f3dd0941c09d9ff018b40822a0c8e10bb8f02",
        100_000_000_007,
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
        debug!("Spawning server");
        serv_run.run(false, false).await.unwrap();
        debug!("Server thread done");
    }));

    let output = Command::new("rosetta-cli")
        .args(&[
            "check:construction",
            "--configuration-file",
            "test/rosetta-cli_construction_test.json",
        ])
        //.stdout(std::process::Stdio::inherit())
        //.stderr(std::process::Stdio::inherit())
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
