use structopt::StructOpt;

use ic_rosetta_api::rosetta_server::RosettaApiServer;
use ic_rosetta_api::{ledger_client, RosettaRequestHandler};
use ic_types::{CanisterId, PrincipalId};

use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short = "a", long = "address", default_value = "127.0.0.1")]
    listen_address: String,
    #[structopt(short = "p", long = "port", default_value = "8080")]
    listen_port: u16,
    #[structopt(
        short = "c",
        long = "canister-id",
        default_value = "ctudu-yiaaa-aaaaa-qacla-cai"
    )]
    ic_canister_id: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let opt = Opt::from_args();
    println!("Listening on {}:{}", opt.listen_address, opt.listen_port);
    let addr = format!("{}:{}", opt.listen_address, opt.listen_port);

    let canister_id =
        CanisterId::new(PrincipalId::from_str(&opt.ic_canister_id[..]).unwrap()).unwrap();

    let url = reqwest::Url::parse("https://gw.dfinity.network").unwrap();

    let client = ledger_client::LedgerClient::create_on_disk(url, canister_id)
        .expect("Failed to initialize ledger client");

    let ledger = Arc::new(client);
    let req_handler = RosettaRequestHandler::new(ledger.clone());

    let serv =
        RosettaApiServer::new(ledger, req_handler, addr).expect("Error creating RosettaApiServer");

    // actix server catches kill signals. After that we still need to stop our
    // server properly
    serv.run().await.unwrap();
    serv.stop().await;

    Ok(())
}
