use structopt::StructOpt;

use ic_rosetta_api::rosetta_server::RosettaApiServer;
use ic_rosetta_api::{ledger_client, RosettaRequestHandler};
use ic_types::{CanisterId, PrincipalId};

use std::{path::PathBuf, str::FromStr, sync::Arc};

shadow_rs::shadow!(build);

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short = "a", long = "address", default_value = "0.0.0.0")]
    listen_address: String,
    #[structopt(short = "p", long = "port", default_value = "8080")]
    listen_port: u16,
    #[structopt(
        short = "c",
        long = "canister-id",
        default_value = "5v3p4-iyaaa-aaaaa-qaaaa-cai"
    )]
    ic_canister_id: String,
    #[structopt(long = "ic-url", default_value = "https://exchanges.dfinity.network")]
    ic_url: String,
    #[structopt(long = "store-location", default_value = "./data")]
    store_location: PathBuf,
    #[structopt(long = "store-max-blocks")]
    store_max_blocks: Option<u64>,
    #[structopt(long = "exit-on-sync")]
    exit_on_sync: bool,
    #[structopt(long = "offline")]
    offline: bool,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    log4rs::init_file("log_config.yml", Default::default()).unwrap();
    let opt = Opt::from_args();
    log::info!(
        "Starting {}, pkg_version: {}",
        build::PROJECT_NAME,
        build::PKG_VERSION,
    );
    log::info!("Listening on {}:{}", opt.listen_address, opt.listen_port);
    let addr = format!("{}:{}", opt.listen_address, opt.listen_port);

    let canister_id =
        CanisterId::new(PrincipalId::from_str(&opt.ic_canister_id[..]).unwrap()).unwrap();

    let url = reqwest::Url::parse(&opt.ic_url[..]).unwrap();

    let client = ledger_client::LedgerClient::create_on_disk(
        url,
        canister_id,
        &opt.store_location,
        opt.store_max_blocks,
        opt.offline,
    )
    .await
    .expect("Failed to initialize ledger client");

    let ledger = Arc::new(client);
    let req_handler = RosettaRequestHandler::new(ledger.clone());

    let serv =
        RosettaApiServer::new(ledger, req_handler, addr).expect("Error creating RosettaApiServer");

    // actix server catches kill signals. After that we still need to stop our
    // server properly
    serv.run(opt.exit_on_sync, opt.offline).await.unwrap();
    serv.stop().await;
    log::info!("Th-th-th-that's all folks!");
    Ok(())
}
