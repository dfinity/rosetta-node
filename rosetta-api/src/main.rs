use structopt::StructOpt;

use ic_rosetta_api::rosetta_server::RosettaApiServer;
use ic_rosetta_api::{ledger_client, RosettaRequestHandler};
use ic_types::{CanisterId, PrincipalId};

use ic_crypto::threshold_sig_public_key_from_der;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use std::{path::Path, path::PathBuf, str::FromStr, sync::Arc};

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
        default_value = "5s2ji-faaaa-aaaaa-qaaaq-cai"
    )]
    ic_canister_id: String,
    #[structopt(long = "ic-url", default_value = "https://exchanges.dfinity.network")]
    ic_url: String,
    #[structopt(
        short = "l",
        long = "log-config-file",
        default_value = "log_config.yml"
    )]
    log_config_file: PathBuf,
    #[structopt(long = "nns-public-key")]
    nns_public_key: Option<PathBuf>,
    #[structopt(long = "store-location", default_value = "./data")]
    store_location: PathBuf,
    #[structopt(long = "store-max-blocks")]
    store_max_blocks: Option<u64>,
    #[structopt(long = "exit-on-sync")]
    exit_on_sync: bool,
    #[structopt(long = "offline")]
    offline: bool,
}

fn parse_threshold_sig_key(pem_file: &Path) -> std::io::Result<ThresholdSigPublicKey> {
    fn invalid_data_err(msg: impl std::string::ToString) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
    }

    let buf = std::fs::read(pem_file)?;
    let s = String::from_utf8_lossy(&buf);
    let lines: Vec<_> = s.trim_end().lines().collect();
    let n = lines.len();

    if n < 3 {
        return Err(invalid_data_err("input file is too short"));
    }

    if !lines[0].starts_with("-----BEGIN PUBLIC KEY-----") {
        return Err(invalid_data_err(
            "PEM file doesn't start with BEGIN PK block",
        ));
    }
    if !lines[n - 1].starts_with("-----END PUBLIC KEY-----") {
        return Err(invalid_data_err("PEM file doesn't end with END PK block"));
    }

    let decoded = base64::decode(&lines[1..n - 1].join(""))
        .map_err(|err| invalid_data_err(format!("failed to decode base64: {}", err)))?;

    let public_key = threshold_sig_public_key_from_der(&decoded)
        .map_err(|err| invalid_data_err(format!("failed to decode public key: {}", err)))?;

    Ok(public_key)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let opt = Opt::from_args();
    if let Err(e) = log4rs::init_file(opt.log_config_file.as_path(), Default::default()) {
        panic!(
            "rosetta-api failed to load log configuration file: {}, error: {}. (current_dir is: {:?})",
            &opt.log_config_file.as_path().display(),
            e,
            std::env::current_dir()
        );
    }

    log::info!(
        "Starting {}, pkg_version: {}",
        build::PROJECT_NAME,
        build::PKG_VERSION,
    );

    let public_key = match opt.nns_public_key {
        Some(nns_public_key_path) => Some(parse_threshold_sig_key(nns_public_key_path.as_path())?),
        None => None,
    };
    log::info!("Listening on {}:{}", opt.listen_address, opt.listen_port);
    let addr = format!("{}:{}", opt.listen_address, opt.listen_port);

    let canister_id =
        CanisterId::new(PrincipalId::from_str(&opt.ic_canister_id[..]).unwrap()).unwrap();

    let url = url::Url::parse(&opt.ic_url[..]).unwrap();

    let client = ledger_client::LedgerClient::create_on_disk(
        url,
        canister_id,
        &opt.store_location,
        opt.store_max_blocks,
        opt.offline,
        public_key,
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
