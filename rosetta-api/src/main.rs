use actix_web::{post, web, App, HttpResponse, HttpServer};
use structopt::StructOpt;

use ic_rosetta_api::ledger_client;
use ic_rosetta_api::models::*;

use std::sync::Arc;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short = "a", long = "address", default_value = "127.0.0.1")]
    listen_address: String,
    #[structopt(short = "p", long = "port", default_value = "8080")]
    listen_port: u16,
}

fn to_rosetta_response<S: serde::Serialize>(result: Result<S, ApiError>) -> HttpResponse {
    match result {
        Ok(x) => match serde_json::to_string(&x) {
            Ok(resp) => HttpResponse::Ok()
                .content_type("application/json")
                .body(resp),
            Err(_) => HttpResponse::InternalServerError()
                .content_type("application/json")
                .body(Error::serialization_error_json_str(None)),
        },
        Err(err) => match serde_json::to_string(&err) {
            Ok(resp) => HttpResponse::InternalServerError()
                .content_type("application/json")
                .body(resp),
            Err(_) => HttpResponse::InternalServerError()
                .content_type("application/json")
                .body(Error::serialization_error_json_str(None)),
        },
    }
}

#[post("/account/balance")]
async fn account_balance(
    msg: web::Json<AccountBalanceRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::account_balance(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/block")]
async fn block(
    msg: web::Json<BlockRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::block(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/block/transaction")]
async fn block_transaction(
    msg: web::Json<BlockTransactionRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::block_transaction(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/combine")]
async fn construction_combine(
    msg: web::Json<ConstructionCombineRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::construction_combine(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/derive")]
async fn construction_derive(
    msg: web::Json<ConstructionDeriveRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::construction_derive(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/hash")]
async fn construction_hash(
    msg: web::Json<ConstructionHashRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::construction_hash(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/metadata")]
async fn construction_metadata(
    msg: web::Json<ConstructionMetadataRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::construction_metadata(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/parse")]
async fn construction_parse(
    msg: web::Json<ConstructionParseRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::construction_parse(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/payloads")]
async fn construction_payloads(
    msg: web::Json<ConstructionPayloadsRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::construction_payloads(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/preprocess")]
async fn construction_preprocess(
    msg: web::Json<ConstructionPreprocessRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res =
        ic_rosetta_api::construction_preprocess(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/submit")]
async fn construction_submit(
    msg: web::Json<ConstructionSubmitRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::construction_submit(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/network/list")]
async fn network_list(
    network_list_request: web::Json<MetadataRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res =
        ic_rosetta_api::network_list(network_list_request.into_inner(), &**ledger.into_inner())
            .await;
    to_rosetta_response(res)
}

#[post("/network/options")]
async fn network_options(
    msg: web::Json<NetworkRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::network_options(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/network/status")]
async fn network_status(
    msg: web::Json<NetworkRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::network_status(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/mempool")]
async fn mempool(
    msg: web::Json<NetworkRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::mempool(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/mempool/transaction")]
async fn mempool_transaction(
    msg: web::Json<MempoolTransactionRequest>,
    ledger: web::Data<Arc<ledger_client::LedgerClient>>,
) -> HttpResponse {
    let res = ic_rosetta_api::mempool_transaction(msg.into_inner(), &**ledger.into_inner()).await;
    to_rosetta_response(res)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let opt = Opt::from_args();
    println!("Listening on {}:{}", opt.listen_address, opt.listen_port);
    let ledger_client = Arc::new(
        ledger_client::LedgerClient::create().expect("Failed to initialize ledger client"),
    );
    println!("Starting Rosetta API server");
    HttpServer::new(move || {
        App::new()
            .data(ledger_client.clone())
            .service(account_balance)
            .service(block)
            .service(block_transaction)
            .service(construction_combine)
            .service(construction_derive)
            .service(construction_hash)
            .service(construction_metadata)
            .service(construction_parse)
            .service(construction_payloads)
            .service(construction_preprocess)
            .service(construction_submit)
            .service(mempool)
            .service(mempool_transaction)
            .service(network_list)
            .service(network_options)
            .service(network_status)
    })
    .bind(format!("{}:{}", opt.listen_address, opt.listen_port))?
    .run()
    .await
}
