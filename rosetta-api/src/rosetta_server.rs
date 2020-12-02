use actix_rt::{spawn, time::interval};
use actix_web::{post, web, App, HttpResponse, HttpServer};

use crate::models::*;
use crate::{ledger_client::LedgerAccess, RosettaRequestHandler};

use futures::channel::oneshot;

use actix_web::dev::Server;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::{Relaxed, SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.account_balance(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/block")]
async fn block(
    msg: web::Json<BlockRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.block(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/block/transaction")]
async fn block_transaction(
    msg: web::Json<BlockTransactionRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.block_transaction(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/combine")]
async fn construction_combine(
    msg: web::Json<ConstructionCombineRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_combine(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/derive")]
async fn construction_derive(
    msg: web::Json<ConstructionDeriveRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_derive(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/hash")]
async fn construction_hash(
    msg: web::Json<ConstructionHashRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_hash(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/metadata")]
async fn construction_metadata(
    msg: web::Json<ConstructionMetadataRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_metadata(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/parse")]
async fn construction_parse(
    msg: web::Json<ConstructionParseRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_parse(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/payloads")]
async fn construction_payloads(
    msg: web::Json<ConstructionPayloadsRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_payloads(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/preprocess")]
async fn construction_preprocess(
    msg: web::Json<ConstructionPreprocessRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_preprocess(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/construction/submit")]
async fn construction_submit(
    msg: web::Json<ConstructionSubmitRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_submit(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/network/list")]
async fn network_list(
    msg: web::Json<MetadataRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.network_list(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/network/options")]
async fn network_options(
    msg: web::Json<NetworkRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.network_options(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/network/status")]
async fn network_status(
    msg: web::Json<NetworkRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.network_status(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/mempool")]
async fn mempool(
    msg: web::Json<NetworkRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.mempool(msg.into_inner()).await;
    to_rosetta_response(res)
}

#[post("/mempool/transaction")]
async fn mempool_transaction(
    msg: web::Json<MempoolTransactionRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.mempool_transaction(msg.into_inner()).await;
    to_rosetta_response(res)
}

pub struct RosettaApiServer {
    stopped: Arc<AtomicBool>,
    ledger: Arc<dyn LedgerAccess + Send + Sync>,
    server: Server,
    sync_thread_join_handle: Mutex<Option<oneshot::Receiver<()>>>,
}

impl RosettaApiServer {
    pub fn new<T: 'static + LedgerAccess + Send + Sync>(
        ledger: Arc<T>,
        req_handler: RosettaRequestHandler,
        addr: String,
    ) -> std::io::Result<Self> {
        let stopped = Arc::new(AtomicBool::new(false));

        let server = HttpServer::new(move || {
            App::new()
                .data(req_handler.clone())
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
        .bind(addr)?
        .run();

        Ok(Self {
            stopped,
            ledger,
            server,
            sync_thread_join_handle: Mutex::new(None),
        })
    }

    pub async fn run(&self) -> std::io::Result<()> {
        println!("Starting Rosetta API server");
        let ledger = self.ledger.clone();
        let stopped = self.stopped.clone();
        let (tx, rx) = oneshot::channel::<()>();
        *self.sync_thread_join_handle.lock().unwrap() = Some(rx);
        // Every second start downloading new blocks, when that's done update the index
        spawn(async move {
            let mut interval = interval(Duration::from_secs(1));
            while !stopped.load(Relaxed) {
                interval.tick().await;

                if let Err(err) = ledger.sync_blocks().await {
                    eprintln!("Error in syncing blocks: {:?}", err);
                }
            }
            tx.send(())
                .expect("Blockchain sync thread: faild to send finish notification");
            println!("Blockchain sync thread finished");
        });
        self.server.clone().await
    }

    pub async fn stop(&self) {
        println!("Stopping server");
        self.stopped.store(true, SeqCst);
        self.server.stop(true).await;
        // wait for the sync_thread to finish
        self.sync_thread_join_handle
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .await
            .expect("Error on waitinf for blockchain thread to finish");
    }
}
