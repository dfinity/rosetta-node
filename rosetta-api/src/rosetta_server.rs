use actix_rt::{spawn, time::interval};
use actix_web::{post, web, App, HttpResponse, HttpServer};

use crate::models::*;
use crate::{ledger_client::LedgerAccess, RosettaRequestHandler};

use futures::channel::oneshot;

use actix_web::dev::Server;
use log::{debug, error, info};
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
                .body(Error::serialization_error_json_str()),
        },
        Err(err) => match serde_json::to_string(&err) {
            Ok(resp) => HttpResponse::InternalServerError()
                .content_type("application/json")
                .body(resp),
            Err(_) => HttpResponse::InternalServerError()
                .content_type("application/json")
                .body(Error::serialization_error_json_str()),
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

#[post("/neuron/derive")]
async fn neuron_derive(
    msg: web::Json<ConstructionDeriveRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.neuron_derive(msg.into_inner()).await;
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

#[post("/search/transactions")]
async fn search_transactions(
    msg: web::Json<SearchTransactionsRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.search_transactions(msg.into_inner()).await;
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
                .data(web::JsonConfig::default().limit(4 * 1024 * 1024))
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
                .service(neuron_derive)
                .service(search_transactions)
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

    pub async fn run(&self, options: RosettaApiServerOpt) -> std::io::Result<()> {
        let RosettaApiServerOpt {
            exit_on_sync,
            offline,
            mainnet,
            not_whitelisted,
        } = options;
        info!("Starting Rosetta API server");
        if offline {
            info!("Running in offline mode");
            return self.server.clone().await;
        }

        let ledger = self.ledger.clone();
        let stopped = self.stopped.clone();
        let (tx, rx) = oneshot::channel::<()>();
        *self.sync_thread_join_handle.lock().unwrap() = Some(rx);
        let server = self.server.clone();
        // Every second start downloading new blocks, when that's done update the index
        spawn(async move {
            let mut interval = interval(Duration::from_secs(1));
            while !stopped.load(Relaxed) {
                interval.tick().await;

                if let Err(err) = ledger.sync_blocks(stopped.clone()).await {
                    let msg_403 = if mainnet && !not_whitelisted && err.is_internal_error_403() {
                        ", You may not be whitelisted; please try running the Rosetta server again with the '--not_whitelisted' flag"
                    } else {
                        ""
                    };
                    error!("Error in syncing blocks{}: {:?}", msg_403, err);
                }

                if exit_on_sync {
                    info!("Blockchain synced, exiting");
                    server.stop(true).await;
                    info!("Stopping blockchain sync thread");
                    break;
                }
            }
            tx.send(())
                .expect("Blockchain sync thread: failed to send finish notification");
            info!("Blockchain sync thread finished");
        });
        self.server.clone().await
    }

    pub async fn stop(&self) {
        info!("Stopping server");
        self.stopped.store(true, SeqCst);
        self.server.stop(true).await;
        // wait for the sync_thread to finish
        if let Some(rx) = self.sync_thread_join_handle.lock().unwrap().take() {
            rx.await
                .expect("Error on waiting for sync thread to finish");
        }
        debug!("Joined with blockchain sync thread");
    }
}

pub struct RosettaApiServerOpt {
    pub exit_on_sync: bool,
    pub offline: bool,
    pub mainnet: bool,
    pub not_whitelisted: bool,
}

impl Default for RosettaApiServerOpt {
    fn default() -> RosettaApiServerOpt {
        RosettaApiServerOpt {
            exit_on_sync: false,
            offline: false,
            mainnet: false,
            not_whitelisted: false,
        }
    }
}
