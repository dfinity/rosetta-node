use ic_canister_client::{HttpClient, HttpContentType, HttpStatusCode};
use ic_rosetta_api::models::Error as RosettaError;
use ic_rosetta_api::models::*;
use ic_types::CanisterId;
//use ic_rosetta_api::models::AccountIdentifier as RosettaAccountIdentifier;

use ledger_canister::{AccountIdentifier, BlockHeight};

use rand::{seq::SliceRandom, thread_rng};
use std::convert::TryFrom;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::delay_for;
use url::Url;

fn to_rosetta_response<T: serde::de::DeserializeOwned>(
    hyper_res: Result<(Vec<u8>, HttpStatusCode), String>,
) -> Result<Result<T, RosettaError>, String> {
    match hyper_res {
        Ok((msg, status)) => match status.as_u16() {
            200 => {
                let resp: T = serde_json::from_slice(&msg).unwrap();
                Ok(Ok(resp))
            }
            500 => {
                let resp: Error = serde_json::from_slice(&msg).unwrap();
                Ok(Err(resp))
            }
            _ => Err(format!(
                "Expected status 200 or 500, got {}",
                status.as_u16()
            )),
        },
        Err(e) => Err(e),
    }
}

pub struct RosettaApiHandle {
    process: std::process::Child,
    can_panic: bool,
    http_client: HttpClient,
    api_url: String,
    ledger_can_id: CanisterId,
    workspace: tempfile::TempDir,
}

impl RosettaApiHandle {
    pub async fn start(
        node_url: Url,
        port: u16,
        ledger_can_id: CanisterId,
        workspace_path: String,
        root_key_file_path: &std::path::Path,
    ) -> Self {
        let log_conf_file = format!("{}/ic_rosetta_api_log_config.yml", workspace_path);

        let workspace = tempfile::Builder::new()
            .prefix("rosetta_api_tmp_")
            .tempdir_in(workspace_path)
            .unwrap();

        let api_addr = "127.0.0.1";
        let api_port = format!("{}", port);
        let api_url = format!("{}:{}", api_addr, api_port);

        let process = std::process::Command::new("ic-rosetta-api")
            .args(&[
                "--ic-url",
                node_url.as_str(),
                "--canister-id",
                &ledger_can_id.get().to_string(),
                "--address",
                api_addr,
                "--port",
                &api_port,
                "--log-config-file",
                &log_conf_file,
                "--store-location",
                &format!("{}/data", workspace.path().display()),
                "--root-key",
                root_key_file_path.to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect("failed to execute rosetta-cli");

        let http_client = HttpClient::new();
        let api_serv = Self {
            process,
            can_panic: true,
            http_client,
            api_url,
            ledger_can_id,
            workspace,
        };

        api_serv.wait_for_startup().await;
        assert_eq!(
            api_serv.network_list().await.unwrap(),
            Ok(NetworkListResponse::new(vec![api_serv.network_id()]))
        );
        api_serv
    }

    // I have hoped to avoid generating configs on the fly, but...
    pub fn generate_rosetta_cli_config(&self, cli_json: &PathBuf, cli_ros: &PathBuf) -> String {
        use std::fs::write;

        let ic_address = hex::encode(&self.ledger_can_id);
        let dst_dir: PathBuf = self.workspace.path().to_owned();

        let cli_json = std::fs::read_to_string(cli_json).expect("Reading rosetta cli json failed");
        let cli_ros = std::fs::read_to_string(cli_ros).expect("Reading rosetta cli ros failed");

        let cli_json = (&cli_json).replace("PUT_ROSETTA_API_URL_HERE", &self.api_url.to_string());
        let cli_json = (&cli_json).replace("PUT_LEDGER_ADDRESS_HERE", &ic_address);
        let cli_ros = (&cli_ros).replace("PUT_LEDGER_ADDRESS_HERE", &ic_address);

        write(dst_dir.join("ros_cli.json"), cli_json).expect("Writing rosetta cli json failed");
        write(dst_dir.join("ros_workflows.ros"), cli_ros).expect("Writing rosetta cli ros failed");

        dst_dir.join("ros_cli.json").to_str().unwrap().to_string()
    }

    pub fn network_id(&self) -> NetworkIdentifier {
        let net_id = hex::encode(self.ledger_can_id.get().into_vec());
        NetworkIdentifier::new("Internet Computer".to_string(), net_id)
    }

    async fn wait_for_startup(&self) {
        let now = std::time::SystemTime::now();
        let timeout = std::time::Duration::from_secs(5);

        while now.elapsed().unwrap() < timeout {
            if self.network_list().await.is_ok() {
                return;
            }
            delay_for(Duration::from_millis(100)).await;
        }
        panic!("Rosetta_api failed to start in {} secs", timeout.as_secs());
    }

    pub async fn construction_derive(
        &self,
        pk: PublicKey,
    ) -> Result<Result<ConstructionDeriveResponse, RosettaError>, String> {
        let req = ConstructionDeriveRequest::new(self.network_id(), pk);
        let resp = self
            .http_client
            .send_post_request(
                &format!("http://{}/construction/derive", self.api_url),
                Some(HttpContentType::JSON),
                Some(serde_json::to_vec(&req).unwrap()),
                None,
            )
            .await;
        to_rosetta_response(resp)
    }

    pub async fn construction_preprocess(
        &self,
        ops: Vec<Operation>,
    ) -> Result<Result<ConstructionPreprocessResponse, RosettaError>, String> {
        let req = ConstructionPreprocessRequest::new(self.network_id(), ops);
        let resp = self
            .http_client
            .send_post_request(
                &format!("http://{}/construction/preprocess", self.api_url),
                Some(HttpContentType::JSON),
                Some(serde_json::to_vec(&req).unwrap()),
                None,
            )
            .await;
        to_rosetta_response(resp)
    }

    pub async fn construction_combine(
        &self,
        unsigned_transaction: String,
        signatures: Vec<Signature>,
    ) -> Result<Result<ConstructionCombineResponse, RosettaError>, String> {
        let req = ConstructionCombineRequest {
            network_identifier: self.network_id(),
            unsigned_transaction,
            signatures,
        };
        let resp = self
            .http_client
            .send_post_request(
                &format!("http://{}/construction/combine", self.api_url),
                Some(HttpContentType::JSON),
                Some(serde_json::to_vec(&req).unwrap()),
                None,
            )
            .await;
        to_rosetta_response(resp)
    }

    pub async fn construction_hash(
        &self,
        signed_transaction: String,
    ) -> Result<Result<ConstructionHashResponse, RosettaError>, String> {
        let req = ConstructionHashRequest {
            network_identifier: self.network_id(),
            signed_transaction,
        };
        let resp = self
            .http_client
            .send_post_request(
                &format!("http://{}/construction/hash", self.api_url),
                Some(HttpContentType::JSON),
                Some(serde_json::to_vec(&req).unwrap()),
                None,
            )
            .await;
        to_rosetta_response(resp)
    }

    pub async fn construction_metadata(
        &self,
        options: Option<Object>,
        public_keys: Option<Vec<PublicKey>>,
    ) -> Result<Result<ConstructionMetadataResponse, RosettaError>, String> {
        let req = ConstructionMetadataRequest {
            network_identifier: self.network_id(),
            options,
            public_keys,
        };
        let resp = self
            .http_client
            .send_post_request(
                &format!("http://{}/construction/metadata", self.api_url),
                Some(HttpContentType::JSON),
                Some(serde_json::to_vec(&req).unwrap()),
                None,
            )
            .await;
        to_rosetta_response(resp)
    }

    pub async fn construction_parse(
        &self,
        signed: bool,
        transaction: String,
    ) -> Result<Result<ConstructionParseResponse, RosettaError>, String> {
        let req = ConstructionParseRequest {
            network_identifier: self.network_id(),
            signed,
            transaction,
        };
        let resp = self
            .http_client
            .send_post_request(
                &format!("http://{}/construction/parse", self.api_url),
                Some(HttpContentType::JSON),
                Some(serde_json::to_vec(&req).unwrap()),
                None,
            )
            .await;
        to_rosetta_response(resp)
    }

    pub async fn construction_payloads(
        &self,
        metadata: Option<Object>,
        operations: Vec<Operation>,
        public_keys: Option<Vec<PublicKey>>,
        ingress_expiry: Option<u64>,
        created_at_time: Option<u64>,
    ) -> Result<Result<ConstructionPayloadsResponse, RosettaError>, String> {
        let mut metadata = metadata.unwrap_or_else(Object::new);
        metadata.insert("memo".to_owned(), 0.into());
        if let Some(t) = ingress_expiry {
            metadata.insert("ingress_end".to_owned(), t.into());
        }
        if let Some(t) = created_at_time {
            metadata.insert("created_at_time".to_owned(), t.into());
        }
        let req = ConstructionPayloadsRequest {
            network_identifier: self.network_id(),
            metadata: Some(metadata),
            operations,
            public_keys,
        };
        let resp = self
            .http_client
            .send_post_request(
                &format!("http://{}/construction/payloads", self.api_url),
                Some(HttpContentType::JSON),
                Some(serde_json::to_vec(&req).unwrap()),
                None,
            )
            .await;
        to_rosetta_response(resp)
    }

    pub async fn construction_submit(
        &self,
        signed_transaction: String,
    ) -> Result<Result<ConstructionSubmitResponse, RosettaError>, String> {
        // Shuffle the messages to check whether the server picks a
        // valid one to send to the IC.
        let mut signed_transaction: Envelopes =
            serde_cbor::from_slice(&hex::decode(&signed_transaction).unwrap()).unwrap();
        let mut rng = thread_rng();
        signed_transaction.shuffle(&mut rng);

        let req = ConstructionSubmitRequest {
            network_identifier: self.network_id(),
            signed_transaction: hex::encode(serde_cbor::to_vec(&signed_transaction).unwrap()),
        };

        let resp = self
            .http_client
            .send_post_request(
                &format!("http://{}/construction/submit", self.api_url),
                Some(HttpContentType::JSON),
                Some(serde_json::to_vec(&req).unwrap()),
                None,
            )
            .await;
        to_rosetta_response(resp)
    }

    pub async fn network_list(&self) -> Result<Result<NetworkListResponse, RosettaError>, String> {
        let req = MetadataRequest::new();
        let resp = self
            .http_client
            .send_post_request(
                &format!("http://{}/network/list", self.api_url),
                Some(HttpContentType::JSON),
                Some(serde_json::to_vec(&req).unwrap()),
                None,
            )
            .await;
        to_rosetta_response(resp)
    }

    pub async fn network_status(
        &self,
    ) -> Result<Result<NetworkStatusResponse, RosettaError>, String> {
        let req = NetworkRequest::new(self.network_id());
        let resp = self
            .http_client
            .send_post_request(
                &format!("http://{}/network/status", self.api_url),
                Some(HttpContentType::JSON),
                Some(serde_json::to_vec(&req).unwrap()),
                None,
            )
            .await;
        to_rosetta_response(resp)
    }

    pub async fn balance(
        &self,
        acc: AccountIdentifier,
    ) -> Result<Result<AccountBalanceResponse, RosettaError>, String> {
        let req = AccountBalanceRequest::new(
            self.network_id(),
            ic_rosetta_api::convert::to_model_account_identifier(&acc),
        );

        let resp = self
            .http_client
            .send_post_request(
                &format!("http://{}/account/balance", self.api_url),
                Some(HttpContentType::JSON),
                Some(serde_json::to_vec(&req).unwrap()),
                None,
            )
            .await;

        to_rosetta_response(resp)
    }

    pub async fn block_at(&self, idx: u64) -> Result<Result<BlockResponse, RosettaError>, String> {
        let block_id = PartialBlockIdentifier {
            index: Some(i64::try_from(idx).unwrap()),
            hash: None,
        };
        let req = BlockRequest::new(self.network_id(), block_id);

        let resp = self
            .http_client
            .send_post_request(
                &format!("http://{}/block", self.api_url),
                Some(HttpContentType::JSON),
                Some(serde_json::to_vec(&req).unwrap()),
                None,
            )
            .await;
        to_rosetta_response(resp)
    }

    pub async fn wait_for_block_at(&self, idx: u64) -> Result<Block, String> {
        let timeout = std::time::Duration::from_secs(5);
        let now = std::time::SystemTime::now();

        while now.elapsed().unwrap() < timeout {
            if let Ok(Ok(resp)) = self.block_at(idx).await {
                if let Some(b) = resp.block {
                    return Ok(b);
                }
            }
            delay_for(Duration::from_millis(100)).await;
        }
        Err(format!("Timeout on waiting for block at {}", idx))
    }

    pub async fn wait_for_tip_sync(&self, tip_idx: BlockHeight) -> Result<(), String> {
        let timeout = std::time::Duration::from_secs(5);
        let now = std::time::SystemTime::now();

        while now.elapsed().unwrap() < timeout {
            if let Ok(Ok(resp)) = self.network_status().await {
                if resp.current_block_identifier.index as u64 >= tip_idx {
                    return Ok(());
                }
            }
            delay_for(Duration::from_millis(100)).await;
        }

        Err(format!("Timeout on waiting for tip at {}", tip_idx))
    }

    // safe to call this multiple times
    pub fn stop(&mut self) {
        use nix::sys::signal::{kill, Signal::SIGTERM};
        use nix::unistd::Pid;
        kill(Pid::from_raw(self.process.id() as i32), SIGTERM).ok();

        let mut tries_left = 100i32;
        let backoff = std::time::Duration::from_millis(100);
        while tries_left > 0 {
            tries_left -= 1;
            match self.process.try_wait() {
                Ok(Some(status)) => {
                    if self.can_panic {
                        assert!(
                            status.success(),
                            "ic-rosetta-api did not finish successfully. Exit status: {}",
                            status,
                        );
                    }
                    break;
                }
                Ok(None) => std::thread::sleep(backoff),
                Err(_) => {
                    if self.can_panic {
                        panic!("wait for rosetta-api finish: rosetta-api did not start(?)")
                    } else {
                        break;
                    }
                }
            }
        }
        if tries_left == 0 {
            self.process.kill().ok();
            if self.can_panic {
                panic!(
                    "rosetta-api did not finish in {} sec",
                    (backoff * 100).as_secs_f32()
                );
            }
        }
    }
}

impl Drop for RosettaApiHandle {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.can_panic = false;
        }
        self.stop();
    }
}
