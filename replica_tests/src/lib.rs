use core::future::Future;
use ic_base_types::{PrincipalId, SubnetId};
use ic_canister_client::agent::Sender;
use ic_config::crypto::CryptoConfig;
use ic_config::Config;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_execution_environment::IngressHistoryReaderImpl;
use ic_interfaces::registry::RegistryClient;
use ic_interfaces::{
    execution_environment::{IngressHistoryReader, QueryHandler},
    p2p::IngressEventHandler,
    state_manager::StateReader,
};
use ic_metrics::MetricsRegistry;
use ic_prep::internet_computer::{IcConfig, TopologyConfig};
use ic_prep::node::{NodeConfiguration, NodeIndex};
use ic_prep::subnet_configuration::SubnetConfig;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_keys::SUBNET_LIST_KEY;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_replica::setup::setup_crypto_provider;
use ic_replicated_state::{CanisterState, ReplicatedState};
use ic_test_utilities::{
    types::ids::user_anonymous_id, types::messages::SignedIngressBuilder,
    universal_canister::UNIVERSAL_CANISTER_WASM, with_test_replica_logger,
};
use ic_transport::transport::create_transport;
use ic_types::user_error::RejectCode;
use ic_types::{
    ic00::{
        CanisterIdRecord, InstallCodeArgs, Method, Payload,
        ProvisionalCreateCanisterWithCyclesArgs, IC_00,
    },
    ingress::{IngressStatus, WasmResult},
    messages::{CanisterInstallMode, SignedIngress, UserQuery},
    replica_config::NODE_INDEX_DEFAULT,
    time::current_time_and_expiry_time,
    transport::TransportFlowConfig,
    user_error::UserError,
    CanisterId, Height, NodeId, RegistryVersion, Time,
};
use ic_utils::ic_features::*;
use slog_scope::info;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread::sleep;
use std::{
    cell::Cell,
    convert::TryFrom,
    thread,
    time::{Duration, Instant},
};

const CYCLES_BALANCE: u64 = 1 << 50;

/// Executes an ingress message and blocks till execution finishes.
///
/// Note: To ensure that this function does not block forever (in case of bugs),
/// this function will panic if the process is not finished in some amount of
/// time.
fn process_ingress(
    ingress_sender: &dyn IngressEventHandler,
    ingress_hist_reader: &dyn IngressHistoryReader,
    msg: SignedIngress,
    time_limit: Duration,
) -> Result<WasmResult, UserError> {
    let msg_id = msg.id();
    ingress_sender
        .on_ingress_message(msg)
        .expect("Failed to submit Ingress Message");

    let start = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(5));
        let ingress_result = (ingress_hist_reader.get_latest_status())(&msg_id);
        match ingress_result {
            IngressStatus::Completed { result, .. } => {
                // Don't forget! Signal the runtime to stop.
                return Ok(result);
            }
            IngressStatus::Failed { error, .. } => {
                // Don't forget! Signal the runtime to stop.
                return Err(error);
            }
            IngressStatus::Received { .. }
            | IngressStatus::Processing { .. }
            | IngressStatus::Unknown => (),
        }
        if Instant::now().duration_since(start) > time_limit {
            panic!("Ingress message did not finish executing in 300 seconds, panicking");
        }

        // Either this requires only few iterations, so waiting a bit is not an
        // issue. Or, it requires a lot of iterations and then we don't want to burn
        // CPU cycles on CI where such loops run in parallel and potentially steal
        // each others CPU time for no good reason.
        sleep(Duration::from_millis(100));
    }
}

fn process_query(
    app: &dyn QueryHandler<State = ReplicatedState>,
    query: UserQuery,
    processing_state: Arc<ReplicatedState>,
) -> Result<WasmResult, UserError> {
    let result = app.query(query, processing_state, Vec::new());
    if let Ok(WasmResult::Reply(result)) = result.clone() {
        info!(
            "Response{}: {}",
            match result.len() {
                0..=99 => "".to_string(),
                _ => format!(" (first 100/{} bytes)", result.len()),
            },
            match result.len() {
                0..=99 => String::from_utf8_lossy(&result),
                _ => String::from_utf8_lossy(&result[..100]),
            }
        )
    };

    result
}

/// This function is here to maintain compatibility with existing tests
/// the *_async is strictly more powerful
pub fn simple_canister_test<F, Out>(f: F) -> Out
where
    F: FnOnce(UniversalCanister) -> Out + 'static,
{
    simple_canister_test_async(|universal_canister| async { f(universal_canister) })
}

/// Initializes a "simple" canister test.
///
/// A simple canister test initializes a `UniversalCanister` that can test
/// different functionality without having the implementor write WAT manually.
pub fn simple_canister_test_async<F, Fut, Out>(f: F) -> Out
where
    Fut: Future<Output = Out>,
    F: FnOnce(UniversalCanister) -> Fut + 'static,
{
    canister_test_async(|runtime| async {
        let canister_id = runtime.create_universal_canister();
        let universal_canister = UniversalCanister {
            runtime,
            canister_id,
        };

        f(universal_canister).await
    })
}

/// An Internet Computer test runtime that:
///
/// * provides an environment with a single replica
/// * does not use http connections
///
/// The code of the replica is the real one, only the interface is changed, with
/// function calls instead of http calls.
pub struct LocalTestRuntime {
    pub query_handler: Arc<dyn QueryHandler<State = ReplicatedState>>,
    pub ingress_sender: Arc<dyn IngressEventHandler>,
    pub ingress_history_reader: Arc<dyn IngressHistoryReader>,
    pub state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    pub node_id: NodeId,
    nonce: std::cell::Cell<u64>,
    pub ingress_time_limit: Duration,
}

/// This function is here to maintain compatibility with existing tests
/// the *_async is strictly more powerful
pub fn canister_test<F, Out>(f: F) -> Out
where
    F: FnOnce(LocalTestRuntime) -> Out + 'static,
{
    canister_test_async(|runtime| async { f(runtime) })
}

pub fn canister_test_async<Fut, F, Out>(test: F) -> Out
where
    Fut: Future<Output = Out>,
    F: FnOnce(LocalTestRuntime) -> Fut + 'static,
{
    let (config, _tmpdir) = Config::temp_config();
    canister_test_with_config_async(
        config,
        ic_config::subnet_config::SubnetConfig::default_system_subnet(),
        get_ic_config(),
        test,
    )
}

pub fn canister_test_with_config<F, Out>(config: Config, f: F) -> Out
where
    F: FnOnce(LocalTestRuntime) -> Out + 'static,
{
    let ic_config = get_ic_config();
    canister_test_with_ic_config(config, ic_config, f)
}

pub fn canister_test_with_ic_config<F, Out>(config: Config, ic_config: IcConfig, f: F) -> Out
where
    F: FnOnce(LocalTestRuntime) -> Out + 'static,
{
    canister_test_with_config_async(
        config,
        ic_config::subnet_config::SubnetConfig::default_system_subnet(),
        ic_config,
        |runtime| async { f(runtime) },
    )
}

pub fn get_ic_config() -> IcConfig {
    let subnet_index = 0;

    // Allocate a temporary directory where ic-prep generates the registry and the
    // crypto state.
    let prep_dir = tempfile::Builder::new()
        .prefix("ic_prep")
        .tempdir()
        .unwrap();

    // We use the `ic-prep` crate to generate the secret key store and registry
    // entries. The topology contains a single node.
    let mut subnet_nodes: BTreeMap<NodeIndex, NodeConfiguration> = BTreeMap::new();
    subnet_nodes.insert(
        NODE_INDEX_DEFAULT,
        NodeConfiguration {
            xnet_api: vec!["http://0.0.0.0:0".parse().expect("can't fail")],
            public_api: vec!["http://0.0.0.0:0".parse().expect("can't fail")],
            private_api: vec![],
            p2p_addr: "org.dfinity.p2p1://0.0.0.0:0".parse().expect("can't fail"),
            prometheus_metrics: vec![],
            p2p_num_flows: 1,
            p2p_start_flow_tag: 0,
            node_operator_principal_id: None,
        },
    );

    let mut topology_config: TopologyConfig = TopologyConfig::default();
    topology_config.insert_subnet(
        subnet_index,
        SubnetConfig::new(
            subnet_index,
            subnet_nodes,
            None,
            None,
            None,
            None,
            None,
            Some(Duration::from_millis(2000)), // Notary time out
            Some(Height::from(19)),            // DKG interval length
            None,
            SubnetType::System,
        ),
    );

    let provisional_whitelist = ProvisionalWhitelist::All;

    // The last argument is true, as that is the default case. False is used only
    // for ic-prep when we handle a specific deployment scenario: deploying
    // without assigning nodes to a particular subnet.
    IcConfig::new(
        prep_dir.path(),
        topology_config,
        /* replica_version_id= */ None,
        /* replica_download_url= */ None,
        /* replica_hash= */ None,
        /* generate_subnet_records= */ true,
        /* nns_subnet_id= */ Some(subnet_index),
        /* release_package_url= */ None,
        /* release_package_sha256_hex= */ None,
        /* provisional_whitelist */ Some(provisional_whitelist),
        None,
        None,
    )
}

fn get_subnet_type(
    registry: &dyn RegistryClient,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
) -> SubnetType {
    loop {
        match registry.get_subnet_record(subnet_id, registry_version) {
            Ok(subnet_record) => {
                break match subnet_record {
                    Some(record) => match SubnetType::try_from(record.subnet_type) {
                        Ok(subnet_type) => subnet_type,
                        Err(e) => panic!("Could not parse SubnetType: {}", e),
                    },
                    // This can only happen if the registry is corrupted, so better to crash.
                    None => panic!(
                        "Failed to find a subnet record for subnet: {} in the registry.",
                        subnet_id
                    ),
                };
            }
            Err(err) => {
                info!(
                    "Unable to read the subnet record: {}\nTrying again...",
                    err.to_string(),
                );
                sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

pub fn canister_test_with_config_async<Fut, F, Out>(
    mut config: Config,
    subnet_config: ic_config::subnet_config::SubnetConfig,
    ic_config: IcConfig,
    test: F,
) -> Out
where
    Fut: Future<Output = Out>,
    F: FnOnce(LocalTestRuntime) -> Fut + 'static,
{
    if subnet_config.cow_memory_manager_config.enabled {
        cow_state_feature::enable(cow_state_feature::cow_state);
    } else {
        cow_state_feature::disable(cow_state_feature::cow_state);
    }

    with_test_replica_logger(|logger| {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let local = tokio::task::LocalSet::new();
        let actix_sys = actix::System::run_in_tokio("canister_test_system", &local);
        let result = rt.enter(|| {
            let metrics_registry = MetricsRegistry::new();

            let init_ic = ic_config.initialize().expect("can't fail");

            let init_subnet = init_ic.initialized_topology.values().next().unwrap();
            let init_node = init_subnet.initialized_nodes.values().next().unwrap();
            let crypto_root = init_node.crypto_path();
            config.crypto = CryptoConfig { crypto_root };

            // load the registry file written by ic-prep
            let data_provider =
                ProtoRegistryDataProvider::load_from_file(init_ic.registry_path().as_path());
            let registry = Arc::new(FakeRegistryClient::new(Arc::new(data_provider)));
            registry.update_to_latest_version();
            let registry = registry as Arc<dyn RegistryClient + Send + Sync>;
            let crypto = setup_crypto_provider(
                &config.crypto,
                registry.clone(),
                logger.clone(),
                Some(&metrics_registry),
            );
            let node_id = crypto.get_node_id();
            let crypto = Arc::new(crypto);
            let subnet_list_pb = registry
                .get_versioned_value(SUBNET_LIST_KEY, registry.get_latest_version())
                .expect("did not find subnet list in registry")
                .value
                .expect("did not find subnet id");
            // FIXME: This is a very bad way of extracting the subnet id from the protobuf
            // list.
            let subnet_id = SubnetId::from(
                PrincipalId::try_from(&subnet_list_pb[2..])
                    .expect("cannot parse subnet id as principal"),
            );

            let subnet_type = get_subnet_type(&*registry, subnet_id, registry.get_latest_version());

            config.transport.node_ip = "0.0.0.0".to_string();
            config.transport.p2p_flows = vec![TransportFlowConfig {
                flow_tag: 0,
                server_port: 1234,
                queue_size: 0,
            }];
            let temp_node = node_id;
            let transport = create_transport(
                node_id,
                config.transport.clone(),
                registry.get_latest_version(),
                metrics_registry.clone(),
                Arc::clone(&crypto) as Arc<dyn TlsHandshake + Send + Sync>,
                tokio::runtime::Handle::current(),
                logger.clone(),
            );
            let (_, state_manager, query_handler, mut p2p, p2p_event_handler, _, _, _) =
                ic_replica::setup_p2p::construct_p2p_stack(
                    logger.clone(),
                    config.clone(),
                    subnet_config,
                    temp_node,
                    subnet_id,
                    subnet_type,
                    registry.clone(),
                    crypto,
                    metrics_registry,
                    transport,
                    None,
                    None,
                )
                .expect("Failed to setup p2p");

            let ingress_history_reader =
                IngressHistoryReaderImpl::new(Arc::clone(&state_manager) as Arc<_>);

            let ingress_sender = p2p_event_handler.clone();

            p2p.run();

            std::thread::sleep(std::time::Duration::from_millis(1000));
            // Before height 1 the replica hasn't figured out what
            // the time is. So it's impossible to construct a message
            // with an expiry time that is simultaneously acceptable
            // before height 1 and after height 1 or above.
            //
            // So, loop until we're at height 1 or above.
            while state_manager.get_latest_state().height().get() < 1 {
                // either this requires only few iterations, so
                // waiting a bit is not an issue. Or, it requires
                // a lot of iterations and then we don't want to
                // burn CPU cycles on CI where such loops run in
                // parallel and potentially steal each others CPU
                // time for no good reason.
                thread::sleep(Duration::from_millis(100));
            }

            let runtime = LocalTestRuntime {
                query_handler,
                ingress_sender,
                ingress_history_reader: Arc::new(ingress_history_reader),
                state_reader: state_manager,
                node_id,
                nonce: Cell::new(0),
                ingress_time_limit: Duration::from_secs(300),
            };
            tokio::runtime::Handle::current().block_on(test(runtime))
        });
        actix::System::current().stop();
        local.block_on(&mut rt, actix_sys).unwrap();
        result
    })
}

impl LocalTestRuntime {
    /// This is not a cryptographically secure nonce, rather this is just a
    /// number which is different every time you call this function in a given
    /// canister test
    pub fn get_nonce(&self) -> u64 {
        let nonce = self.nonce.get();
        self.nonce.set(nonce + 1);
        nonce
    }

    pub fn upgrade_canister(
        &self,
        canister_id: &CanisterId,
        wat: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.install_canister_helper(InstallCodeArgs::new(
            CanisterInstallMode::Upgrade,
            *canister_id,
            wabt::wat2wasm(wat).expect("couldn't convert wat -> wasm"),
            payload,
            None,
            None,
            None,
        ))
    }

    pub fn create_canister(&self) -> Result<CanisterId, UserError> {
        self.create_canister_with_anonymous(self.get_nonce(), CYCLES_BALANCE)
    }

    pub fn create_canister_with_cycles(&self, num_cycles: u64) -> Result<CanisterId, UserError> {
        self.create_canister_with_anonymous(self.get_nonce(), num_cycles)
    }

    pub fn create_canister_with_nonce(&self, nonce: u64) -> Result<CanisterId, UserError> {
        self.create_canister_with_anonymous(nonce, CYCLES_BALANCE)
    }

    pub fn create_canister_with_anonymous(
        &self,
        nonce: u64,
        num_cycles: u64,
    ) -> Result<CanisterId, UserError> {
        let res = process_ingress(
            self.ingress_sender.as_ref(),
            self.ingress_history_reader.as_ref(),
            SignedIngressBuilder::new()
                .expiry_time(current_time_and_expiry_time().1)
                .method_name(Method::ProvisionalCreateCanisterWithCycles)
                .canister_id(IC_00)
                .method_payload(
                    ProvisionalCreateCanisterWithCyclesArgs::new(Some(num_cycles)).encode(),
                )
                .nonce(nonce)
                .build(),
            self.ingress_time_limit,
        )?;

        let canister_id = match res {
            WasmResult::Reply(reply) => CanisterIdRecord::decode(reply.as_slice())
                .unwrap()
                .get_canister_id(),
            // Got an unexpected result.
            unexpected => panic!("Got unexpected val {:?}", unexpected),
        };

        Ok(canister_id)
    }

    pub fn install_canister(
        &self,
        canister_id: &CanisterId,
        wat: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.install_canister_wasm(
            canister_id,
            wabt::wat2wasm(wat).expect("couldn't convert wat -> wasm"),
            payload,
            None,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install_canister_wasm(
        &self,
        canister_id: &CanisterId,
        wasm: Vec<u8>,
        payload: Vec<u8>,
        compute_allocation: Option<u64>,
        memory_allocation: Option<u64>,
        query_allocation: Option<u64>,
    ) -> Result<WasmResult, UserError> {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Install,
            *canister_id,
            wasm,
            payload,
            compute_allocation,
            memory_allocation,
            query_allocation,
        );

        self.install_canister_helper(args)
    }

    /// Create (and install) the universal canister.
    pub fn create_universal_canister(&self) -> CanisterId {
        self.create_universal_canister_with_args(vec![], CYCLES_BALANCE)
    }

    pub fn create_universal_canister_with_args<P: Into<Vec<u8>>>(
        &self,
        payload: P,
        num_cycles: u64,
    ) -> CanisterId {
        let (canister_id, res) = self.create_and_install_canister_wasm(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            payload.into(),
            None,
            None,
            None,
            num_cycles,
        );
        res.unwrap();
        canister_id
    }

    pub fn create_and_install_canister(
        &self,
        wat: &str,
        payload: Vec<u8>,
    ) -> (CanisterId, Result<WasmResult, UserError>) {
        let canister_id = self.create_canister().unwrap();
        (
            canister_id,
            self.install_canister(&canister_id, wat, payload),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_and_install_canister_wasm(
        &self,
        wasm: Vec<u8>,
        payload: Vec<u8>,
        compute_allocation: Option<u64>,
        memory_allocation: Option<u64>,
        query_allocation: Option<u64>,
        num_cycles: u64,
    ) -> (CanisterId, Result<WasmResult, UserError>) {
        let canister_id = self.create_canister_with_cycles(num_cycles).unwrap();
        (
            canister_id,
            self.install_canister_wasm(
                &canister_id,
                wasm,
                payload,
                compute_allocation,
                memory_allocation,
                query_allocation,
            ),
        )
    }

    pub fn install_canister_helper(
        &self,
        install_code_args: InstallCodeArgs,
    ) -> Result<WasmResult, UserError> {
        process_ingress(
            self.ingress_sender.as_ref(),
            self.ingress_history_reader.as_ref(),
            SignedIngressBuilder::new()
                .expiry_time(current_time_and_expiry_time().1)
                .canister_id(IC_00)
                .method_name(Method::InstallCode)
                .method_payload(install_code_args.encode())
                .nonce(self.get_nonce())
                .build(),
            self.ingress_time_limit,
        )
    }

    pub fn canister_state(&self, canister_id: &CanisterId) -> CanisterState {
        self.state_reader
            .get_latest_state()
            .get_ref()
            .canister_state(&canister_id)
            .cloned()
            .unwrap()
    }

    pub fn query_raw<M: Into<String>>(
        &self,
        canister_id: CanisterId,
        method_name: M,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.query_handler.query(
            UserQuery {
                receiver: canister_id,
                source: user_anonymous_id(),
                method_name: method_name.into(),
                method_payload,
                ingress_expiry: 0,
                nonce: None,
            },
            self.state_reader.get_latest_state().take(),
            Vec::new(),
        )
    }

    pub fn query<M: Into<String>, P: Into<Vec<u8>>>(
        &self,
        canister_id: CanisterId,
        method_name: M,
        method_payload: P,
    ) -> Result<WasmResult, UserError> {
        process_query(
            self.query_handler.as_ref(),
            UserQuery {
                receiver: canister_id,
                source: user_anonymous_id(),
                method_name: method_name.into(),
                method_payload: method_payload.into(),
                ingress_expiry: 0,
                nonce: None,
            },
            self.state_reader.get_latest_state().take(),
        )
    }

    pub fn ingress<M: ToString, P: Into<Vec<u8>>>(
        &self,
        canister_id: CanisterId,
        method_name: M,
        payload: P,
    ) -> Result<WasmResult, UserError> {
        self.ingress_with_nonce(canister_id, method_name, payload, self.get_nonce())
    }

    pub fn ingress_with_sender<M: ToString, P: Into<Vec<u8>>>(
        &self,
        canister_id: CanisterId,
        method_name: M,
        payload: P,
        sender: &Sender,
    ) -> Result<WasmResult, UserError> {
        process_ingress(
            self.ingress_sender.as_ref(),
            self.ingress_history_reader.as_ref(),
            SignedIngressBuilder::new()
                .expiry_time(current_time_and_expiry_time().1)
                .canister_id(canister_id)
                .method_name(method_name.to_string())
                .method_payload(payload.into())
                .nonce(self.get_nonce())
                .sign_for_sender(sender)
                .build(),
            self.ingress_time_limit,
        )
    }

    pub fn ingress_with_expiry_and_nonce<M: ToString, P: Into<Vec<u8>>>(
        &self,
        canister_id: CanisterId,
        method_name: M,
        payload: P,
        expiry_time: Time,
        nonce: u64,
    ) -> Result<WasmResult, UserError> {
        process_ingress(
            self.ingress_sender.as_ref(),
            self.ingress_history_reader.as_ref(),
            SignedIngressBuilder::new()
                .expiry_time(expiry_time)
                .canister_id(canister_id)
                .method_name(method_name.to_string())
                .method_payload(payload.into())
                .nonce(nonce)
                .build(),
            self.ingress_time_limit,
        )
    }

    pub fn ingress_with_nonce<M: ToString, P: Into<Vec<u8>>>(
        &self,
        canister_id: CanisterId,
        method_name: M,
        payload: P,
        nonce: u64,
    ) -> Result<WasmResult, UserError> {
        process_ingress(
            self.ingress_sender.as_ref(),
            self.ingress_history_reader.as_ref(),
            SignedIngressBuilder::new()
                .expiry_time(current_time_and_expiry_time().1)
                .canister_id(canister_id)
                .method_name(method_name.to_string())
                .method_payload(payload.into())
                .nonce(nonce)
                .build(),
            self.ingress_time_limit,
        )
    }
}

/// A simple wrapper for bundling the universal canister and the test runtime.
pub struct UniversalCanister {
    runtime: LocalTestRuntime,
    canister_id: CanisterId,
}

impl<'a> UniversalCanister {
    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }
    pub fn node_id(&self) -> NodeId {
        self.runtime.node_id
    }

    pub fn query<P: Into<Vec<u8>>>(&self, payload: P) -> Result<WasmResult, UserError> {
        self.runtime
            .query(self.canister_id(), "query", payload.into())
    }

    pub fn update<P: Into<Vec<u8>>>(&self, payload: P) -> Result<WasmResult, UserError> {
        self.runtime
            .ingress(self.canister_id(), "update", payload.into())
    }
}

pub fn assert_reject(res: Result<WasmResult, UserError>, reject_code: RejectCode) {
    match res {
        Ok(WasmResult::Reject(rej)) => assert_eq!(rej.as_bytes()[0], reject_code as u8),
        _ => unreachable!("Assert reject failed."),
    }
}

pub fn assert_reply(res: Result<WasmResult, UserError>, bytes: &[u8]) {
    match res {
        Ok(WasmResult::Reply(res)) => assert_eq!(res.as_slice(), bytes),
        _ => unreachable!("Assert reply failed."),
    }
}
