//! Transport client implementation for testing.

use async_trait::async_trait;
///
/// The test client instantiates the transport object and goes through the
/// sequence, expected to be followed by transport clients like P2P:
///   - Register a client (of type P2P)
///   - Adds valid peers
///
/// The topology:
///   - Node 1 is the source, Node 2 and 3 are relays
///   - These are connected in a ring. The message flow: 1 -> 2 -> 3 -> 1
///   - Node 1 generates a message, other nodes relay it to next node in the
///     ring, until Node 1 gets it back
///  - There are two flows/connections between each pair: 1 <-> 2, 2 <-> 3, 3
///    <-> 1 (total 6 flows/connections)
///
/// To run (repeat this for nodes {1, 2, 3}):
/// cargo run --bin transport_client --
///     --node <node_id>
///     --message_count <count>
///
/// If not specified, message_count = 100 (default, applies only for the source
/// node)
use clap::{App, Arg, ArgMatches};
use crossbeam_channel::{self, Receiver, RecvTimeoutError, Sender};
use rand::Rng;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

pub mod test_utils;

use ic_interfaces::transport::{AsyncTransportEventHandler, SendError, Transport};
use ic_logger::{error, info, warn, LoggerImpl, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::node::v1::{
    connection_endpoint::Protocol, ConnectionEndpoint, FlowEndpoint, NodeRecord,
};
use ic_transport::transport::create_transport;
use ic_types::transport::TransportErrorCode;
use ic_types::{
    transport::{
        FlowId, FlowTag, TransportClientType, TransportConfig, TransportFlowConfig,
        TransportFlowInfo, TransportPayload, TransportStateChange,
    },
    NodeId, PrincipalId, RegistryVersion, SubnetId,
};
use test_utils::{create_crypto, to_node_id};

// From the on_message() handler
struct TestMessage {
    flow_id: FlowId,
    payload: TransportPayload,
}

type MpscSender = Sender<TestMessage>;
type MpscReceiver = Receiver<TestMessage>;

const ARG_NODE_ID: &str = "node";
const ARG_MSG_COUNT: &str = "count";

const REG_V1: RegistryVersion = RegistryVersion::new(1);
const SUBNET_ID: u8 = 100;
const FLOW_TAG_1: u32 = 1234;
const FLOW_TAG_2: u32 = 5678;

const TEST_MESSAGE_LEN: usize = 1_000_000;

#[derive(Debug)]
enum Role {
    Source,
    Relay,
}

struct TestClient {
    transport: Arc<dyn Transport>,
    client_type: TransportClientType,
    _event_handler: Arc<TestClientEventHandler>,
    prev: NodeId,
    next: NodeId,
    prev_node_record: NodeRecord,
    next_node_record: NodeRecord,
    receiver: MpscReceiver,
    active_flows: Arc<Mutex<HashSet<TransportFlowInfo>>>,
    registry_version: RegistryVersion,
    log: ReplicaLogger,
}

impl TestClient {
    fn new(
        transport: Arc<dyn Transport>,
        registry_node_list: &[(NodeId, NodeRecord)],
        prev: &NodeId,
        next: &NodeId,
        registry_version: RegistryVersion,
        log: ReplicaLogger,
    ) -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let active_flows = Arc::new(Mutex::new(HashSet::new()));
        let event_handler = Arc::new(TestClientEventHandler {
            sender,
            active_flows: active_flows.clone(),
            log: log.clone(),
        });
        let client_type = TransportClientType::P2P;
        if let Err(e) = transport.register_client(client_type, event_handler.clone()) {
            warn!(log, "Failed to register client: {:?}", e);
            exit(1);
        };

        let prev_node_record = match registry_node_list.iter().position(|n| n.0 == *prev) {
            Some(pos) => registry_node_list[pos].1.clone(),
            None => panic!("Failed to find prev record"),
        };
        let next_node_record = match registry_node_list.iter().position(|n| n.0 == *next) {
            Some(pos) => registry_node_list[pos].1.clone(),
            None => panic!("Failed to find next record"),
        };

        TestClient {
            transport,
            client_type,
            _event_handler: event_handler,
            prev: *prev,
            next: *next,
            prev_node_record,
            next_node_record,
            receiver,
            active_flows,
            registry_version,
            log,
        }
    }

    fn start_connections(&self) {
        if let Err(e) = self.transport.start_connections(
            self.client_type,
            &self.prev,
            &self.prev_node_record,
            self.registry_version,
        ) {
            warn!(
                self.log,
                "Failed to start_connections(): peer = {:?} err = {:?}", self.prev, e
            );
            exit(1);
        }
        if let Err(e) = self.transport.start_connections(
            self.client_type,
            &self.next,
            &self.next_node_record,
            self.registry_version,
        ) {
            warn!(
                self.log,
                "Failed to start_connections(): peer = {:?} err = {:?}", self.next, e
            );
            exit(1);
        }
    }

    fn stop_connections(&self) {
        if let Err(e) =
            self.transport
                .stop_connections(self.client_type, &self.prev, self.registry_version)
        {
            warn!(
                self.log,
                "Failed to stop_connections(): peer = {:?} err = {:?}", self.prev, e
            );
            exit(1);
        }
        if let Err(e) =
            self.transport
                .stop_connections(self.client_type, &self.next, self.registry_version)
        {
            warn!(
                self.log,
                "Failed to stop_connections(): peer = {:?} err = {:?}", self.next, e
            );
            exit(1);
        }
    }

    // Waits for the flows/connections to be up
    fn wait_for_flow_up(&self) {
        let expected_flows = 4;
        for _ in 0..10 {
            let num_flows = self.active_flows.lock().unwrap().len();
            if num_flows == expected_flows {
                info!(self.log, "Expected flows up: {}", expected_flows);
                return;
            }
            info!(
                self.log,
                "Flows up: {}/{}, to wait ...", num_flows, expected_flows
            );
            thread::sleep(time::Duration::from_secs(3));
        }

        warn!(self.log, "All flows not up, exiting");
        exit(1);
    }

    // Relay processing. Receives the messages and relays it to next peer.
    fn relay_loop(&self) {
        loop {
            let msg = self.receiver.recv().unwrap();
            if msg.flow_id.peer_id != self.prev {
                warn!(self.log, "relay(): unexpected flow id: {:?}", msg.flow_id);
                exit(1);
            }

            let flow_id = msg.flow_id;
            let msg_len = msg.payload.0.len();
            if let Err(e) =
                self.transport
                    .send(self.client_type, &self.next, flow_id.flow_tag, msg.payload)
            {
                warn!(
                    self.log,
                    "relay(): Failed to send(): peer = {:?}, flow = {:?}, err = {:?}",
                    self.next,
                    flow_id,
                    e
                );
                exit(1);
            } else {
                info!(
                    self.log,
                    "relay(): relayed from {:?} -> peer {:?}, msg_len = {}",
                    flow_id,
                    self.next,
                    msg_len
                );
            }
        }
    }

    // Source mode: send the  message, receive the echoed the message, compare them
    fn send_receive_compare(&self, count: usize, flow_tag: FlowTag) {
        let send_flow = FlowId::new(TransportClientType::P2P, self.next, flow_tag);
        let receive_flow = FlowId::new(TransportClientType::P2P, self.prev, flow_tag);
        let send_msg = TestClient::build_message();
        let send_copy = send_msg.clone();
        if let Err(e) = self.transport.send(
            self.client_type,
            &send_flow.peer_id,
            send_flow.flow_tag,
            send_msg,
        ) {
            warn!(
                self.log,
                "send_receive_compare(): failed to send(): flow = {:?} err = {:?}", send_flow, e
            );
            exit(1);
        } else {
            info!(
                self.log,
                "send_receive_compare([{}]): sent message: flow = {:?}, msg_len = {}",
                count,
                send_flow,
                send_copy.0.len(),
            );
        }

        let rcv_msg = match self.receive() {
            Some(msg) => msg,
            None => exit(1),
        };
        info!(
            self.log,
            "send_receive_compare([{}]): received response: flow = {:?}, msg_len = {}",
            count,
            rcv_msg.flow_id,
            rcv_msg.payload.0.len()
        );

        if !self.compare(receive_flow, send_copy, rcv_msg) {
            exit(1);
        }
    }

    // Reads the next message from the channel
    fn receive(&self) -> Option<TestMessage> {
        match self.receiver.recv_timeout(time::Duration::from_secs(10)) {
            Ok(msg) => Some(msg),
            Err(RecvTimeoutError::Timeout) => {
                warn!(self.log, "Message receive timed out");
                None
            }
            Err(e) => {
                warn!(self.log, "Failed to receive message: {:?}", e);
                exit(1);
            }
        }
    }

    // Builds the transport message with the given client/message types, and
    // randomized payload
    fn build_message() -> TransportPayload {
        let mut rng = rand::thread_rng();
        let mut v: Vec<u8> = Vec::new();
        for _ in 0..TEST_MESSAGE_LEN {
            v.push(rng.gen::<u8>());
        }

        TransportPayload(v)
    }

    // Compares the two messages(hdr and payload parts)
    fn compare(&self, flow_id: FlowId, payload: TransportPayload, rcv_msg: TestMessage) -> bool {
        if rcv_msg.flow_id != flow_id {
            warn!(self.log, "compare(): FlowTag mismatch");
            return false;
        }

        if payload.0.len() != rcv_msg.payload.0.len() {
            warn!(self.log, "compare(): Length mismatch");
            return false;
        }

        for i in 0..payload.0.len() {
            if payload.0[i] != rcv_msg.payload.0[i] {
                warn!(self.log, "Payload mismatch");
                return false;
            }
        }

        true
    }
}

struct TestClientEventHandler {
    sender: MpscSender,
    active_flows: Arc<Mutex<HashSet<TransportFlowInfo>>>,
    log: ReplicaLogger,
}

impl TestClientEventHandler {
    fn on_message(&self, flow_id: FlowId, message: TransportPayload) -> Option<TransportPayload> {
        self.sender
            .send(TestMessage {
                flow_id,
                payload: message,
            })
            .expect("on_message(): failed to send");

        None
    }

    fn on_error(&self, flow: FlowId, error: TransportErrorCode) {
        error!(self.log, "on_error(): Flow: {:?}, error: {:?}", flow, error);
    }

    fn on_state_change(&self, change: TransportStateChange) {
        info!(self.log, "on_state_change(): {:?}", change);
        match change {
            TransportStateChange::PeerFlowUp(flow) => {
                self.active_flows.lock().unwrap().insert(flow);
            }
            TransportStateChange::PeerFlowDown(flow) => {
                self.active_flows.lock().unwrap().remove(&flow);
            }
        }
    }
}

#[async_trait]
impl AsyncTransportEventHandler for TestClientEventHandler {
    async fn send_message(&self, flow: FlowId, message: TransportPayload) -> Result<(), SendError> {
        self.on_message(flow, message);
        Ok(())
    }

    async fn state_changed(&self, state_change: TransportStateChange) {
        self.on_state_change(state_change)
    }

    async fn error(&self, flow: FlowId, error: TransportErrorCode) {
        self.on_error(flow, error);
    }
}

// Returns the command line argument matcher.
fn cmd_line_matches() -> ArgMatches<'static> {
    App::new("Test Transport Client")
        .about("Test program to test the transport layer")
        .arg(
            Arg::with_name(ARG_NODE_ID)
                .long("node")
                .help("node id [1..3]")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(ARG_MSG_COUNT)
                .long("message_count")
                .help("Message Count")
                .default_value("100")
                .takes_value(true),
        )
        .get_matches()
}

#[derive(Debug)]
struct ConfigAndRecords {
    config: TransportConfig,
    node_records: Vec<(NodeId, NodeRecord)>,
}

// Generates the config and the registry node records for the three nodes
// Returns a map of NodeId -> (TransportConfig, NodeRecord)
// TODO: this should come off config files instead of hardcoding.
fn generate_config_and_registry(node_id: &NodeId) -> ConfigAndRecords {
    // Tuples: (NodeId, IP, server port 1, server port 2)
    let node_info = vec![
        (to_node_id(1), "127.0.0.1".to_string(), 4100, 4101),
        (to_node_id(2), "127.0.0.1".to_string(), 4102, 4103),
        (to_node_id(3), "127.0.0.1".to_string(), 4104, 4105),
    ];

    let mut config = None;
    let mut node_records = Vec::new();
    for n in node_info.iter() {
        if *node_id == n.0 {
            config = Some(TransportConfig {
                node_ip: n.1.clone(),
                p2p_flows: vec![
                    TransportFlowConfig {
                        flow_tag: FLOW_TAG_1,
                        server_port: n.2,
                        queue_size: 1024,
                    },
                    TransportFlowConfig {
                        flow_tag: FLOW_TAG_2,
                        server_port: n.3,
                        queue_size: 1024,
                    },
                ],
            });
        }

        let mut node_record: NodeRecord = Default::default();
        node_record.p2p_flow_endpoints.push(FlowEndpoint {
            flow_tag: FLOW_TAG_1,
            endpoint: Some(ConnectionEndpoint {
                ip_addr: n.1.clone(),
                port: n.2 as u32,
                protocol: Protocol::P2p1Tls13 as i32,
            }),
        });
        node_record.p2p_flow_endpoints.push(FlowEndpoint {
            flow_tag: FLOW_TAG_2,
            endpoint: Some(ConnectionEndpoint {
                ip_addr: n.1.clone(),
                port: n.3 as u32,
                protocol: Protocol::P2p1Tls13 as i32,
            }),
        });

        node_records.push((n.0, node_record));
    }

    ConfigAndRecords {
        config: config.unwrap(),
        node_records,
    }
}

// Returns the peers: prev/next in the ring.
fn parse_topology(
    registry_node_list: &[(NodeId, NodeRecord)],
    node_id: &NodeId,
) -> (NodeId, NodeId, Role) {
    let node_ids: Vec<NodeId> = registry_node_list.iter().map(|n| n.0).collect();
    assert_eq!(node_ids.contains(&node_id), true);

    let l = node_ids.len();
    assert_eq!(l >= 3, true);
    let role = if *node_id == node_ids[0] {
        Role::Source
    } else {
        Role::Relay
    };
    match registry_node_list.iter().position(|n| n.0 == *node_id) {
        Some(pos) => {
            let prev = if pos == 0 { l - 1 } else { pos - 1 };
            let next = (pos + 1) % l;
            (node_ids[prev], node_ids[next], role)
        }
        None => panic!("Node not found in registry.json"),
    }
}

#[tokio::main]
async fn main() {
    // Cmd line params.
    let matches = cmd_line_matches();
    let v: Vec<u8> = vec![SUBNET_ID];
    let subnet_id = SubnetId::from(PrincipalId::try_from(v.as_slice()).unwrap());
    let node_id_val = matches
        .value_of(ARG_NODE_ID)
        .unwrap()
        .parse::<u8>()
        .unwrap();
    let message_count = matches
        .value_of(ARG_MSG_COUNT)
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let node_id = to_node_id(node_id_val);
    let node_number = node_id_val as usize;

    let logger = LoggerImpl::new(&Default::default(), "transport_test_client".to_string());
    let log = ReplicaLogger::new(logger.root.clone().into());
    let config_and_records = generate_config_and_registry(&node_id);

    let (prev, next, role) = parse_topology(config_and_records.node_records.as_slice(), &node_id);
    info!(log, "subnet_id = {:?} node_id = {:?}", subnet_id, node_id,);
    info!(
        log,
        "prev = {:?}, next = {:?}, role = {:?}", prev, next, role
    );

    let registry_version = REG_V1;
    let crypto = match create_crypto(node_number, 3, node_id, registry_version) {
        Ok(crypto) => crypto,
        Err(_) => {
            panic!("unable to create crypto");
        }
    };

    println!("starting transport...");
    let transport = create_transport(
        node_id,
        config_and_records.config.clone(),
        registry_version,
        MetricsRegistry::global(),
        crypto,
        tokio::runtime::Handle::current(),
        log.clone(),
    );

    let test_client = TestClient::new(
        transport,
        config_and_records.node_records.as_slice(),
        &prev,
        &next,
        registry_version,
        log.clone(),
    );
    test_client.start_connections();

    match role {
        Role::Source => {
            test_client.wait_for_flow_up();
            for i in 1..=message_count {
                test_client.send_receive_compare(i, FlowTag::from(FLOW_TAG_1));
                test_client.send_receive_compare(i, FlowTag::from(FLOW_TAG_2));
            }
            test_client.stop_connections();
            info!(log, "Test successful");
        }
        Role::Relay => test_client.relay_loop(),
    }
}
