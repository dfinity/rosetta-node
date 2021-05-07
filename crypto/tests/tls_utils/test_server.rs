#![allow(clippy::unwrap_used)]
use crate::tls_utils::{temp_crypto_component_with_tls_keys, REG_V1};
use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_tls_interfaces::{
    AllowedClients, AuthenticatedPeer, Peer, SomeOrAllNodes, TlsHandshake, TlsReadHalf,
    TlsServerHandshakeError, TlsWriteHalf,
};
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client::fake::FakeRegistryClient;
use ic_types::NodeId;
use proptest::std_facade::BTreeSet;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct ServerBuilder {
    node_id: NodeId,
    msg_for_client: Option<String>,
    msg_expected_from_client: Option<String>,
    allowed_nodes: Option<SomeOrAllNodes>,
    allowed_certs: Vec<X509PublicKeyCert>,
}

impl ServerBuilder {
    pub fn with_msg_for_client(mut self, msg: &str) -> ServerBuilder {
        self.msg_for_client = Some(msg.to_string());
        self
    }

    pub fn expect_msg_from_client(mut self, msg: &str) -> ServerBuilder {
        self.msg_expected_from_client = Some(msg.to_string());
        self
    }

    pub fn add_allowed_client(mut self, client: NodeId) -> ServerBuilder {
        match self.allowed_nodes {
            None => {
                self.allowed_nodes = {
                    let mut allowed = BTreeSet::new();
                    allowed.insert(client);
                    Some(SomeOrAllNodes::Some(allowed))
                };
                self
            }
            Some(SomeOrAllNodes::Some(mut nodes)) => {
                nodes.insert(client);
                self.allowed_nodes = Some(SomeOrAllNodes::Some(nodes));
                self
            }
            Some(SomeOrAllNodes::All) => {
                panic!("invalid use of builder: cannot add node if all nodes are allowed")
            }
        }
    }

    pub fn allow_all_nodes(mut self) -> ServerBuilder {
        match self.allowed_nodes {
            None => {
                self.allowed_nodes = Some(SomeOrAllNodes::All);
                self
            }
            Some(SomeOrAllNodes::Some(_)) => panic!(
                "invalid use of builder: cannot allow all nodes if some individual nodes are allowed"
            ),
            Some(SomeOrAllNodes::All) => self,
        }
    }

    pub fn add_allowed_client_cert(mut self, cert: X509PublicKeyCert) -> ServerBuilder {
        self.allowed_certs.push(cert);
        self
    }

    pub fn build(self, registry: Arc<FakeRegistryClient>) -> Server {
        let listener = std::net::TcpListener::bind(("0.0.0.0", 0)).expect("failed to bind");
        let (crypto, cert) = temp_crypto_component_with_tls_keys(registry, self.node_id);
        let allowed_clients = AllowedClients::new(
            self.allowed_nodes
                .unwrap_or_else(|| SomeOrAllNodes::Some(BTreeSet::new())),
            self.allowed_certs,
        )
        .expect("failed to construct allowed clients");
        Server {
            listener,
            crypto,
            allowed_clients,
            msg_for_client: self.msg_for_client,
            msg_expected_from_client: self.msg_expected_from_client,
            cert,
        }
    }
}

/// A wrapper around the crypto TLS server implementation under test. Allows for
/// easy testing.
pub struct Server {
    listener: std::net::TcpListener,
    crypto: TempCryptoComponent,
    allowed_clients: AllowedClients,
    msg_for_client: Option<String>,
    msg_expected_from_client: Option<String>,
    cert: X509PublicKeyCert,
}

impl Server {
    pub fn builder(node_id: NodeId) -> ServerBuilder {
        ServerBuilder {
            node_id,
            msg_for_client: None,
            msg_expected_from_client: None,
            allowed_nodes: None,
            allowed_certs: Vec::new(),
        }
    }

    pub async fn run(self) -> Result<AuthenticatedPeer, TlsServerHandshakeError> {
        let tcp_stream = self.accept_connection_on_listener().await;

        let (tls_stream, authenticated_node) = self
            .crypto
            .perform_tls_server_handshake(tcp_stream, self.allowed_clients.clone(), REG_V1)
            .await?;
        let (tls_read_half, tls_write_half) = tls_stream.split();

        self.send_msg_to_client_if_configured(tls_write_half).await;
        self.expect_msg_from_client_if_configured(tls_read_half)
            .await;
        Ok(authenticated_node)
    }

    pub async fn run_with_optional_client_auth(self) -> Result<Peer, TlsServerHandshakeError> {
        let tcp_stream = self.accept_connection_on_listener().await;

        let (tls_stream, peer) = self
            .crypto
            .perform_tls_server_handshake_temp_with_optional_client_auth(
                tcp_stream,
                self.allowed_clients.clone(),
                REG_V1,
            )
            .await?;
        let (tls_read_half, tls_write_half) = tls_stream.split();

        self.send_msg_to_client_if_configured(tls_write_half).await;
        self.expect_msg_from_client_if_configured(tls_read_half)
            .await;
        Ok(peer)
    }

    async fn accept_connection_on_listener(&self) -> TcpStream {
        let mut tokio_tcp_listener = TcpListener::from_std(self.listener.try_clone().unwrap())
            .expect("failed to create tokio TcpListener");
        let (tcp_stream, _peer_address) = tokio_tcp_listener
            .accept()
            .await
            .expect("failed to accept connection");
        tcp_stream
    }

    async fn expect_msg_from_client_if_configured(&self, mut read_half: TlsReadHalf) {
        if let Some(msg_expected_from_client) = &self.msg_expected_from_client {
            let mut bytes_from_client = Vec::new();
            // Depending on the OS, the client terminates the connection after sending the
            // message (the following call returns an Err), or it keeps the connection alive
            // (the following call returns Ok). This behaviour is not relevant for this test
            // and thus we do not evaluate the result.
            let _ = read_half.read_to_end(&mut bytes_from_client).await;
            let msg_from_client = String::from_utf8(bytes_from_client.to_vec()).unwrap();
            assert_eq!(msg_from_client, msg_expected_from_client.clone());
        }
    }

    async fn send_msg_to_client_if_configured(&self, mut write_half: TlsWriteHalf) {
        if let Some(msg_for_client) = &self.msg_for_client {
            let num_bytes_written = write_half.write(&msg_for_client.as_bytes()).await.unwrap();
            assert_eq!(num_bytes_written, msg_for_client.as_bytes().len());
        }
    }

    pub fn port(&self) -> u16 {
        self.listener
            .local_addr()
            .expect("failed to get local_addr")
            .port()
    }

    pub fn cert(&self) -> X509PublicKeyCert {
        self.cert.clone()
    }

    pub fn allowed_clients(&self) -> &BTreeSet<NodeId> {
        match self.allowed_clients.nodes() {
            SomeOrAllNodes::Some(nodes) => nodes,
            SomeOrAllNodes::All => unimplemented!(),
        }
    }
}
