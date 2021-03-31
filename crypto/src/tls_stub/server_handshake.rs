use crate::tls_stub::{
    ensure_certificates_equal, node_id_from_cert_subject_common_name, tls_cert_from_registry,
    TlsCertFromRegistryError,
};
use ic_crypto_internal_csp::api::CspTlsServerHandshake;
use ic_crypto_tls_interfaces::{
    AllowedClients, AuthenticatedPeer, Peer, PeerNotAllowedError, SomeOrAllNodes,
    TlsServerHandshakeError, TlsStream, TlsStreamInsecure,
};
use ic_interfaces::registry::RegistryClient;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client::helper::node::NodeRegistry;
use ic_types::{NodeId, PrincipalId, RegistryVersion};
use openssl::x509::X509;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::net::TcpStream;

/// This method will be removed once the P2P team finished integrating the new
/// TLS handshake API. Removal of this insecure method is tracked in CRP-775.
pub async fn perform_tls_server_handshake_insecure(
    tcp_stream: TcpStream,
    allowed_clients: AllowedClients,
) -> Result<(TlsStreamInsecure, AuthenticatedPeer), TlsServerHandshakeError> {
    let peer = dummy_authenticated_peer(&allowed_clients);
    Ok((tokio::io::split(tcp_stream), peer))
}

fn dummy_authenticated_peer(allowed_clients: &AllowedClients) -> AuthenticatedPeer {
    if let Some(cert) = allowed_clients.certs().iter().cloned().next() {
        AuthenticatedPeer::Cert(cert)
    } else {
        match allowed_clients.nodes() {
            SomeOrAllNodes::Some(node_ids) => AuthenticatedPeer::Node(
                node_ids.iter().copied().next().expect("invariant violated"),
            ),
            SomeOrAllNodes::All => {
                AuthenticatedPeer::Node(NodeId::from(PrincipalId::new_node_test_id(0)))
            }
        }
    }
}

// TODO (CRP-772): Simplify handshake code by moving cert equality check to CSP
// TODO (CRP-773): Use X509 domain object instead of protobuf in API
pub async fn perform_tls_server_handshake<C: CspTlsServerHandshake>(
    csp: &C,
    self_node_id: NodeId,
    registry_client: &Arc<dyn RegistryClient>,
    tcp_stream: TcpStream,
    allowed_clients: AllowedClients,
    registry_version: RegistryVersion,
) -> Result<(TlsStream, AuthenticatedPeer), TlsServerHandshakeError> {
    let (tls_stream, peer) = perform_tls_server_handshake_temp_with_optional_client_auth(
        csp,
        self_node_id,
        registry_client,
        tcp_stream,
        allowed_clients,
        registry_version,
    )
    .await?;
    match peer {
        Peer::Authenticated(peer) => Ok((tls_stream, peer)),
        Peer::Unauthenticated => Err(TlsServerHandshakeError::UnauthenticatedClient),
    }
}

pub async fn perform_tls_server_handshake_temp_with_optional_client_auth<
    C: CspTlsServerHandshake,
>(
    csp: &C,
    self_node_id: NodeId,
    registry_client: &Arc<dyn RegistryClient>,
    tcp_stream: TcpStream,
    allowed_authenticating_clients: AllowedClients,
    registry_version: RegistryVersion,
) -> Result<(TlsStream, Peer), TlsServerHandshakeError> {
    let self_tls_cert = tls_cert_from_registry(registry_client, self_node_id, registry_version)?;
    let trusted_node_certs = tls_certs_from_registry(
        registry_client,
        &allowed_authenticating_clients.nodes(),
        registry_version,
    )?;
    let trusted_client_certs =
        combine_certs(&trusted_node_certs, allowed_authenticating_clients.certs());

    let (tls_stream, peer_cert) = csp
        .perform_tls_server_handshake(tcp_stream, self_tls_cert, trusted_client_certs)
        .await?;

    match peer_cert {
        Some(peer_cert) => {
            let peer = authenticated_peer(
                &peer_cert,
                &allowed_authenticating_clients.certs(),
                &trusted_node_certs,
            )?;
            Ok((tls_stream, Peer::Authenticated(peer)))
        }
        None => Ok((tls_stream, Peer::Unauthenticated)),
    }
}

fn tls_certs_from_registry(
    registry_client: &Arc<dyn RegistryClient>,
    nodes: &SomeOrAllNodes,
    registry_version: RegistryVersion,
) -> Result<BTreeMap<NodeId, X509PublicKeyCert>, TlsCertFromRegistryError> {
    match nodes {
        SomeOrAllNodes::Some(nodes) => {
            tls_certs_from_registry_for_nodes(nodes, registry_client, registry_version)
        }
        SomeOrAllNodes::All => {
            let all_nodes = registry_client
                .get_node_ids(registry_version)?
                .into_iter()
                .collect();
            tls_certs_from_registry_for_nodes(&all_nodes, registry_client, registry_version)
        }
    }
}

fn tls_certs_from_registry_for_nodes(
    allowed_clients: &BTreeSet<NodeId>,
    registry_client: &Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
) -> Result<BTreeMap<NodeId, X509PublicKeyCert>, TlsCertFromRegistryError> {
    let mut node_id_to_cert = BTreeMap::new();
    for client in allowed_clients {
        node_id_to_cert.insert(
            *client,
            tls_cert_from_registry(registry_client, *client, registry_version)?,
        );
    }
    Ok(node_id_to_cert)
}

fn combine_certs(
    node_certs: &BTreeMap<NodeId, X509PublicKeyCert>,
    certs: &[X509PublicKeyCert],
) -> Vec<X509PublicKeyCert> {
    let mut node_certs_and_certs: Vec<_> = node_certs.values().cloned().collect();
    node_certs_and_certs.extend(certs.iter().cloned());
    node_certs_and_certs
}

fn authenticated_peer(
    client_cert_from_handshake: &X509,
    allowed_client_certs: &[X509PublicKeyCert],
    trusted_node_certs: &BTreeMap<NodeId, X509PublicKeyCert>,
) -> Result<AuthenticatedPeer, TlsServerHandshakeError> {
    let client_cert_from_handshake_proto = x509_to_proto(&client_cert_from_handshake)?;
    if allowed_client_certs
        .iter()
        .any(|cert| cert == &client_cert_from_handshake_proto)
    {
        Ok(AuthenticatedPeer::Cert(client_cert_from_handshake_proto))
    } else {
        let authenticated_node = check_cert_and_get_authenticated_client_node_id(
            trusted_node_certs,
            &client_cert_from_handshake,
        )?;
        Ok(AuthenticatedPeer::Node(authenticated_node))
    }
}

fn x509_to_proto(cert: &X509) -> Result<X509PublicKeyCert, TlsServerHandshakeError> {
    Ok(X509PublicKeyCert {
        certificate_der: cert
            .to_der()
            .map_err(|e| TlsServerHandshakeError::HandshakeError {
                internal_error: format!("failed to DER-encode peer certificate {}", e),
            })?,
    })
}

fn check_cert_and_get_authenticated_client_node_id(
    trusted_node_certs: &BTreeMap<NodeId, X509PublicKeyCert>,
    client_cert_from_handshake: &X509,
) -> Result<NodeId, TlsServerHandshakeError> {
    let client_node_id_from_handshake_cert =
        node_id_from_cert_subject_common_name(&client_cert_from_handshake)?;
    let trusted_client_cert_from_registry =
        cert_for_node_id(client_node_id_from_handshake_cert, trusted_node_certs)?;
    ensure_certificates_equal(
        &client_cert_from_handshake,
        trusted_client_cert_from_registry,
    )?;
    Ok(client_node_id_from_handshake_cert)
}

fn cert_for_node_id(
    claimed_node_id_from_handshake_cert: NodeId,
    trusted_node_certs: &BTreeMap<NodeId, X509PublicKeyCert>,
) -> Result<X509PublicKeyCert, TlsServerHandshakeError> {
    trusted_node_certs
        .get(&claimed_node_id_from_handshake_cert)
        .cloned()
        .ok_or(TlsServerHandshakeError::ClientNotAllowed(
            PeerNotAllowedError::HandshakeCertificateNodeIdNotAllowed,
        ))
}

impl From<TlsCertFromRegistryError> for TlsServerHandshakeError {
    fn from(cert_from_registry_error: TlsCertFromRegistryError) -> Self {
        match cert_from_registry_error {
            TlsCertFromRegistryError::RegistryError(e) => TlsServerHandshakeError::RegistryError(e),
            TlsCertFromRegistryError::CertificateNotInRegistry {
                node_id,
                registry_version,
            } => TlsServerHandshakeError::CertificateNotInRegistry {
                node_id,
                registry_version,
            },
        }
    }
}
