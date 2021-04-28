use super::*;
use async_trait::async_trait;
use ic_crypto_tls_interfaces::{
    AllowedClients, AuthenticatedPeer, MalformedPeerCertificateError, Peer, PeerNotAllowedError,
    TlsClientHandshakeError, TlsHandshake, TlsServerHandshakeError, TlsStream,
};
use ic_logger::{debug, new_logger};
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::registry::RegistryClientError;
use ic_types::{NodeId, PrincipalId, RegistryVersion};
use openssl::nid::Nid;
use openssl::string::OpensslString;
use openssl::x509::X509;
use openssl::x509::{X509NameEntries, X509NameEntryRef};
use std::str::FromStr;
use tokio::net::TcpStream;

mod client_handshake;
mod server_handshake;

#[async_trait]
impl<CSP> TlsHandshake for CryptoComponentFatClient<CSP>
where
    CSP: CryptoServiceProvider + Send + Sync,
{
    async fn perform_tls_server_handshake(
        &self,
        tcp_stream: TcpStream,
        allowed_clients: AllowedClients,
        registry_version: RegistryVersion,
    ) -> Result<(TlsStream, AuthenticatedPeer), TlsServerHandshakeError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "TlsHandshake",
            crypto.method_name => "perform_tls_server_handshake",
            crypto.registry_version => registry_version.get(),
            crypto.allowed_tls_clients => format!("{:?}", allowed_clients),
        );
        debug!(logger; crypto.description => "start",);
        let result = server_handshake::perform_tls_server_handshake(
            &self.csp,
            self.node_id,
            &self.registry_client,
            tcp_stream,
            allowed_clients,
            registry_version,
        )
        .await;
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    async fn perform_tls_server_handshake_temp_with_optional_client_auth(
        &self,
        tcp_stream: TcpStream,
        allowed_authenticating_clients: AllowedClients,
        registry_version: RegistryVersion,
    ) -> Result<(TlsStream, Peer), TlsServerHandshakeError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "TlsHandshake",
            crypto.method_name => "perform_tls_server_handshake_temp_with_optional_client_auth",
            crypto.registry_version => registry_version.get(),
            crypto.allowed_tls_clients => format!("{:?}", allowed_authenticating_clients),
        );
        debug!(logger; crypto.description => "start",);
        let result = server_handshake::perform_tls_server_handshake_temp_with_optional_client_auth(
            &self.csp,
            self.node_id,
            &self.registry_client,
            tcp_stream,
            allowed_authenticating_clients,
            registry_version,
        )
        .await;
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    async fn perform_tls_client_handshake(
        &self,
        tcp_stream: TcpStream,
        server: NodeId,
        registry_version: RegistryVersion,
    ) -> Result<TlsStream, TlsClientHandshakeError> {
        let logger = new_logger!(&self.logger;
            crypto.trait_name => "TlsHandshake",
            crypto.method_name => "perform_tls_client_handshake",
            crypto.registry_version => registry_version.get(),
            crypto.tls_server => format!("{}", server),
        );
        debug!(logger; crypto.description => "start",);
        let result = client_handshake::perform_tls_client_handshake(
            &self.csp,
            self.node_id,
            &self.registry_client,
            tcp_stream,
            server,
            registry_version,
        )
        .await;
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}

fn node_id_from_cert_subject_common_name(
    cert: &X509,
) -> Result<NodeId, MalformedPeerCertificateError> {
    let common_name_entry = ensure_exactly_one_subject_common_name_entry(cert)?;
    let common_name = common_name_entry_as_string(common_name_entry)?;
    let principal_id = parse_principal_id(common_name)?;
    Ok(NodeId::from(principal_id))
}

fn ensure_exactly_one_subject_common_name_entry(
    cert: &X509,
) -> Result<&X509NameEntryRef, MalformedPeerCertificateError> {
    if common_name_entries(cert).count() > 1 {
        return Err(MalformedPeerCertificateError::new(
            "Too many X509NameEntryRefs",
        ));
    }
    common_name_entries(cert)
        .next()
        .ok_or_else(|| MalformedPeerCertificateError::new("Missing X509NameEntryRef"))
}

fn common_name_entry_as_string(
    common_name_entry: &X509NameEntryRef,
) -> Result<OpensslString, MalformedPeerCertificateError> {
    common_name_entry.data().as_utf8().map_err(|e| {
        MalformedPeerCertificateError::new(&format!("ASN1 to UTF-8 conversion error: {}", e))
    })
}

fn parse_principal_id(
    common_name: OpensslString,
) -> Result<PrincipalId, MalformedPeerCertificateError> {
    PrincipalId::from_str(common_name.as_ref()).map_err(|e| {
        MalformedPeerCertificateError::new(&format!("Principal ID parse error: {}", e))
    })
}

fn common_name_entries(cert: &X509) -> X509NameEntries {
    cert.subject_name().entries_by_nid(Nid::COMMONNAME)
}

fn ensure_certificates_equal(
    peer_cert_from_handshake: &X509,
    trusted_cert_from_registry: X509PublicKeyCert,
) -> Result<(), PeerNotAllowedError> {
    let client_cert_from_handshake_der = peer_cert_from_handshake.to_der().map_err(|e| {
        PeerNotAllowedError::CannotDerEncodePeerCertFromHandshake {
            internal_error: format!("{}", e),
        }
    })?;
    if trusted_cert_from_registry.certificate_der != client_cert_from_handshake_der {
        return Err(PeerNotAllowedError::CertificatesDiffer);
    }
    Ok(())
}

fn tls_cert_from_registry(
    registry: &Arc<dyn RegistryClient>,
    node_id: NodeId,
    registry_version: RegistryVersion,
) -> Result<X509PublicKeyCert, TlsCertFromRegistryError> {
    use ic_registry_client::helper::crypto::CryptoRegistry;
    registry
        .get_tls_certificate(node_id, registry_version)?
        .ok_or_else(|| TlsCertFromRegistryError::CertificateNotInRegistry {
            node_id,
            registry_version,
        })
}

#[derive(Debug)]
enum TlsCertFromRegistryError {
    RegistryError(RegistryClientError),
    CertificateNotInRegistry {
        node_id: NodeId,
        registry_version: RegistryVersion,
    },
}

impl From<RegistryClientError> for TlsCertFromRegistryError {
    fn from(registry_error: RegistryClientError) -> Self {
        TlsCertFromRegistryError::RegistryError(registry_error)
    }
}

fn log_err<T: fmt::Display>(error_option: Option<&T>) -> String {
    if let Some(error) = error_option {
        return format!("{}", error);
    }
    "none".to_string()
}
