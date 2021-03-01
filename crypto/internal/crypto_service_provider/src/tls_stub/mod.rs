use crate::api::tls_errors::{CspTlsClientHandshakeError, CspTlsServerHandshakeError};
use crate::keygen::tls_registry_cert_hash_as_key_id;
use crate::secret_key_store::SecretKeyStore;
use crate::types::CspSecretKey;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509VerifyResult, X509};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

mod client_handshake;
mod server_handshake;

#[cfg(test)]
mod test_utils;

fn key_from_secret_key_store<S: SecretKeyStore>(
    secret_key_store: &S,
    self_cert: &X509PublicKeyCert,
) -> Result<PKey<Private>, CspTlsSecretKeyError> {
    let secret_key: CspSecretKey = secret_key_store
        .get(&tls_registry_cert_hash_as_key_id(self_cert.clone()))
        .ok_or_else(|| CspTlsSecretKeyError::SecretKeyNotFound)?;
    let secret_key_der_bytes = match secret_key {
        CspSecretKey::TlsEd25519(secret_key_der_bytes) => Ok(secret_key_der_bytes),
        _ => Err(CspTlsSecretKeyError::WrongSecretKeyType),
    }?;
    PKey::private_key_from_der(&secret_key_der_bytes.bytes).map_err(|e| {
        CspTlsSecretKeyError::MalformedSecretKey {
            internal_error: format!("{}", e),
        }
    })
}

enum CspTlsSecretKeyError {
    SecretKeyNotFound,
    MalformedSecretKey { internal_error: String },
    WrongSecretKeyType,
}

fn peer_cert_from_stream(
    tls_stream: &SslStream<TcpStream>,
) -> Result<Option<X509>, CspPeerCertFromStreamError> {
    let peer_cert = tls_stream.ssl().peer_certificate();
    if peer_cert.is_some() && tls_stream.ssl().verify_result() != X509VerifyResult::OK {
        return Err(CspPeerCertFromStreamError::PeerCertificateNotVerified);
    }
    Ok(peer_cert)
}

#[derive(Debug)]
enum CspPeerCertFromStreamError {
    PeerCertificateNotVerified,
}

impl From<CspPeerCertFromStreamError> for CspTlsClientHandshakeError {
    fn from(peer_cert_error: CspPeerCertFromStreamError) -> Self {
        match peer_cert_error {
            CspPeerCertFromStreamError::PeerCertificateNotVerified => {
                CspTlsClientHandshakeError::HandshakeError {
                    internal_error: "The server certificate was not verified during the handshake."
                        .to_string(),
                }
            }
        }
    }
}

impl From<CspPeerCertFromStreamError> for CspTlsServerHandshakeError {
    fn from(peer_cert_error: CspPeerCertFromStreamError) -> Self {
        match peer_cert_error {
            CspPeerCertFromStreamError::PeerCertificateNotVerified => {
                CspTlsServerHandshakeError::HandshakeError {
                    internal_error: "The client certificate was not verified during the handshake."
                        .to_string(),
                }
            }
        }
    }
}
