use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::fmt;

pub use client_handshake::{perform_tls_client_handshake, TlsClientHandshakeError};
pub use keygen::generate_tls_keys;

mod client_handshake;
mod keygen;

// TODO (CRP-773): Use this domain object also in the `TlsHandshake`
#[allow(unused)]
#[derive(Clone, Debug)]
pub struct TlsPublicKeyCert {
    cert: X509,
}

#[allow(unused)]
impl TlsPublicKeyCert {
    // Creates a certificate from PEM encoding
    pub fn new_from_pem(cert_pem: Vec<u8>) -> Result<Self, TlsPemParsingError> {
        let cert = X509::from_pem(&cert_pem).map_err(|e| TlsPemParsingError {
            internal_error: format!("Error parsing PEM: {}", e),
        })?;
        Ok(Self { cert })
    }

    pub fn new_from_x509(cert: X509) -> Self {
        Self { cert }
    }

    // Returns the certificate in PEM format
    pub fn to_pem(&self) -> Result<Vec<u8>, TlsEncodingError> {
        self.cert.to_pem().map_err(|e| TlsEncodingError {
            internal_error: format!("Error encoding PEM: {}", e),
        })
    }

    // Returns the certificate in DER format
    pub fn to_der(&self) -> Result<Vec<u8>, TlsEncodingError> {
        self.cert.to_der().map_err(|e| TlsEncodingError {
            internal_error: format!("Error encoding DER: {}", e),
        })
    }

    pub fn as_x509(&self) -> &X509 {
        &self.cert
    }
}

#[allow(unused)]
#[derive(Clone)]
pub struct TlsPrivateKey {
    private_key: PKey<Private>,
}

#[allow(unused)]
impl TlsPrivateKey {
    // Creates a private key from a PEM encoding
    pub fn new_from_pem(private_key_pem: Vec<u8>) -> Result<Self, TlsPemParsingError> {
        // nb. Make sure we don't leak sensitive info in the error message.
        let private_key =
            PKey::private_key_from_pem(&private_key_pem).map_err(|_| TlsPemParsingError {
                internal_error: "Error parsing PEM via OpenSSL".to_string(),
            })?;
        Ok(Self { private_key })
    }

    fn new_from_pkey(private_key: PKey<Private>) -> Self {
        Self { private_key }
    }

    // Returns the private key in PEM encoding
    pub fn to_pem(&self) -> Result<Vec<u8>, TlsEncodingError> {
        self.private_key
            .private_key_to_pem_pkcs8()
            .map_err(|_| TlsEncodingError {
                internal_error: "Error encoding PEM via OpenSSL".to_string(),
            })
    }

    pub fn as_pkey(&self) -> &PKey<Private> {
        &self.private_key
    }
}

impl fmt::Debug for TlsPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED")
    }
}

#[allow(unused)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsPemParsingError {
    pub internal_error: String,
}

#[allow(unused)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsEncodingError {
    pub internal_error: String,
}
