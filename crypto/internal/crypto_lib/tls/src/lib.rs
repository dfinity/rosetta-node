#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

pub mod keygen;

mod connection;
pub use connection::{
    tls_acceptor, tls_connector, CreateTlsAcceptorError, CreateTlsConnectorError,
};
