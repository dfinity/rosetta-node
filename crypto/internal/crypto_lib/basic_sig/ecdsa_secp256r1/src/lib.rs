#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! Basic signatures implemented with ECDSA
pub mod api;
pub mod types;
pub use api::*;
