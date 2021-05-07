#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! Multisignature module
mod api;
mod crypto;
#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod tests;
pub mod types;
pub use api::*;
