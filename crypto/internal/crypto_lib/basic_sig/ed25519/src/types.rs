//! Simple signature types
#![allow(clippy::unit_arg)] // Arbitrary is a unit arg in: derive(proptest_derive::Arbitrary)
pub use serde::{Deserialize, Serialize};
pub use zeroize::Zeroize;

mod conversions;
mod generic_traits;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Zeroize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct SecretKeyBytes(pub [u8; SecretKeyBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(SecretKeyBytes, SecretKeyBytes::SIZE);
impl SecretKeyBytes {
    pub const SIZE: usize = 32;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct PublicKeyBytes(pub [u8; PublicKeyBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(PublicKeyBytes, PublicKeyBytes::SIZE);
impl PublicKeyBytes {
    pub const SIZE: usize = 32;
}

#[derive(Copy, Clone)]
pub struct SignatureBytes(pub [u8; SignatureBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(SignatureBytes, SignatureBytes::SIZE);
impl SignatureBytes {
    pub const SIZE: usize = 64;
}
