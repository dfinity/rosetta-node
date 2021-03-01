//! Multisignature types
#![allow(clippy::unit_arg)] // Arbitrary is a unit arg in: derive(proptest_derive::Arbitrary)
use ic_crypto_internal_bls12381_common as bls;
use pairing::bls12_381::{FrRepr, G1, G2};
use zeroize::Zeroize;

#[cfg(test)]
pub mod arbitrary;

pub mod conversions;
mod generic_traits;

pub type SecretKey = FrRepr;
pub type PublicKey = G2;
pub type CombinedPublicKey = G2;
pub type IndividualSignature = G1;
pub type Pop = G1;
pub type CombinedSignature = G1;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Zeroize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct SecretKeyBytes(pub [u8; SecretKeyBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(SecretKeyBytes, SecretKeyBytes::SIZE);
impl SecretKeyBytes {
    pub const SIZE: usize = bls::FR_SIZE;
}

#[derive(Copy, Clone)]
pub struct IndividualSignatureBytes(pub [u8; IndividualSignatureBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(IndividualSignatureBytes, IndividualSignatureBytes::SIZE);
impl IndividualSignatureBytes {
    pub const SIZE: usize = bls::G1_SIZE;
}

#[derive(Copy, Clone)]
pub struct PopBytes(pub [u8; PopBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(PopBytes, PopBytes::SIZE);
impl PopBytes {
    pub const SIZE: usize = bls::G1_SIZE;
}

#[derive(Copy, Clone)]
pub struct CombinedSignatureBytes(pub [u8; CombinedSignatureBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(CombinedSignatureBytes, CombinedSignatureBytes::SIZE);
impl CombinedSignatureBytes {
    pub const SIZE: usize = bls::G1_SIZE;
}

#[derive(Copy, Clone)]
pub struct PublicKeyBytes(pub [u8; PublicKeyBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(PublicKeyBytes, PublicKeyBytes::SIZE);
impl PublicKeyBytes {
    pub const SIZE: usize = bls::G2_SIZE;
}
