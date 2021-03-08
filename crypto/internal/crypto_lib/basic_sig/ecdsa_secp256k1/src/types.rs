//! Simple signature types
#![allow(clippy::unit_arg)] // Arbitrary is a unit arg in: derive(proptest_derive::Arbitrary)
pub use serde::{Deserialize, Serialize};
pub use zeroize::Zeroize;

mod conversions;
mod generic_traits;

pub const FIELD_SIZE: usize = 32;

// NOTE: PublicKeyBytes, SecretKeyDerBytes, use Vec<u8>
// (rather than [u8; <KEY_SIZE>]) for convenience and to avoid copying,
// as Rust OpenSSL works mostly Vec<u8>.

// Unsigned big integer in DER-encoding.
#[derive(Zeroize, Serialize, Deserialize)]
pub struct SecretKeyBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

// The public key is a point (x, y) on secp256k1, uncompressed.
// Affine coordinates of the public key.
#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct PublicKeyBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);
impl PublicKeyBytes {
    // 1-byte prefix + 2 coordinates.
    pub const SIZE: usize = 1 + 2 * FIELD_SIZE;
}

// Signature consists of two unsigned big integers (r,s),
// each of FIELD_SIZE bytes, concatenated yielding exactly
// SignatureBytes::SIZE bytes.
#[derive(Copy, Clone)]
pub struct SignatureBytes(pub [u8; SignatureBytes::SIZE]);
ic_crypto_internal_types::derive_serde!(SignatureBytes, SignatureBytes::SIZE);

impl SignatureBytes {
    pub const SIZE: usize = 2 * FIELD_SIZE;
}
