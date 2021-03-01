//! Types for arbitrary  NiDKG methods.

#![allow(clippy::unit_arg)] // Arbitrary is a unit arg in: derive(proptest_derive::Arbitrary)

use super::groth20_bls12_381::types as groth20_bls12_381;
use serde::{Deserialize, Serialize};
use strum_macros::IntoStaticStr;
use zeroize::Zeroize;

#[cfg(test)]
use proptest_derive::Arbitrary;

/// Forward secure encryption secret key
#[derive(Clone, Debug, Eq, PartialEq, IntoStaticStr, Serialize, Deserialize, Zeroize)]
#[allow(non_camel_case_types)]
pub enum CspFsEncryptionSecretKey {
    Groth20_Bls12_381(groth20_bls12_381::FsEncryptionSecretKey),
}

/// Forward secure encryption secret key
#[derive(Clone, Debug, Eq, PartialEq, IntoStaticStr, Serialize, Deserialize, Zeroize)]
#[cfg_attr(test, derive(Arbitrary))]
#[allow(non_camel_case_types)]
pub enum CspFsEncryptionKeySet {
    Groth20_Bls12_381(groth20_bls12_381::FsEncryptionKeySet),
}
