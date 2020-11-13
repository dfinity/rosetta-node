//! Data types for public coefficients.
//!
//! Note: Public coefficients are a generalised public key for threshold
//! signatures.

use serde::{Deserialize, Serialize};
use strum_macros::IntoStaticStr;

#[derive(Clone, Eq, Debug, IntoStaticStr, PartialEq, Hash, Serialize, Deserialize)]
pub enum PublicCoefficients {
    Bls12_381(bls12_381::PublicCoefficients),
}

pub type CspPublicCoefficients = PublicCoefficients;

pub mod bls12_381 {
    use crate::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
    use serde::{Deserialize, Serialize};

    /// The public coefficients of a threshold public key.
    ///
    /// Any individual or combined signature can be verified by deriving the
    /// corresponding public key from the public coefficients and then verifying
    /// the signature against that public key.
    #[derive(Clone, Eq, Debug, PartialEq, Hash, Serialize, Deserialize)]
    pub struct PublicCoefficients {
        pub coefficients: Vec<PublicKeyBytes>,
    }
}
