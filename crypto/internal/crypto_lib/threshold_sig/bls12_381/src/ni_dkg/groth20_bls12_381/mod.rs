//! Non-interactive Distributed Key Generation
//! Modules are used in this order:
//! * dealing
mod dealing;
mod encryption;
mod transcript;

pub mod types;

pub use dealing::{create_dealing, verify_dealing, verify_resharing_dealing};
pub use encryption::conversions::public_key_into_miracl;
pub use encryption::{
    create_forward_secure_key_pair, update_forward_secure_epoch, verify_forward_secure_key,
};
pub use transcript::{
    compute_threshold_signing_key, create_resharing_transcript, create_transcript,
};

use ic_types::crypto::AlgorithmId;
const ALGORITHM_ID: AlgorithmId = AlgorithmId::NiDkg_Groth20_Bls12_381;
