//! These are boilerplate implementations of standard traits that cannot be
//! auto-generated in the normal way because Rust doesn't have const generics
//! yet. This code is in a separate file to avoid cluttering the types file with
//! implementation details.

use super::*;
use secp256k1::curve::Affine;
use std::fmt;

/////////////////
// PopBytes
// Note: This is needed because Rust doesn't support const generics yet.
impl fmt::Debug for EphemeralPopBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self.0[..])
    }
}
impl PartialEq for EphemeralPopBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Eq for EphemeralPopBytes {}

////////////
// PublicKey
// Note: This is needed because public keys can have multiple representations
impl PartialEq for EphemeralPublicKey {
    fn eq(&self, other: &Self) -> bool {
        Affine::from_gej(&self.0) == Affine::from_gej(&other.0)
    }
}
impl Eq for EphemeralPublicKey {}

/////////////////////////////
// SecretKey
impl Zeroize for EphemeralSecretKey {
    fn zeroize(&mut self) {
        // TODO(DFN-1475)
    }
}
/* TODO(CRP-103): Zeroize all secret keys properly; Zeroize does not work as originally thought.
impl Drop for EphemeralSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
*/

/////////////////////////////
// KeySet
impl Zeroize for EphemeralKeySetBytes {
    fn zeroize(&mut self) {
        self.secret_key_bytes.zeroize();
    }
}
