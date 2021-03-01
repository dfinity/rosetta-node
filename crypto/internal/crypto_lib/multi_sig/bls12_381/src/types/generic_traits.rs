//! These are boilerplate implementations of standard traits that cannot be
//! auto-generated in the normal way because Rust doesn't have const generics
//! yet. This code is in a separate file to avoid cluttering the types file with
//! implementation details.

use super::*;
use std::fmt;

#[cfg(test)]
mod tests;

/////////////////
// PublicKeyBytes
// Note: This is needed because Rust doesn't support const generics yet.
impl fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self.0[..])
    }
}
impl PartialEq for PublicKeyBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Eq for PublicKeyBytes {}

///////////////////////////
// IndividualSignatureBytes
// Note: This is needed because Rust doesn't support const generics yet.
impl fmt::Debug for IndividualSignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self.0[..])
    }
}
impl PartialEq for IndividualSignatureBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Eq for IndividualSignatureBytes {}

///////////////////////////
// PopBytes
// Note: This is needed because Rust doesn't support const generics yet.
impl fmt::Debug for PopBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self.0[..])
    }
}
impl PartialEq for PopBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Eq for PopBytes {}

/////////////////
// CombinedSignatureBytes
// Note: This is needed because Rust doesn't support const generics yet.
impl fmt::Debug for CombinedSignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self.0[..])
    }
}
impl PartialEq for CombinedSignatureBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}
impl Eq for CombinedSignatureBytes {}
