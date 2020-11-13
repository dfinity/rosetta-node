use candid::de::IDLDeserialize;
use candid::CandidType;
use on_wire::witness;
use on_wire::{FromWire, IntoWire, NewType};
use serde::de::DeserializeOwned;

pub mod decode;
pub mod encode;

use decode::DecodeArguments;

pub struct Candid<T>(pub T);

impl<T> NewType for Candid<T> {
    type Inner = T;
    fn from_inner(t: Self::Inner) -> Self {
        Candid(t)
    }
    fn into_inner(self) -> Self::Inner {
        self.0
    }
}

impl<Tuple: encode::EncodeArguments> IntoWire for Candid<Tuple> {
    fn into_bytes(self) -> Result<Vec<u8>, String> {
        encode::encode_args(self.0).map_err(|e| e.to_string())
    }
}

impl<Tuple: for<'a> DecodeArguments<'a>> FromWire for Candid<Tuple> {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let de = IDLDeserialize::new(&bytes[..]).map_err(|e| e.to_string())?;
        let (de, res) = DecodeArguments::decode_arguments(de).map_err(|e| e.to_string())?;
        de.done().map_err(|e| e.to_string())?;
        Ok(Candid(res))
    }
}

pub struct CandidOne<T>(pub T);

impl<T> NewType for CandidOne<T> {
    type Inner = T;
    fn from_inner(t: Self::Inner) -> Self {
        CandidOne(t)
    }
    fn into_inner(self) -> Self::Inner {
        self.0
    }
}

impl<T: CandidType> IntoWire for CandidOne<T> {
    fn into_bytes(self) -> Result<Vec<u8>, String> {
        encode::encode_one(self.0).map_err(|e| e.to_string())
    }
}

impl<A1: DeserializeOwned> FromWire for CandidOne<A1> {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let mut de = IDLDeserialize::new(&bytes[..]).map_err(|e| e.to_string())?;
        let res = de.get_value().map_err(|e| e.to_string())?;
        Ok(CandidOne(res))
    }
}

/// this is a private mirror of the type in dfn_core::api which generates the
/// serialization/deserialization for it without putting a dependency on candid
/// in dfn_core

/// This is a bit of a weird type witness. Candid is multi arity in both inputs
/// and outputs the outputs don't fit in well with rust. To make writing candid
/// nicer we assume that every function is going to try and return one value, if
/// you'd actually prefer to return multiple use candid_multi_arity.
pub fn candid<A, B>(a: CandidOne<A>, b: B) -> (A, Candid<B>) {
    witness(a, b)
}

/// This type witness will force the function to return a tuple of arguments
pub fn candid_multi_arity<A, B>(a: Candid<A>, b: B) -> (A, Candid<B>) {
    witness(a, b)
}

/// This is a candid function that takes one argument and returns another
pub fn candid_one<A, B>(a: CandidOne<A>, b: B) -> (A, CandidOne<B>) {
    witness(a, b)
}
