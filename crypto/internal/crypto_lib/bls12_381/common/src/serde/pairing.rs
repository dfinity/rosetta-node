// Serialisation and deserialisation of the pairing library BLS12-381 types.

use ff::PrimeFieldRepr;
use group::{CurveAffine, CurveProjective, EncodedPoint, GroupDecodingError};
use pairing::bls12_381::{FrRepr, G1Affine, G2Affine, G1, G2};

pub const FR_SIZE: usize = 32;
pub const G1_SIZE: usize = 48;
pub const G2_SIZE: usize = 96;

#[cfg(test)]
mod test_vectors_g1;
#[cfg(test)]
mod test_vectors_g2;
#[cfg(test)]
mod tests;

pub fn g1_from_bytes(bytes: &[u8; G1_SIZE]) -> Result<G1, GroupDecodingError> {
    let mut compressed: <G1Affine as CurveAffine>::Compressed = EncodedPoint::empty();
    compressed.as_mut().copy_from_slice(bytes);
    compressed
        .into_affine()
        .map(|affine| affine.into_projective())
}
pub fn g1_to_bytes(g1: &G1) -> [u8; G1_SIZE] {
    let mut bytes = [0u8; G1_SIZE];
    bytes.copy_from_slice(g1.into_affine().into_compressed().as_ref());
    bytes
}
pub fn g2_from_bytes(bytes: &[u8; G2_SIZE]) -> Result<G2, GroupDecodingError> {
    let mut compressed: <G2Affine as CurveAffine>::Compressed = EncodedPoint::empty();
    compressed.as_mut().copy_from_slice(bytes);
    compressed
        .into_affine()
        .map(|affine| affine.into_projective())
}
pub fn g2_to_bytes(g2: &G2) -> [u8; G2_SIZE] {
    let mut bytes = [0u8; G2_SIZE];
    bytes.copy_from_slice(g2.into_affine().into_compressed().as_ref());
    bytes
}
pub fn fr_to_bytes(fr: &FrRepr) -> [u8; FR_SIZE] {
    let mut ans = [0u8; FR_SIZE];
    fr.write_be(&mut ans[0..]).unwrap();
    ans
}
pub fn fr_from_bytes(bytes: &[u8; FR_SIZE]) -> FrRepr {
    let mut ans = FrRepr([0; 4]);
    let mut reader = &bytes[..];
    ans.read_be(&mut reader).unwrap();
    ans
}
