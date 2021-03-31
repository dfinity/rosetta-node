// blynn: I've tried to follow the notation in the paper.
//   * Clippy complains about too many single-character variable names, so we
//     prefix `spec_` to some of them.
//   * We replace uppercase single-character variables with two copies of its
//     lowercase version, e.g. `A` -> `aa`.
//   * Greek letters are replaced by their names in English, e.g. `tau`.
//
// We build on top of MIRACL's `bls12381`.
//
//   rom::CURVE_ORDER  What the paper calls `p`.
//   rom::MODULUS      The order of FP, the field where the elliptic curve
// lives.
//
//   FP    The field Z_MODULUS (not Z_p).
//   FP12  The field where pairing outputs live.
//   BIG   Holds integers modulo `p`; also integers modulo MODULUS.
//   ECP   The group G_1.
//   ECP2  The group G_2.
//
// I wrote barebones serialization and deserialization functions, in case
// we want to use this code as soon as possible.
// I assume these will eventually be replaced by fancy serde versions.

pub mod forward_secure;
pub mod nizk_chunking;
pub mod nizk_sharing;
pub mod random_oracles;
pub mod utils;
