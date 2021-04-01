//! Hashing to BLS12-381 primitives

use ff::Field;
use group::{CurveAffine, EncodedPoint};
use ic_crypto_sha256::Sha256;
use pairing::bls12_381::{Fr, G1Affine, G1};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

#[cfg(test)]
mod tests;

pub fn hash_to_g1(domain: &[u8], msg: &[u8]) -> G1 {
    hash_to_g1_miracl(domain, msg)
}

// Based on MIRACL's TestHTP.rs.
fn hash_to_field_bls12381(
    hash: usize,
    hlen: usize,
    dst: &[u8],
    msg: &[u8],
    ctr: usize,
) -> [miracl_core::bls12381::fp::FP; 2] {
    use miracl_core::bls12381::big::BIG;
    use miracl_core::bls12381::dbig::DBIG;
    use miracl_core::bls12381::fp::FP;
    use miracl_core::bls12381::rom;
    use miracl_core::hmac;

    let mut uu: [FP; 2] = [FP::new(), FP::new()];

    let qq = BIG::new_ints(&rom::MODULUS);
    let kk = qq.nbits();
    let rr = BIG::new_ints(&rom::CURVE_ORDER);
    let mm = rr.nbits();
    let ll = ceil(kk + ceil(mm, 2), 8);
    let mut okm: [u8; 512] = [0; 512];
    hmac::xmd_expand(hash, hlen, &mut okm, ll * ctr, &dst, &msg);
    let mut fd: [u8; 256] = [0; 256];
    for i in 0..ctr {
        for j in 0..ll {
            fd[j] = okm[i * ll + j];
        }
        let mut dx = DBIG::frombytes(&fd[0..ll]);
        let w = FP::new_big(&dx.dmod(&qq));
        uu[i].copy(&w);
    }
    uu
}

// Returns ceil(a/b). Assumes a>0.
fn ceil(a: usize, b: usize) -> usize {
    (a - 1) / b + 1
}

// Hash to curve via MIRACL.
// This follows https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/
fn hash_to_g1_miracl(dst: &[u8], msg: &[u8]) -> G1 {
    use miracl_core::bls12381::ecp;
    use miracl_core::bls12381::ecp::ECP;
    use miracl_core::hmac;
    let u = hash_to_field_bls12381(hmac::MC_SHA2, ecp::HASH_TYPE, dst, msg, 2);

    let mut p = ECP::map2point(&u[0]);
    let p1 = ECP::map2point(&u[1]);
    p.add(&p1);
    p.cfp();
    p.affine();

    g1_from_miracl(&p)
}

// Conversions to and from Miracl
// TODO(CRP-811): Maybe a standard serialisation of miracl types.  Note the
// three flag bits in the standard encoding, two in miracl.
pub fn g1_from_miracl(p: &miracl_core::bls12381::ecp::ECP) -> G1 {
    // MIRACL: 1-byte tag <> 48-byte x-coord <> 48-byte y-coord
    // Serialize without compression.
    let mut buf: [u8; 97] = [0; 97];
    p.tobytes(&mut buf, false);

    // pairing: 3-bit tag <> x-coord <> y-coord
    // A tag of 000 means an uncompressed, finite point.
    // Thus to convert, we simply ignore MIRACL's 1-byte tag and read the rest.
    // Thankfully both libraries encode in big-endian.
    let mut pairing_p: <G1Affine as CurveAffine>::Uncompressed = EncodedPoint::empty();
    pairing_p.as_mut().copy_from_slice(&buf[1..97]);
    pairing_p.into_affine().unwrap().into_projective()
}

pub fn hash_to_fr(hash: Sha256) -> Fr {
    let hash = hash.finish();
    Fr::random(&mut ChaChaRng::from_seed(hash))
}
