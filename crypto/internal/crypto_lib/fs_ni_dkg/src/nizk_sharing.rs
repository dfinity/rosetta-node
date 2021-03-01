use crate::utils::*;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::rand::RAND;
use std::vec::Vec;

/// Domain separators for the zk proof of sharing
pub const DOMAIN_PROOF_OF_SHARING_INSTANCE: &[u8; 0x20] = b"\x1fic-zk-proof-of-sharing-instance";
pub const DOMAIN_PROOF_OF_SHARING_CHALLENGE: &[u8; 0x21] = b"\x20ic-zk-proof-of-sharing-challenge";

/// Section 8.4 of paper.
///   instance = (g_1,g_2,[y_1..y_n], [A_0..A_{t-1}], R, [C_1..C_n])
///   g_1 is the generator of G1
///   g_2 is the generator of G2
pub struct SharingInstance {
    pub g1_gen: ECP,
    pub g2_gen: ECP2,
    pub public_keys: Vec<ECP>,
    pub public_coefficients: Vec<ECP2>,
    pub combined_rand: ECP,
    pub combined_ciphertexts: Vec<ECP>,
}

///   Witness = (r, s= [s_1..s_n])
pub struct SharingWitness {
    pub rand_r: BIG,
    pub rand_s: Vec<BIG>,
}

pub struct ProofSharing {
    pub ff: ECP,
    pub aa: ECP2,
    pub yy: ECP,
    pub z_r: BIG,
    pub z_alpha: BIG,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkProofSharingError {
    InvalidProof,
    InvalidInstance,
}

impl SharingInstance {
    // Computes the hash of the instance.
    pub fn instance_oracle(&self) -> BIG {
        let mut oracle = miracl_core::hash256::HASH256::new();
        oracle.process_array(DOMAIN_PROOF_OF_SHARING_INSTANCE);
        process_ecp(&mut oracle, &self.g1_gen);
        process_ecp2(&mut oracle, &self.g2_gen);
        self.public_keys
            .iter()
            .for_each(|point| process_ecp(&mut oracle, point));
        self.public_coefficients
            .iter()
            .for_each(|point| process_ecp2(&mut oracle, point));
        process_ecp(&mut oracle, &self.combined_rand);
        self.combined_ciphertexts
            .iter()
            .for_each(|point| process_ecp(&mut oracle, point));
        let rng = &mut RAND_ChaCha20::new(oracle.hash());
        BIG::randomnum(&curve_order(), rng)
    }
    pub fn check_instance(&self) -> Result<(), ZkProofSharingError> {
        if self.public_keys.is_empty() || self.public_coefficients.is_empty() {
            return Err(ZkProofSharingError::InvalidInstance);
        };
        if self.public_keys.len() != self.combined_ciphertexts.len() {
            return Err(ZkProofSharingError::InvalidInstance);
        };
        Ok(())
    }
}

fn challenge_oracle(hashed_instance: &BIG, ff: &ECP, aa: &ECP2, yy: &ECP) -> BIG {
    let mut oracle = miracl_core::hash256::HASH256::new();
    oracle.process_array(DOMAIN_PROOF_OF_SHARING_CHALLENGE);
    process_fr(&mut oracle, &hashed_instance);
    process_ecp(&mut oracle, ff);
    process_ecp2(&mut oracle, aa);
    process_ecp(&mut oracle, yy);
    let rng = &mut RAND_ChaCha20::new(oracle.hash());
    BIG::randomnum(&curve_order(), rng)
}

// Section 8.4 of paper.
//   instance = ([y_1..y_n], [A_0..A_{t-1}], R, [C_1..C_n])
//   witness = (r, [s_1..s_n])
pub fn prove_sharing(
    instance: &SharingInstance,
    witness: &SharingWitness,
    rng: &mut impl RAND,
) -> ProofSharing {
    instance
        .check_instance()
        .expect("The sharing proof instance is invalid");
    // Hash of instance: x = oracle(instance)
    let x = instance.instance_oracle();

    // First move (prover)
    // alpha, rho <- random Z_p
    let alpha: BIG = BIG::randomnum(&curve_order(), rng);
    let rho: BIG = BIG::randomnum(&curve_order(), rng);
    // F = g_1^rho
    // A = g_2^alpha
    // Y = product [y_i^x^i | i <- [1..n]]^rho * g_1^alpha
    let ff: ECP = instance.g1_gen.mul(&rho);
    let aa: ECP2 = instance.g2_gen.mul(&alpha);
    let mut yy: ECP = instance
        .public_keys
        .iter()
        .rev()
        .fold(ecp_inf(), |mut acc, point| {
            acc.add(&point);
            acc.mul(&x)
        });

    yy = yy.mul2(&rho, &instance.g1_gen, &alpha);

    // Second move (verifier's challenge)
    // x' = oracle(x, F, A, Y)
    let x_challenge: BIG = challenge_oracle(&x, &ff, &aa, &yy);

    // Third move (prover)
    // z_r = r * x' + rho mod p
    // z_alpha = x' * sum [s_i*x^i | i <- [1..n]] + alpha mod p
    let mut z_r: BIG = field_mul(&witness.rand_r, &x_challenge);
    z_r = field_add(&z_r, &rho);

    let mut z_alpha: BIG = witness
        .rand_s
        .iter()
        .rev()
        .fold(big_zero(), |mut acc, scalar| {
            acc = field_add(&acc, &scalar);
            field_mul(&acc, &x)
        });

    z_alpha = field_mul(&z_alpha, &x_challenge);
    z_alpha = field_add(&z_alpha, &alpha);
    ProofSharing {
        ff,
        aa,
        yy,
        z_r,
        z_alpha,
    }
}

pub fn verify_sharing(
    instance: &SharingInstance,
    nizk: &ProofSharing,
) -> Result<(), ZkProofSharingError> {
    instance.check_instance()?;
    // Hash of Instance
    // x = oracle(instance)
    let x: BIG = instance.instance_oracle();

    // Verifier's challenge
    // x' = oracle(x, F, A, Y)
    let x_challenge: BIG = challenge_oracle(&x, &nizk.ff, &nizk.aa, &nizk.yy);

    // First verification equation
    // R^x' * F == g_1^z_r
    let mut lhs: ECP = instance.combined_rand.mul(&x_challenge);
    lhs.add(&nizk.ff);
    let rhs = instance.g1_gen.mul(&nizk.z_r);
    if !lhs.equals(&rhs) {
        return Err(ZkProofSharingError::InvalidProof);
    }

    // Second verification equation
    // Verify: product [A_k ^ sum [i^k * x^i | i <- [1..n]] | k <- [0..t-1]]^x' * A
    // == g_2^z_alpha
    let mut kbig: BIG = big_zero();
    let one: BIG = big_one();
    let mut lhs: ECP2 = ecp2_inf();
    instance.public_coefficients.iter().for_each(|aa_k| {
        let mut acc = big_zero();
        let mut xpow = x;
        let mut ibig = big_one();
        instance.public_keys.iter().for_each(|_| {
            let tmp = field_mul(&ibig.powmod(&kbig, &curve_order()), &xpow);
            acc = field_add(&acc, &tmp);
            xpow = field_mul(&xpow, &x);
            ibig = field_add(&ibig, &one);
        });
        lhs.add(&aa_k.mul(&acc));
        kbig = field_add(&kbig, &one);
    });
    lhs = lhs.mul(&x_challenge);
    lhs.add(&nizk.aa);
    let rhs = instance.g2_gen.mul(&nizk.z_alpha);

    if !lhs.equals(&rhs) {
        return Err(ZkProofSharingError::InvalidProof);
    }

    // Third verification equation
    // LHS = product [C_i ^ x^i | i <- [1..n]]^x' * Y
    // RHS = product [y_i ^ x^i | i <- 1..n]^z_r * g_1^z_alpha
    let mut lhs: ECP =
        instance
            .combined_ciphertexts
            .iter()
            .rev()
            .fold(ecp_inf(), |mut acc, point| {
                acc.add(&point);
                acc.mul(&x)
            });
    lhs = lhs.mul(&x_challenge);
    lhs.add(&nizk.yy);

    let mut rhs: ECP = instance
        .public_keys
        .iter()
        .rev()
        .fold(ecp_inf(), |mut acc, point| {
            acc.add(&point);
            acc.mul(&x)
        });
    rhs = rhs.mul2(&nizk.z_r, &instance.g1_gen, &nizk.z_alpha);
    if !lhs.equals(&rhs) {
        return Err(ZkProofSharingError::InvalidProof);
    }
    Ok(())
}
