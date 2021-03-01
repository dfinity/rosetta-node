//! Elliptic curve crypt
//! This uses the core elliptic curve operations but expresses them in
//! cryptographic terms.
use crate::types::{
    CombinedPublicKey, CombinedSignature, IndividualSignature, Pop, PublicKey, PublicKeyBytes,
    SecretKey,
};
use group::CurveProjective;
use ic_crypto_internal_bls12381_common as bls;
use ic_crypto_internal_types::context::{Context, DomainSeparationContext};
use pairing::bls12_381::{Bls12, FrRepr, G1, G2};
use pairing::Engine;
use rand::{CryptoRng, Rng};

/// Domain separator for Hash-to-G1 to be used for signature generation in a
/// scheme supporting proof of possession, as specified for the Proof of
/// Possession ciphersuite in https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-4.2.3
const DOMAIN_HASH_MSG_TO_G1_BLS12381_SIG_WITH_POP: &[u8; 43] =
    b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
/// Domain separator for Hash-to-G1 to be used in a proof of possession as
/// as specified for the Proof of Possession ciphersuite in
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-4.2.3
const DOMAIN_HASH_PUB_KEY_TO_G1_BLS12381_SIG_WITH_POP: &[u8; 43] =
    b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
/// Domain separation string used in the creation of proof of possessions of BLS
/// multi-signature public keys.
pub const DOMAIN_MULTI_SIG_BLS12_381_POP: &str = "ic-multi-sig-bls12381-pop";

pub fn hash_message_to_g1(msg: &[u8]) -> G1 {
    bls::hash_to_g1(&DOMAIN_HASH_MSG_TO_G1_BLS12381_SIG_WITH_POP[..], msg)
}

pub fn hash_public_key_to_g1(public_key: &[u8]) -> G1 {
    bls::hash_to_g1(
        &DOMAIN_HASH_PUB_KEY_TO_G1_BLS12381_SIG_WITH_POP[..],
        &public_key,
    )
}

pub fn keypair_from_seed(seed: [u64; 4]) -> Option<(SecretKey, PublicKey)> {
    let secret_key: FrRepr = FrRepr(seed);
    let public_key: G2 = bls::scalar_multiply(G2::one(), secret_key);
    if public_key.is_zero() {
        None
    } else {
        Some((secret_key, public_key))
    }
}
pub fn keypair_from_rng<R: Rng + CryptoRng>(rng: &mut R) -> (SecretKey, PublicKey) {
    loop {
        if let Some(pair) = keypair_from_seed(rng.gen::<[u64; 4]>()) {
            return pair;
        }
    }
}

pub fn sign_point(point: G1, secret_key: SecretKey) -> IndividualSignature {
    bls::scalar_multiply(point, secret_key)
}
pub fn sign_message(message: &[u8], secret_key: SecretKey) -> IndividualSignature {
    sign_point(hash_message_to_g1(message), secret_key)
}

pub fn create_pop(public_key: PublicKey, secret_key: SecretKey) -> Pop {
    let public_key_bytes = PublicKeyBytes::from(public_key);
    let mut domain_separated_public_key: Vec<u8> = vec![];
    domain_separated_public_key
        .extend(DomainSeparationContext::new(DOMAIN_MULTI_SIG_BLS12_381_POP).as_bytes());
    domain_separated_public_key.extend(&public_key_bytes.0[..]);
    sign_point(
        hash_public_key_to_g1(&domain_separated_public_key),
        secret_key,
    )
}

pub fn combine_signatures(signatures: &[IndividualSignature]) -> CombinedSignature {
    bls::sum(signatures)
}
pub fn combine_public_keys(public_keys: &[PublicKey]) -> CombinedPublicKey {
    bls::sum(public_keys)
}

pub fn verify_point(hash: G1, signature: G1, public_key: PublicKey) -> bool {
    Bls12::pairing(signature, G2::one()) == Bls12::pairing(hash, public_key)
}
pub fn verify_individual_message_signature(
    message: &[u8],
    signature: IndividualSignature,
    public_key: PublicKey,
) -> bool {
    let hash = hash_message_to_g1(message);
    verify_point(hash, signature, public_key)
}
pub fn verify_pop(pop: Pop, public_key: PublicKey) -> bool {
    let public_key_bytes = PublicKeyBytes::from(public_key);
    let mut domain_separated_public_key: Vec<u8> = vec![];
    domain_separated_public_key
        .extend(DomainSeparationContext::new(DOMAIN_MULTI_SIG_BLS12_381_POP).as_bytes());
    domain_separated_public_key.extend(&public_key_bytes.0[..]);
    let hash = hash_public_key_to_g1(&domain_separated_public_key);
    verify_point(hash, pop, public_key)
}

pub fn verify_combined_message_signature(
    message: &[u8],
    signature: CombinedSignature,
    public_keys: &[PublicKey],
) -> bool {
    let hash = hash_message_to_g1(message);
    let public_key = combine_public_keys(public_keys);
    verify_point(hash, signature, public_key)
}
