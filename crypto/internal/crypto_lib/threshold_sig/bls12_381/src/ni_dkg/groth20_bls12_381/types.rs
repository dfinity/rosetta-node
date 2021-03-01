//! CSP-internal types for the Groth20 NiDKG implementation.

use ic_crypto_internal_types::curves::bls12_381::{G1 as G1Bytes, G2 as G2Bytes};
use ic_crypto_internal_types::encrypt::forward_secure::groth20_bls12_381::{
    FsEncryptionPok, FsEncryptionPublicKey,
};
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;

#[cfg(test)]
pub mod arbitrary;

/// Forward secure encryption secret key used in Groth20.
///
/// Note: This is the CBOR serialised form of a linked list.  Given that the
/// list is bounded in size we could use a fixed size representation.  We
/// may also want to expose the data structure here, depending on the
/// strategic decisions regarding CBOR and protobufs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FsEncryptionSecretKey {
    pub bte_nodes: Vec<BTENode>,
}
impl Zeroize for FsEncryptionSecretKey {
    fn zeroize(&mut self) {
        for node in self.bte_nodes.iter_mut() {
            node.zeroize();
        }
    }
}

/// Lib independent representation:
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BTENode {
    // Notation from section 7.2.
    #[serde(with = "serde_bytes")]
    pub tau: Vec<u8>,
    pub a: G1Bytes,
    pub b: G2Bytes,
    pub d_t: Vec<G2Bytes>,
    pub d_h: Vec<G2Bytes>,
    pub e: G2Bytes,
}

impl Zeroize for BTENode {
    fn zeroize(&mut self) {
        // Note: Alas size_of() doesn't work on generic types, afaik.  There are open
        // issues on rust-lang about this.
        fn zeroize_g1(item: &mut G1Bytes) {
            #[cfg_attr(tarpaulin, skip)]
            unsafe {
                core::mem::transmute::<G1Bytes, [u8; core::mem::size_of::<G1Bytes>()]>(*item)
                    .copy_from_slice(&[0u8; core::mem::size_of::<G1Bytes>()]);
            }
        }
        fn zeroize_g2(item: &mut G2Bytes) {
            #[cfg_attr(tarpaulin, skip)]
            unsafe {
                core::mem::transmute::<G2Bytes, [u8; core::mem::size_of::<G2Bytes>()]>(*item)
                    .copy_from_slice(&[0u8; core::mem::size_of::<G2Bytes>()]);
            }
        }
        // tau is not secret.  It is a common parameter and doesn't need to be zeroed.
        zeroize_g1(&mut self.a);
        zeroize_g2(&mut self.b);
        for node in self.d_t.iter_mut() {
            zeroize_g2(node);
        }
        for node in self.d_h.iter_mut() {
            zeroize_g2(node);
        }
        zeroize_g2(&mut self.e);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FsEncryptionKeySet {
    pub public_key: FsEncryptionPublicKey,
    pub pok: FsEncryptionPok,
    pub secret_key: FsEncryptionSecretKey,
}
impl Zeroize for FsEncryptionKeySet {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
    }
}
