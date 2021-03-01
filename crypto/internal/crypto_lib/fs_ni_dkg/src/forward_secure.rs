//! Methods for forward secure encryption
use zeroize::Zeroize;

use std::collections::LinkedList;
use std::io::IoSliceMut;
use std::io::Read;
use std::vec::Vec;

// NOTE: the paper uses multiplicative notation for operations on G1, G2, GT,
// while miracl's API uses additive naming convention, hence
//    u*v  corresponds to u.add(v)
// and
//    g^x  corresponds to g.mul(x)

use crate::nizk_chunking::CHALLENGE_BITS;
use crate::nizk_chunking::NUM_ZK_REPETITIONS;
use crate::utils::*;
use ic_crypto_internal_bls12381_serde_miracl::{
    miracl_fr_from_bytes, miracl_fr_to_bytes, miracl_g1_from_bytes, miracl_g1_to_bytes, FrBytes,
    G1Bytes,
};
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::fp12::FP12;
use miracl_core::bls12381::rom;
use miracl_core::bls12381::{big, big::BIG};
use miracl_core::rand::RAND;

#[cfg(test)]
mod tests;

const FP12_SIZE: usize = 12 * big::MODBYTES;

pub const MESSAGE_BYTES: usize = 32; // We assume that the ciphertext is an element of Fr.
pub const CHUNK_BYTES: usize = 2; // We assume an integer number of bytes
pub const CHUNK_SIZE: isize = 1 << (CHUNK_BYTES << 3); // Number of distinct chunks
pub const CHUNK_MIN: isize = 0;
pub const CHUNK_MAX: isize = CHUNK_MIN + CHUNK_SIZE - 1;
pub const NUM_CHUNKS: usize = (MESSAGE_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Bit {
    Zero = 0,
    One = 1,
}

impl From<u8> for Bit {
    fn from(i: u8) -> Self {
        if i == 0 {
            Bit::Zero
        } else {
            // TODO: Should we distinguish 1 and other non-zero values?
            Bit::One
        }
    }
}

impl From<&Bit> for u8 {
    fn from(b: &Bit) -> u8 {
        match &b {
            Bit::Zero => 0,
            Bit::One => 1,
        }
    }
}

impl From<&Bit> for i32 {
    fn from(b: &Bit) -> i32 {
        match &b {
            Bit::Zero => 0,
            Bit::One => 1,
        }
    }
}

/// Generates tau (a vector of bits) from an epoch.
pub fn tau_from_u32(sys: &SysParam, epoch: u32) -> Vec<Bit> {
    (0..sys.lambda_t)
        .rev()
        .map(|index| {
            if (epoch >> index) & 1 == 0 {
                Bit::Zero
            } else {
                Bit::One
            }
        })
        .collect()
}

/// A node of a Binary Tree Encryption scheme.
///
/// Notation from section 7.2.
pub struct BTENode {
    // Bit-vector, indicating a path in a binary tree.
    pub tau: Vec<Bit>,

    pub a: ECP,
    pub b: ECP2,

    // We split the d's into two groups.
    // The vector `d_h` always contains the last lambda_H points
    // of d_l,...,d_lambda.
    // The list `d_t` contains the other elements. There are at most lambda_T of them.
    // The longer this list, the higher up we are in the binary tree,
    // and the more leaf node keys we are able to derive.
    pub d_t: LinkedList<ECP2>,
    pub d_h: Vec<ECP2>,

    pub e: ECP2,
}

impl zeroize::Zeroize for BTENode {
    fn zeroize(&mut self) {
        self.tau.iter_mut().for_each(|t| *t = Bit::Zero);
        // Overwrite all group elements with generators.
        let g1 = ECP::generator();
        let g2 = ECP2::generator();
        self.a.copy(&g1);
        self.b.copy(&g2);
        self.d_h.iter_mut().for_each(|x| x.copy(&g2));
        self.d_t.iter_mut().for_each(|x| x.copy(&g2));
        self.e.copy(&g2);
    }
}

pub struct ZeroizedBIG {
    pub big: BIG,
}

impl zeroize::Zeroize for ZeroizedBIG {
    fn zeroize(&mut self) {
        self.big.zero();
    }
}

/// A forward-secure secret key is a list of BTE nodes. We can derive the keys
/// of any descendant of any node in the list.
/// We obtain forward security by maintaining the list so that
/// we can derive current and future private keys, but none of the past keys.
pub struct SecretKey {
    pub bte_nodes: LinkedList<BTENode>,
}

#[derive(Clone)]
pub struct PublicKey {
    pub y: ECP,
    pub nizk_a: ECP,
    pub nizk_z: BIG,
}

/// Domain separator for the zk proof of knowledge of DLOG in FS Encryption
pub const DOMAIN_POK_DLOG_FS_ENCRYPTION: &[u8; 0x12] = b"\x11ic-zk-pok-dlog-fs";

impl PublicKey {
    pub fn challenge_oracle(y: &ECP, nizk_a: &ECP) -> BIG {
        let mut oracle = miracl_core::hash256::HASH256::new();
        oracle.process_array(DOMAIN_POK_DLOG_FS_ENCRYPTION);
        process_ecp(&mut oracle, &ECP::generator());
        process_ecp(&mut oracle, &y);
        process_ecp(&mut oracle, &nizk_a);
        let rng = &mut RAND_ChaCha20::new(oracle.hash());
        BIG::randomnum(&curve_order(), rng)
    }
    pub fn verify(&self) -> bool {
        let nizk_e = Self::challenge_oracle(&self.y, &self.nizk_a);
        let mut lhs = self.y.mul(&nizk_e);
        lhs.add(&self.nizk_a);
        let g1 = ECP::generator();
        let rhs = g1.mul(&self.nizk_z);
        lhs.equals(&rhs)
    }
    pub fn serialize(&self) -> Vec<u8> {
        [
            &miracl_g1_to_bytes(&self.y).0[..],
            &miracl_g1_to_bytes(&self.nizk_a).0[..],
            &miracl_fr_to_bytes(&self.nizk_z).0[..],
        ]
        .concat()
        .to_vec()
    }
    pub fn deserialize(buf: &[u8]) -> PublicKey {
        let mut buf = buf;
        let expected_length = G1Bytes::SIZE + G1Bytes::SIZE + FrBytes::SIZE;
        let mut y = G1Bytes([0u8; G1Bytes::SIZE]);
        let mut nizk_a = G1Bytes([0u8; G1Bytes::SIZE]);
        let mut nizk_z = FrBytes([0u8; FrBytes::SIZE]);
        assert_eq!(
            buf.read_vectored(&mut [
                IoSliceMut::new(&mut y.0),
                IoSliceMut::new(&mut nizk_a.0),
                IoSliceMut::new(&mut nizk_z.0)
            ])
            .expect("Read failed"),
            expected_length,
            "Input too short"
        );
        PublicKey {
            y: miracl_g1_from_bytes(&y.0).expect("Malformed y"),
            nizk_a: miracl_g1_from_bytes(&nizk_a.0).expect("Malformed nizk_a"),
            nizk_z: miracl_fr_from_bytes(&nizk_z.0).expect("Malformed nizk_z"),
        }
    }
}
impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "y: ")?;
        format_ecp(f, &self.y)?;
        write!(f, ", ...}}")
    }
}

pub struct SysParam {
    pub lambda_t: usize,
    pub lambda_h: usize,
    pub f0: ECP2,       // f_0 in the paper.
    pub f: Vec<ECP2>,   // f_1, ..., f_{lambda_T} in the paper.
    pub f_h: Vec<ECP2>, // The remaining lambda_H f_i's in the paper.
    pub h: ECP2,
}

/// Generates a (public key, secret key) pair for of forward-secure
/// public-key encryption scheme for the specified system parameters,
/// using the given random generator `rng`.
/// (KGen of Section 9.1)
pub fn kgen(sys: &SysParam, rng: &mut impl RAND) -> (PublicKey, SecretKey) {
    let g1 = ECP::generator();
    let g2 = ECP2::generator();
    let spec_p = BIG::new_ints(&rom::CURVE_ORDER);
    // x <- getRandomZp
    // rho <- getRandomZp
    // let y = g1^x
    // let pk = (y, pi_dlog)
    // let dk = (g1^rho, g2^x * f0^rho, f1^rho, ..., f_lambda^rho, h^rho)
    // return (pk, dk)
    let spec_x = BIG::randomnum(&spec_p, rng);
    let rho = BIG::randomnum(&spec_p, rng);
    let a = g1.mul(&rho);
    let mut b = g2.mul(&spec_x);
    b.add(&sys.f0.mul(&rho));
    let mut d_t = LinkedList::new();
    for f in sys.f.iter() {
        d_t.push_back(f.mul(&rho));
    }
    let mut d_h = Vec::new();
    for f in sys.f_h.iter() {
        d_h.push(f.mul(&rho));
    }
    let e = sys.h.mul(&rho);
    let bte_root = BTENode {
        tau: Vec::new(),
        a,
        b,
        d_t,
        d_h,
        e,
    };
    let sk = SecretKey::new(bte_root);

    let y = g1.mul(&spec_x);

    // NIZK proof. See section 8.3.
    //   r <- getRandomZp
    //   let a = g1^r
    //   let e = oracle(y, a)
    //   let z = e*x + r
    //   pi_dlog = (a, z)
    let mut nizk_r = ZeroizedBIG {
        big: BIG::randomnum(&spec_p, rng),
    };
    let nizk_a = g1.mul(&nizk_r.big);
    let nizk_e = PublicKey::challenge_oracle(&y, &nizk_a);
    let mut nizk_z = BIG::modmul(&nizk_e, &spec_x, &spec_p);
    nizk_z = BIG::modadd(&nizk_z, &nizk_r.big, &spec_p);
    nizk_r.zeroize();
    (PublicKey { y, nizk_a, nizk_z }, sk)
}

/// Generates the specified child of a given BTE node.
pub fn node_gen(node: &BTENode, child: Bit, rng: &mut impl RAND, sys: &SysParam) -> BTENode {
    let spec_r = BIG::new_ints(&rom::CURVE_ORDER);
    let delta = BIG::randomnum(&spec_r, rng);
    let g1 = ECP::generator();

    // Construct new tau.
    let mut new_tau = node.tau.clone();
    new_tau.push(child);

    // Compute new a: new_a = a * g_1 ^ delta
    let mut new_a = g1.mul(&delta);
    new_a.add(&node.a);

    // Compute new b and new d_t.
    let mut new_b = node.b.clone();
    let mut new_d_t = LinkedList::new();
    let f_tau = ftau_partial(&new_tau, &sys).unwrap(); // TODO: remove unwrap()
    let offset = node.tau.len();
    let mut iter = node.d_t.iter().enumerate();
    // The first entry of `d_t` is used for `new_b`
    if let Some((_, d)) = iter.next() {
        new_b.add(&f_tau.mul(&delta));
        if child == Bit::One {
            new_b.add(&d);
        }
    };
    // The remanining entries of `d_t` are used for `new_d_t`
    for (i, d) in iter {
        let mut new_d = sys.f[offset + i].mul(&delta);
        new_d.add(d);
        new_d_t.push_back(new_d);
    }

    // Compute new d_h.
    let mut new_d_h = Vec::with_capacity(node.d_h.len());
    for (i, d) in node.d_h.iter().enumerate() {
        let mut new_d = sys.f_h[i].mul(&delta);
        new_d.add(d);
        new_d_h.push(new_d);
    }

    // Compute new e.
    let mut new_e = sys.h.mul(&delta);
    new_e.add(&node.e);

    BTENode {
        tau: new_tau,
        a: new_a,
        b: new_b,
        d_t: new_d_t,
        d_h: new_d_h,
        e: new_e,
    }
}

impl SecretKey {
    /// The current key (the end of list of BTENodes) of a `SecretKey` should
    /// always correspond to an epoch described by lambda_t bits. Some
    /// internal operations break this invariant, leaving less than lambda_t
    /// bits in the current key. This function should be called when this
    /// happens; it modifies the list so the current key corresponds to the
    /// first epoch of the subtree described by the current key.
    ///
    /// For example, if lambda_t = 5, then [..., 011] will change to
    /// [..., 0111, 01101, 01100].
    /// The current key's `tau` now has 5 bits, and the other entries cover the
    /// rest of the 011 subtree after we delete the current key.
    ///
    /// Another example: during the very first epoch the private key is
    /// [1, 01, 001, 0001, 00001, 00000].
    ///
    /// This makes key update easy: pop off the current key, then call this
    /// function.
    ///
    /// An alternative is to only store the root nodes of the subtrees that
    /// cover the remaining valid keys. Thus the first epoch, the private
    /// key would simply be [0], and would only change to [1, 01, 001, 0001,
    /// 00001] after the first update. Generally, some computations
    /// happen one epoch later than they would with our current scheme. However,
    /// key update is a bit fiddlier.
    ///
    /// No-op if `self` is empty.
    pub fn fast_derive(&mut self, sys: &SysParam, rng: &mut impl RAND) {
        let mut epoch = Vec::new();
        if self.bte_nodes.is_empty() {
            return;
        }
        let now = self.current().unwrap();
        for i in 0..sys.lambda_t {
            if i < now.tau.len() {
                epoch.push(now.tau[i]);
            } else {
                epoch.push(Bit::Zero);
            }
        }
        self.update_to(&epoch, &sys, rng);
    }

    /// A simpler but slower variant of the above.
    pub fn slow_derive(&mut self, sys: &SysParam, rng: &mut impl RAND) {
        let mut append_me = match self.bte_nodes.pop_back() {
            None => return,
            Some(mut node) => {
                let mut ks = LinkedList::new();
                loop {
                    if node.d_t.is_empty() {
                        ks.push_back(node);
                        break;
                    }
                    ks.push_back(node_gen(&node, Bit::One, rng, sys));
                    node = node_gen(&node, Bit::Zero, rng, sys);
                }
                ks
            }
        };
        self.bte_nodes.append(&mut append_me);
    }

    fn new(bte_root: BTENode) -> SecretKey {
        let mut bte_nodes = LinkedList::new();
        bte_nodes.push_back(bte_root);
        SecretKey { bte_nodes }
    }

    /// Returns this key's  BTE-node that corresponds to the current epoch.
    pub fn current(&self) -> Option<&BTENode> {
        self.bte_nodes.back()
    }

    /// Updates this key to the next epoch.  After an update,
    /// the decryption keys for previous epochs are not accessible any more.
    /// (KUpd(dk, 1) from Sect. 9.1)
    // TODO: consider removing `sys` and `rng` as arguments.
    pub fn update(&mut self, sys: &SysParam, rng: &mut impl RAND) {
        self.fast_derive(sys, rng);
        match self.bte_nodes.pop_back() {
            None => {}
            Some(mut dk) => {
                dk.zeroize();
                self.fast_derive(sys, rng);
            }
        }
    }
    pub fn epoch(&mut self) -> Option<&[Bit]> {
        match self.bte_nodes.back() {
            None => None,
            Some(node) => Some(&node.tau),
        }
    }
    /// Updates `self` to the given `epoch`.
    ///
    /// If `epoch` is in the past, then disables `self`.
    pub fn update_to(&mut self, epoch: &[Bit], sys: &SysParam, rng: &mut impl RAND) {
        // dropWhileEnd (\node -> not $ tau node `isPrefixOf` epoch) bte_nodes
        loop {
            match self.bte_nodes.back() {
                None => return,
                Some(cur) => {
                    if is_prefix(&cur.tau, &epoch) {
                        break;
                    }
                }
            }
            self.bte_nodes.pop_back().unwrap().zeroize();
        }

        let g1 = ECP::generator();
        let spec_r = BIG::new_ints(&rom::CURVE_ORDER);
        // At this point, bte_nodes.back() is a prefix of `epoch`.
        // Replace it with the nodes for `epoch` and later (in the subtree).
        //
        // For example, with a 5-bit epoch, if `node` is 011, and `epoch` is
        // 01101, then we replace [..., 011] with [..., 0111, 01101]:
        //   * The current epoch is now 01101.
        //   * We can still derive the keys for 01110 and 01111 from 0111.
        //   * We can no longer decrypt 01100.
        let mut node = self.bte_nodes.pop_back().unwrap();
        let mut n = node.tau.len();
        // Nothing to do if `node.tau` is already `epoch`.
        if n == epoch.len() {
            self.bte_nodes.push_back(node);
            return;
        }
        let mut d_t = node.d_t.clone();
        // Accumulators.
        //   b_acc = b * product [d_i^tau_i | i <- [1..n]]
        //   f_acc = f0 * product [f_i^tau_i | i <- [1..n]]
        let mut b_acc = node.b.clone();
        let mut f_acc = ftau_partial(&node.tau, sys).unwrap();
        let mut tau = node.tau.clone();
        while n < epoch.len() {
            if epoch[n] == Bit::Zero {
                // Save the root of the right subtree for later.
                let mut tau_1 = tau.clone();
                tau_1.push(Bit::One);
                let delta = BIG::randomnum(&spec_r, rng);

                let mut a_blind = g1.mul(&delta);
                a_blind.add(&node.a);
                let mut b_blind = d_t.pop_front().unwrap();
                b_blind.add(&b_acc);
                let mut ftmp = f_acc.clone();
                ftmp.add(&sys.f[n]);
                b_blind.add(&ftmp.mul(&delta));

                let mut e_blind = sys.h.mul(&delta);
                e_blind.add(&node.e);
                let mut d_t_blind = LinkedList::new();
                let mut k = n + 1;
                d_t.iter().for_each(|d| {
                    let mut tmp = sys.f[k].mul(&delta);
                    tmp.add(&d);
                    d_t_blind.push_back(tmp);
                    k += 1;
                });
                let mut d_h_blind = Vec::new();
                node.d_h.iter().zip(&sys.f_h).for_each(|(d, f)| {
                    let mut tmp = f.mul(&delta);
                    tmp.add(&d);
                    d_h_blind.push(tmp);
                });
                self.bte_nodes.push_back(BTENode {
                    tau: tau_1,
                    a: a_blind,
                    b: b_blind,
                    d_t: d_t_blind,
                    d_h: d_h_blind,
                    e: e_blind,
                });
            } else {
                // Update accumulators.
                f_acc.add(&sys.f[n]);
                b_acc.add(&d_t.pop_front().unwrap());
            }
            tau.push(epoch[n]);
            n += 1;
        }

        let delta = BIG::randomnum(&spec_r, rng);
        let mut a = g1.mul(&delta);
        a.add(&node.a);
        let mut e = sys.h.mul(&delta);
        e.add(&node.e);
        b_acc.add(&f_acc.mul(&delta));

        let mut d_t_blind = LinkedList::new();
        // Typically `d_t_blind` remains empty.
        // It is only nontrivial if `epoch` is less than LAMBDA_T bits.
        let mut k = n;
        d_t.iter().for_each(|d| {
            let mut tmp = sys.f[k].mul(&delta);
            tmp.add(&d);
            d_t_blind.push_back(tmp);
            k += 1;
        });
        let mut d_h_blind = Vec::new();
        node.d_h.iter().zip(&sys.f_h).for_each(|(d, f)| {
            let mut tmp = f.mul(&delta);
            tmp.add(&d);
            d_h_blind.push(tmp);
        });

        self.bte_nodes.push_back(BTENode {
            tau,
            a,
            b: b_acc,
            d_t: d_t_blind,
            d_h: d_h_blind,
            e,
        });
        node.zeroize();
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: [u8; 1 + 48] = [0; 1 + 48];
        let mut buf2: [u8; 1 + 96] = [0; 1 + 96];
        let mut v = Vec::new();
        leb128(&mut v, self.bte_nodes.len());
        for it in self.bte_nodes.iter() {
            leb128(&mut v, it.tau.len());
            for i in it.tau.iter() {
                v.push(i.into());
            }
            it.a.tobytes(&mut buf, true);
            v.extend_from_slice(&buf);
            it.b.tobytes(&mut buf2, true);
            v.extend_from_slice(&buf2);
            leb128(&mut v, it.d_t.len());
            for d in it.d_t.iter() {
                d.tobytes(&mut buf2, true);
                v.extend_from_slice(&buf2);
            }
            leb128(&mut v, it.d_h.len());
            for d in it.d_h.iter() {
                d.tobytes(&mut buf2, true);
                v.extend_from_slice(&buf2);
            }
            it.e.tobytes(&mut buf2, true);
            v.extend_from_slice(&buf2);
        }
        v
    }

    pub fn deserialize(buf: &[u8]) -> SecretKey {
        let mut cur = 0;
        let listlen = unleb128(&buf, &mut cur);
        let mut bte_nodes = LinkedList::new();
        for _i in 0..listlen {
            let taulen = unleb128(&buf, &mut cur);
            let mut tau: Vec<Bit> = Vec::new();
            for _i in 0..taulen {
                tau.push(Bit::from(buf[cur]));
                cur += 1;
            }
            let a = unecp(&buf, &mut cur);
            let b = unecp2(&buf, &mut cur);
            let dslen = unleb128(&buf, &mut cur);

            let mut d_t = LinkedList::new();
            for _i in 0..dslen {
                let d = unecp2(&buf, &mut cur);
                d_t.push_back(d);
            }
            let d_hlen = unleb128(&buf, &mut cur);
            let mut d_h = Vec::new();
            for _i in 0..d_hlen {
                let d = unecp2(&buf, &mut cur);
                d_h.push(d);
            }
            let e = unecp2(&buf, &mut cur);
            bte_nodes.push_back(BTENode {
                tau,
                a,
                b,
                d_t,
                d_h,
                e,
            });
        }
        SecretKey { bte_nodes }
    }
}

fn leb128(v: &mut Vec<u8>, mut n: usize) {
    loop {
        let mut b = n & 127;
        if n > 127 {
            b |= 128
        };
        v.push(b as u8);
        n >>= 7;
        if n == 0 {
            break;
        }
    }
}

fn unleb128(v: &[u8], cur: &mut usize) -> usize {
    let mut n = 0;
    let mut m = 1;
    loop {
        let b = v[*cur] as usize;
        *cur += 1;
        n += m * (b & 127);
        if b < 128 {
            break;
        }
        m *= 128;
    }
    n
}

fn unecp(buf: &[u8], cur: &mut usize) -> ECP {
    let a = ECP::frombytes(&buf[*cur..]);
    *cur = *cur + 1 + 48;
    a
}

fn unecp2(buf: &[u8], cur: &mut usize) -> ECP2 {
    let a = ECP2::frombytes(&buf[*cur..]);
    *cur = *cur + 1 + 96;
    a
}

pub struct SingleCiphertext {
    pub cc: ECP,
    pub rr: ECP,
    pub ss: ECP,
    pub zz: ECP2,
}

/// The `Enc` function of section 7.2.
///
/// For testing. In practice, we only use forward-secure encryption with NIDKG.
pub fn enc_single(
    pk: &ECP,
    msg: isize,
    tau: &[Bit],
    rng: &mut impl RAND,
    sys: &SysParam,
) -> SingleCiphertext {
    let p = BIG::new_ints(&rom::CURVE_ORDER);
    let spec_r = BIG::randomnum(&p, rng);
    let s = BIG::randomnum(&p, rng);
    let g1 = ECP::generator();
    let m = BIG::new_int(msg);
    let cc = pk.mul2(&spec_r, &g1, &m);
    let rr = g1.mul(&spec_r);
    let ss = g1.mul(&s);
    let id = ftau_partial(tau, sys).unwrap();
    let mut zz = id.mul(&spec_r);
    zz.add(&sys.h.mul(&s));
    SingleCiphertext { cc, rr, ss, zz }
}

/// The `Dec` function of Section 7.2.
///
/// For testing. In practice, we only use forward-secure encryption with NIDKG.
pub fn dec_single(dks: &mut SecretKey, ct: &SingleCiphertext, sys: &SysParam) -> isize {
    use miracl_core::bls12381::pair;
    let g1 = ECP::generator();
    let g2 = ECP2::generator();

    let dk = dks.current().unwrap();

    // Sanity check.
    let id = ftau_partial(&dk.tau, sys).unwrap();

    let mut g1neg = g1.clone();
    g1neg.neg();
    let mut x = pair::ate2(&id, &ct.rr, &sys.h, &ct.ss);
    x.mul(&pair::ate(&ct.zz, &g1neg));
    println!("sanity check? {}", pair::fexp(&x).isunity());

    let mut rneg = ct.rr.clone();
    rneg.neg();
    let mut sneg = ct.ss.clone();
    sneg.neg();
    x = pair::ate2(&g2, &ct.cc, &dk.b, &rneg);
    x.mul(&pair::ate2(&ct.zz, &dk.a, &dk.e, &sneg));
    x = pair::fexp(&x);

    let base = pair::fexp(&pair::ate(&g2, &g1));
    baby_giant(&x, &base, 0, CHUNK_SIZE).unwrap()
}

pub struct CRSZ {
    pub cc: Vec<Vec<ECP>>,
    pub rr: Vec<ECP>,
    pub ss: Vec<ECP>,
    pub zz: Vec<ECP2>,
}

fn format_ecp(f: &mut std::fmt::Formatter<'_>, ecp: &ECP) -> std::fmt::Result {
    let mut ecp_buffer = [0; 49];
    ecp.tobytes(&mut ecp_buffer, true);
    write!(f, "0x{}", hex::encode(&ecp_buffer[..]))
}

impl std::fmt::Debug for CRSZ {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CRSZ{{\n  cc: [")?;
        for ciphertext in &self.cc {
            writeln!(f, "    [")?;
            for chunk in ciphertext {
                write!(f, "      ")?;
                format_ecp(f, chunk)?;
                writeln!(f)?;
            }
            writeln!(f, "    ],")?;
        }
        write!(f, "  ], ... }}")
    }
}

/// Randomness needed for NIZK proofs.
pub struct ToxicWaste {
    pub spec_r: Vec<BIG>,
    pub s: Vec<BIG>,
}

impl zeroize::Zeroize for ToxicWaste {
    fn zeroize(&mut self) {
        self.spec_r.iter_mut().for_each(|big| big.zero());
        self.s.iter_mut().for_each(|big| big.zero());
    }
}

/// Encrypt chunks. Returns ciphertext as well as the random spec_r's and s's
/// chosen, for later use in NIZK proofs.
pub fn enc_chunks(
    sij: &[Vec<isize>],
    pks: Vec<&ECP>,
    tau: &[Bit],
    sys: &SysParam,
    rng: &mut impl RAND,
) -> Option<(CRSZ, ToxicWaste)> {
    // do
    //   chunks <- headMay allChunks
    //   guard $ all (== chunks) allChunks
    let all_chunks: LinkedList<_> = sij.iter().map(Vec::len).collect();
    let chunks = *all_chunks.front().unwrap();
    for si in sij.iter() {
        if si.len() != chunks {
            return None; // Chunk lengths disagree.
        }
    }
    use miracl_core::bls12381::pair::g1mul;
    use miracl_core::bls12381::pair::g2mul;
    let g1 = ECP::generator();
    let p = BIG::new_ints(&rom::CURVE_ORDER);

    // do
    //   spec_r <- replicateM chunks getRandom
    //   s <- replicateM chunks getRandom
    //   let rr = (g1^) <$> spec_r
    //   let ss = (g1^) <$> s
    let mut spec_r = Vec::new();
    let mut s = Vec::new();
    let mut rr = Vec::new();
    let mut ss = Vec::new();
    for _j in 0..chunks {
        {
            let tmp = BIG::randomnum(&p, rng);
            spec_r.push(tmp);
            rr.push(g1mul(&g1, &tmp));
        }
        {
            let tmp = BIG::randomnum(&p, rng);
            s.push(tmp);
            ss.push(g1mul(&g1, &tmp));
        }
    }
    // [[pk^spec_r * g1^s | (spec_r, s) <- zip rs si] | (pk, si) <- zip pks sij]
    let cc: Vec<Vec<_>> = sij
        .iter()
        .zip(&pks)
        .map(|(sj, pk)| {
            sj.iter()
                .zip(&spec_r)
                .map(|(s, spec_r)| pk.mul2(&spec_r, &g1, &BIG::new_int(*s)))
                .collect()
        })
        .collect();

    let extendedtau = extend_tau(&cc, &rr, &ss, &tau);
    let id = ftau(&extendedtau, sys).unwrap();
    let mut zz = Vec::new();
    for j in 0..chunks {
        let mut tmp = g2mul(&id, &spec_r[j]);
        tmp.add(&g2mul(&sys.h, &s[j]));
        zz.push(tmp);
    }
    Some((CRSZ { cc, rr, ss, zz }, ToxicWaste { spec_r, s }))
}

pub fn is_prefix(xs: &[Bit], ys: &[Bit]) -> bool {
    // isPrefix [] _ = True
    // isPrefix _ [] = False
    // isPrefix (x:xt) (y:yt) = x == y && isPrefix xt yt
    if xs.len() > ys.len() {
        return false;
    }
    for i in 0..xs.len() {
        if xs[i] != ys[i] {
            return false;
        }
    }
    true
}

pub fn find_prefix<'a>(dks: &'a SecretKey, tau: &[Bit]) -> Option<&'a BTENode> {
    for node in dks.bte_nodes.iter() {
        if is_prefix(&node.tau, tau) {
            return Some(node);
        }
    }
    None
}

/// Solves discrete log problem with baby-step giant-step. Returns:
///
///   find (\x -> base^x == tgt) [lo..lo + range - 1]
///
/// using an O(sqrt(N)) approach rather than a naive O(N) search.
///
/// We call `reduce()` before every `tobytes()` because this algorithm requires
/// the same element to serialize identically every time. (MIRACL does not
/// automatically perform Montgomery reduction for serialization, so in general
/// x == y does not imply x.tobytes() == y.tobytes().)
///
/// We cut the exponent in half, that is, for a range of 2^46, we build a table
/// of size 2^23 then perform up to 2^23 FP12 multiplications and lookups.
/// Depending on the cost of CPU versus RAM, it may be better to split
/// differently.
pub fn baby_giant(tgt: &FP12, base: &FP12, lo: isize, range: isize) -> Option<isize> {
    if range <= 0 {
        return None;
    }
    use std::collections::HashMap;
    let mut babies = HashMap::new();
    let mut n = 0;
    let mut g = FP12::new();
    g.one();
    loop {
        if n * n >= range {
            break;
        }
        let mut bytes = vec![0; FP12_SIZE];
        g.reduce();
        g.tobytes(&mut bytes);
        babies.insert(bytes, n);
        g.mul(&base);
        n += 1;
    }
    g.inverse();

    let mut t = *base;
    if lo >= 0 {
        t = t.pow(&BIG::new_int(lo));
        t.inverse();
    } else {
        t = t.pow(&BIG::new_int(-lo));
    }
    t.mul(&tgt);

    let mut x = lo;
    loop {
        let mut bytes = vec![0; FP12_SIZE];
        t.reduce();
        t.tobytes(&mut bytes);
        if let Some(i) = babies.get(&bytes) {
            return Some(x + i);
        }
        t.mul(&g);
        x += n;
        if x >= lo + range {
            break;
        }
    }
    None
}

#[derive(Debug)]
pub enum DecErr {
    ExpiredKey,
    /// One or more dlogs failed to compute.
    ///
    /// * good: Vec<(dealer index, discrete log)>
    /// * bad: Vec<(dealer index, value for which dlog has not been found)>
    DLogCheat {
        good: Vec<(usize, isize)>,
        bad: Vec<(usize, FP12)>,
    },
}

/// Decrypt the i-th group of chunks.
///
/// Decrypting a message for a future epoch hardly costs more than a message for
/// a current epoch: at most lambda_t point additions.
///
/// Upgrading a key is expensive in comparison because we must compute new
/// subtree roots and re-"blind" them (the random deltas of the paper) to hide
/// ciphertexts from future keys. Each re-blinding costs at least lambda_h
/// (which is 256 in our system) point multiplications.
///
/// Caller must ensure i < n, where n = crsz.cc.len().
pub fn dec_chunks(
    dks: &SecretKey,
    i: usize,
    crsz: &CRSZ,
    tau: &[Bit],
) -> Result<Vec<isize>, DecErr> {
    let extendedtau = extend_tau(&crsz.cc, &crsz.rr, &crsz.ss, &tau);
    let dk = match find_prefix(dks, &tau) {
        None => return Err(DecErr::ExpiredKey),
        Some(node) => node,
    };
    let mut bneg = dk.b.clone();
    let mut l = dk.tau.len();
    for tmp in dk.d_t.iter() {
        if extendedtau[l] == Bit::One {
            bneg.add(&tmp);
        }
        l += 1
    }
    for k in 0..LAMBDA_H {
        if extendedtau[LAMBDA_T + k] == Bit::One {
            bneg.add(&dk.d_h[k]);
        }
    }
    bneg.neg();
    let g1 = ECP::generator();
    let g2 = ECP2::generator();
    let mut eneg = dk.e.clone();
    eneg.neg();
    let cj = &crsz.cc[i];
    use miracl_core::bls12381::pair;

    // zipWith4 f cj rr ss zz where
    //   f c spec_r s z =
    //     ate(g2, c) * ate(bneg, spec_r) * ate(z, dk_a) * ate(eneg, s)
    let powers: Vec<_> = cj
        .iter()
        .zip(crsz.rr.iter().zip(crsz.ss.iter().zip(crsz.zz.iter())))
        .map(|(c, (spec_r, (s, z)))| {
            let mut m = pair::ate2(&g2, &c, &bneg, &spec_r);
            m.mul(&pair::ate2(&z, &dk.a, &eneg, &s));
            pair::fexp(&m)
        })
        .collect();

    // Find discrete log of powers with baby-step-giant-step in [0..CHUNK_SIZE].
    // If at least one log lies outside this range, then return a DLogCheat
    // error identifying the good and bad logs by index.
    let base = pair::fexp(&pair::ate(&g2, &g1));
    let mut bad = Vec::new();
    let mut good = Vec::new();
    for (idx, item) in powers.iter().enumerate() {
        match baby_giant(item, &base, 0, CHUNK_SIZE) {
            Some(dlog) => good.push((idx, dlog)),
            None => bad.push((idx, *item)),
        }
    }
    if !bad.is_empty() {
        return Err(DecErr::DLogCheat { good, bad });
    }
    Ok(good.iter().map(|(_, base)| *base).collect())
}

pub fn solve_all_logs(spec_n: usize, spec_m: usize, dec_err: &DecErr) -> Vec<(usize, BIG)> {
    match dec_err {
        DecErr::DLogCheat { good, bad } => {
            let mut solved_bad: Vec<_> = bad
                .iter()
                .map(|(idx, tgt)| (*idx, solve_cheater_log(spec_n, spec_m, &tgt).unwrap()))
                .collect();
            let mut solved: Vec<_> = good
                .iter()
                .map(|(idx, n)| (*idx, BIG::new_int(*n)))
                .collect();
            solved.append(&mut solved_bad);
            solved.sort_by(|(a, _), (b, _)| a.cmp(b));
            solved
        }
        _ => {
            panic!("BUG! Want a DLogCheat struct.");
        }
    }
}

// Part of DVfy of Section 9.1.
// In addition to verifying the proofs of chunking and sharing,
// we must also verify ciphertext integrity.
pub fn verify_ciphertext_integrity(crsz: &CRSZ, tau: &[Bit], sys: &SysParam) -> Result<(), ()> {
    let n = if crsz.cc.is_empty() {
        0
    } else {
        crsz.cc[0].len()
    };
    if crsz.rr.len() != n || crsz.ss.len() != n || crsz.zz.len() != n {
        // In theory, this is unreachable fail because deserialization only succeeds
        // when the vectors of a CRSZ have the same length. (In practice, it's
        // surprising how often "unreachable" code is reached!)
        return Err(());
    }

    use miracl_core::bls12381::pair;
    let g1 = ECP::generator();
    let extendedtau = extend_tau(&crsz.cc, &crsz.rr, &crsz.ss, &tau);
    let id = ftau(&extendedtau, sys).unwrap();

    // check for all j:
    //   e(g1, Z_j) = e(R_j, f_0 \Prod_{i=0}^{\lambda) f_i^{\tau_i) * e(S_j, h)
    let checks: Result<(), ()> = crsz
        .rr
        .iter()
        .zip(crsz.ss.iter().zip(crsz.zz.iter()))
        .map(|(spec_r, (s, z))| {
            let lhs = pair::fexp(&pair::ate(z, &g1));
            let rhs = pair::fexp(&pair::ate2(&id, spec_r, &sys.h, s));
            if lhs.equals(&rhs) {
                Ok(())
            } else {
                Err(())
            }
        })
        .collect();
    checks
}

/// Returns tau ++ bitsOf (sha256 (cc, rr, ss, tau)).
///
/// See the description of Deal in Section 9.1.
fn extend_tau(cc: &[Vec<ECP>], rr: &[ECP], ss: &[ECP], tau: &[Bit]) -> Vec<Bit> {
    let mut h = miracl_core::hash256::HASH256::new();
    cc.iter()
        .for_each(|cc_i| cc_i.iter().for_each(|cc_ij| process_ecp(&mut h, cc_ij)));
    rr.iter().for_each(|point| process_ecp(&mut h, point));
    ss.iter().for_each(|point| process_ecp(&mut h, point));
    tau.iter().for_each(|t| h.process_num(t.into()));

    let mut extendedtau: Vec<Bit> = tau.to_vec();
    h.hash().iter().for_each(|byte| {
        for b in 0..8 {
            extendedtau.push(Bit::from((byte >> b) & 1));
        }
    });
    extendedtau
}

/// Computes the function f of the paper.
///
/// The bit vector tau must have length lambda_T + lambda_H.
fn ftau(tau: &[Bit], sys: &SysParam) -> Option<ECP2> {
    if tau.len() != sys.lambda_t + sys.lambda_h {
        return None;
    }
    let mut id = sys.f0.clone();
    for (n, t) in tau.iter().enumerate() {
        if *t == Bit::One {
            if n < sys.lambda_t {
                id.add(&sys.f[n]);
            } else {
                id.add(&sys.f_h[n - sys.lambda_t]);
            }
        }
    }
    Some(id)
}

/// Computes f for bit vectors tau <= lambda_T.
fn ftau_partial(tau: &[Bit], sys: &SysParam) -> Option<ECP2> {
    if tau.len() > sys.lambda_t {
        return None;
    }
    // id = product $ f0 : [f | (t, f) <- zip tau sys_fs, t == 1]
    let mut id = sys.f0.clone();
    tau.iter().zip(sys.f.iter()).for_each(|(t, f)| {
        if *t == Bit::One {
            id.add(&f);
        }
    });
    Some(id)
}

/// An FS key upgrade can take up to 2 * LAMBDA_T * LAMBDA_H point
/// multiplications. This is tolerable in practice for LAMBDA_T = 32, but in
/// tests, smaller values are preferable.
pub const LAMBDA_T: usize = 32;
pub const LAMBDA_H: usize = 256;

pub fn mk_sys_params() -> SysParam {
    let mut f = Vec::new();
    let dst = b"DFX01-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
    let f0 = htp2_bls12381(dst, &"f0");
    for i in 0..LAMBDA_T {
        let s = format!("f{}", i + 1);
        f.push(htp2_bls12381(dst, &s));
    }
    let mut f_h = Vec::new();
    for i in 0..LAMBDA_H {
        let s = format!("f_h{}", i);
        f_h.push(htp2_bls12381(dst, &s));
    }
    SysParam {
        lambda_t: LAMBDA_T,
        lambda_h: LAMBDA_H,
        f0,
        f,
        f_h,
        h: htp2_bls12381(dst, &"h"),
    }
}

// Miracl's documentation cautions against using BIG to hold negative integers.
// However, sometimes our code produces negative isize values representing
// elements of Z_r (where r is the order of G1).
pub fn negative_safe_new_int(n: isize) -> BIG {
    if n < 0 {
        let mut tmp = BIG::new_int(-n);
        tmp.rsub(&curve_order());
        tmp
    } else {
        BIG::new_int(n)
    }
}

// Brute-forces a discrete log for a malicious DKG participant whose NIZK
// chunking proof checks out.
// For some Delta in [1..E - 1] the answer s satisfies (Delta * s) in [1 - Z..Z
// - 1].
pub fn solve_cheater_log(spec_n: usize, spec_m: usize, target: &FP12) -> Option<BIG> {
    use miracl_core::bls12381::pair;
    let bb_constant = CHUNK_SIZE as usize;
    let ee = 1 << CHALLENGE_BITS;
    let ss = spec_n * spec_m * (bb_constant - 1) * (ee - 1);
    let zz = (2 * NUM_ZK_REPETITIONS * ss) as isize;
    let base = pair::fexp(&pair::ate(&ECP2::generator(), &ECP::generator()));
    let mut target_power = FP12::new_int(1);
    let spec_r = BIG::new_ints(&rom::CURVE_ORDER);
    // For each Delta in [1..E - 1] we compute target^Delta and use
    // baby-step-giant-step to find `scaled_answer` such that:
    //   base^scaled_answer = target^Delta
    // Then base^(scaled_answer * invDelta) = target where
    //   invDelta = inverse of Delta mod spec_r
    // That is, answer = scaled_answer * invDelta.
    for delta in 1..ee {
        target_power.mul(&target);
        match baby_giant(&target_power, &base, 1 - zz, 2 * zz - 1) {
            None => {}
            Some(scaled_answer) => {
                let mut answer = BIG::new_int(delta as isize);
                answer.invmodp(&spec_r);
                answer = BIG::modmul(&answer, &negative_safe_new_int(scaled_answer), &spec_r);
                answer.norm();
                return Some(answer);
            }
        }
    }
    None
}
