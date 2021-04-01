//! Tests for combined forward secure encryption and ZK proofs

use ic_crypto_internal_fs_ni_dkg as dkg;

use dkg::forward_secure::*;
use dkg::utils::RAND_ChaCha20;
use miracl_core::rand::RAND;

#[test]
fn fs_keys_should_be_valid() {
    let sys = &mk_sys_params();
    let rng = &mut RAND_ChaCha20::new([42; 32]);

    let (pk, _dk) = kgen(sys, rng);
    assert!(pk.verify(), "Generated public key should be valid");
}

#[test]
fn encrypt_decrypt_single() {
    let sys = &mk_sys_params();
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let (mut pk, mut dk) = kgen(sys, rng);
    let v = pk.serialize();
    pk = PublicKey::deserialize(&v);
    assert!(pk.verify(), "Forward secure public key failed validation");
    let epoch0 = vec![Bit::Zero; 5];
    let message = 123;
    let ct = enc_single(&pk.y, message, &epoch0, rng, sys);
    let plain = dec_single(&mut dk, &ct, sys);
    assert!(plain == message, "plaintext mismatch");
}

/// Tests that a chunk encrypted to a particular epoch can be decrypted.
///
/// Note: This can be extended further by:
/// * Varying the secret key epoch; this is always zero in this test.
/// * Varying the plaintexts more; here we have only fairly noddy variation.
fn encrypted_chunks_should_decrypt(epoch: u32) {
    let sys = &mk_sys_params();
    let rng = &mut RAND_ChaCha20::new([42; 32]);

    let mut keys = Vec::new();
    for i in 0u8..3 {
        println!("generating key pair {}...", i);
        rng.seed(32, &[0x10 | i; 32]);
        let key_pair = kgen(sys, rng);
        println!("{:#?}", &key_pair.0);
        keys.push(key_pair);
    }
    let public_keys_with_zk: Vec<_> = keys.iter().map(|key| &key.0).collect();
    let pks = public_keys_with_zk.iter().map(|key| &key.y).collect();

    let sij: Vec<_> = (0..keys.len())
        .map(|receiver_index| {
            let chunk =
                (receiver_index | (receiver_index << 8) | 0x0FF00FF0) % (CHUNK_SIZE as usize);
            vec![chunk as isize; NUM_CHUNKS]
        })
        .collect();
    println!("Messages: {:#?}", sij);

    let tau = tau_from_u32(sys, epoch);
    let encryption_seed = [105; 32];
    rng.seed(32, &encryption_seed);
    let (crsz, _toxic) = enc_chunks(&sij[..], pks, &tau, sys, rng).expect("Encryption failed");
    println!(
        "Ciphertext:\n  Seed: {:?}\n  {:#?}",
        &encryption_seed, &crsz
    );

    let dk = &mut keys[1].1;
    verify_ciphertext_integrity(&crsz, &tau, sys).expect("ciphertext integrity check failed");
    let out = dec_chunks(&dk, 1, &crsz, &tau);
    println!("decrypted: {:?}", out);
    assert!(out.unwrap() == sij[1], "decrypt . encrypt == id");
}

#[test]
fn encrypted_chunks_should_decrypt_00() {
    encrypted_chunks_should_decrypt(0)
}
#[test]
fn encrypted_chunks_should_decrypt_01() {
    encrypted_chunks_should_decrypt(1)
}
#[test]
fn encrypted_chunks_should_decrypt_05() {
    encrypted_chunks_should_decrypt(5)
}
#[test]
fn encrypted_chunks_should_decrypt_10() {
    encrypted_chunks_should_decrypt(10)
}

// Returns a random element of FP12 of order CURVE_ORDER (i.e. call fexp()
// before returning).
// Our tests call FP12::pow(), which only works on elements of order
// CURVE_ORDER.
fn fp12_rand(rng: &mut impl RAND) -> miracl_core::bls12381::fp12::FP12 {
    use miracl_core::bls12381::fp12::FP12;
    use miracl_core::bls12381::fp4::FP4;
    use miracl_core::bls12381::pair;
    pair::fexp(&FP12::new_fp4s(
        &FP4::new_rand(rng),
        &FP4::new_rand(rng),
        &FP4::new_rand(rng),
    ))
}

#[test]
fn baby_giant_1000() {
    use miracl_core::bls12381::big::BIG;
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    for x in 0..1000 {
        let base = fp12_rand(rng);
        let tgt = base.pow(&BIG::new_int(x));
        assert!(
            baby_giant(&tgt, &base, -24, 1024).unwrap() == x,
            "baby-giant finds x"
        );
    }
}

#[test]
fn baby_giant_negative() {
    use miracl_core::bls12381::big::BIG;
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    for x in 0..1000 {
        let base = fp12_rand(rng);
        let mut tgt = base.pow(&BIG::new_int(x));
        tgt.inverse();
        assert!(
            baby_giant(&tgt, &base, -999, 1000).unwrap() == -x,
            "baby-giant finds x"
        );
    }
}

// The bounds of the NIZK chunking proof are loose, so a malicious DKG
// participant can force us to search around 2^40 candidates for a discrete log.
// (This is not the entire cost. We must also search for a cofactor Delta.)
#[test]
fn baby_giant_big_range() {
    use miracl_core::bls12381::big::BIG;
    let rng = &mut RAND_ChaCha20::new([42; 32]);
    let base = fp12_rand(rng);
    let x = (1 << 39) + 123;
    let tgt = base.pow(&BIG::new_int(x));
    assert!(
        baby_giant(&tgt, &base, -(1 << 10), 1 << 40).unwrap() == x,
        "baby-giant finds x"
    );
}

// Find the log for a cheater who exceeds the bounds by a little.
#[test]
fn slightly_dishonest_dlog() {
    use miracl_core::bls12381::big::BIG;
    use miracl_core::bls12381::ecp::ECP;
    use miracl_core::bls12381::ecp2::ECP2;
    use miracl_core::bls12381::pair;
    use miracl_core::bls12381::rom;

    let base = pair::fexp(&pair::ate(&ECP2::generator(), &ECP::generator()));
    let spec_r = BIG::new_ints(&rom::CURVE_ORDER);
    // Last I checked:
    //   E = 128
    //   Z = 31960108800 * m * n
    // So searching for Delta < 10 with m = n = 1 should be tolerable.
    let mut answer = BIG::new_int(8);
    answer.invmodp(&spec_r);
    answer = BIG::modmul(&answer, &BIG::new_int(12345678), &spec_r);
    answer.norm();
    let soln = solve_cheater_log(1, 1, &base.pow(&answer)).unwrap();
    assert!(BIG::comp(&soln, &answer) == 0);

    // Check negative numbers also work.
    let mut answer = BIG::new_int(5);
    answer.invmodp(&spec_r);
    answer = BIG::modmul(&answer, &negative_safe_new_int(-12345678), &spec_r);
    answer.norm();
    let soln = solve_cheater_log(1, 1, &base.pow(&answer)).unwrap();
    assert!(BIG::comp(&soln, &answer) == 0);
}

#[test]
fn deserialize_invalid_point() {
    use miracl_core::bls12381::ecp::ECP;
    let g1 = ECP::generator();
    let mut buf = [0; 1 + 2 * 48];
    g1.tobytes(&mut buf, false);
    for (cell, i) in buf[10..20].iter_mut().zip(10..) {
        *cell = i;
    }
    let y = ECP::frombytes(&buf);
    assert!(y.is_infinity(), "invalid point deserializes as infinity");
}
