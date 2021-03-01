//! Verify that the MIRACL serialisation adheres to the standard
use crate::{miracl_g1_from_bytes, miracl_g1_to_bytes};
use ic_crypto_internal_types::curves::bls12_381::conversions::g1_bytes_from_vec;
use ic_crypto_internal_types::curves::bls12_381::G1;
use ic_crypto_internal_types::curves::test_vectors::bls12_381 as test_vectors;
use miracl_core::bls12381::ecp::ECP;

/// Note:
/// * ECP does not implement Debug.
/// * Implementing pretty-print would be good too.
/// * Ditto Eq.  Note that miracl `.equals` takes mutable arguments.

/// Verifies that conversions between a value and a test vector work as
/// expected.
fn g1_serde_should_be_correct(hex_test_vector: &str, value: &ECP, test_name: &str) {
    let serialised = miracl_g1_to_bytes(value).0;
    assert_eq!(
        hex_test_vector,
        hex::encode(&serialised[..]),
        "Serialisation does not match for {}",
        test_name
    );
    let bytes = hex::decode(hex_test_vector).expect("Invalid test vector hex encoding");
    let bytes = g1_bytes_from_vec(&bytes);
    let parsed = miracl_g1_from_bytes(&bytes).expect("Failed to parse test vector");
    assert!(
        parsed.equals(&value),
        "Parsed value does not match for {} {}",
        test_name,
        {
            let mut neg = parsed;
            neg.neg();
            if neg.equals(&value) {
                "due to sign error"
            } else {
                ""
            }
        }
    );
}

/// Verifies that `ECP::new()` returns inf.
///
/// The current implementation of `ECP::new()` returns inf, however this is not
/// guaranteed in any way and there is no documented contract that this will
/// always be so.
#[test]
fn g1_new_is_assumed_to_be_inf() {
    assert!(ECP::new().is_infinity());
}

#[test]
fn g1_serde_should_match_identity_test_vector() {
    g1_serde_should_be_correct(
        test_vectors::g1::INFINITY,
        &ECP::new(),
        "Number 0 (infinity)",
    );
}

#[test]
fn g1_generator_should_match_test_vector() {
    g1_serde_should_be_correct(
        test_vectors::g1::GENERATOR,
        &ECP::generator(),
        "Number 1 (generator)",
    );
}

#[test]
fn powers_of_2_should_be_correct() {
    test_vectors::g1::POWERS_OF_2.iter().enumerate().fold(
        ECP::generator(),
        |value, (index, test_vector)| {
            g1_serde_should_be_correct(test_vector, &value, &format!("Number {}", 1 << index));
            let mut double = value.clone();
            double.add(&value);
            double
        },
    );
}

#[test]
fn positive_numbers_should_be_correct() {
    test_vectors::g1::POSITIVE_NUMBERS.iter().enumerate().fold(
        ECP::new(),
        |mut value, (index, test_vector)| {
            value.add(&ECP::generator());
            g1_serde_should_be_correct(test_vector, &value, &format!("Number {}", index + 1));
            value
        },
    );
}

#[test]
fn negative_numbers_should_be_correct() {
    test_vectors::g1::NEGATIVE_NUMBERS.iter().enumerate().fold(
        ECP::new(),
        |mut value, (index, test_vector)| {
            value.sub(&ECP::generator());
            g1_serde_should_be_correct(
                test_vector,
                &value,
                &format!("Number {}", -(index as i64 + 1)),
            );
            value
        },
    );
}

#[test]
fn infinity_without_the_infinity_bit_should_fail_to_parse() {
    let hex_test_vector = test_vectors::g1::INFINITY;
    let infinity = hex::decode(hex_test_vector).expect("Invalid test vector hex encoding");
    let mut bytes = g1_bytes_from_vec(&infinity);
    bytes[G1::FLAG_BYTE_OFFSET] &= !G1::INFINITY_FLAG;
    if miracl_g1_from_bytes(&bytes).is_ok() {
        panic!("Should not be able to parse infinity without the infinity bit:\n Infinity: {}\n Unset:    {}", hex_test_vector, hex::encode(&bytes[..]));
    }
}

#[test]
fn finite_value_with_the_infinity_bit_should_fail_to_parse() {
    let hex_test_vector = test_vectors::g1::GENERATOR;
    let bytes = hex::decode(hex_test_vector).expect("Invalid test vector hex encoding");
    let mut bytes = g1_bytes_from_vec(&bytes);
    bytes[G1::FLAG_BYTE_OFFSET] |= G1::INFINITY_FLAG;
    if miracl_g1_from_bytes(&bytes).is_ok() {
        panic!(
            "A finite value should not be able to parse as infinity:\n {}",
            hex::encode(&bytes[..])
        );
    }
}

#[test]
fn too_large_x_should_fail_to_parse() {
    let hex_test_vector = test_vectors::g1::GENERATOR;
    let bytes = hex::decode(hex_test_vector).expect("Invalid test vector hex encoding");
    let mut bytes = g1_bytes_from_vec(&bytes);
    // Set X to -1
    bytes[G1::FLAG_BYTE_OFFSET] |= G1::NON_FLAG_BITS;
    for byte in bytes[1..10].iter_mut() {
        *byte = 0xff;
    }
    if miracl_g1_from_bytes(&bytes).is_ok() {
        panic!(
            "Should not be able to parse when X is too large: {}",
            hex::encode(&bytes[..])
        );
    }
}
