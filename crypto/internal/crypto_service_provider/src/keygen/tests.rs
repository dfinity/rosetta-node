use super::*;
use crate::secret_key_store::volatile_store::VolatileSecretKeyStore;
use ic_crypto_internal_test_vectors::unhex::hex_to_32_bytes;
use ic_crypto_internal_tls::keygen::TlsEd25519CertificateDerBytes;
use ic_types_test_utils::ids::node_test_id;
use openssl::x509::X509NameEntries;
use openssl::{asn1::Asn1Time, bn::BigNum, nid::Nid, x509::X509};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn should_correctly_generate_ed25519_keys() {
    let csprng = csprng_seeded_with(42);
    let csp = Csp::of(csprng, volatile_key_store());

    let (key_id, pk) = csp.gen_key_pair(AlgorithmId::Ed25519).unwrap();

    assert_eq!(
        key_id,
        KeyId::from(hex_to_32_bytes(
            "be652632635fa33651721671afa29c576396beaec8af0d8ba819605fc7dea8e4"
        )),
    );
    assert_eq!(
        pk,
        CspPublicKey::ed25519_from_hex(
            "78eda21ba04a15e2000fe8810fe3e56741d23bb9ae44aa9d5bb21b76675ff34b"
        )
    );
}

#[test]
fn should_retrieve_newly_generated_secret_key_from_store() {
    let csprng = csprng_seeded_with(42);
    let csp = Csp::of(csprng, volatile_key_store());
    let (key_id, _) = csp.gen_key_pair(AlgorithmId::Ed25519).unwrap();

    let retrieved_sk = csp.sks_read_lock().get(&key_id);

    assert_eq!(
        retrieved_sk,
        Some(CspSecretKey::ed25519_from_hex(
            "7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a"
        ))
    );
}

#[test]
/// If this test fails, old key IDs in the SKS will no longer work!
fn should_correctly_convert_tls_cert_hash_as_key_id() {
    let key_id = tls_cert_hash_as_key_id(&TlsEd25519CertificateDerBytes {
        bytes: vec![42; 10],
    });

    // We expect the following hard coded key id:
    let expected_key_id =
        hex_to_32_bytes("72b4aa974fd37a17b896f2f39a57ed7bc943f5a96f663f342bf8785f3ca24e08");
    assert_eq!(key_id, KeyId(expected_key_id));
}

fn csprng_seeded_with(seed: u64) -> impl CryptoRng + Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

fn volatile_key_store() -> VolatileSecretKeyStore {
    VolatileSecretKeyStore::new()
}

mod multi {
    use super::*;
    use ic_crypto_internal_multi_sig_bls12381::types::{PopBytes, PublicKeyBytes};
    use ic_crypto_internal_test_vectors::unhex::{hex_to_48_bytes, hex_to_96_bytes};

    struct TestVector {
        seed: u64,
        key_id: KeyId,
        public_key: CspPublicKey,
        proof_of_possession: CspPop,
    }

    fn test_vector_42() -> TestVector {
        TestVector {
            seed: 42,
            key_id: KeyId::from(hex_to_32_bytes(
                "250224d6a3e0edbaafd958bb480dc81255ec8744e36ac5eefa83e747d531272b",
            )),
            public_key: CspPublicKey::MultiBls12_381(PublicKeyBytes(hex_to_96_bytes(
                "8985344664badd2aa2d24167fa478ec03a6fc76eb05ba1c3fac9dd88b74a44ccdd5\
                 d088bb6975c06a8df4b1006f8e5350adbf82b3a758613f56d4519da62f9075adfdd\
                 882b35f35a55f532471191348924a5c3858529f83cfb032cc8962f7922",
            ))),
            proof_of_possession: CspPop::MultiBls12_381(PopBytes(hex_to_48_bytes(
                "9347f963a3d79d07515d4f1c740d2030226d84f626be4b807b1e4f5c8ec3073a34820ec08c63e5cbda02d3b862cb1570",
            ))),
        }
    }

    /// This test checks that the functionality is consistent; the values are
    /// not "correct" but they must never change.
    #[test]
    fn key_generation_is_stable() {
        let test_vector = test_vector_42();
        let csprng = csprng_seeded_with(test_vector.seed);
        let csp = Csp::of(csprng, volatile_key_store());
        let (key_id, public_key) = csp.gen_key_pair(AlgorithmId::MultiBls12_381).unwrap();

        assert_eq!(key_id, test_vector.key_id);
        assert_eq!(public_key, test_vector.public_key);
    }

    /// This test checks that the functionality is consistent; the values are
    /// not "correct" but they must never change.
    #[test]
    fn key_generation_with_pop_is_stable() {
        let test_vector = test_vector_42();
        let csprng = csprng_seeded_with(test_vector.seed);
        let csp = Csp::of(csprng, volatile_key_store());
        let (key_id, public_key, pop) = csp
            .gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)
            .expect("Failed to generate key pair with PoP");

        assert_eq!(key_id, test_vector.key_id);
        assert_eq!(public_key, test_vector.public_key);
        assert_eq!(pop, test_vector.proof_of_possession);
    }
}

mod tls {
    use super::*;
    use crate::secret_key_store::test_utils::MockSecretKeyStore;
    use ic_crypto_internal_tls::keygen::TlsEd25519CertificateDerBytes;
    use openssl::pkey::{Id, PKey};
    use openssl::x509::X509VerifyResult;

    const NODE_1: u64 = 4241;
    const NODE_2: u64 = 4242;
    const NODE_3: u64 = 4243;
    const FIXED_SEED: u64 = 42;
    const NOT_AFTER: &str = "25670102030405Z";

    #[test]
    fn should_insert_secret_key_into_store_in_der_format() {
        let sks = volatile_key_store();
        let mut csp = Csp::of(rng(), sks);

        let der_cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let x509_cert = x509_cert(&der_cert);
        let secret_key = secret_key_from_store(&mut csp, x509_cert);
        if let CspSecretKey::TlsEd25519(sk_der_bytes) = secret_key {
            let private_key = PKey::private_key_from_der(&sk_der_bytes.bytes)
                .expect("unable to parse DER secret key");
            assert_eq!(private_key.id(), Id::ED25519);
        } else {
            panic!("secret key has the wrong type");
        }
    }

    #[test]
    #[should_panic(expected = "has already been inserted")]
    fn should_panic_if_secret_key_insertion_yields_duplicate_error() {
        let mut sks_returning_error_on_insert = MockSecretKeyStore::new();
        sks_returning_error_on_insert
            .expect_insert()
            .times(1)
            .return_const(Err(SecretKeyStoreError::DuplicateKeyId(KeyId::from(
                [42; 32],
            ))));

        let mut csp = Csp::of(rng(), sks_returning_error_on_insert);

        let _ = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);
    }

    #[test]
    fn should_return_der_encoded_self_signed_certificate() {
        let mut csp = Csp::of(rng(), volatile_key_store());

        let der_cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let x509_cert = x509_cert(&der_cert);
        let public_key = x509_cert.public_key().unwrap();
        assert_eq!(x509_cert.verify(&public_key).ok(), Some(true));
        assert_eq!(x509_cert.issued(&x509_cert), X509VerifyResult::OK);
    }

    #[test]
    fn should_set_cert_subject_cn_as_node_id() {
        let mut csp = Csp::of(rng(), volatile_key_store());

        let der_cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let x509_cert = x509_cert(&der_cert);
        assert_eq!(cn_entries(&x509_cert).count(), 1);
        let subject_cn = cn_entries(&x509_cert).next().unwrap();
        let expected_subject_cn = node_test_id(NODE_1).get().to_string();
        assert_eq!(expected_subject_cn.as_bytes(), subject_cn.data().as_slice());
    }

    #[test]
    fn should_use_stable_node_id_string_representation_as_subject_cn() {
        let mut csp = Csp::of(rng(), volatile_key_store());

        let der_cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let x509_cert = x509_cert(&der_cert);
        let subject_cn = cn_entries(&x509_cert).next().unwrap();
        assert_eq!(b"w43gn-nurca-aaaaa-aaaap-2ai", subject_cn.data().as_slice());
    }

    #[test]
    fn should_set_cert_issuer_cn_as_node_id() {
        let mut csp = Csp::of(rng(), volatile_key_store());

        let der_cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let x509_cert = x509_cert(&der_cert);
        let issuer_cn = x509_cert
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap();
        let expected_issuer_cn = node_test_id(NODE_1).get().to_string();
        assert_eq!(expected_issuer_cn.as_bytes(), issuer_cn.data().as_slice());
    }

    #[test]
    fn should_not_set_cert_subject_alt_name() {
        let mut csp = Csp::of(rng(), volatile_key_store());

        let der_cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let x509_cert = x509_cert(&der_cert);
        let subject_alt_names = x509_cert.subject_alt_names();
        assert!(subject_alt_names.is_none());
    }

    #[test]
    fn should_set_random_cert_serial_number() {
        let mut csp = Csp::of(csprng_seeded_with(FIXED_SEED), volatile_key_store());

        let der_cert = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);

        let x509_cert = x509_cert(&der_cert);
        let cert_serial = x509_cert.serial_number().to_bn().unwrap();
        let expected_randomness = csprng_seeded_with(FIXED_SEED).gen::<[u8; 19]>();
        let expected_serial = BigNum::from_slice(&expected_randomness).unwrap();
        assert_eq!(expected_serial, cert_serial);
    }

    #[test]
    fn should_set_different_serial_numbers_for_multiple_certs() {
        let mut csp = Csp::of(rng(), volatile_key_store());

        let der_cert_1 = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);
        let der_cert_2 = csp.gen_tls_key_pair(node_test_id(NODE_2), NOT_AFTER);
        let der_cert_3 = csp.gen_tls_key_pair(node_test_id(NODE_3), NOT_AFTER);

        let serial_1 = serial_number(&der_cert_1);
        let serial_2 = serial_number(&der_cert_2);
        let serial_3 = serial_number(&der_cert_3);
        assert_ne!(serial_1, serial_2);
        assert_ne!(serial_2, serial_3);
        assert_ne!(serial_1, serial_3);
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        let mut csp = Csp::of(rng(), volatile_key_store());
        let not_after = NOT_AFTER;

        let cert = csp.gen_tls_key_pair(node_test_id(NODE_1), not_after);

        assert!(x509_cert(&cert).not_after() == Asn1Time::from_str_x509(not_after).unwrap());
    }

    #[test]
    #[should_panic(expected = "invalid X.509 certificate expiration date (not_after)")]
    fn should_panic_on_invalid_not_after_date() {
        let mut csp = Csp::of(rng(), volatile_key_store());

        let _panic = csp.gen_tls_key_pair(node_test_id(NODE_1), "invalid_not_after_date");
    }

    #[test]
    #[should_panic(expected = "'not after' date must not be in the past")]
    fn should_panic_if_not_after_date_is_in_the_past() {
        let mut csp = Csp::of(rng(), volatile_key_store());
        let date_in_the_past = "20000102030405Z";

        let _panic = csp.gen_tls_key_pair(node_test_id(NODE_1), &date_in_the_past);
    }

    fn x509_cert(cert: &X509PublicKeyCert) -> X509 {
        X509::from_der(&cert.certificate_der).unwrap()
    }

    fn rng() -> impl CryptoRng + Rng {
        csprng_seeded_with(42)
    }

    fn secret_key_from_store(
        csp: &mut Csp<impl CryptoRng + Rng, VolatileSecretKeyStore>,
        x509_cert: X509,
    ) -> CspSecretKey {
        let cert_der = TlsEd25519CertificateDerBytes {
            bytes: x509_cert.to_der().expect("DER-conversion failed."),
        };
        let key_id = tls_keygen::tls_cert_hash_as_key_id(&cert_der);
        csp.sks_read_lock()
            .get(&key_id)
            .expect("secret key not found")
    }

    fn cn_entries(x509_cert: &X509) -> X509NameEntries {
        x509_cert.subject_name().entries_by_nid(Nid::COMMONNAME)
    }

    fn serial_number(der_cert: &X509PublicKeyCert) -> BigNum {
        x509_cert(&der_cert).serial_number().to_bn().unwrap()
    }
}
