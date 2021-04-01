use super::*;
use crate::common::test_utils::crypto_component::crypto_component_with;
use crate::sign::tests::*;
use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3, NODE_4};
use ic_types::crypto::KeyId;

/*
TODO(DFN-1229): Cosider adding the below test cases for the new multisig API, then remove this comment

mod test_combine_sigs {
    use super::*;
    use proptest::prelude::*;
    mod combine_sigs_helpers {
        use super::*;
        prop_compose! {
            /// Create a lot of signatures with the given purpose and algorithm.
            /// For this to be useful, signatories and their public keys also need to be generated.
            pub fn fixture(key_purpose: KeyPurpose, algorithm_id: AlgorithmId) (
                mut contributions in proptest::collection::hash_map(
                    arbitrary_types::node_id(),
                    (arbitrary_crypto::public_key_registry_record(), arbitrary_crypto::signature()),
                1..5)) -> HashMap<NodeId, (PublicKeyRegistryRecord, Signature)> {

                for (node_id, (record, _)) in contributions.iter_mut() {
                    record.node_id = *node_id;
                    record.key_purpose = key_purpose;
                    record.algorithm_id = algorithm_id;
                }
                contributions
            }
        }
    }
    proptest! {
        #[test]
        fn combine_sigs_returns_ok(
            message: Vec<u8>,
            registry_version in arbitrary_types::registry_version(),
            contributions in combine_sigs_helpers::fixture(KeyPurpose::CommitteeMember, AlgorithmId::MultiBls12_381),
            ) {
            let message_type = MessageType::BlockProposal; // TODO(DFN-1002): Use an arbitrary message type that uses multisig.
            let public_key_registry_records: Vec<PublicKeyRegistryRecord> = contributions.values().map(|(record, _)| record).cloned().collect();
            let registry_version = {
              let max_record_version = public_key_registry_records.iter().map(|record| record.version).max().unwrap().get();
              prop_assume!(max_record_version < std::u64::MAX);
              RegistryVersion::from(std::u64::MAX - (registry_version.get() % (std::u64::MAX - max_record_version)))
            };
            let signatures: Vec<(Signature, NodeId)> = contributions.iter().map(|(node_id, (_, signature))| (signature.clone(), *node_id)).collect();
            let crypto = crypto_component_with(mock_registry_with_records(public_key_registry_records), MockSecretKeyStore::new());

            assert!(crypto.combine_sigs(signatures, &message, message_type, registry_version).is_ok());
        }

        #[test]
        fn combine_sigs_fails_if_public_keys_are_not_found(
            message: Vec<u8>,
            registry_version in arbitrary_types::registry_version(),
            contributions in combine_sigs_helpers::fixture(KeyPurpose::CommitteeMember, AlgorithmId::MultiBls12_381),
            ) {
            let message_type = MessageType::BlockProposal; // TODO(DFN-1002): Use an arbitrary message type that uses multisig.
            let signatures: Vec<(Signature, NodeId)> = contributions.iter().map(|(node_id, (_, signature))| (signature.clone(), *node_id)).collect();
            let crypto = crypto_component_with(mock_registry_with_records(Vec::new()), MockSecretKeyStore::new());
            assert!(crypto.combine_sigs(signatures, &message, message_type, registry_version).unwrap_err().is_public_key_not_found());
        }

        #[test]
        #[should_panic]
        fn combine_sigs_panics_with_no_sigs(
            message: Vec<u8>,
            registry_version in arbitrary_types::registry_version(),
            contributions in combine_sigs_helpers::fixture(KeyPurpose::CommitteeMember, AlgorithmId::MultiBls12_381),
            ){
            let message_type = MessageType::BlockProposal; // TODO(DFN-1002): Use an arbitrary message type that uses multisig.
            let public_key_registry_records: Vec<PublicKeyRegistryRecord> = contributions.values().map(|(record, _)| record).cloned().collect();
            prop_assume!(public_key_registry_records.iter().map(|record| record.version).max().unwrap() < registry_version);
            let signatures: Vec<(Signature, NodeId)> = Vec::new();
            let crypto = crypto_component_with(mock_registry_with_records(public_key_registry_records), MockSecretKeyStore::new());

            crypto.combine_sigs(signatures, &message, message_type, registry_version).unwrap_err();
        }

        #[test]
        fn combine_sigs_fails_with_an_inconsistent_algorithm(
            message: Vec<u8>,
            registry_version in arbitrary_types::registry_version(),
            contributions in combine_sigs_helpers::fixture(KeyPurpose::CommitteeMember, AlgorithmId::MultiBls12_381)
                .prop_filter("single entry maps cannot be inconsistent", |map| map.len() > 1),
            different_contribution_index: usize,
            ){
            let message_type = MessageType::BlockProposal; // TODO(DFN-1002): Use an arbitrary message type that uses multisig.
            let mut public_key_registry_records: Vec<PublicKeyRegistryRecord> = contributions.values().map(|(record, _)| record).cloned().collect();
            let different_contribution_index = different_contribution_index % public_key_registry_records.len();
            public_key_registry_records[different_contribution_index].algorithm_id = AlgorithmId::ThresBls12_381;
            prop_assume!(public_key_registry_records.iter().map(|record| record.version).max().unwrap() < registry_version);
            let signatures: Vec<(Signature, NodeId)> = contributions.iter().map(|(node_id, (_, signature))| (signature.clone(), *node_id)).collect();
            let crypto = crypto_component_with(mock_registry_with_records(public_key_registry_records), MockSecretKeyStore::new());

            assert!(crypto.combine_sigs(signatures, &message, message_type, registry_version).unwrap_err().is_inconsistent_algorithms());
        }
    }
}
*/

mod test_multi_sign {
    use super::*;
    use crate::common::test_utils::multi_bls12_381;
    use crate::common::test_utils::multi_bls12_381::MultiBls12381TestVector::{
        STABILITY_1, STABILITY_2, STABILITY_3, STABILITY_4,
    };

    #[test]
    fn should_correctly_multi_sign() {
        for (index, node, testvec) in &[
            (1, NODE_1, STABILITY_1),
            (2, NODE_2, STABILITY_2),
            (3, NODE_3, STABILITY_3),
            (4, NODE_4, STABILITY_4),
        ] {
            let (sk, pk, _pop, msg, expected_sig) = multi_bls12_381::testvec(*testvec);
            let key_id = public_key_hash_as_key_id(&pk);
            let key_record = committee_signing_record_with(
                *node,
                pk.multi_bls12_381_bytes().unwrap().to_vec(),
                key_id.to_owned(),
                REG_V2,
            );
            let secret_key_store = secret_key_store_with(key_id, sk);
            let crypto = crypto_component_with(registry_with(key_record), secret_key_store);
            let signature = crypto.sign_multi(&msg, *node, REG_V2).unwrap();
            assert_eq!(signature, expected_sig, "Test vector {} failed.", index);
        }
    }

    // TODO: DFN-1229 Add more tests in addition to the above happy-path test.
}

mod test_multi_sig_verification {
    use super::*;
    use crate::common::test_utils::hex_to_byte_vec;
    use crate::common::test_utils::multi_bls12_381;
    use crate::common::test_utils::multi_bls12_381::MultiBls12381TestVector::{
        STABILITY_1, STABILITY_2,
    };
    use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_COMB_SIG_1_2;

    #[test]
    fn should_correctly_verify_multi_sig_individual() {
        for (index, node, testvec) in &[(1, NODE_1, STABILITY_1), (2, NODE_2, STABILITY_2)] {
            let (sk, pk, _pop, msg, sig) = multi_bls12_381::testvec(*testvec);
            let key_id = public_key_hash_as_key_id(&pk);

            let key_record = committee_signing_record_with(
                *node,
                pk.multi_bls12_381_bytes().unwrap().to_vec(),
                key_id,
                REG_V1,
            );
            let secret_key_store = secret_key_store_with(key_id, sk);
            let crypto = crypto_component_with(registry_with(key_record), secret_key_store);

            let result = crypto.verify_multi_sig_individual(&sig, &msg, *node, REG_V1);
            assert!(result.is_ok(), format!("Test vector {} failed", index));
        }
    }

    #[test]
    fn should_correctly_combine_multi_sig_individuals() {
        let (_, pk_1, _, _, sig_1) = multi_bls12_381::testvec(STABILITY_1);
        let (_, pk_2, _, _, sig_2) = multi_bls12_381::testvec(STABILITY_2);
        let pk_rec_1 = committee_signing_record_with(
            NODE_1,
            pk_1.multi_bls12_381_bytes().unwrap().to_vec(),
            KeyId::from(KEY_ID_1),
            REG_V1,
        );
        let pk_rec_2 = committee_signing_record_with(
            NODE_2,
            pk_2.multi_bls12_381_bytes().unwrap().to_vec(),
            KeyId::from(KEY_ID_2),
            REG_V1,
        );
        let signatures = vec![(NODE_1, sig_1), (NODE_2, sig_2)].into_iter().collect();
        let combined_sig = CombinedMultiSigOf::new(CombinedMultiSig(hex_to_byte_vec(
            TESTVEC_MULTI_BLS12_381_COMB_SIG_1_2,
        )));

        let crypto = crypto_component_with(
            registry_with_records(vec![pk_rec_1, pk_rec_2]),
            secret_key_store_panicking_on_usage(),
        );

        assert_eq!(
            crypto
                .combine_multi_sig_individuals(signatures, REG_V1)
                .unwrap(),
            combined_sig
        );
    }

    #[test]
    fn should_correctly_verify_multi_sig_combined() {
        let (_, pk_1, _, msg_1, _) = multi_bls12_381::testvec(STABILITY_1);
        let (_, pk_2, _, msg_2, _) = multi_bls12_381::testvec(STABILITY_2);
        assert_eq!(msg_1, msg_2);
        let pk_rec_1 = committee_signing_record_with(
            NODE_1,
            pk_1.multi_bls12_381_bytes().unwrap().to_vec(),
            KeyId::from(KEY_ID_1),
            REG_V1,
        );
        let pk_rec_2 = committee_signing_record_with(
            NODE_2,
            pk_2.multi_bls12_381_bytes().unwrap().to_vec(),
            KeyId::from(KEY_ID_2),
            REG_V1,
        );
        let nodes: BTreeSet<NodeId> = vec![NODE_1, NODE_2].into_iter().collect();
        let combined_sig = CombinedMultiSigOf::new(CombinedMultiSig(hex_to_byte_vec(
            TESTVEC_MULTI_BLS12_381_COMB_SIG_1_2,
        )));

        let crypto = crypto_component_with(
            registry_with_records(vec![pk_rec_1, pk_rec_2]),
            secret_key_store_panicking_on_usage(),
        );

        assert!(crypto
            .verify_multi_sig_combined(&combined_sig, &msg_1, nodes, REG_V1)
            .is_ok());
    }

    // TODO: DFN-1233 Add more tests in addition to the above happy-path test.
}
