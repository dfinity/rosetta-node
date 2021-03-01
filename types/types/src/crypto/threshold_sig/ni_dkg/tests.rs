use super::*;
use crate::crypto::tests::set_of;
use crate::NumberOfNodes;
use ic_crypto_internal_types::curves::bls12_381::{Fr, G1, G2};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    Dealing, EncryptedShares, PublicCoefficientsBytes, ZKProofDec, ZKProofShare, NUM_CHUNKS,
    NUM_ZK_REPETITIONS,
};

#[test]
fn should_correctly_convert_csp_dkg_dealing_to_dkg_dealing() {
    let csp_dealing = csp_dealing();

    assert_eq!(
        NiDkgDealing::from(csp_dealing.clone()),
        NiDkgDealing {
            internal_dealing: csp_dealing
        }
    );
}

#[test]
fn should_correctly_convert_dkg_dealing_to_csp_dkg_dealing() {
    let csp_dealing = csp_dealing();
    let dealing = NiDkgDealing {
        internal_dealing: csp_dealing.clone(),
    };

    assert_eq!(CspNiDkgDealing::from(dealing), csp_dealing);
}

#[test]
fn should_correctly_convert_ni_dkg_transcript_to_csp_dkg_transcript() {
    let csp_dkg_transcript = empty_ni_csp_dkg_transcript();
    let dkg_transcript = transcript_with_internal_csp_transcript(&csp_dkg_transcript);

    assert_eq!(
        CspNiDkgTranscript::from(&dkg_transcript),
        csp_dkg_transcript
    );
}

#[test]
// This is explicitly tested since this appears in debug log messages. The
// message should be well readable and in particular contain hex encodings where
// applicable.
fn should_correctly_format_dealing_display_message() {
    let dealing = NiDkgDealing::dummy_dealing_for_tests(0);

    let display_text = format!("{}", dealing);

    let expected_text =
        "NiDkgDealing { internal_dealing: Groth20_Bls12_381(Dealing { public_coefficients: PublicCoefficientsBytes { coefficients: [] }, \
        ciphertexts: FsEncryptionCiphertext { rand_r: [G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)], \
        rand_s: [G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)], \
        rand_z: [G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)], \
        ciphertext_chunks: [[G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)]] }, \
        zk_proof_decryptability: ZKProofDecHelper { first_move_y0: \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        first_move_b: [G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)], \
        first_move_c: [G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)], \
        second_move_d: [G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        G1(0x010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101)], \
        second_move_y: G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        response_z_r: [Fr(\"0000000000000000000000000000000000000000000000000000000000000000\")], \
        response_z_s: [Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        Fr(\"0000000000000000000000000000000000000000000000000000000000000000\")], \
        response_z_b: Fr(\"0000000000000000000000000000000000000000000000000000000000000000\") }, \
        zk_proof_correct_sharing: ZKProofShare { \
        first_move_f: G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        first_move_a: G2(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        first_move_y: G1(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), \
        response_z_r: Fr(\"0000000000000000000000000000000000000000000000000000000000000000\"), \
        response_z_a: Fr(\"0000000000000000000000000000000000000000000000000000000000000000\") } }) }";

    assert_eq!(display_text, expected_text);
}

fn transcript_with_internal_csp_transcript(
    csp_dkg_transcript: &CspNiDkgTranscript,
) -> NiDkgTranscript {
    NiDkgTranscript {
        dkg_id: NiDkgId {
            start_block_height: Height::new(42),
            dealer_subnet: SubnetId::from(PrincipalId::new_subnet_test_id(1)),
            dkg_tag: NiDkgTag::LowThreshold,
            target_subnet: NiDkgTargetSubnet::Local,
        },
        threshold: NiDkgThreshold::new(NumberOfNodes::new(2)).unwrap(),
        committee: NiDkgReceivers::new(set_of(&[NodeId::new(PrincipalId::new_subnet_test_id(1))]))
            .unwrap(),
        registry_version: Default::default(),
        internal_csp_transcript: csp_dkg_transcript.clone(),
    }
}

fn csp_dealing() -> CspNiDkgDealing {
    CspNiDkgDealing::Groth20_Bls12_381(Dealing {
        public_coefficients: PublicCoefficientsBytes {
            coefficients: vec![],
        },
        ciphertexts: EncryptedShares {
            rand_r: [G1([1; G1::SIZE]); NUM_CHUNKS],
            rand_s: [G1([12; G1::SIZE]); NUM_CHUNKS],
            rand_z: [G2([123; G2::SIZE]); NUM_CHUNKS],
            ciphertext_chunks: vec![[G1([234; G1::SIZE]); NUM_CHUNKS]],
        },
        zk_proof_decryptability: zk_proof_dec(),
        zk_proof_correct_sharing: zk_proof_share(),
    })
}

pub fn zk_proof_dec() -> ZKProofDec {
    let fr = Fr([0u8; Fr::SIZE]);
    let g1 = G1([0u8; G1::SIZE]);

    ZKProofDec {
        first_move_y0: g1,
        first_move_b: [g1; NUM_ZK_REPETITIONS],
        first_move_c: [g1; NUM_ZK_REPETITIONS],
        second_move_d: Vec::new(),
        second_move_y: g1,
        response_z_r: Vec::new(),
        response_z_s: [fr; NUM_ZK_REPETITIONS],
        response_z_b: fr,
    }
}

pub fn zk_proof_share() -> ZKProofShare {
    let fr = Fr([0u8; Fr::SIZE]);
    let g1 = G1([0u8; G1::SIZE]);
    let g2 = G2([0u8; G2::SIZE]);

    ZKProofShare {
        first_move_f: g1,
        first_move_a: g2,
        first_move_y: g1,
        response_z_r: fr,
        response_z_a: fr,
    }
}

fn empty_ni_csp_dkg_transcript() -> CspNiDkgTranscript {
    CspNiDkgTranscript::Groth20_Bls12_381(ni_dkg_groth20_bls12_381::Transcript {
        public_coefficients: PublicCoefficientsBytes {
            coefficients: vec![],
        },
        receiver_data: Default::default(),
    })
}

#[test]
fn should_correctly_convert_i32_to_ni_dkg_tag() {
    assert!(NiDkgTag::try_from(-1).is_err());
    assert!(NiDkgTag::try_from(0).is_err());
    assert_eq!(NiDkgTag::try_from(1), Ok(NiDkgTag::LowThreshold));
    assert_eq!(NiDkgTag::try_from(2), Ok(NiDkgTag::HighThreshold));
    assert!(NiDkgTag::try_from(3).is_err());
}

#[test]
fn should_correctly_convert_ni_dkg_tag_to_i32() {
    assert_eq!(NiDkgTag::LowThreshold as i32, 1);
    assert_eq!(NiDkgTag::HighThreshold as i32, 2);
}
