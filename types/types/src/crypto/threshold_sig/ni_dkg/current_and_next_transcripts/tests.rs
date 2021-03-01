use crate::crypto::threshold_sig::ni_dkg::current_and_next_transcripts::CurrentAndNextTranscripts;
use crate::crypto::threshold_sig::ni_dkg::errors::current_and_next_transcripts_validation_error::CurrentAndNextTranscriptsValidationError;
use crate::crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTranscript};
use ic_base_types::RegistryVersion;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    PublicCoefficientsBytes, Transcript,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::CspPublicCoefficients;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use std::collections::BTreeMap;

pub const REG_V1: RegistryVersion = RegistryVersion::new(1);
pub const REG_V2: RegistryVersion = RegistryVersion::new(2);
pub const REG_V3: RegistryVersion = RegistryVersion::new(3);
pub const REG_V4: RegistryVersion = RegistryVersion::new(4);

#[test]
fn should_create_valid_transcripts_without_next() {
    let (current_low, current_high) = (low_transcript(REG_V1), high_transcript(REG_V1));
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(None, None);

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert!(result.is_ok());
}

#[test]
fn should_create_valid_transcripts_with_next_transcripts() {
    let (current_low, current_high) = (low_transcript(REG_V1), high_transcript(REG_V1));
    let (next_low, next_high) = (low_transcript(REG_V2), high_transcript(REG_V2));
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(Some(next_low), Some(next_high));

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert!(result.is_ok());
}

#[test]
fn should_create_valid_transcripts_with_next_transcripts_if_all_use_same_registry_version() {
    let (current_low, current_high) = (low_transcript(REG_V1), high_transcript(REG_V1));
    let (next_low, next_high) = (low_transcript(REG_V1), high_transcript(REG_V1));
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(Some(next_low), Some(next_high));

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert!(result.is_ok());
}

#[test]
fn should_create_valid_transcripts_with_next_low_only() {
    let (current_low, current_high) = (low_transcript(REG_V1), high_transcript(REG_V1));
    let next_low = low_transcript(REG_V2);
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(Some(next_low), None);

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert!(result.is_ok());
}

#[test]
fn should_create_valid_transcripts_with_next_high_only() {
    let (current_low, current_high) = (low_transcript(REG_V1), high_transcript(REG_V1));
    let next_high = high_transcript(REG_V2);
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(None, Some(next_high));

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert!(result.is_ok());
}

#[test]
fn should_return_error_if_current_low_missing() {
    let current_high = high_transcript(REG_V1);
    let current_transcripts = transcript_map(None, Some(current_high));
    let next_transcripts = transcript_map(None, None);

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert_eq!(
        result.unwrap_err(),
        CurrentAndNextTranscriptsValidationError::CurrentLowTranscriptMissing
    );
}

#[test]
fn should_return_error_if_current_high_missing() {
    let current_low = low_transcript(REG_V1);
    let current_transcripts = transcript_map(Some(current_low), None);
    let next_transcripts = transcript_map(None, None);

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert_eq!(
        result.unwrap_err(),
        CurrentAndNextTranscriptsValidationError::CurrentHighTranscriptMissing
    );
}

#[test]
fn should_return_error_if_current_low_invalid() {
    let (invalid_current_low, current_high) = (high_transcript(REG_V1), high_transcript(REG_V1));
    let current_transcripts = transcript_map(Some(invalid_current_low), Some(current_high));
    let next_transcripts = transcript_map(None, None);

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert_eq!(
        result.unwrap_err(),
        CurrentAndNextTranscriptsValidationError::CurrentLowTranscriptInvalidTag
    );
}

#[test]
fn should_return_error_if_current_high_invalid() {
    let (current_low, invalid_current_high) = (low_transcript(REG_V1), low_transcript(REG_V1));
    let current_transcripts = transcript_map(Some(current_low), Some(invalid_current_high));
    let next_transcripts = transcript_map(None, None);

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert_eq!(
        result.unwrap_err(),
        CurrentAndNextTranscriptsValidationError::CurrentHighTranscriptInvalidTag
    );
}

#[test]
fn should_return_error_if_next_low_invalid() {
    let (current_low, current_high) = (low_transcript(REG_V1), high_transcript(REG_V1));
    let (invalid_next_low, next_high) = (high_transcript(REG_V2), high_transcript(REG_V2));
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(Some(invalid_next_low), Some(next_high));

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert_eq!(
        result.unwrap_err(),
        CurrentAndNextTranscriptsValidationError::NextLowTranscriptInvalidTag
    );
}

#[test]
fn should_return_error_if_next_high_invalid() {
    let (current_low, current_high) = (low_transcript(REG_V1), high_transcript(REG_V1));
    let (next_low, invalid_next_high) = (low_transcript(REG_V2), low_transcript(REG_V2));
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(Some(next_low), Some(invalid_next_high));

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert_eq!(
        result.unwrap_err(),
        CurrentAndNextTranscriptsValidationError::NextHighTranscriptInvalidTag
    );
}

#[test]
fn should_return_error_if_current_low_older_than_next_low() {
    let (current_low, current_high) = (low_transcript(REG_V3), high_transcript(REG_V3));
    let (next_low, next_high) = (low_transcript(REG_V2), high_transcript(REG_V4));
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(Some(next_low), Some(next_high));

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert_eq!(
        result.unwrap_err(),
        CurrentAndNextTranscriptsValidationError::CurrentLowRegistryVersionGreaterThanNextLow
    );
}

#[test]
fn should_return_error_if_current_high_older_than_next_high() {
    let (current_low, current_high) = (low_transcript(REG_V3), high_transcript(REG_V4));
    let (next_low, next_high) = (low_transcript(REG_V4), high_transcript(REG_V3));
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(Some(next_low), Some(next_high));

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert_eq!(
        result.unwrap_err(),
        CurrentAndNextTranscriptsValidationError::CurrentHighRegistryVersionGreaterThanNextHigh
    );
}

#[test]
fn should_display_registry_versions() {
    let (current_low, current_high) = (low_transcript(REG_V1), high_transcript(REG_V2));
    let (next_low, next_high) = (low_transcript(REG_V3), high_transcript(REG_V4));
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(Some(next_low), Some(next_high));

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert_eq!(
        result.unwrap().display_dkg_ids_and_registry_versions(),
        "CurrentAndNextTranscripts registry versions - \
        current: low [dkg_id NiDkgId { start_block_height: 0, dealer_subnet: fscpm-uiaaa-aaaaa-aaaap-yai, dkg_tag: LowThreshold, target_subnet: Local }, registry version 1], \
        high [dkg_id NiDkgId { start_block_height: 0, dealer_subnet: fscpm-uiaaa-aaaaa-aaaap-yai, dkg_tag: HighThreshold, target_subnet: Local }, registry version 2]; \
        next: low [dkg_id NiDkgId { start_block_height: 0, dealer_subnet: fscpm-uiaaa-aaaaa-aaaap-yai, dkg_tag: LowThreshold, target_subnet: Local }, registry version 3], \
        high [dkg_id NiDkgId { start_block_height: 0, dealer_subnet: fscpm-uiaaa-aaaaa-aaaap-yai, dkg_tag: HighThreshold, target_subnet: Local }, registry version 4]"
    );
}

#[test]
fn should_return_min_registry_version() {
    let (current_low, current_high) = (low_transcript(REG_V2), high_transcript(REG_V1));
    let (next_low, next_high) = (low_transcript(REG_V3), high_transcript(REG_V4));
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(Some(next_low), Some(next_high));

    let result = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts);

    assert_eq!(result.unwrap().min_registry_version(), REG_V1);
}

#[test]
fn should_return_correct_public_keys_if_no_next_transcripts_present() {
    let cur_low_coeffs = pub_coeffs(1);
    let cur_high_coeffs = pub_coeffs(2);
    let (current_low, current_high) = (
        low_transcript_with_pub_coeffs(REG_V2, cur_low_coeffs.clone()),
        high_transcript_with_pub_coeffs(REG_V1, cur_high_coeffs.clone()),
    );
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(None, None);

    let active_keys = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts)
        .unwrap()
        .public_keys();

    assert_eq!(active_keys.len(), 2);
    assert!(active_keys.contains(&CspPublicCoefficients::Bls12_381(cur_low_coeffs)));
    assert!(active_keys.contains(&CspPublicCoefficients::Bls12_381(cur_high_coeffs)));
}

#[test]
fn should_return_all_public_keys_if_next_transcripts_present() {
    let cur_low_coeffs = pub_coeffs(1);
    let cur_high_coeffs = pub_coeffs(2);
    let next_low_coeffs = pub_coeffs(3);
    let next_high_coeffs = pub_coeffs(4);
    let (current_low, current_high) = (
        low_transcript_with_pub_coeffs(REG_V2, cur_low_coeffs.clone()),
        high_transcript_with_pub_coeffs(REG_V1, cur_high_coeffs.clone()),
    );
    let (next_low, next_high) = (
        low_transcript_with_pub_coeffs(REG_V3, next_low_coeffs.clone()),
        high_transcript_with_pub_coeffs(REG_V4, next_high_coeffs.clone()),
    );
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(Some(next_low), Some(next_high));

    let active_keys = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts)
        .unwrap()
        .public_keys();

    assert_eq!(active_keys.len(), 4);
    assert!(active_keys.contains(&CspPublicCoefficients::Bls12_381(cur_low_coeffs)));
    assert!(active_keys.contains(&CspPublicCoefficients::Bls12_381(cur_high_coeffs)));
    assert!(active_keys.contains(&CspPublicCoefficients::Bls12_381(next_low_coeffs)));
    assert!(active_keys.contains(&CspPublicCoefficients::Bls12_381(next_high_coeffs)));
}

#[test]
fn should_return_correct_public_keys_if_a_next_transcript_is_none() {
    let cur_low_coeffs = pub_coeffs(1);
    let cur_high_coeffs = pub_coeffs(2);
    let next_low_coeffs = pub_coeffs(3);
    let (current_low, current_high) = (
        low_transcript_with_pub_coeffs(REG_V2, cur_low_coeffs.clone()),
        high_transcript_with_pub_coeffs(REG_V1, cur_high_coeffs.clone()),
    );
    let next_low = low_transcript_with_pub_coeffs(REG_V3, next_low_coeffs.clone());
    let current_transcripts = transcript_map(Some(current_low), Some(current_high));
    let next_transcripts = transcript_map(Some(next_low), None);

    let active_keys = CurrentAndNextTranscripts::new(&current_transcripts, &next_transcripts)
        .unwrap()
        .public_keys();

    assert_eq!(active_keys.len(), 3);
    assert!(active_keys.contains(&CspPublicCoefficients::Bls12_381(cur_low_coeffs)));
    assert!(active_keys.contains(&CspPublicCoefficients::Bls12_381(cur_high_coeffs)));
    assert!(active_keys.contains(&CspPublicCoefficients::Bls12_381(next_low_coeffs)));
}

fn transcript_map(
    low_transcript: Option<NiDkgTranscript>,
    high_transcript: Option<NiDkgTranscript>,
) -> BTreeMap<NiDkgTag, NiDkgTranscript> {
    let mut transcripts = BTreeMap::new();
    if let Some(low_transcript) = low_transcript {
        transcripts.insert(NiDkgTag::LowThreshold, low_transcript);
    }
    if let Some(high_transcript) = high_transcript {
        transcripts.insert(NiDkgTag::HighThreshold, high_transcript);
    }
    transcripts
}

fn low_transcript(registry_version: RegistryVersion) -> NiDkgTranscript {
    low_transcript_with_pub_coeffs(registry_version, pub_coeffs(0))
}

fn low_transcript_with_pub_coeffs(
    registry_version: RegistryVersion,
    pub_coeffs: PublicCoefficientsBytes,
) -> NiDkgTranscript {
    let mut transcript = NiDkgTranscript::dummy_transcript_for_tests();
    transcript.dkg_id.dkg_tag = NiDkgTag::LowThreshold;
    transcript.registry_version = registry_version;
    transcript.internal_csp_transcript = csp_transcript_with_pub_coeffs(pub_coeffs);
    transcript
}

fn high_transcript(registry_version: RegistryVersion) -> NiDkgTranscript {
    high_transcript_with_pub_coeffs(registry_version, pub_coeffs(0))
}

fn high_transcript_with_pub_coeffs(
    registry_version: RegistryVersion,
    pub_coeffs: PublicCoefficientsBytes,
) -> NiDkgTranscript {
    let mut transcript = NiDkgTranscript::dummy_transcript_for_tests();
    transcript.dkg_id.dkg_tag = NiDkgTag::HighThreshold;
    transcript.registry_version = registry_version;
    transcript.internal_csp_transcript = csp_transcript_with_pub_coeffs(pub_coeffs);
    transcript
}

fn csp_transcript_with_pub_coeffs(pub_coeffs: PublicCoefficientsBytes) -> CspNiDkgTranscript {
    CspNiDkgTranscript::Groth20_Bls12_381(Transcript {
        public_coefficients: pub_coeffs,
        receiver_data: BTreeMap::new(),
    })
}

fn pub_coeffs(pub_coeffs: u8) -> PublicCoefficientsBytes {
    PublicCoefficientsBytes {
        coefficients: vec![PublicKeyBytes([pub_coeffs; PublicKeyBytes::SIZE])],
    }
}
