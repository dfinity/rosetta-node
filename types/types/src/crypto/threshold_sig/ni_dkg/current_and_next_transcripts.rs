use super::*;
use crate::crypto::threshold_sig::ni_dkg::errors::current_and_next_transcripts_validation_error::CurrentAndNextTranscriptsValidationError;
use std::cmp::min;
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

#[allow(unused)]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CurrentAndNextTranscripts<'a> {
    // fields must be private to avoid invariant violations
    current_low_threshold_transcript: &'a NiDkgTranscript,
    current_high_threshold_transcript: &'a NiDkgTranscript,
    next_low_threshold_transcript: Option<&'a NiDkgTranscript>,
    next_high_threshold_transcript: Option<&'a NiDkgTranscript>,
}

impl<'a> CurrentAndNextTranscripts<'a> {
    /// Creates new and valid `CurrentAndNextTranscripts`. The following
    /// invariants must hold:
    /// * `current_transcripts` contains exactly two entries, one with key
    ///   `NiDkgTag::LowThreshold`, and one with key `NiDkgTag::HighThreshold`
    /// * For both `current_transcripts` and `next_transcripts`, if an entry
    ///   with key `LowThreshold` (resp. `HighThreshold`) is present, then it
    ///   contains a transcript with tag `LowThreshold` (resp. `HighThreshold`).
    /// * Let c_low and c_high (n_low and n_high) be the registry versions of
    ///   the LowThreshold and the HighThreshold `current_transcripts`
    ///   (`next_transcripts`), respectively. Then c_low <= n_low and c_high <=
    ///   n_high
    /// If any of these invariants does not hold, an
    /// `InvalidCurrentAndNextTranscriptsError` is returned.
    pub fn new(
        current_transcripts: &'a BTreeMap<NiDkgTag, NiDkgTranscript>,
        next_transcripts: &'a BTreeMap<NiDkgTag, NiDkgTranscript>,
    ) -> Result<Self, CurrentAndNextTranscriptsValidationError> {
        let result = Self {
            current_low_threshold_transcript: current_transcripts
                .get(&NiDkgTag::LowThreshold)
                .ok_or(CurrentAndNextTranscriptsValidationError::CurrentLowTranscriptMissing)?,
            current_high_threshold_transcript: current_transcripts
                .get(&NiDkgTag::HighThreshold)
                .ok_or(CurrentAndNextTranscriptsValidationError::CurrentHighTranscriptMissing)?,
            next_low_threshold_transcript: next_transcripts.get(&NiDkgTag::LowThreshold),
            next_high_threshold_transcript: next_transcripts.get(&NiDkgTag::HighThreshold),
        };
        result.ensure_current_transcripts_valid()?;
        result.ensure_next_transcripts_valid()?;
        result.ensure_correct_registry_versions()?;
        Ok(result)
    }

    pub fn public_keys(&self) -> BTreeSet<CspPublicCoefficients> {
        let mut active_public_keys = BTreeSet::new();
        active_public_keys.insert(pub_coeffs(self.current_low_threshold_transcript));
        active_public_keys.insert(pub_coeffs(self.current_high_threshold_transcript));
        if let Some(transcript) = self.next_low_threshold_transcript {
            active_public_keys.insert(pub_coeffs(transcript));
        }
        if let Some(transcript) = self.next_high_threshold_transcript {
            active_public_keys.insert(pub_coeffs(transcript));
        }
        active_public_keys
    }

    pub fn display_dkg_ids_and_registry_versions(&self) -> String {
        format!(
            "CurrentAndNextTranscripts registry versions - \
        current: low {}, high {}; \
        next: low {}, high {}",
            display_dkg_id_and_registry_version(&self.current_low_threshold_transcript),
            display_dkg_id_and_registry_version(&self.current_high_threshold_transcript),
            &self
                .next_low_threshold_transcript
                .map(display_dkg_id_and_registry_version)
                .unwrap_or_else(|| "none".to_string()),
            &self
                .next_high_threshold_transcript
                .map(display_dkg_id_and_registry_version)
                .unwrap_or_else(|| "none".to_string())
        )
    }

    // Returns the minimum registry version of all transcripts
    pub fn min_registry_version(&self) -> RegistryVersion {
        // since c_low <= n_low and c_high <= n_high, we only need to consider the
        // current transcripts:
        min(
            self.current_low_threshold_transcript.registry_version,
            self.current_high_threshold_transcript.registry_version,
        )
    }

    fn ensure_current_transcripts_valid(
        &self,
    ) -> Result<(), CurrentAndNextTranscriptsValidationError> {
        if self.current_low_threshold_transcript.dkg_id.dkg_tag != NiDkgTag::LowThreshold {
            return Err(CurrentAndNextTranscriptsValidationError::CurrentLowTranscriptInvalidTag);
        }
        if self.current_high_threshold_transcript.dkg_id.dkg_tag != NiDkgTag::HighThreshold {
            return Err(CurrentAndNextTranscriptsValidationError::CurrentHighTranscriptInvalidTag);
        }
        Ok(())
    }

    fn ensure_next_transcripts_valid(
        &self,
    ) -> Result<(), CurrentAndNextTranscriptsValidationError> {
        if let Some(next_low_transcript) = self.next_low_threshold_transcript {
            if next_low_transcript.dkg_id.dkg_tag != NiDkgTag::LowThreshold {
                return Err(CurrentAndNextTranscriptsValidationError::NextLowTranscriptInvalidTag);
            }
        }
        if let Some(next_high_transcript) = self.next_high_threshold_transcript {
            if next_high_transcript.dkg_id.dkg_tag != NiDkgTag::HighThreshold {
                return Err(CurrentAndNextTranscriptsValidationError::NextHighTranscriptInvalidTag);
            }
        }
        Ok(())
    }

    fn ensure_correct_registry_versions(
        &self,
    ) -> Result<(), CurrentAndNextTranscriptsValidationError> {
        let c_low = self.current_low_threshold_transcript.registry_version;
        let c_high = self.current_high_threshold_transcript.registry_version;
        let n_low = self
            .next_low_threshold_transcript
            .map(|t| t.registry_version);
        let n_high = self
            .next_high_threshold_transcript
            .map(|t| t.registry_version);
        if let Some(n_low) = n_low {
            if c_low > n_low {
                return Err(CurrentAndNextTranscriptsValidationError::CurrentLowRegistryVersionGreaterThanNextLow);
            }
        }
        if let Some(n_high) = n_high {
            if c_high > n_high {
                return Err(CurrentAndNextTranscriptsValidationError::CurrentHighRegistryVersionGreaterThanNextHigh);
            }
        }
        Ok(())
    }
}

fn pub_coeffs(transcript: &NiDkgTranscript) -> CspPublicCoefficients {
    let CspNiDkgTranscript::Groth20_Bls12_381(transcript) = &transcript.internal_csp_transcript;
    CspPublicCoefficients::Bls12_381(transcript.public_coefficients.clone())
}

fn display_dkg_id_and_registry_version(transcript: &NiDkgTranscript) -> String {
    format!(
        "[dkg_id {}, registry version {}]",
        transcript.dkg_id, transcript.registry_version
    )
}
