use serde::__private::Formatter;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CurrentAndNextTranscriptsValidationError {
    CurrentLowTranscriptMissing,
    CurrentLowTranscriptInvalidTag,
    CurrentHighTranscriptMissing,
    CurrentHighTranscriptInvalidTag,
    NextLowTranscriptInvalidTag,
    NextHighTranscriptInvalidTag,
    CurrentLowRegistryVersionGreaterThanNextLow,
    CurrentHighRegistryVersionGreaterThanNextHigh,
}

impl fmt::Display for CurrentAndNextTranscriptsValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
