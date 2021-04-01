use serde::__private::Formatter;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TranscriptsToRetainValidationError {
    NoLowTranscripts,
    NoHighTranscripts,
}

impl fmt::Display for TranscriptsToRetainValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
