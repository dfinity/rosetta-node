use ic_types::crypto::AlgorithmId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClibThresholdSignError {
    MalformedSecretKey { algorithm: AlgorithmId },
}
