/// Combined threshold signature.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ThresholdSignature {
    #[prost(bytes, tag="1")]
    pub signature: std::vec::Vec<u8>,
    #[prost(message, optional, tag="2")]
    pub signer: ::std::option::Option<super::super::super::types::v1::NiDkgId>,
}
/// State tree root hash.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CertificationContent {
    #[prost(bytes, tag="2")]
    pub hash: std::vec::Vec<u8>,
}
/// Certification of state tree root hash.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Certification {
    #[prost(uint64, tag="1")]
    pub height: u64,
    #[prost(message, optional, tag="2")]
    pub content: ::std::option::Option<CertificationContent>,
    #[prost(message, optional, tag="3")]
    pub signature: ::std::option::Option<ThresholdSignature>,
}
/// XNet stream slice with certification and matching Merkle proof.
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CertifiedStreamSlice {
    /// Serialized part of the state tree containing the stream data.
    #[prost(bytes, tag="1")]
    pub payload: std::vec::Vec<u8>,
    /// Witness that can be used to recompute the root hash from the payload.
    #[prost(bytes, tag="2")]
    pub merkle_proof: std::vec::Vec<u8>,
    /// Certification of the root hash.
    #[prost(message, optional, tag="3")]
    pub certification: ::std::option::Option<Certification>,
}
