#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PublicKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(enumeration="AlgorithmId", tag="2")]
    pub algorithm: i32,
    #[prost(bytes, tag="3")]
    pub key_value: std::vec::Vec<u8>,
    #[prost(message, optional, tag="4")]
    pub proof_data: ::std::option::Option<::std::vec::Vec<u8>>,
}
/// DER-encoded X509 public key certificate
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct X509PublicKeyCert {
    #[prost(bytes, tag="1")]
    pub certificate_der: std::vec::Vec<u8>,
}
/// Should be moved to crypto-code, replacing the original ic_types::crypto::AlgorithmId.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum AlgorithmId {
    Unspecified = 0,
    MultiBls12381 = 1,
    ThresBls12381 = 2,
    SchnorrSecp256k1 = 3,
    StaticDhSecp256k1 = 4,
    HashSha256 = 5,
    Tls = 6,
    Ed25519 = 7,
    Secp256k1 = 8,
    Groth20Bls12381 = 9,
    NidkgGroth20Bls12381 = 10,
    EcdsaP256 = 11,
}
