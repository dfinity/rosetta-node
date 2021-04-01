use super::super::types::{CspPop, CspPublicKey};
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::crypto::{AlgorithmId, CryptoError, KeyId};
use ic_types::NodeId;

pub trait CspKeyGenerator {
    fn gen_key_pair(&self, alg_id: AlgorithmId) -> Result<(KeyId, CspPublicKey), CryptoError>;
    fn gen_key_pair_with_pop(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey, CspPop), CryptoError>;

    /// Generates TLS key material for node with ID `node_id`.
    ///
    /// The secret key is stored in the key store and used to create a
    /// self-signed X.509 public key certificate with
    /// * a random serial,
    /// * the common name of both subject and issuer being the `ToString` form
    ///   of the given `node_id`,
    /// * validity starting at the time of calling this method, and
    /// * validity ending at `not_after`, which must be specified according to
    ///   section 4.1.2.5 in RFC 5280.
    ///
    /// Returns the public key certificate.
    ///
    /// # Panics
    /// Panics if `not_after` is not specified according to RFC 5280 or if
    /// `not_after` is in the past.
    fn gen_tls_key_pair(&mut self, node_id: NodeId, not_after: &str) -> X509PublicKeyCert;
}

pub trait CspSecretKeyStoreChecker {
    /// Checks whether the store contains a key with the given `id`.
    fn sks_contains(&self, key_id: &KeyId) -> bool;

    /// Checks whether the store contains a private key for the given `cert`.
    fn sks_contains_tls_key(&self, cert: &X509PublicKeyCert) -> bool;
}

pub trait NodePublicKeyData {
    /// Returns the public keys of this node.
    fn node_public_keys(&self) -> NodePublicKeys;
    /// Returns the id of the node signing key.
    fn node_signing_key_id(&self) -> KeyId;
    /// Returns the id of the dkg dealing encryption key.
    fn dkg_dealing_encryption_key_id(&self) -> KeyId;
}
