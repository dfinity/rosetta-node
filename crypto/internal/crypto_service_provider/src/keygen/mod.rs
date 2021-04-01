use crate::api::{CspKeyGenerator, CspSecretKeyStoreChecker};
use crate::hash::Sha256Hasher;
use crate::secret_key_store::{SecretKeyStore, SecretKeyStoreError};
use crate::types::{CspPop, CspPublicKey, CspSecretKey};
use crate::Csp;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use ic_crypto_internal_multi_sig_bls12381 as multi_sig;
use ic_crypto_internal_tls::keygen::generate_tls_key_pair_der;
use ic_crypto_internal_types::context::{Context, DomainSeparationContext};
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::crypto::{AlgorithmId, CryptoError, KeyId};
use ic_types::NodeId;
use openssl::asn1::Asn1Time;
use rand::{CryptoRng, Rng};
use std::convert::TryFrom;

const KEY_ID_DOMAIN: &str = "ic-key-id";

use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPublicKey;
use ic_crypto_sha256::Sha256;
pub use tls_keygen::tls_cert_hash_as_key_id;
pub use tls_keygen::tls_registry_cert_hash_as_key_id;

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore> CspKeyGenerator for Csp<R, S> {
    fn gen_key_pair(&self, alg_id: AlgorithmId) -> Result<(KeyId, CspPublicKey), CryptoError> {
        let (sk, pk) = self.generate_keypair_without_pop(alg_id)?;
        let sk_id = public_key_hash_as_key_id(&pk);
        self.store_secret_key_or_panic(sk, sk_id);
        Ok((sk_id, pk))
    }
    fn gen_key_pair_with_pop(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey, CspPop), CryptoError> {
        match algorithm_id {
            AlgorithmId::MultiBls12_381 => {
                let (sk_bytes, pk_bytes) = multi_sig::keypair_from_rng(&mut *self.rng_write_lock());
                let sk = CspSecretKey::MultiBls12_381(sk_bytes);
                let pk = CspPublicKey::MultiBls12_381(pk_bytes);
                let proof_of_possession =
                    CspPop::MultiBls12_381(multi_sig::create_pop(pk_bytes, sk_bytes)?);
                let sk_id = public_key_hash_as_key_id(&pk);
                self.store_secret_key_or_panic(sk, sk_id);
                Ok((sk_id, pk, proof_of_possession))
            }
            _ => Err(CryptoError::InvalidArgument {
                message: format!(
                    "Cannot generate key pair for unsupported algorithm: {:?}",
                    algorithm_id
                ),
            }),
        }
    }

    fn gen_tls_key_pair(&mut self, node: NodeId, not_after: &str) -> X509PublicKeyCert {
        let serial = self.rng_write_lock().gen::<[u8; 19]>();
        let common_name = &node.get().to_string()[..];
        let not_after = Asn1Time::from_str_x509(not_after)
            .expect("invalid X.509 certificate expiration date (not_after)");
        let (cert, secret_key) = generate_tls_key_pair_der(common_name, serial, &not_after);

        let x509_pk_cert = X509PublicKeyCert {
            certificate_der: cert.bytes.clone(),
        };
        let _key_id = self.store_tls_secret_key(cert, secret_key);
        x509_pk_cert
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> CspSecretKeyStoreChecker for Csp<R, S> {
    fn sks_contains(&self, id: &KeyId) -> bool {
        self.sks_read_lock().contains(id)
    }

    fn sks_contains_tls_key(&self, cert: &X509PublicKeyCert) -> bool {
        // we calculate the key_id first to minimize locking time:
        let key_id = tls_registry_cert_hash_as_key_id(cert.clone());
        self.sks_read_lock().contains(&key_id)
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> Csp<R, S> {
    fn generate_keypair_without_pop(
        &self,
        alg_id: AlgorithmId,
    ) -> Result<(CspSecretKey, CspPublicKey), CryptoError> {
        match alg_id {
            AlgorithmId::Ed25519 => {
                let (sk_bytes, pk_bytes) = ed25519::keypair_from_rng(&mut *self.rng_write_lock());
                let sk = CspSecretKey::Ed25519(sk_bytes);
                let pk = CspPublicKey::Ed25519(pk_bytes);
                Ok((sk, pk))
            }
            AlgorithmId::MultiBls12_381 => {
                let (secret_key_bytes, public_key_bytes) =
                    multi_sig::keypair_from_rng(&mut *self.rng_write_lock());
                let secret_key = CspSecretKey::MultiBls12_381(secret_key_bytes);
                let public_key = CspPublicKey::MultiBls12_381(public_key_bytes);
                Ok((secret_key, public_key))
            }
            _ => Err(CryptoError::InvalidArgument {
                message: format!(
                    "Cannot generate key pair for unsupported algorithm: {:?}",
                    alg_id
                ),
            }),
        }
    }

    fn store_secret_key_or_panic(&self, csp_secret_key: CspSecretKey, key_id: KeyId) {
        match &self.sks_write_lock().insert(key_id, csp_secret_key, None) {
            Ok(()) => {}
            Err(SecretKeyStoreError::DuplicateKeyId(key_id)) => {
                panic!("A key with ID {} has already been inserted", key_id);
            }
        };
    }
}

// KeyId is SHA256 computed on the bytes:
//     domain_separator | algorithm_id | size(pk_bytes) | pk_bytes
// where  domain_separator is DomainSeparationContext(KEY_ID_DOMAIN),
// algorithm_id is a 1-byte value, and size(pk_bytes) is the size of
// pk_bytes as u32 in BigEndian format.
pub fn public_key_hash_as_key_id(pk: &CspPublicKey) -> KeyId {
    bytes_hash_as_key_id(pk.algorithm_id(), pk.pk_bytes())
}

fn bytes_hash_as_key_id(alg_id: AlgorithmId, bytes: &[u8]) -> KeyId {
    let mut hasher = Sha256Hasher::new(&DomainSeparationContext::new(KEY_ID_DOMAIN.to_string()));
    hasher.update(&[alg_id as u8]);
    let bytes_size = u32::try_from(bytes.len()).expect("type conversion error");
    hasher.update(&bytes_size.to_be_bytes());
    hasher.update(bytes);
    KeyId::from(hasher.finalize())
}

pub fn forward_secure_key_id(public_key: &CspFsEncryptionPublicKey) -> KeyId {
    let mut hash = Sha256::new();
    hash.write(DomainSeparationContext::new("KeyId from CspFsEncryptionPublicKey").as_bytes());
    let variant: &'static str = public_key.into();
    hash.write(DomainSeparationContext::new(variant).as_bytes());
    match public_key {
        CspFsEncryptionPublicKey::Groth20_Bls12_381(public_key) => {
            hash.write(public_key.as_bytes())
        }
    }
    KeyId::from(hash.finish())
}

mod tls_keygen {
    use super::*;
    use ic_crypto_internal_tls::keygen::{
        TlsEd25519CertificateDerBytes, TlsEd25519SecretKeyDerBytes,
    };

    pub fn tls_cert_hash_as_key_id(cert: &TlsEd25519CertificateDerBytes) -> KeyId {
        bytes_hash_as_key_id(AlgorithmId::Tls, &cert.bytes)
    }

    pub fn tls_registry_cert_hash_as_key_id(cert: X509PublicKeyCert) -> KeyId {
        tls_cert_hash_as_key_id(&TlsEd25519CertificateDerBytes {
            bytes: cert.certificate_der,
        })
    }

    impl<R: Rng + CryptoRng, S: SecretKeyStore> Csp<R, S> {
        pub(super) fn store_tls_secret_key(
            &mut self,
            cert: TlsEd25519CertificateDerBytes,
            secret_key: TlsEd25519SecretKeyDerBytes,
        ) -> KeyId {
            let key_id = tls_cert_hash_as_key_id(&cert);
            self.store_secret_key_or_panic(CspSecretKey::TlsEd25519(secret_key), key_id);
            key_id
        }
    }
}

pub mod utils {
    use ic_crypto_internal_types::encrypt::forward_secure::{
        CspFsEncryptionPok, CspFsEncryptionPublicKey,
    };
    use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
    use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;

    pub fn dkg_dealing_encryption_pk_to_proto(
        pk: CspFsEncryptionPublicKey,
        pok: CspFsEncryptionPok,
    ) -> PublicKeyProto {
        match (pk, pok) {
            (
                CspFsEncryptionPublicKey::Groth20_Bls12_381(fs_enc_pk),
                CspFsEncryptionPok::Groth20_Bls12_381(_),
            ) => PublicKeyProto {
                algorithm: AlgorithmIdProto::Groth20Bls12381 as i32,
                key_value: fs_enc_pk.as_bytes().to_vec(),
                version: 0,
                proof_data: Some(serde_cbor::to_vec(&pok).expect(
                    "Failed to serialize DKG dealing encryption key proof of knowledge (PoK) to CBOR",
                )),
            },
        }
    }
}