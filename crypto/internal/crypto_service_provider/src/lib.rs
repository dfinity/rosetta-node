#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
//#![deny(missing_docs)]

//! Interface for the cryptographic service provider

pub mod api;
pub mod crypto_lib;
pub mod imported_test_utils;
pub mod imported_utilities;
pub mod public_key_store;
mod remaining_conversions;
pub mod secret_key_store;
pub mod threshold;
pub mod tls_stub;
pub mod types;

pub use crypto_lib::hash;

use crate::api::{
    CspKeyGenerator, CspSecretKeyInjector, CspSecretKeyStoreChecker, CspSigner,
    CspTlsClientHandshake, CspTlsServerHandshake, DistributedKeyGenerationCspClient,
    NiDkgCspClient, NodePublicKeyData, ThresholdSignatureCspClient,
};
use crate::keygen::{forward_secure_key_id, public_key_hash_as_key_id};
use crate::public_key_store::read_node_public_keys;
use crate::secret_key_store::volatile_store::VolatileSecretKeyStore;
use crate::secret_key_store::SecretKeyStore;
use crate::types::CspPublicKey;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPublicKey;
use ic_logger::{new_logger, replica_logger::no_op_logger, ReplicaLogger};
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_types::crypto::KeyId;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use secret_key_store::proto_store::ProtoSecretKeyStore;
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Instant;

/// Describes the interface of the crypto service provider (CSP), e.g. for
/// signing and key generation. The Csp struct implements this trait.
pub trait CryptoServiceProvider:
    CspSigner
    + CspKeyGenerator
    + ThresholdSignatureCspClient
    + DistributedKeyGenerationCspClient
    + NiDkgCspClient
    + CspSecretKeyInjector
    + CspSecretKeyStoreChecker
    + CspTlsServerHandshake
    + CspTlsClientHandshake
    + NodePublicKeyData
{
}

impl<T> CryptoServiceProvider for T where
    T: CspSigner
        + CspKeyGenerator
        + ThresholdSignatureCspClient
        + DistributedKeyGenerationCspClient
        + NiDkgCspClient
        + CspSecretKeyInjector
        + CspSecretKeyStoreChecker
        + CspTlsServerHandshake
        + CspTlsClientHandshake
        + NodePublicKeyData
{
}

struct SksKeyIds {
    node_signing_key_id: Option<KeyId>,
    dkg_dealing_encryption_key_id: Option<KeyId>,
}

struct PublicKeyData {
    node_public_keys: NodePublicKeys,
    sks_key_ids: SksKeyIds,
}

impl PublicKeyData {
    fn new(node_public_keys: NodePublicKeys) -> Self {
        let node_signing_key_id = match node_public_keys.node_signing_pk.to_owned() {
            None => None,
            Some(node_signing_pk) => {
                let csp_pk = CspPublicKey::try_from(node_signing_pk)
                    .expect("Unsupported public key proto as node signing public key.");
                Some(public_key_hash_as_key_id(&csp_pk))
            }
        };

        let dkg_dealing_encryption_key_id = match node_public_keys
            .dkg_dealing_encryption_pk
            .to_owned()
        {
            None => None,
            Some(dkg_dealing_encryption_pk) => {
                let csp_pk = CspFsEncryptionPublicKey::try_from(dkg_dealing_encryption_pk)
                    .expect("Unsupported public key proto as dkg dealing encryption public key.");
                Some(forward_secure_key_id(&csp_pk))
            }
        };
        let sks_key_ids = SksKeyIds {
            node_signing_key_id,
            dkg_dealing_encryption_key_id,
        };
        PublicKeyData {
            node_public_keys,
            sks_key_ids,
        }
    }
}

/// Implements the CryptoServiceProvider for an RNG and a SecretKeyStore.
pub struct Csp<R: Rng + CryptoRng, S: SecretKeyStore> {
    // CSPRNG stands for cryptographically secure random number generator.
    csprng: CspRwLock<R>,
    secret_key_store: CspRwLock<S>,
    public_key_data: PublicKeyData,
    logger: ReplicaLogger,
}

/// This lock provides the option to add metrics about lock acquisition times.
struct CspRwLock<T> {
    name: String,
    rw_lock: RwLock<T>,
    metrics: Arc<CryptoMetrics>,
}

impl<T> CspRwLock<T> {
    pub fn new_for_rng(content: T, metrics: Arc<CryptoMetrics>) -> Self {
        // Note: The name will appear on metric dashboards and may be used in alerts, do
        // not change this unless you are also updating the monitoring.
        Self::new(content, "csprng".to_string(), metrics)
    }

    pub fn new_for_sks(content: T, metrics: Arc<CryptoMetrics>) -> Self {
        // Note: The name will appear on metric dashboards and may be used in alerts, do
        // not change this unless you are also updating the monitoring.
        Self::new(content, "secret_key_store".to_string(), metrics)
    }

    fn new(content: T, lock_name: String, metrics: Arc<CryptoMetrics>) -> Self {
        Self {
            name: lock_name,
            rw_lock: RwLock::new(content),
            metrics,
        }
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        let start_time = self.metrics.now();
        let write_guard = self.rw_lock.write();
        self.observe(&self.metrics, "write", start_time);
        write_guard
    }

    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        let start_time = self.metrics.now();
        let read_guard = self.rw_lock.read();
        self.observe(&self.metrics, "read", start_time);
        read_guard
    }

    fn observe(&self, metrics: &CryptoMetrics, access: &str, start_time: Option<Instant>) {
        metrics.observe_lock_acquisition_duration_seconds(&self.name, access, start_time);
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> Csp<R, S> {
    fn rng_write_lock(&self) -> RwLockWriteGuard<'_, R> {
        // TODO (CRP-696): inline this method
        self.csprng.write()
    }

    fn sks_write_lock(&self) -> RwLockWriteGuard<'_, S> {
        // TODO (CRP-696): inline this method
        self.secret_key_store.write()
    }

    fn sks_read_lock(&self) -> RwLockReadGuard<'_, S> {
        // TODO (CRP-696): inline this method
        self.secret_key_store.read()
    }
}

impl Csp<OsRng, ProtoSecretKeyStore> {
    /// Creates a production-grade crypto service provider.
    pub fn new(
        config: &CryptoConfig,
        logger: Option<ReplicaLogger>,
        metrics: Arc<CryptoMetrics>,
    ) -> Self {
        let logger = logger.unwrap_or_else(no_op_logger);
        let secret_key_store =
            ProtoSecretKeyStore::open(&config.crypto_root, Some(new_logger!(&logger)));
        let node_public_keys = match read_node_public_keys(&config.crypto_root) {
            Ok(node_pks) => node_pks,
            Err(_) => Default::default(),
        };
        let public_key_data = PublicKeyData::new(node_public_keys);

        Csp {
            csprng: CspRwLock::new_for_rng(OsRng::default(), Arc::clone(&metrics)),
            public_key_data,
            secret_key_store: CspRwLock::new_for_sks(secret_key_store, metrics),
            logger,
        }
    }
}

impl<R: Rng + CryptoRng> Csp<R, ProtoSecretKeyStore> {
    /// Creates a crypto service provider for testing.
    ///
    /// Note: This MUST NOT be used in production as the secrecy of the random
    /// number generator, hence the keys, is not guaranteed.
    pub fn new_with_rng(csprng: R, config: &CryptoConfig) -> Self {
        let node_public_keys = match read_node_public_keys(&config.crypto_root) {
            Ok(node_pks) => node_pks,
            Err(_) => Default::default(),
        };
        let public_key_data = PublicKeyData::new(node_public_keys);
        Csp {
            csprng: CspRwLock::new_for_rng(csprng, Arc::new(CryptoMetrics::none())),
            public_key_data,
            secret_key_store: CspRwLock::new_for_sks(
                ProtoSecretKeyStore::open(&config.crypto_root, None),
                Arc::new(CryptoMetrics::none()),
            ),
            logger: no_op_logger(),
        }
    }
}

impl<R: Rng + CryptoRng> Csp<R, VolatileSecretKeyStore> {
    /// Resets public key data according to the given `NodePublicKeys`.
    ///
    /// Note: This is for testing only and MUST NOT be used in production.
    pub fn reset_public_key_data(&mut self, node_public_keys: NodePublicKeys) {
        self.public_key_data = PublicKeyData::new(node_public_keys);
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> NodePublicKeyData for Csp<R, S> {
    fn node_public_keys(&self) -> NodePublicKeys {
        self.public_key_data.node_public_keys.clone()
    }

    fn node_signing_key_id(&self) -> KeyId {
        self.public_key_data
            .sks_key_ids
            .node_signing_key_id
            .to_owned()
            .expect("Missing node signing key id")
    }

    fn dkg_dealing_encryption_key_id(&self) -> KeyId {
        self.public_key_data
            .sks_key_ids
            .dkg_dealing_encryption_key_id
            .to_owned()
            .expect("Missing dkg dealing encryption key id")
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> Csp<R, S> {
    /// Creates a crypto service provider for testing.
    ///
    /// Note: This MUST NOT be used in production as the secrecy of the secret
    /// key store is not guaranteed.
    pub fn of(csprng: R, secret_key_store: S) -> Self {
        let node_public_keys = Default::default();
        let public_key_data = PublicKeyData::new(node_public_keys);
        let metrics = Arc::new(CryptoMetrics::none());
        Csp {
            csprng: CspRwLock::new_for_rng(csprng, Arc::clone(&metrics)),
            public_key_data,
            secret_key_store: CspRwLock::new_for_sks(secret_key_store, metrics),
            logger: no_op_logger(),
        }
    }
}

// Trait implementations:
pub mod keygen;
mod signer;
