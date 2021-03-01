pub mod api;
pub mod crypto_lib;
pub mod imported_test_utils;
pub mod imported_utilities;
pub mod public_key_store;
pub mod remaining_conversions;
pub mod secret_key_store;
pub mod threshold;
pub mod tls_stub;
pub mod types;

pub use crypto_lib::hash;

use crate::api::{
    CspKeyGenerator, CspNodePublicKeys, CspSecretKeyInjector, CspSecretKeyStoreChecker, CspSigner,
    CspTlsClientHandshake, CspTlsServerHandshake, DistributedKeyGenerationCspClient,
    NiDkgCspClient, ThresholdSignatureCspClient,
};
use crate::public_key_store::read_node_public_keys;
use crate::secret_key_store::SecretKeyStore;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_logmon::metrics::Metrics;
use ic_logger::{new_logger, replica_logger::no_op_logger, ReplicaLogger};
use ic_protobuf::crypto::v1::NodePublicKeys;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use secret_key_store::proto_store::ProtoSecretKeyStore;
use std::sync::Arc;
use std::time;
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
    + CspNodePublicKeys
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
        + CspNodePublicKeys
{
}

/// Implements the CryptoServiceProvider for an RNG and a SecretKeyStore.
pub struct Csp<R: Rng + CryptoRng, S: SecretKeyStore> {
    // CSPRNG stands for cryptographically secure random number generator.
    csprng: CspRwLock<R>,
    secret_key_store: CspRwLock<S>,
    node_public_keys: NodePublicKeys,
    logger: ReplicaLogger,
}

/// This lock provides the option to add metrics about lock acquisition times.
struct CspRwLock<T> {
    name: String,
    rw_lock: RwLock<T>,
    metrics: Option<Arc<Metrics>>,
}

impl<T> CspRwLock<T> {
    pub fn new_for_rng(content: T, metrics: Option<Arc<Metrics>>) -> Self {
        // Note: The name will appear on metric dashboards and may be used in alerts, do
        // not change this unless you are also updating the monitoring.
        Self::new(content, "csprng".to_string(), metrics)
    }

    pub fn new_for_sks(content: T, metrics: Option<Arc<Metrics>>) -> Self {
        // Note: The name will appear on metric dashboards and may be used in alerts, do
        // not change this unless you are also updating the monitoring.
        Self::new(content, "secret_key_store".to_string(), metrics)
    }

    fn new(content: T, lock_name: String, metrics: Option<Arc<Metrics>>) -> Self {
        Self {
            name: lock_name,
            rw_lock: RwLock::new(content),
            metrics,
        }
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        if let Some(metrics) = self.metrics.as_ref() {
            let start_time = time::Instant::now();
            let write_guard = self.rw_lock.write();
            self.observe(metrics, "write", start_time);
            return write_guard;
        }
        self.rw_lock.write()
    }

    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        if let Some(metrics) = self.metrics.as_ref() {
            let start_time = time::Instant::now();
            let read_guard = self.rw_lock.read();
            self.observe(metrics, "read", start_time);
            return read_guard;
        }
        self.rw_lock.read()
    }

    fn observe(&self, metrics: &Metrics, access: &str, start_time: Instant) {
        metrics
            .ic_crypto_lock_acquisition_duration_seconds
            .with_label_values(&[&self.name, access])
            .observe(start_time.elapsed().as_secs_f64());
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
        metrics: Option<Metrics>,
    ) -> Self {
        let logger = logger.unwrap_or_else(no_op_logger);
        let secret_key_store =
            ProtoSecretKeyStore::open(&config.crypto_root, Some(new_logger!(&logger)));
        let node_public_keys = match read_node_public_keys(&config.crypto_root) {
            Ok(node_pks) => node_pks,
            Err(_) => Default::default(),
        };

        let metrics_arc = metrics.map(Arc::new);
        Csp {
            csprng: CspRwLock::new_for_rng(OsRng::default(), metrics_arc.as_ref().map(Arc::clone)),
            node_public_keys,
            secret_key_store: CspRwLock::new_for_sks(secret_key_store, metrics_arc),
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
        Csp {
            csprng: CspRwLock::new_for_rng(csprng, None),
            node_public_keys,
            secret_key_store: CspRwLock::new_for_sks(
                ProtoSecretKeyStore::open(&config.crypto_root, None),
                None,
            ),
            logger: no_op_logger(),
        }
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> CspNodePublicKeys for Csp<R, S> {
    fn node_public_keys(&self) -> NodePublicKeys {
        self.node_public_keys.clone()
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore> Csp<R, S> {
    /// Creates a crypto service provider for testing.
    ///
    /// Note: This MUST NOT be used in production as the secrecy of the secret
    /// key store is not guaranteed.
    pub fn of(csprng: R, secret_key_store: S) -> Self {
        Csp {
            csprng: CspRwLock::new_for_rng(csprng, None),
            node_public_keys: Default::default(),
            secret_key_store: CspRwLock::new_for_sks(secret_key_store, None),
            logger: no_op_logger(),
        }
    }
}

// Trait implementations:
pub mod keygen;
mod signer;
