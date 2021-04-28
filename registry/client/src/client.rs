//! Implementation of the registry client. Calls to the API always return
//! immediately. The provided data provider is polled periodically in the
//! background when start_polling() is called.
pub use ic_config::registry_client::DataProviderConfig;
pub use ic_interfaces::registry::{
    empty_zero_registry_record, RegistryClient, RegistryClientVersionedResult,
    RegistryDataProvider, RegistryTransportRecord, ZERO_REGISTRY_VERSION,
};
use ic_metrics::MetricsRegistry;
use ic_registry_common::local_store::LocalStoreImpl;
use ic_registry_common::{
    bootstrap_registry_data_provider::BootstrapRegistryDataProvider,
    data_provider::{CertifiedNnsDataProvider, NnsDataProvider},
    proto_registry_data_provider::ProtoRegistryDataProvider,
    registry::RegistryCanister,
};
pub use ic_types::{
    crypto::threshold_sig::ThresholdSigPublicKey,
    registry::{RegistryClientError, RegistryDataProviderError},
    RegistryVersion,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::time::Duration;
use url::Url;

use crate::metrics::Metrics;

const POLLING_PERIOD: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct RegistryClientImpl {
    cache: Arc<RwLock<CacheState>>,
    data_provider: Arc<dyn RegistryDataProvider>,
    metrics: Arc<Metrics>,
    started: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
}

/// RegistryClientImpl polls the registry on the NNS subnet and caches the
/// responses.
impl RegistryClientImpl {
    /// Creates a new instance of the RegistryClient.
    pub fn new(
        data_provider: Arc<dyn RegistryDataProvider>,
        metrics_registry: Option<&MetricsRegistry>,
    ) -> Self {
        let metrics = match metrics_registry {
            Some(metrics_registry) => Arc::new(Metrics::new(&metrics_registry)),
            None => Arc::new(Metrics::new(&MetricsRegistry::new())),
        };

        Self {
            cache: Arc::new(RwLock::new(CacheState::new())),
            data_provider,
            metrics,
            started: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Calls `poll_once()` synchronously, if it succeeds a background task is
    /// spawned that continuously polls for updates.
    /// The background task is stopped when the object is dropped.
    pub fn fetch_and_start_polling(&self) -> Result<(), RegistryClientError> {
        if self
            .started
            .compare_and_swap(false, true, Ordering::Relaxed)
        {
            return Err(RegistryClientError::PollLockFailed {
                error: "'fetch_and_start_polling' already called".to_string(),
            });
        }
        self.poll_once()?;
        let cancelled = Arc::clone(&self.cancelled);
        let self_ = self.clone();
        tokio::spawn(async move {
            while !cancelled.load(Ordering::Relaxed) {
                tokio::time::delay_for(POLLING_PERIOD).await;
                if let Ok(()) = self_.poll_once() {}
            }
        });

        Ok(())
    }

    /// Fetches the newest updates from the registry data provider.
    ///
    /// Returns an error if a poll is already in progress or querying the data
    /// provider failed. Returns `Ok` if querying the data provider succeeded,
    /// regardless of whether a newer registry version was available or not.
    pub fn poll_once(&self) -> Result<(), RegistryClientError> {
        let (records, version) = {
            let latest_version = self.cache.read().unwrap().latest_version;
            match self
                .data_provider
                .get_updates_since(latest_version)
            {
                Ok((records, version)) if version > latest_version => {
                    (records, version)
                }
                Ok(_) /*if version == cache_state.latest_version*/ => return Ok(()),
                Err(e) => return Err(RegistryClientError::from(e)),
            }
        };

        // Ensure exclusive access to the cache.
        let mut cache_state = self.cache.write().unwrap();

        // Check version again under write lock, to prevent race conditions.
        if version > cache_state.latest_version {
            self.metrics
                .ic_registry_client_registry_version
                .set(version.get() as i64);
            cache_state.update(records, version);
        }
        Ok(())
    }

    fn check_version(
        &self,
        version: RegistryVersion,
    ) -> Result<RwLockReadGuard<CacheState>, RegistryClientError> {
        let cache_state = self.cache.read().unwrap();
        if version > cache_state.latest_version {
            return Err(RegistryClientError::VersionNotAvailable { version });
        }
        Ok(cache_state)
    }
}

impl Drop for RegistryClientImpl {
    fn drop(&mut self) {
        self.cancelled.fetch_or(true, Ordering::Relaxed);
    }
}

/// Instantiate a data provider from a `DataProviderConfig`. In case of
/// `DataProviderConfig::Bootstrap` and
/// `DataProviderConfig::RegistryCanisterUrl`, a corresponding
/// `ThresholdSigPublicKey` can be provided to verify certified updates provided
/// by the registry canister.
pub fn create_data_provider(
    data_provider_config: &DataProviderConfig,
    optional_nns_public_key: Option<ThresholdSigPublicKey>,
) -> Arc<dyn RegistryDataProvider> {
    let nns_data_provider = |urls: Vec<Url>| -> Arc<dyn RegistryDataProvider> {
        let registry_canister = RegistryCanister::new(urls);
        match optional_nns_public_key {
            Some(nns_pk) => Arc::new(CertifiedNnsDataProvider::new(registry_canister, nns_pk)),
            None => Arc::new(NnsDataProvider::new(registry_canister)),
        }
    };

    match data_provider_config {
        DataProviderConfig::RegistryCanisterUrl(url) => nns_data_provider(url.clone()),
        DataProviderConfig::ProtobufFile(path) => {
            Arc::new(ProtoRegistryDataProvider::load_from_file(path))
        }
        DataProviderConfig::Bootstrap {
            initial_registry_file,
            registry_canister_url,
        } => {
            let dp = BootstrapRegistryDataProvider::new(
                Arc::new(ProtoRegistryDataProvider::load_from_file(
                    initial_registry_file,
                )),
                nns_data_provider(registry_canister_url.clone()),
            );
            Arc::new(dp)
        }
        DataProviderConfig::LocalStore(path) => Arc::new(LocalStoreImpl::new(path)),
    }
}

#[derive(Clone)]
struct CacheState {
    records: Vec<RegistryTransportRecord>,
    latest_version: RegistryVersion,
}

impl CacheState {
    fn new() -> Self {
        Self {
            records: vec![],
            latest_version: ZERO_REGISTRY_VERSION,
        }
    }

    fn update(&mut self, records: Vec<RegistryTransportRecord>, new_version: RegistryVersion) {
        assert!(new_version > self.latest_version);

        for record in records {
            assert!(record.version > self.latest_version);
            let search_key = (&record.key, &record.version);
            match self
                .records
                .binary_search_by_key(&search_key, |r| (&r.key, &r.version))
            {
                Ok(_) => (),
                Err(i) => {
                    self.records.insert(i, record);
                }
            };
        }
        self.latest_version = new_version;
    }
}

impl RegistryClient for RegistryClientImpl {
    fn get_versioned_value(
        &self,
        key: &str,
        version: RegistryVersion,
    ) -> RegistryClientVersionedResult<Vec<u8>> {
        if version == ZERO_REGISTRY_VERSION {
            return Ok(empty_zero_registry_record(key));
        }
        let cache_state = self.check_version(version)?;

        let search_key = &(key, &version);
        let record = match cache_state
            .records
            .binary_search_by_key(search_key, |r| (&r.key, &r.version))
        {
            // We have an exact match
            Ok(idx) => cache_state.records[idx].clone(),
            // A record with the same key and record version < version
            Err(idx) if idx > 0 && cache_state.records[idx - 1].key == key => {
                cache_state.records[idx - 1].clone()
            }
            // No entry found, key does not exist
            _ => empty_zero_registry_record(key),
        };

        Ok(record)
    }

    fn get_key_family(
        &self,
        key_prefix: &str,
        version: RegistryVersion,
    ) -> Result<Vec<String>, RegistryClientError> {
        if version == ZERO_REGISTRY_VERSION {
            return Ok(vec![]);
        }
        let cache_state = self.check_version(version)?;

        let first_registry_version = RegistryVersion::from(1);
        // The pair (k, version) is unique and no entry exists with version 0. Thus, the
        // first entry of interest is at the insertion point of (prefix, 1).
        let search_key = &(key_prefix, &first_registry_version);

        let first_match_index = match cache_state
            .records
            .binary_search_by_key(search_key, |r| (&r.key, &r.version))
        {
            // An exact match just means the key family will have size 1.
            Ok(idx) => idx,
            // The entry at idx cannot be lexicographically less than key_prefix, otherwise the
            // correctness assumption about bin search would not hold.
            Err(idx) => {
                // If the key at this position does not start with `key_prefix`, the set of keys
                // starting with `key_prefix` is empty.
                if !cache_state.records[idx].key.starts_with(key_prefix) {
                    return Ok(vec![]);
                }
                idx
            }
        };

        // 1. Skip all entries up to the first_match_index
        // 2. Filter out all versions newer than the one we are interested in
        // 3. Only consider the subsequence that starts with the given prefix
        let res = cache_state
            .records
            .iter()
            .skip(first_match_index) // (1)
            .filter(|r| r.version <= version) // (2)
            .take_while(|r| r.key.starts_with(key_prefix)) // (3)
            .fold(vec![], |mut acc, r| {
                // is_set iff the key is set in this transport record.
                let is_set = r.value.is_some();
                // if this record indicates a removal for the last key in the list, we need to
                // remove that key.
                if !is_set && acc.last().map(|k| k == &r.key).unwrap_or(false) {
                    acc.pop();
                } else if is_set {
                    acc.push(r.key.clone());
                }
                acc
            });
        Ok(res)
    }

    fn get_latest_version(&self) -> RegistryVersion {
        let cache_state = self.cache.read().unwrap();
        cache_state.latest_version
    }
}

/// An empty registry data provider that emulates a static, empty registry.
pub struct EmptyRegistryDataProvider();

impl RegistryDataProvider for EmptyRegistryDataProvider {
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<(Vec<RegistryTransportRecord>, RegistryVersion), RegistryDataProviderError> {
        Ok((vec![], version))
    }
}

#[cfg(test)]
#[allow(dead_code, unused_imports)]
mod tests {
    use super::*;
    use ic_interfaces::registry::ZERO_REGISTRY_VERSION;
    use ic_registry_common::{
        pb::test_protos::v1::TestProto, proto_registry_data_provider::ProtoRegistryDataProvider,
        test_proto::TestProtoHelper,
    };
    use std::collections::HashSet;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    #[test]
    fn empty_registry_should_report_zero_as_latest_version() {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry = RegistryClientImpl::new(data_provider, None);

        // test whether the empty registry is actually empty
        assert_eq!(registry.get_latest_version(), ZERO_REGISTRY_VERSION);
    }

    #[test]
    fn empty_registry_reports_none_for_zero_version() {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry = RegistryClientImpl::new(data_provider, None);

        assert!(registry
            .get_test_proto("any_key", RegistryVersion::new(0))
            .unwrap()
            .is_none());
    }

    #[test]
    fn can_retrieve_entries_correctly() {
        // In this test, for a bunch of keys, we insert a number of records where the
        // test_value is equal to the version at which the record was inserted. For each
        // key, the test then runs through all versions in order up to
        // get_latest_version().
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry = RegistryClientImpl::new(data_provider.clone(), None);
        let get = |key: &str, t: u64| registry.get_test_proto(key, RegistryVersion::new(t));
        let family =
            |key_prefix: &str, t: u64| registry.get_key_family(key_prefix, RegistryVersion::new(t));
        let set = |key: &str, ver: u64| data_provider.add(key, v(ver), Some(value(ver))).unwrap();
        let rem = |key: &str, ver: u64| data_provider.add::<TestProto>(key, v(ver), None).unwrap();

        set("A", 1);
        set("A", 3);
        set("A", 6);
        set("B", 6);
        set("B2", 5);
        rem("B2", 6);
        set("B3", 5);
        set("C", 6);

        // test key families
        set("F0_1", 1);
        for v in (1..8).step_by(2) {
            set("FA_1", v);
            rem("FA_1", v + 1);
        }
        for v in (1..8).step_by(4) {
            set("FA_2", v);
            rem("FA_2", v + 2);
        }
        set("FA_3", 1);
        rem("FA_3", 5);
        for v in 1..=8 {
            set("FB_1", v);
        }

        assert!(registry.get_test_proto("A", v(1)).is_err());

        // Poll the data_provider.
        registry.poll_once().unwrap();

        let latest_version = 8;
        assert_eq!(registry.get_latest_version(), v(latest_version));

        assert!(get("A", 0).unwrap().is_none());
        assert_eq!(get("A", 1).unwrap(), Some(value(1)));
        assert_eq!(get("A", 2).unwrap(), Some(value(1)));
        assert_eq!(get("A", 3).unwrap(), Some(value(3)));
        assert_eq!(get("A", 4).unwrap(), Some(value(3)));
        assert_eq!(get("A", 5).unwrap(), Some(value(3)));
        assert_eq!(get("A", 6).unwrap(), Some(value(6)));
        assert!(get("A", latest_version + 1).is_err());

        for t in 0..6 {
            assert!(get("B", t).unwrap().is_none());
        }
        assert_eq!(get("B", 6).unwrap(), Some(value(6)));
        assert!(get("B", latest_version + 1).is_err());

        for t in 0..5 {
            assert!(get("B2", t).unwrap().is_none());
        }
        assert_eq!(get("B2", 5).unwrap(), Some(value(5)));
        assert!(get("B2", 6).unwrap().is_none());
        assert!(get("B2", latest_version + 1).is_err());

        let test_family = |key_prefix: &str, version: u64, exp_result: &[&str]| {
            assert_eq!(
                family(key_prefix, version)
                    .unwrap()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<HashSet<_>>(),
                exp_result
                    .iter()
                    .map(ToString::to_string)
                    .collect::<HashSet<_>>()
            );
        };

        test_family("B", 6, &["B", "B3"]);
        test_family("F", 1, &["F0_1", "FA_1", "FA_2", "FA_3", "FB_1"]);
        test_family("FA_", 1, &["FA_1", "FA_2", "FA_3"]);
        test_family("FA_", 2, &["FA_2", "FA_3"]);
        test_family("FA_", 3, &["FA_1", "FA_3"]);
        test_family("FA_", 4, &["FA_3"]);
        test_family("FA_", 5, &["FA_1", "FA_2"]);
        test_family("FA_", 6, &["FA_2"]);
        test_family("FA_", 7, &["FA_1"]);
        test_family("FA_", 8, &[]);
    }

    #[test]
    fn can_poll_new_versions_from_data_provider() {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry = RegistryClientImpl::new(data_provider.clone(), None);
        let get = |key: &str, t: u64| registry.get_test_proto(key, RegistryVersion::new(t));

        data_provider.add("A", v(1), Some(value(1))).unwrap();

        registry.poll_once().unwrap();
        assert_eq!(registry.get_latest_version(), v(1));
        assert!(get("A", 0).unwrap().is_none());
        assert_eq!(get("A", 1).unwrap(), Some(value(1)));
        assert!(get("B2", 1).unwrap().is_none());
        assert!(get("B2", 2).is_err());

        data_provider.add("A", v(3), Some(value(3))).unwrap();
        data_provider.add("B2", v(5), Some(value(5))).unwrap();
        data_provider.add::<TestProto>("B2", v(6), None).unwrap();

        registry.poll_once().unwrap();
        assert_eq!(registry.get_latest_version(), v(6));
        assert_eq!(get("A", 3).unwrap(), Some(value(3)));
        assert_eq!(get("A", 4).unwrap(), Some(value(3)));
        assert_eq!(get("A", 5).unwrap(), Some(value(3)));
        assert_eq!(get("A", 6).unwrap(), Some(value(3)));
        assert!(get("A", 7).is_err());

        for t in 0..5 {
            assert!(get("B2", t).unwrap().is_none());
        }
        assert_eq!(get("B2", 5).unwrap(), Some(value(5)));
        assert!(get("B2", 6).unwrap().is_none());
        assert!(get("B2", 7).is_err());
    }

    #[tokio::test]
    async fn start_polling_actually_polls_data_provider() {
        let data_provider = Arc::new(FakeDataProvider {
            poll_counter: Arc::new(AtomicUsize::new(0)),
        });
        let registry = RegistryClientImpl::new(data_provider.clone(), None);

        if let Err(e) = registry.fetch_and_start_polling() {
            panic!("fetch_and_start_polling failed: {}", e);
        }
        tokio::time::delay_for(Duration::from_secs(1)).await;
        std::mem::drop(registry);

        assert!(data_provider.poll_counter.load(Ordering::Relaxed) > 0);
    }

    #[cfg(test)]
    mod metrics {
        use ic_test_utilities::metrics::fetch_int_gauge;

        use super::*;

        #[test]
        fn ic_registry_client_registry_version_updates() {
            let data_provider = Arc::new(ProtoRegistryDataProvider::new());
            let metrics_registry = MetricsRegistry::new();
            let registry = RegistryClientImpl::new(data_provider.clone(), Some(&metrics_registry));

            data_provider.add("A", v(1), Some(value(1))).unwrap();

            registry.poll_once().unwrap();
            assert_eq!(registry.get_latest_version(), v(1));
            assert_eq!(
                fetch_int_gauge(&metrics_registry, "ic_registry_client_registry_version"),
                Some(1)
            );

            data_provider.add("A", v(3), Some(value(3))).unwrap();

            registry.poll_once().unwrap();
            assert_eq!(registry.get_latest_version(), v(3));
            assert_eq!(
                fetch_int_gauge(&metrics_registry, "ic_registry_client_registry_version"),
                Some(3)
            );
        }
    }

    fn v(v: u64) -> RegistryVersion {
        RegistryVersion::new(v)
    }

    fn value(v: u64) -> TestProto {
        let mut test_proto = TestProto::default();
        test_proto.test_value = v;
        test_proto
    }

    struct FakeDataProvider {
        pub poll_counter: Arc<AtomicUsize>,
    }

    impl RegistryDataProvider for FakeDataProvider {
        fn get_updates_since(
            &self,
            _version: RegistryVersion,
        ) -> Result<(Vec<RegistryTransportRecord>, RegistryVersion), RegistryDataProviderError>
        {
            self.poll_counter.fetch_add(1, Ordering::Relaxed);
            Ok((vec![], ZERO_REGISTRY_VERSION))
        }
    }
}
