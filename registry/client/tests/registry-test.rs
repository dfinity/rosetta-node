use lazy_static::lazy_static;
use url::Url;

use ic_registry_common::data_provider::NnsDataProvider;
use ic_registry_common::registry::*;

use ic_registry_client::client::RegistryClientImpl;
use ic_registry_transport::pb::v1::RegistryMutation;

use ic_interfaces::registry::RegistryClient;
use std::sync::Arc;

lazy_static! {
    static ref HOST: Url = Url::parse("http://localhost:8080").expect("url parsing failed");
}

#[tokio::test]
#[ignore]
async fn registry_client_test() {
    let sample_key = vec![1, 2, 3, 4];
    let sample_value = vec![5, 6, 7, 8];

    // First insert succeeds (if we started on version 0)
    println!("Running registry client tests");
    let registry_canister = RegistryCanister::new(vec![HOST.clone()]);

    let provider = NnsDataProvider::new(registry_canister);

    let registry_client = RegistryClientImpl::new(Arc::new(provider), None);

    let start_version = registry_client.get_latest_version();
    println!("Initial version after instantiation: {:?}", start_version);

    let registry_canister = RegistryCanister::new(vec![HOST.clone()]);

    let mut mutation = RegistryMutation::default();
    mutation.mutation_type = 0;
    mutation.key = sample_key.clone();
    mutation.value = sample_value.clone();

    let res = registry_canister
        .atomic_mutate(vec![mutation.clone()], vec![])
        .await;

    assert!(
        res.is_ok()
            || res.err().unwrap().get(0)
                == Some(&ic_registry_transport::Error::KeyAlreadyPresent(
                    sample_key.clone()
                ))
    );

    if let Err(e) = registry_client.start_polling() {
        panic!("start_polling failed: {}", e);
    }
    std::thread::sleep(std::time::Duration::from_secs(5));

    let end_version = registry_client.get_latest_version();
    println!(
        "Version of the registry after a little wait: {:?}",
        end_version
    );

    assert_eq!(start_version.get() + 1, end_version.get());
}
