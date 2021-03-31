use lazy_static::lazy_static;
use url::Url;

use ic_registry_common::data_provider::NnsDataProvider;
use ic_registry_common::registry::*;
use ic_types::RegistryVersion;

use ic_interfaces::registry::RegistryDataProvider;
use ic_registry_transport::{pb::v1::RegistryMutation, Error};

lazy_static! {
    static ref HOST: Url = Url::parse("http://localhost:8080").expect("url parsing failed");
}

#[test]
#[ignore]
fn data_provider_test() {
    let registry_canister = RegistryCanister::new(vec![HOST.clone()]);

    let provider = NnsDataProvider::new(registry_canister);
    let result = provider.get_updates_since(RegistryVersion::from(0));

    println!("{:?}", result);
    assert!(result.is_ok());
}

#[tokio::test()]
#[ignore]
async fn registry_integration_test() {
    // FIXME the following code will allow to install a canister. forthcoming!
    //
    //    canister_test(|r| {
    // let client_path =
    // std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
    //     .join("..")
    //     .join("canister");

    // let proj = Project::new(client_path.to_str().unwrap());

    // println!("Starting registry");
    // let canister = proj
    //     .cargo_bin("registry-canister")
    //     .install(&r)
    //     .bytes(Vec::new());
    // println!(".. done");

    let sample_key = vec![1, 2, 3, 4];
    let sample_value = vec![5, 6, 7, 8];

    let registry_canister = RegistryCanister::new(vec![HOST.clone()]);

    let changes = registry_canister.get_changes_since(0).await;
    println!("Initial registry diff: {:?}", changes);

    let (_, start_version) = changes.unwrap();
    println!("📦 Initial version diff: {:?}", start_version);

    let mut mutation = RegistryMutation::default();
    mutation.mutation_type = 0;
    mutation.key = sample_key.clone();
    mutation.value = sample_value.clone();

    // First insert succeeds (if we started on version 0)
    let res = registry_canister
        .atomic_mutate(vec![mutation.clone()], vec![])
        .await;
    assert!(res.is_ok() || start_version != 0);

    // Second insert fails with key already present error
    let res = registry_canister
        .atomic_mutate(vec![mutation], vec![])
        .await;
    assert!(res.is_err());

    let error: Vec<Error> = res.err().unwrap();
    assert!(
        error.get(0)
            == Some(&ic_registry_transport::Error::KeyAlreadyPresent(
                sample_key.clone()
            ))
    );

    let changes = registry_canister.get_changes_since(0).await;
    println!("Current registry diff: {:?}", changes);

    let (_, new_version) = changes.unwrap();
    println!("📦 Current version diff: {:?}", new_version);

    // XXX is it correct that the second failing insert yields a new version?
    assert_eq!(new_version, start_version + 2);

    let value = registry_canister.get_value(sample_key.clone(), None).await;
    assert!(value.is_ok());

    let (value, version_updated) = value.unwrap();
    assert_eq!(value, sample_value.clone());
    // If we started with an empty registry, the second latest reported version is
    // the one that changed the key The one that was created by the
    // redundant insert should not have touched it.
    assert!(version_updated == new_version - 1 || start_version != 0);
    //  })
}
