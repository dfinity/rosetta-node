use super::*;
use ic_rosetta_api::store::{BlockStore, BlockStoreError, InMemoryStore, OnDiskStore};

#[actix_rt::test]
async fn in_memory_store_smoke_test() {
    init_test_logger();
    let store = InMemoryStore::new();
    store_smoke_test(store);
}

#[actix_rt::test]
async fn in_memory_store_prune_test() {
    init_test_logger();
    let store = InMemoryStore::new();
    store_prune_test(store);
}

#[actix_rt::test]
async fn in_memory_store_prune_corner_cases_test() {
    init_test_logger();
    let store = InMemoryStore::new();
    store_prune_corner_cases_test(store);
}

#[actix_rt::test]
async fn on_disk_store_smoke_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let store = OnDiskStore::new(tmpdir.path().into()).unwrap();
    store_smoke_test(store);
}

#[actix_rt::test]
async fn on_disk_store_prune_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let store = OnDiskStore::new(tmpdir.path().into()).unwrap();
    store_prune_test(store);
}

#[actix_rt::test]
async fn on_disk_store_prune_corner_cases_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let store = OnDiskStore::new(tmpdir.path().into()).unwrap();
    store_prune_corner_cases_test(store);
}

#[actix_rt::test]
async fn on_disk_store_prune_first_balance_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let store = OnDiskStore::new(tmpdir.path().into()).unwrap();
    store_prune_first_balance_test(store);
}

#[actix_rt::test]
async fn on_disk_store_prune_and_load_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let mut store = OnDiskStore::new(tmpdir.path().into()).unwrap();

    let scribe = Scribe::new_with_sample_data(10, 100);

    for hb in &scribe.blockchain {
        store.push(hb.clone()).unwrap();
    }

    prune(&scribe, &mut store, 10);
    verify_pruned(&scribe, &mut store, 10);
    verify_balance_snapshot(&scribe, &mut store, 10);

    prune(&scribe, &mut store, 20);
    verify_pruned(&scribe, &mut store, 20);
    verify_balance_snapshot(&scribe, &mut store, 20);

    drop(store);
    // Now reload from disk
    let mut store = OnDiskStore::new(tmpdir.path().into()).unwrap();
    verify_pruned(&scribe, &mut store, 20);
    verify_balance_snapshot(&scribe, &mut store, 20);

    prune(&scribe, &mut store, 30);
    verify_pruned(&scribe, &mut store, 30);
    verify_balance_snapshot(&scribe, &mut store, 30);

    drop(store);
    // Reload once again
    let mut store = OnDiskStore::new(tmpdir.path().into()).unwrap();
    verify_pruned(&scribe, &mut store, 30);
    verify_balance_snapshot(&scribe, &mut store, 30);
}

fn store_smoke_test(mut store: impl BlockStore) {
    let scribe = Scribe::new_with_sample_data(10, 100);

    for hb in &scribe.blockchain {
        store.push(hb.clone()).unwrap();
    }

    for hb in &scribe.blockchain {
        assert_eq!(store.get_at(hb.index).unwrap(), *hb);
    }

    let last_idx = scribe.blockchain.back().unwrap().index;
    assert_eq!(
        store.get_at(last_idx + 1).unwrap_err(),
        BlockStoreError::NotFound(last_idx + 1)
    );
}

fn store_prune_test(mut store: impl BlockStore) {
    let scribe = Scribe::new_with_sample_data(10, 100);

    for hb in &scribe.blockchain {
        store.push(hb.clone()).unwrap();
    }

    prune(&scribe, &mut store, 10);
    verify_pruned(&scribe, &mut store, 10);

    prune(&scribe, &mut store, 20);
    verify_pruned(&scribe, &mut store, 20);
}

fn store_prune_first_balance_test(mut store: impl BlockStore) {
    let scribe = Scribe::new_with_sample_data(10, 100);

    for hb in &scribe.blockchain {
        store.push(hb.clone()).unwrap();
    }

    prune(&scribe, &mut store, 10);
    verify_pruned(&scribe, &mut store, 10);
    verify_balance_snapshot(&scribe, &mut store, 10);

    prune(&scribe, &mut store, 20);
    verify_pruned(&scribe, &mut store, 20);
    verify_balance_snapshot(&scribe, &mut store, 20);
}

fn store_prune_corner_cases_test(mut store: impl BlockStore) {
    let scribe = Scribe::new_with_sample_data(10, 100);

    for hb in &scribe.blockchain {
        store.push(hb.clone()).unwrap();
    }

    prune(&scribe, &mut store, 0);
    verify_pruned(&scribe, &mut store, 0);

    prune(&scribe, &mut store, 1);
    verify_pruned(&scribe, &mut store, 1);

    let last_idx = scribe.blockchain.back().unwrap().index;

    prune(&scribe, &mut store, last_idx);
    verify_pruned(&scribe, &mut store, last_idx);
}

fn prune(scribe: &Scribe, store: &mut impl BlockStore, prune_at: u64) {
    let oldest_idx = prune_at;
    let oldest_block = scribe.blockchain.get(oldest_idx as usize).unwrap();
    let oldest_balance = to_balances(
        scribe
            .balance_history
            .get(oldest_idx as usize)
            .unwrap()
            .clone(),
    );

    store.prune(oldest_block, &oldest_balance).unwrap();
}

fn verify_pruned(scribe: &Scribe, store: &mut impl BlockStore, prune_at: u64) {
    let after_last_idx = scribe.blockchain.len() as u64;
    let oldest_idx = prune_at;

    // Genesis block (at idx 0) should still be accessible
    assert_eq!(store.get_at(0).unwrap(), *scribe.blockchain.get(0).unwrap());

    for i in 1..oldest_idx {
        assert_eq!(
            store.get_at(i).unwrap_err(),
            BlockStoreError::NotAvailable(i)
        );
    }

    for i in oldest_idx..after_last_idx {
        assert_eq!(
            store.get_at(i).unwrap(),
            *scribe.blockchain.get(i as usize).unwrap()
        );
    }
    assert_eq!(
        store.get_at(after_last_idx).unwrap_err(),
        BlockStoreError::NotFound(after_last_idx)
    );
}

fn verify_balance_snapshot(scribe: &Scribe, store: &mut impl BlockStore, prune_at: u64) {
    let oldest_idx = prune_at as usize;
    let (oldest_block, balances) = store.first_snapshot().unwrap().clone();
    assert_eq!(oldest_block, *scribe.blockchain.get(oldest_idx).unwrap());
    assert_eq!(
        balances.store,
        to_balances(scribe.balance_history.get(oldest_idx).unwrap().clone(),).store
    );
}
