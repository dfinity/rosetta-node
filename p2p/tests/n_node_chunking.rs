use ic_test_utilities::metrics::fetch_int_counter;
use std::time::Duration;
// Objective: test artifacts are synced to completion using chunking
//
// Procedure Startup N nodes with a single artifact each with Q chunks. Run
// gossip.
//
// Expected Results: By end of the test, each node has received (N -1)  chunked
// artifacts from (N-1) peers. Total Chunks received are (N-1) *
// Q
//
// Notes:  Most of the logic is driven by a test artifact manager

pub mod framework;

// NOTE !!!!
// the barrier strings constants have to be unique for a every barrier in the
// test
const ALL_NODES_SYNCED: &str = "ALL_NODES_SYNCED";
const MAX_ALLOWED_ITER: u32 = 200;
#[cfg(test)]
const NUM_TEST_INSTANCES: u16 = 3;
#[tokio::test]
async fn n_node_chunking() {
    framework::spawn_replicas_as_threads(false, NUM_TEST_INSTANCES, |p2p_test_context| {
        p2p_test_context.p2p.run();
        let mut iter = 0;
        loop {
            std::thread::sleep(Duration::from_millis(600));
            iter += 1;
            if iter > MAX_ALLOWED_ITER {
                panic!("Test exceeded  {} iterations", MAX_ALLOWED_ITER);
            }

            let artifacts_recv_count = fetch_int_counter(
                &p2p_test_context.metrics_registry,
                "gossip_artifacts_received",
            )
            .expect("Test cannot read gauge");
            println!(
                "Node {:?} Artifact recv count {}",
                p2p_test_context.node_id, artifacts_recv_count
            );
            if artifacts_recv_count < NUM_TEST_INSTANCES as u64 - 1 {
                continue;
            }

            // Node has received all artifacts, continue operating till
            // all other nodes signal that they too have synced all the
            //artifacts
            match p2p_test_context
                .test_synchronizer
                .try_wait_on_barrier(ALL_NODES_SYNCED.to_string())
            {
                Err(_) => {
                    continue;
                }
                Ok(_) => {
                    break;
                }
            }
        }
    });
}
