pub mod framework;

#[cfg(test)]
const NUM_TEST_INSTANCES: u16 = 8;
const INVERSE_RATIO_FAILSTOP_NODES: u64 = 4; // IVR
const MAX_CERTIFIED_HEIGHT: u64 = 3; // A height can only be certified, after it has been finalized.
#[tokio::test]
async fn n_node_gossip_with_failstop() {
    framework::spawn_replicas_as_threads(true, NUM_TEST_INSTANCES, |p2p_test_context| {
        std::println!("Node id: {}", p2p_test_context.node_id);
        // Drop out for 1/IVR of the nodes (FAILSTOP)

        if (p2p_test_context.node_num + 1) % INVERSE_RATIO_FAILSTOP_NODES == 0 {
            println!("Stopping node {:?}", p2p_test_context.node_id.clone().get());
            return;
        }
        p2p_test_context.p2p.run();
        println!("Runnning node {:?}", p2p_test_context.node_id.clone().get());

        framework::replica_run_till_height(&p2p_test_context, MAX_CERTIFIED_HEIGHT)
    });
}
