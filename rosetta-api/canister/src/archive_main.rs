use ic_types::CanisterId;
use ledger_canister::{get_chain_prefix, RawBlock};
use std::collections::VecDeque;

use std::sync::RwLock;

lazy_static::lazy_static! {
    // Wasm bytecode of an Archive Node
    // FIXME: handle ledger-archive-node-canister.wasm dependency.
    pub static ref NODE_BYTECODE: RwLock<Vec<u8>> = RwLock::new(std::include_bytes!("../wasm/ledger-archive-node-canister.wasm").to_vec());
    // List of Archive Nodes
    pub static ref NODES: RwLock<Vec<CanisterId>> = RwLock::new(vec![]);
    // Maximum amount of data that can be stored in an Archive Node canister
    pub static ref NODE_MAX_MEMORY_SIZE_BYTES: RwLock<usize> = RwLock::new(2 * (1024^3));
    // Maximum inter-canister message size in bytes
    pub static ref MAX_MESSAGE_SIZE_BYTES: RwLock<usize> = RwLock::new(2 * (1024^2));
}

// Helper to print messages in green
fn print<S: std::convert::AsRef<str>>(s: S)
where
    yansi::Paint<S>: std::string::ToString,
{
    dfn_core::api::print(yansi::Paint::green(s).to_string());
}

// Helper function to create a canister and install the node Wasm bytecode.
async fn create_and_initialize_node_canister() -> (CanisterId, usize) {
    print("[archive] calling create_canister()");
    let node_canister_id: CanisterId = ledger_canister::spawn::create_canister().await;
    let node_bytecode: &[u8] = &*NODE_BYTECODE.read().unwrap();
    print("[archive] calling install_code()");
    ledger_canister::spawn::install_code(
        node_canister_id,
        node_bytecode.to_vec(),
        dfn_candid::Candid((Some(*NODE_MAX_MEMORY_SIZE_BYTES.read().unwrap()),)),
        // Set the memory allocation to how much data we want to store in the
        // node + 32 MiB of "scratch" space
        Some(*NODE_MAX_MEMORY_SIZE_BYTES.read().unwrap() + 32 * 1024 * 1024),
    )
    .await;
    NODES.write().unwrap().push(node_canister_id);

    let remaining_capacity: usize = dfn_core::call(
        node_canister_id,
        "remaining_capacity",
        dfn_candid::candid_one,
        (),
    )
    .await
    .unwrap();

    (node_canister_id, remaining_capacity)
}

/// Helper function to find the CanisterId of the node that can accept blocks,
/// or create one, and find how many blocks can be accepted.
async fn node_and_capacity(needed: usize) -> (CanisterId, usize) {
    let last_node_canister_id: Option<CanisterId> = NODES.read().unwrap().last().copied();
    match last_node_canister_id {
        // Not a single archive node exists. Create one.
        None => {
            print("[archive] creating the first archive node");
            let (node_canister_id, remaining_capacity) =
                create_and_initialize_node_canister().await;
            print(format!("[archive] node canister id: {}", node_canister_id));

            (node_canister_id, remaining_capacity)
        }
        // Some archive node exists. Use it, or, if already full, create a
        // new node.
        Some(last_node_canister_id) => {
            let remaining_capacity: usize = dfn_core::call(
                last_node_canister_id,
                "remaining_capacity",
                dfn_candid::candid,
                (),
            )
            .await
            .unwrap();
            if remaining_capacity < needed {
                print("[archive] last node is full. creating a new archive node");
                let (node_canister_id, remaining_capacity) =
                    create_and_initialize_node_canister().await;
                print(format!("[archive] node canister id: {}", node_canister_id));
                (node_canister_id, remaining_capacity)
            } else {
                print(format!(
                    "[archive] reusing existing last node {} with capacity {}",
                    last_node_canister_id, remaining_capacity
                ));
                (last_node_canister_id, remaining_capacity)
            }
        }
    }
}

async fn archive_blocks(blocks: Vec<RawBlock>) {
    print("[archive] archive_blocks(): start");

    let mut blocks = VecDeque::from(blocks);

    while !blocks.is_empty() {
        print(format!(
            "[archive] archive_blocks(): number of blocks remaining: {}",
            blocks.len()
        ));

        // Get the CanisterId and remaining capacity of the node that can
        // accept at least the first block
        let (node_canister_id, remaining_capacity) = node_and_capacity(blocks[0].len()).await;

        // Take as many blocks as can be sent and send those in
        let mut first_blocks: VecDeque<_> =
            get_chain_prefix(&mut blocks, remaining_capacity).into();
        assert!(!first_blocks.is_empty());

        print(format!(
            "[archive] appending blocks to node {:?}. number of blocks that fit: {}, remaining blocks to archive: {}",
            node_canister_id.get(),
            first_blocks.len(),
            blocks.len()
        ));

        // Additionally, need to respect the inter-canister message size
        while !first_blocks.is_empty() {
            let chunk =
                get_chain_prefix(&mut first_blocks, *MAX_MESSAGE_SIZE_BYTES.read().unwrap());
            assert!(!chunk.is_empty());
            print(format!(
                "[archive] calling append_blocks() with a chunk of size {}",
                chunk.len()
            ));
            let () = dfn_core::call(
                node_canister_id,
                "append_blocks",
                dfn_candid::candid_one,
                chunk,
            )
            .await
            .unwrap();
        }
    }

    print("[archive] archive_blocks() done");
}

async fn get_nodes() -> Vec<CanisterId> {
    NODES.read().unwrap().clone()
}

fn init(node_max_memory_size_bytes: Option<usize>, max_message_size_bytes: Option<usize>) {
    match node_max_memory_size_bytes {
        None => {
            print(format!(
                "[archive] init(): using default maximum node memory size: {}",
                NODE_MAX_MEMORY_SIZE_BYTES.read().unwrap()
            ));
        }
        Some(node_max_memory_size_bytes) => {
            *NODE_MAX_MEMORY_SIZE_BYTES.write().unwrap() = node_max_memory_size_bytes;
            print(format!(
                "[archive] init(): using maximum node memory size: {}",
                node_max_memory_size_bytes
            ));
        }
    }
    match max_message_size_bytes {
        None => {
            print(format!(
                "[archive] init(): using default maximum message size: {}",
                MAX_MESSAGE_SIZE_BYTES.read().unwrap()
            ));
        }
        Some(max_message_size_bytes) => {
            *MAX_MESSAGE_SIZE_BYTES.write().unwrap() = max_message_size_bytes;
            print(format!(
                "[archive] init(): using maximum message size: {}",
                max_message_size_bytes
            ));
        }
    }
}

#[export_name = "canister_init"]
fn main() {
    dfn_core::over_init(
        |dfn_candid::Candid((opt_node_max_memory_size_bytes, opt_max_message_size_bytes))| {
            init(opt_node_max_memory_size_bytes, opt_max_message_size_bytes)
        },
    )
}

#[export_name = "canister_update archive_blocks"]
fn archive_blocks_() {
    dfn_core::over_async(dfn_candid::candid_one, archive_blocks);
}

#[export_name = "canister_query get_nodes"]
fn get_nodes_() {
    dfn_core::over_async(dfn_candid::candid, |()| get_nodes());
}
