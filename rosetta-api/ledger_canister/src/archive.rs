use crate::{get_chain_prefix, spawn, ArchiveOptions, EncodedBlock};
use ic_types::CanisterId;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

// Wasm bytecode of an Archive Node
const ARCHIVE_NODE_BYTECODE: &[u8] =
    std::include_bytes!("../wasm/ledger-archive-node-canister.wasm");

#[derive(Serialize, Deserialize, Debug)]
pub struct Archive {
    // List of Archive Nodes
    nodes: Vec<CanisterId>,

    // BlockHeights of Blocks stored in each archive node.

    // We need this because Blocks are stored in encoded format as
    // EncodedBlocks, and different EncodedBlocks may have different lengths.
    // Moreover, archive node capacity is specified in bytes instead of a fixed
    // number of Blocks. Thus, it is not possible to statically compute how
    // many EncodedBlocks will fit into an archive node -- the actual number
    // will vary slightly.

    // To facilitate lookup by index we will keep track of the number of Blocks
    // stored in each archive. We store an inclusive range [from, to]. Thus,
    // the range [0..9] means we store 10 blocks with indices from 0 to 9
    nodes_block_ranges: Vec<(u64, u64)>,

    // Maximum amount of data that can be stored in an Archive Node canister
    node_max_memory_size_bytes: usize,

    // Maximum inter-canister message size in bytes
    max_message_size_bytes: usize,

    /// How many blocks have been sent to the archive
    num_archived_blocks: u64,
}

impl Archive {
    pub fn new(options: ArchiveOptions) -> Self {
        Self {
            nodes: vec![],
            nodes_block_ranges: vec![],
            node_max_memory_size_bytes: options
                .node_max_memory_size_bytes
                .unwrap_or(2 * (1024 ^ 3)),
            max_message_size_bytes: options.max_message_size_bytes.unwrap_or(2 * (1024 ^ 2)),
            num_archived_blocks: 0,
        }
    }

    pub fn nodes(&self) -> &[CanisterId] {
        &self.nodes
    }

    pub async fn archive_blocks(&mut self, mut blocks: VecDeque<EncodedBlock>) {
        print("[archive] archive_blocks(): start");
        self.num_archived_blocks += blocks.len() as u64;

        while !blocks.is_empty() {
            print(format!(
                "[archive] archive_blocks(): number of blocks remaining: {}",
                blocks.len()
            ));

            // Get the CanisterId and remaining capacity of the node that can
            // accept at least the first block
            let (node_canister_id, node_index, remaining_capacity) =
                self.node_and_capacity(blocks[0].size_bytes()).await;

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
                let chunk = get_chain_prefix(&mut first_blocks, self.max_message_size_bytes);
                let chunk_len = chunk.len() as u64;
                assert!(!chunk.is_empty());
                print(format!(
                    "[archive] calling append_blocks() with a chunk of size {}",
                    chunk_len
                ));
                let () = dfn_core::call(
                    node_canister_id,
                    "append_blocks",
                    dfn_candid::candid_one,
                    chunk,
                )
                .await
                .unwrap();

                // Keep track of BlockHeights
                let heights = self.nodes_block_ranges.get_mut(node_index);
                match heights {
                    // We haven't inserted any Blocks into this archive node yet.
                    None => {
                        match self.nodes_block_ranges.last().copied() {
                            // If we haven't recorded any heights yet in any of the
                            // nodes then this is the **first archive node** and it
                            // starts with Block at height 0
                            None => self.nodes_block_ranges.push((0, chunk_len - 1)),
                            // If we haven't recorded any heights for this node but
                            // a previous node exists then the current heights
                            // start one above those in the previous node
                            Some((_, last_height)) => self
                                .nodes_block_ranges
                                .push((last_height + 1, last_height + chunk_len)),
                        }
                    }
                    // We have already inserted some Blocks into this archive node.
                    // Hence, we already have a value to work with
                    Some(heights) => {
                        heights.1 += chunk_len as u64;
                    }
                }

                print(format!(
                    "[archive] archive node [{}] block heights {:?}",
                    node_index,
                    self.nodes_block_ranges.get(node_index)
                ));
            }
        }

        print("[archive] archive_blocks() done");
    }

    // Helper function to create a canister and install the node Wasm bytecode.
    async fn create_and_initialize_node_canister(&mut self) -> (CanisterId, usize, usize) {
        print("[archive] calling create_canister()");
        let node_canister_id: CanisterId = spawn::create_canister().await;
        let node_block_height_offset: u64 = self
            .nodes_block_ranges
            .last()
            .map(|(_, height_to)| *height_to + 1)
            .unwrap_or(0);
        print("[archive] calling install_code()");
        spawn::install_code(
            node_canister_id,
            ARCHIVE_NODE_BYTECODE.to_vec(),
            dfn_candid::Candid((
                dfn_core::api::id(),
                node_block_height_offset,
                Some(self.node_max_memory_size_bytes),
            )),
            // Set the memory allocation to how much data we want to store in the
            // node + 32 MiB of "scratch" space
            Some(self.node_max_memory_size_bytes + 32 * 1024 * 1024),
        )
        .await
        .unwrap_err();
        self.nodes.push(node_canister_id);

        let node_index = self.last_node_index();

        let remaining_capacity: usize = dfn_core::call(
            node_canister_id,
            "remaining_capacity",
            dfn_candid::candid_one,
            (),
        )
        .await
        .unwrap();

        (node_canister_id, node_index, remaining_capacity)
    }

    /// Helper function to find the CanisterId of the node that can accept
    /// blocks, or create one, and find how many blocks can be accepted.
    async fn node_and_capacity(&mut self, needed: usize) -> (CanisterId, usize, usize) {
        let last_node_canister_id: Option<CanisterId> = self.nodes.last().copied();
        match last_node_canister_id {
            // Not a single archive node exists. Create one.
            None => {
                print("[archive] creating the first archive node");
                let (node_canister_id, node_index, remaining_capacity) =
                    self.create_and_initialize_node_canister().await;
                print(format!(
                    "[archive] node canister id: {}, index: {}",
                    node_canister_id, node_index
                ));

                (node_canister_id, node_index, remaining_capacity)
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
                    let (node_canister_id, node_index, remaining_capacity) =
                        self.create_and_initialize_node_canister().await;
                    print(format!(
                        "[archive] node canister id: {}, index: {}",
                        node_canister_id, node_index
                    ));
                    (node_canister_id, node_index, remaining_capacity)
                } else {
                    let node_index = self.last_node_index();
                    print(format!(
                        "[archive] reusing existing last node {} with index {} and capacity {}",
                        last_node_canister_id, node_index, remaining_capacity
                    ));
                    (last_node_canister_id, node_index, remaining_capacity)
                }
            }
        }
    }

    fn last_node_index(&self) -> usize {
        self.nodes.len() - 1
    }

    pub fn index(&self) -> Vec<((u64, u64), CanisterId)> {
        self.nodes_block_ranges
            .iter()
            .cloned()
            .zip(self.nodes.clone())
            .collect()
    }

    pub fn num_archived_blocks(&self) -> u64 {
        self.num_archived_blocks
    }
}

// Helper to print messages in green
fn print<S: std::convert::AsRef<str>>(s: S)
where
    yansi::Paint<S>: std::string::ToString,
{
    dfn_core::api::print(yansi::Paint::green(s).to_string());
}
