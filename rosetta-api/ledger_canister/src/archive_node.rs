use ledger_canister::{BlockHeight, BlockRes, EncodedBlock, GetBlocksArgs, IterBlocksArgs};

use dfn_protobuf::protobuf;
use std::sync::RwLock;

lazy_static::lazy_static! {
    // FIXME: use a single RwLock?
    pub static ref MAX_MEMORY_SIZE_BYTES: RwLock<usize> = RwLock::new(1024 * 1024 * 1024);
    pub static ref BLOCK_HEIGHT_OFFSET: RwLock<u64> = RwLock::new(0);
    pub static ref BLOCKS: RwLock<Vec<EncodedBlock>> = RwLock::new(Vec::new());
    pub static ref TOTAL_BLOCK_SIZE: RwLock<usize> = RwLock::new(0);
    pub static ref LEDGER_CANISTER_ID: RwLock<Option<ic_types::CanisterId>> = RwLock::new(None);
}

// Helper to print messages in cyan
fn print<S: std::convert::AsRef<str>>(s: S)
where
    yansi::Paint<S>: std::string::ToString,
{
    dfn_core::api::print(yansi::Paint::cyan(s).to_string());
}

// Append the Blocks to the internal Vec
fn append_blocks(mut blocks: Vec<EncodedBlock>) {
    assert_eq!(
        dfn_core::api::caller(),
        LEDGER_CANISTER_ID.read().unwrap().unwrap().get(),
        "Only Ledger canister is allowed to append blocks to an Archive Node"
    );
    let mut archive = BLOCKS.write().unwrap();
    print(format!(
        "[archive node] append_blocks(): archive size: {} blocks, appending {} blocks",
        archive.len(),
        blocks.len()
    ));
    // FIXME: race with other append_blocks calls?
    let mut total_block_size = *TOTAL_BLOCK_SIZE.read().unwrap();
    for block in &blocks {
        total_block_size += block.size_bytes();
    }
    assert!(
        total_block_size < *MAX_MEMORY_SIZE_BYTES.read().unwrap(),
        "No space left"
    );
    *TOTAL_BLOCK_SIZE.write().unwrap() = total_block_size;
    archive.append(&mut blocks);
    print(format!(
        "[archive node] append_blocks(): done. archive size: {} blocks",
        archive.len()
    ));
}

// Return the number of bytes the canister can still accommodate
fn remaining_capacity() -> usize {
    let total_block_size = *TOTAL_BLOCK_SIZE.read().unwrap();
    let max_memory_size_bytes = *MAX_MEMORY_SIZE_BYTES.read().unwrap();
    let remaining_capacity = max_memory_size_bytes.checked_sub(total_block_size).unwrap();
    print(format!(
        "[archive node] remaining_capacity: {} bytes",
        remaining_capacity
    ));
    remaining_capacity
}

fn init(
    archive_main_canister_id: ic_types::CanisterId,
    block_height_offset: u64,
    max_memory_size_bytes: Option<usize>,
) {
    *BLOCK_HEIGHT_OFFSET.write().unwrap() = block_height_offset;
    match max_memory_size_bytes {
        None => {
            print(format!(
                "[archive node] init(): using default maximum memory size: {} bytes and height offset {}",
                MAX_MEMORY_SIZE_BYTES.read().unwrap(),
                block_height_offset
            ));
        }
        Some(max_memory_size_bytes) => {
            *MAX_MEMORY_SIZE_BYTES.write().unwrap() = max_memory_size_bytes;
            *BLOCKS.write().unwrap() = Vec::new();
            print(format!(
                "[archive node] init(): using maximum memory size: {} bytes and height offset {}",
                max_memory_size_bytes, block_height_offset
            ));
        }
    }

    *LEDGER_CANISTER_ID.write().unwrap() = Some(archive_main_canister_id);
}

/// Get Block by BlockHeight. If the BlockHeight is outside the range stored in
/// this Node the result is None
fn get_block(block_height: BlockHeight) -> BlockRes {
    let adjusted_height = block_height - *BLOCK_HEIGHT_OFFSET.read().unwrap();
    let block: Option<EncodedBlock> = BLOCKS
        .read()
        .unwrap()
        .get(adjusted_height as usize)
        .cloned();
    // Will never return CanisterId like its counterpart in Ledger. Want to
    // keep the same signature though
    BlockRes(block.map(Ok))
}

#[export_name = "canister_query get_block_pb"]
fn get_block_() {
    dfn_core::over(protobuf, get_block);
}

#[export_name = "canister_init"]
fn main() {
    dfn_core::over_init(
        |dfn_candid::Candid((archive_canister_id, block_height_offset, opt_max_size))| {
            init(archive_canister_id, block_height_offset, opt_max_size)
        },
    )
}

#[export_name = "canister_update remaining_capacity"]
fn remaining_capacity_() {
    dfn_core::over(dfn_candid::candid, |()| remaining_capacity());
}

#[export_name = "canister_update append_blocks"]
fn append_blocks_() {
    dfn_core::over(dfn_candid::candid_one, append_blocks);
}

/// Get multiple blocks by *offset into the container* (not BlockHeight) and
/// length. Note that this simply iterates the blocks available in the this
/// particular archive node without taking into account the ledger or the
/// remainder of the archive. For example, if the node contains blocks with
/// heights [100, 199] then iter_blocks(0, 1) will return the block with height
/// 100.
#[export_name = "canister_query iter_blocks_pb"]
fn iter_blocks_() {
    dfn_core::over(protobuf, |IterBlocksArgs { start, length }| {
        let blocks = BLOCKS.read().unwrap();
        ledger_canister::iter_blocks(&blocks, start, length)
    });
}

/// Get multiple Blocks by BlockHeight and length. If the query is outside the
/// range stored in the Node the result is an error.
#[export_name = "canister_query get_blocks_pb"]
fn get_blocks_() {
    dfn_core::over(protobuf, |GetBlocksArgs { start, length }| {
        let blocks = BLOCKS.read().unwrap();
        let from_offset = *BLOCK_HEIGHT_OFFSET.read().unwrap();
        ledger_canister::get_blocks(&blocks, from_offset, start, length)
    });
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    dfn_core::over_init(|_: dfn_core::BytesS| {
        let bytes = dfn_core::stable::get();
        let mut blocks: Vec<EncodedBlock> =
            candid::decode_one(&bytes).expect("Decoding stable memory failed");
        let mut state = BLOCKS.write().unwrap();
        state.append(&mut blocks)
    })
}

#[export_name = "canister_pre_upgrade"]
fn pre_upgrade() {
    dfn_core::setup::START.call_once(|| {
        dfn_core::printer::hook();
    });

    let chain: &[EncodedBlock] = &BLOCKS
        .read()
        // This should never happen, but it's better to be safe than sorry
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let bytes = dfn_candid::encode_one(chain);
    match bytes {
        Ok(bs) => dfn_core::stable::set(&bs),
        // If candid fails for some reason we may be able to recover something
        // This is only going to work on small ledgers, because the encoding is not compact
        Err(e) => {
            let bs = format!("{} {:?}", e, chain);
            dfn_core::stable::set(bs.as_bytes());
        }
    };
}
