use ledger_canister::RawBlock;

use std::sync::RwLock;

lazy_static::lazy_static! {
    // FIXME: use a single RwLock?
    pub static ref MAX_MEMORY_SIZE_BYTES: RwLock<usize> = RwLock::new(256);
    pub static ref BLOCKS: RwLock<Vec<RawBlock>> = RwLock::new(Vec::new());
    pub static ref TOTAL_BLOCK_SIZE: RwLock<usize> = RwLock::new(0);
}

// Helper to print messages in cyan
fn print<S: std::convert::AsRef<str>>(s: S)
where
    yansi::Paint<S>: std::string::ToString,
{
    dfn_core::api::print(yansi::Paint::cyan(s).to_string());
}

// Append the Blocks to the internal Vec
fn append_blocks(mut blocks: Vec<RawBlock>) {
    let mut archive = BLOCKS.write().unwrap();
    print(format!(
        "[archive node] append_blocks(): capacity: {}, archive size: {}, appending {} blocks",
        archive.capacity(),
        archive.len(),
        blocks.len()
    ));
    // FIXME: race with other append_blocks calls?
    let mut total_block_size = *TOTAL_BLOCK_SIZE.read().unwrap();
    for block in &blocks {
        total_block_size += block.len();
    }
    assert!(total_block_size < *MAX_MEMORY_SIZE_BYTES.read().unwrap());
    *TOTAL_BLOCK_SIZE.write().unwrap() = total_block_size;
    archive.append(&mut blocks);
    print(format!(
        "[archive node] append_blocks(): done. archive size: {}",
        archive.len()
    ));
}

// Return all Blocks
fn get_blocks(offset: usize, length: usize) -> Vec<RawBlock> {
    let blocks = BLOCKS.read().unwrap();
    let start = std::cmp::min(offset, blocks.len());
    let end = std::cmp::min(start + length, blocks.len());
    let blocks = BLOCKS.read().unwrap()[start..end].to_vec();
    print(format!(
        "[archive node] get_blocks(offset={}, length={}): returning {} blocks",
        offset,
        length,
        blocks.len()
    ));
    blocks
}

// Return the number of bytes the canister can still accommodate
fn remaining_capacity() -> usize {
    let total_block_size = *TOTAL_BLOCK_SIZE.read().unwrap();
    let max_memory_size_bytes = *MAX_MEMORY_SIZE_BYTES.read().unwrap();
    let remaining_capacity = max_memory_size_bytes.checked_sub(total_block_size).unwrap();
    print(format!(
        "[archive node] remaining_capacity: {}",
        remaining_capacity
    ));
    remaining_capacity
}

fn init(max_memory_size_bytes: Option<usize>) {
    match max_memory_size_bytes {
        None => {
            print(format!(
                "[archive node] init(): using default maximum memory size: {}. default archive capacity: {} blocks",
                MAX_MEMORY_SIZE_BYTES.read().unwrap(),
                BLOCKS.read().unwrap().capacity()
            ));
        }
        Some(max_memory_size_bytes) => {
            *MAX_MEMORY_SIZE_BYTES.write().unwrap() = max_memory_size_bytes;
            *BLOCKS.write().unwrap() = Vec::new();
            print(format!(
                "[archive node] init(): using maximum memory size: {}, archive capacity: {} blocks",
                max_memory_size_bytes,
                BLOCKS.read().unwrap().capacity()
            ));
        }
    }
}

#[export_name = "canister_init"]
fn main() {
    dfn_core::over_init(|dfn_candid::Candid((opt_max_size,))| init(opt_max_size))
}

#[export_name = "canister_update remaining_capacity"]
fn remaining_capacity_() {
    dfn_core::over(dfn_candid::candid, |()| remaining_capacity());
}

#[export_name = "canister_update append_blocks"]
fn append_blocks_() {
    dfn_core::over(dfn_candid::candid_one, append_blocks);
}

#[export_name = "canister_query get_blocks"]
fn get_blocks_() {
    dfn_core::over(dfn_candid::candid, |(offset, len)| get_blocks(offset, len));
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    dfn_core::over_init(|_: dfn_core::BytesS| {
        let bytes = dfn_core::stable::get();
        let mut blocks: Vec<RawBlock> =
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

    let chain: &[RawBlock] = &BLOCKS
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
