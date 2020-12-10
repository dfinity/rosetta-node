pub mod error;
mod slot_mgr;

use crate::PAGE_SIZE;
use libc::{
    c_void, mmap, mprotect, munmap, MAP_FAILED, MAP_FIXED, MAP_NORESERVE, MAP_PRIVATE, MAP_SHARED,
    PROT_NONE, PROT_READ, PROT_WRITE,
};

#[cfg(target_os = "linux")]
use libc::MAP_ANON;

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    fs::{File, OpenOptions},
    io::Error,
    marker::PhantomData,
    os::unix::io::AsRawFd,
    path::PathBuf,
    ptr,
    sync::{Arc, RwLock},
};

use crate::cow_state::{error::*, slot_mgr::*};
use enum_dispatch::*;
use ic_utils::ic_features::*;
use num_integer::*;

//Note: Following arrangement is temporary
const META_OFFSET: u64 = 0; // 0th page for metadata
const META_LEN: usize = 1; // 1 page size for metadata

const GLOBALS_OFFSET: u64 = META_LEN as u64; // first page
const GLOBALS_LEN: usize = 1; // 1 page size for globals

const HEAP_OFFSET: u64 = GLOBALS_OFFSET as u64 + GLOBALS_LEN as u64;
const HEAP_LEN: usize = 1024 * 1024; // 1Million pages ~ 4GB

const STATE_MAGIC: u64 = 0x0044_4649_4e49_5459; // DFINITY in hex

pub trait AccessPolicy {}
pub trait ReadOnlyPolicy: AccessPolicy {}
pub trait ReadWritePolicy: AccessPolicy {}
#[derive(Clone)]
pub enum ReadOnly {}
#[derive(Clone)]
pub enum ReadWrite {}

impl AccessPolicy for ReadOnly {}
impl ReadOnlyPolicy for ReadOnly {}

impl AccessPolicy for ReadWrite {}
impl ReadWritePolicy for ReadWrite {}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct StateMeta {
    magic: u64,
    meta_offset: u64,
    meta_len: usize,
    globals_offset: u64,
    globals_len: usize,
    heap_offset: u64,
    heap_len: usize,
}

impl Default for StateMeta {
    fn default() -> Self {
        Self {
            magic: 0,
            meta_offset: 0,
            meta_len: 0,
            globals_offset: 0,
            globals_len: 0,
            heap_offset: 0,
            heap_len: 0,
        }
    }
}

#[enum_dispatch]
pub trait MappedState {
    /// Returns the base of memory region where canister
    /// heap begins.
    fn get_heap_base(&self) -> *mut u8;

    /// Returns the max heap len when the heap
    /// was first initialized.
    fn get_heap_len(&self) -> usize;

    /// Resets the permission on the heap
    /// based on the type
    fn make_heap_accessible(&self);

    /// Returns slice of globals memory associated
    /// with this mapped_state.
    fn get_globals(&self) -> &[u8];

    /// Update the globals memory with new globals.
    fn update_globals(&self, _encoded_globals: &[u8]) {
        unimplemented!("Updates of globals is not supported for readonly CowMemoryManager");
    }

    /// soft_commit ensures that all modified pages (mutations) represented by
    /// pages slice become part of the "current" state. This
    /// means even after MappedState object is dropped, mutations will be
    /// reflected in subsequent MappedState object and can eventually become
    /// part of some round. Mutations not soft_committed have a lifetime of
    /// MappedState object and will disappear once MappedState object is
    /// dropped.
    fn soft_commit(&self, _pages: &[u64]) {
        unimplemented!("Soft-committing not supported for readonly CowMemoryManager");
    }

    /// Using update_heap_page, individual heap pages can be modified. This is
    /// useful during canister installation to patch up initial pages.
    /// Once the heap is modified, soft_commit is necessary to ensure that the
    /// modifications become part of "current" state.
    fn update_heap_page(&self, _page_idx: u64, _bytes: &[u8]) {
        unimplemented!("Heap updates not supported for readonly CowMemoryManager");
    }

    fn copy_to_heap(&self, _offset: u64, _bytes: &[u8]) -> Vec<u64> {
        unimplemented!("Heap updates not supported for readonly CowMemoryManager");
    }

    fn copy_from_heap(&self, _offset: u64, _len: u64) -> &[u8];

    fn clear(&self) {
        unimplemented!("Heap reset not supported for readonly CowMemoryManager");
    }
}

#[enum_dispatch(MappedState)]
enum MappedStates {
    ReadOnly(MappedStateCommon<ReadOnly>),
    ReadWrite(MappedStateCommon<ReadWrite>),
}

impl MappedStates {
    fn unmap(&mut self) {
        match self {
            Self::ReadOnly(mapped_state) => mapped_state.unmap(),
            Self::ReadWrite(mapped_state) => mapped_state.unmap(),
        }
    }
}

struct MapInfo {
    mapped_base: u64,
    mapped_len: usize,
    file: File,
    slot_mgr: Arc<SlotMgr>,
    current_mappings: BTreeMap<u64, u64>,
}

struct MappedStateCommon<T> {
    mapped_base: u64,
    mapped_len: usize,
    meta: StateMeta,
    file: File,
    slot_mgr: Arc<SlotMgr>,
    current_mappings: BTreeMap<u64, u64>,
    _marker: PhantomData<T>,
}

pub struct MappedStateImpl {
    mapped_state: MappedStates,
}

impl<T: AccessPolicy> MappedStateCommon<T> {
    fn get_mapped_base(&self) -> *mut u8 {
        self.mapped_base as *mut u8
    }

    fn get_heap_base(&self) -> *mut u8 {
        unsafe {
            self.get_mapped_base()
                .add(self.meta.heap_offset as usize * *PAGE_SIZE)
        }
    }

    fn get_heap_len(&self) -> usize {
        if let Some(max_key) = self.current_mappings.keys().max() {
            (max_key - HEAP_OFFSET + 1) as usize * *PAGE_SIZE
        } else {
            0
        }
    }

    fn get_globals_base(&self) -> *mut u8 {
        unsafe {
            self.get_mapped_base()
                .add(self.meta.globals_offset as usize * *PAGE_SIZE)
        }
    }

    fn get_globals_len(&self) -> usize {
        self.meta.globals_len * *PAGE_SIZE
    }

    fn get_globals(&self) -> &[u8] {
        unsafe {
            let globals_base = self.get_globals_base();
            reset_mem_protection(globals_base, self.get_globals_len(), PROT_READ | PROT_WRITE);
            std::slice::from_raw_parts(self.get_globals_base() as *const u8, self.get_globals_len())
        }
    }

    fn unmap(&mut self) {
        if self.mapped_len > 0 {
            unsafe {
                let rc = munmap(self.mapped_base as *mut c_void, self.mapped_len);
                assert_eq!(rc, 0, "munmap failed: {}", Error::last_os_error());
            }
            self.mapped_len = 0;
        }
    }

    fn soft_commit(&self, pages: &[u64]) {
        let mut mappings_to_put = HashMap::new();

        let raw_fd = self.file.as_raw_fd();

        #[cfg(target_os = "linux")]
        let (rpipe, wpipe) = nix::unistd::pipe().unwrap();

        #[cfg(target_os = "linux")]
        // Max 1MB pipe size
        nix::fcntl::fcntl(wpipe, nix::fcntl::FcntlArg::F_SETPIPE_SZ(1024 * 1024))
            .expect("Unable to set pipe size");

        // allocate all slots in 1 go to minimize transactions
        let mut allocated_slots = self.slot_mgr.alloc_free_slots(pages.len() as u32);
        for page_num in pages.iter() {
            let heap_page = page_num;
            let offset = *heap_page as usize * *PAGE_SIZE;

            let existing_pba = *self
                .current_mappings
                .get(&heap_page)
                .unwrap_or(&INVALID_SLOT);

            let is_shared = SlotMgr::is_shared(existing_pba);

            let slot_to_use = if is_shared {
                allocated_slots.remove(0)
            } else {
                SlotMgr::get_slot(existing_pba)
            };

            // println!("Using slot:{} is new {} {}", slot_to_use, is_shared, *page_num);

            // dont overwrite physical metapage
            let what_to_map = (slot_to_use + self.meta.meta_len as u64) * *PAGE_SIZE as u64;

            #[cfg(target_os = "linux")]
            // On linux copying of memory to files can be accomplished using splicing.
            // It is very efficient approach and avoids user/kernel & kernel/kernel copy overheads.
            // Instead of copying page contents, splicing presents opportunity to kernel
            // to "move" pages using refcounting and other accounting magic.

            // Here by "gifting" the pages we are letting kernel know that we no longer
            // want to own the "private pages". Kernel simply "moves" them into page cache
            // making the dirty data part of the heap file without paying copy penalty.

            // https://en.wikipedia.org/wiki/Splice_(system_call)
            // https://web.archive.org/web/20130521163124/http://kerneltrap.org/node/6505
            unsafe {
                let vec = nix::sys::uio::IoVec::from_slice(&::std::slice::from_raw_parts(
                    self.get_mapped_base().add(offset),
                    *PAGE_SIZE,
                ));

                nix::fcntl::vmsplice(wpipe, &[vec], nix::fcntl::SpliceFFlags::SPLICE_F_GIFT)
                    .expect("Unable to vmsplice");
                nix::fcntl::splice(
                    rpipe,
                    None,
                    raw_fd,
                    Some(&mut (what_to_map as i64)),
                    *PAGE_SIZE,
                    nix::fcntl::SpliceFFlags::SPLICE_F_MOVE,
                )
                .expect("splice failed");
            }

            #[cfg(not(target_os = "linux"))]
            unsafe {
                let dst = mmap(
                    ptr::null_mut(),
                    *PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED,
                    raw_fd,
                    what_to_map as i64,
                );
                if dst == MAP_FAILED {
                    panic!("mmap failed: {}", Error::last_os_error());
                }

                let src = self.get_mapped_base().add(offset);
                ptr::copy_nonoverlapping(src as *mut c_void, dst as *mut c_void, *PAGE_SIZE);

                munmap(dst, *PAGE_SIZE);
            }

            if is_shared {
                mappings_to_put.insert(*heap_page, (slot_to_use, existing_pba));
            }
        }

        #[cfg(target_os = "linux")]
        {
            let _ = nix::unistd::close(rpipe);
            let _ = nix::unistd::close(wpipe);
        }

        // free slots that we didnt use
        self.slot_mgr.free_unused_slots(allocated_slots);

        // put all mappings in one go
        self.slot_mgr.put_all_mappings(mappings_to_put);
    }

    fn copy_from_heap(&self, offset: u64, len: u64) -> &[u8] {
        // FixME: add validations here
        unsafe {
            let base = self.get_heap_base().add(offset as usize);
            reset_mem_protection(base, len as usize, PROT_READ);
            std::slice::from_raw_parts(base as *const u8, len as usize)
        }
    }
}

impl MappedState for MappedStateCommon<ReadOnly> {
    fn get_heap_base(&self) -> *mut u8 {
        self.get_heap_base()
    }

    fn get_heap_len(&self) -> usize {
        self.get_heap_len()
    }

    fn make_heap_accessible(&self) {
        reset_mem_protection(self.get_heap_base(), self.get_heap_len(), PROT_READ);
    }

    fn get_globals(&self) -> &[u8] {
        self.get_globals()
    }

    fn copy_from_heap(&self, offset: u64, len: u64) -> &[u8] {
        self.copy_from_heap(offset, len)
    }
}

impl MappedState for MappedStateCommon<ReadWrite> {
    fn get_heap_base(&self) -> *mut u8 {
        self.get_heap_base()
    }

    fn get_heap_len(&self) -> usize {
        self.get_heap_len()
    }

    fn make_heap_accessible(&self) {
        reset_mem_protection(
            self.get_heap_base(),
            self.get_heap_len(),
            PROT_READ | PROT_WRITE,
        );
    }

    fn get_globals(&self) -> &[u8] {
        self.get_globals()
    }

    fn update_globals(&self, encoded_globals: &[u8]) {
        if encoded_globals.len() > self.get_globals_len() {
            panic!("globals too big, cannot be persisted");
        }

        unsafe {
            let dst = self.get_globals_base();
            reset_mem_protection(dst, encoded_globals.len(), PROT_READ | PROT_WRITE);
            std::ptr::copy_nonoverlapping(encoded_globals.as_ptr(), dst, encoded_globals.len());
        }
        self.soft_commit(&[self.meta.globals_offset]);
    }

    fn soft_commit(&self, pages: &[u64]) {
        let heap_pages: Vec<u64> = pages
            .iter()
            .map(|page| page + self.meta.heap_offset)
            .collect();
        self.soft_commit(&heap_pages)
    }

    fn copy_to_heap(&self, offset: u64, bytes: &[u8]) -> Vec<u64> {
        let len_to_copy = bytes.len();
        let heap_base = self.get_heap_base() as u64;
        let copy_base = heap_base + offset;
        let page_size = *PAGE_SIZE as u64;

        // find the aligned base address to reset the permissions from
        let aligned_base = (copy_base).prev_multiple_of(&page_size);
        let total_len = (copy_base + len_to_copy as u64) - aligned_base;

        reset_mem_protection(
            aligned_base as *mut u8,
            total_len as usize,
            PROT_READ | PROT_WRITE,
        );

        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), copy_base as *mut u8, len_to_copy) }

        let start_page = (aligned_base - heap_base) / page_size;
        let nr_pages = (total_len).div_ceil(&page_size);

        (0..nr_pages).map(|p| p + start_page).collect()
    }

    fn update_heap_page(&self, page_idx: u64, bytes: &[u8]) {
        let offset = page_idx as usize * *PAGE_SIZE;
        assert!(bytes.len().is_multiple_of(&PAGE_SIZE));
        unsafe {
            let dst = self.get_heap_base().add(offset);
            reset_mem_protection(dst, *PAGE_SIZE, PROT_READ | PROT_WRITE);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, *PAGE_SIZE);
        };
    }

    fn copy_from_heap(&self, offset: u64, len: u64) -> &[u8] {
        self.copy_from_heap(offset, len)
    }

    fn clear(&self) {
        self.slot_mgr.clear_current();
    }
}

impl MappedState for MappedStateImpl {
    fn get_heap_base(&self) -> *mut u8 {
        self.mapped_state.get_heap_base()
    }

    fn get_heap_len(&self) -> usize {
        self.mapped_state.get_heap_len()
    }

    fn make_heap_accessible(&self) {
        self.mapped_state.make_heap_accessible();
    }

    fn get_globals(&self) -> &[u8] {
        self.mapped_state.get_globals()
    }

    fn update_globals(&self, encoded_globals: &[u8]) {
        self.mapped_state.update_globals(encoded_globals);
    }

    fn soft_commit(&self, pages: &[u64]) {
        self.mapped_state.soft_commit(pages);
    }

    fn update_heap_page(&self, page_idx: u64, bytes: &[u8]) {
        self.mapped_state.update_heap_page(page_idx, bytes);
    }

    fn copy_to_heap(&self, offset: u64, bytes: &[u8]) -> Vec<u64> {
        self.mapped_state.copy_to_heap(offset, bytes)
    }

    fn copy_from_heap(&self, offset: u64, len: u64) -> &[u8] {
        self.mapped_state.copy_from_heap(offset, len)
    }

    fn clear(&self) {
        self.mapped_state.clear()
    }
}

impl Drop for MappedStateImpl {
    fn drop(&mut self) {
        self.mapped_state.unmap();
    }
}

#[enum_dispatch]
pub trait CowMemoryManager {
    /// get_map returns a MappedState representing "current" mapped state
    /// of the canister (heap and globals for time being). This state can be
    /// used for example during canister execution and can be freely mutated.
    /// "current_state" can be updated with mutations by calling "soft_commmit".
    fn get_map(&self) -> MappedStateImpl {
        unimplemented!("Get current map is not supported on ReadOnly CowMemoryManager");
    }

    /// get_map_for_snapshot returns a MappedState representing in memory mapped
    /// state of canister (heap and globals for time being) at the end of a
    /// specific round. This state, although can be freely mutated, the
    /// mutations cannot be made part round state using "soft_commit".
    /// MappedState returned by get_map_for_snapshot can be used for query type
    /// canister operations.
    fn get_map_for_snapshot(&self, _round_to_use: u64) -> Result<MappedStateImpl, CowError>;

    /// create_snapshot creates a snapshot of all soft_committed mutations to
    /// canister state the last snapshot
    fn create_snapshot(&self, _end_round: u64) {
        unimplemented!("create_snapshot is not supported on ReadOnly CowMemoryManager");
    }

    /// checkpoint primarily ensures slot_mgr's internal metadata is flushed to
    /// disk Collapsing older rounds would be added here later.
    fn checkpoint(&self) {
        unimplemented!("Checkpointing is not supported on ReadOnly CowMemoryManager");
    }

    /// Reset's canister's "current" state to "vanilla" initial state.
    fn upgrade(&self) {
        unimplemented!("Upgrade is not supported on ReadOnly CowMemoryManager");
    }
}

fn reset_mem_protection(base: *mut u8, len: usize, new_permissions: libc::c_int) {
    unsafe {
        let page_size = *PAGE_SIZE as u64;

        // find the aligned base address to reset the permissions from
        let aligned_base = (base as u64).prev_multiple_of(&page_size);
        let total_len = (base as u64 + len as u64) - aligned_base;

        let result = mprotect(
            aligned_base as *mut c_void,
            total_len as usize,
            new_permissions,
        );

        assert_eq!(
            result,
            0,
            "mprotect failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[enum_dispatch(CowMemoryManager)]
#[derive(Clone, Debug)]
pub enum CowMemoryManagerImpl {
    ReadOnly(CowMemoryManagerCommon<ReadOnly>),
    ReadWrite(CowMemoryManagerCommon<ReadWrite>),
}

impl CowMemoryManagerImpl {
    pub fn open_readonly(state_root: PathBuf) -> Self {
        if cow_state_feature::is_enabled(cow_state_feature::cow_state) {
            Self::ReadOnly(CowMemoryManagerCommon::<ReadOnly>::open(state_root))
        } else {
            Self::ReadOnly(CowMemoryManagerCommon::<ReadOnly>::open_fake())
        }
    }

    pub fn open_readwrite(state_root: PathBuf) -> Self {
        if cow_state_feature::is_enabled(cow_state_feature::cow_state) {
            Self::ReadWrite(CowMemoryManagerCommon::<ReadWrite>::open(state_root))
        } else {
            Self::ReadWrite(CowMemoryManagerCommon::<ReadWrite>::open_fake())
        }
    }

    pub fn open_readwrite_fake() -> Self {
        Self::ReadWrite(CowMemoryManagerCommon::<ReadWrite>::open_fake())
    }
}

#[derive(Clone)]
pub struct CowMemoryManagerCommon<T> {
    state_root: PathBuf,
    meta: StateMeta,
    slot_mgr: Arc<RwLock<Option<Arc<SlotMgr>>>>,
    _marker: PhantomData<T>,
}

impl CowMemoryManagerCommon<ReadOnly> {
    fn validate(state_file: File) -> StateMeta {
        unsafe {
            // map just the header portion
            let raw_fd = state_file.as_raw_fd();
            let header_base = mmap(
                ptr::null_mut(),
                *PAGE_SIZE,
                PROT_READ,
                MAP_SHARED,
                raw_fd,
                0,
            );
            if header_base == MAP_FAILED {
                panic!("mmap failed: {}", Error::last_os_error());
            }
            let sm = std::ptr::read(header_base as *mut StateMeta);

            assert_eq!(sm.magic, STATE_MAGIC);
            munmap(header_base, *PAGE_SIZE);
            sm
        }
    }

    fn open_state_file(state_root: &PathBuf) -> File {
        let mut state_file = state_root.clone();
        state_file.push("state_file");
        assert!(
            state_file.exists(),
            format!("state_file should exists {:?}", state_file)
        );

        OpenOptions::new()
            .read(true)
            .open(state_file)
            .expect("failed to open file")
    }

    pub fn open_fake() -> Self {
        Self {
            state_root: "NOT_USED".into(),
            meta: StateMeta::default(),
            slot_mgr: Arc::new(RwLock::new(None)),
            _marker: PhantomData::<ReadOnly>,
        }
    }

    pub fn open(state_root: PathBuf) -> Self {
        let state_file = Self::open_state_file(&state_root);

        let mapping_db = state_root.join("slot_db");
        assert!(mapping_db.exists(), "mapping db path should exists");

        let meta = Self::validate(state_file);
        Self {
            state_root,
            meta,
            slot_mgr: Arc::new(RwLock::new(None)),
            _marker: PhantomData::<ReadOnly>,
        }
    }
}

impl CowMemoryManagerCommon<ReadWrite> {
    fn validate(state_file: File) -> StateMeta {
        unsafe {
            // map just the header portion
            let raw_fd = state_file.as_raw_fd();
            let header_base = mmap(
                ptr::null_mut(),
                *PAGE_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                raw_fd,
                0,
            );

            if header_base == MAP_FAILED {
                panic!("mmap failed: {}", Error::last_os_error());
            }

            let mut sm = std::ptr::read(header_base as *mut StateMeta);

            if sm.magic != STATE_MAGIC {
                sm.magic = STATE_MAGIC;

                sm.meta_offset = META_OFFSET;
                sm.meta_len = META_LEN;

                sm.globals_offset = GLOBALS_OFFSET;
                sm.globals_len = GLOBALS_LEN;

                sm.heap_offset = HEAP_OFFSET;
                sm.heap_len = HEAP_LEN;

                std::ptr::write(header_base as *mut StateMeta, sm);
            }

            munmap(header_base, *PAGE_SIZE);
            sm
        }
    }

    fn open_state_file(state_root: &PathBuf) -> File {
        let mut state_file = state_root.clone();

        state_file.push("state_file");
        let file_exists = state_file.exists();

        if !file_exists {
            let parent = state_file.parent().unwrap();
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("failed to create path {:?}, {}", parent, e));
        }

        let file = OpenOptions::new()
            .create(!file_exists)
            .read(true)
            .write(true)
            .open(state_file.clone())
            .unwrap_or_else(|e| panic!("failed to open file {:?}, {}", state_file, e));

        if !file_exists {
            // Grow the file to 8G initially
            file.set_len(8 * 1024 * 1024 * 1024)
                .expect("failed to grow state file to 8GiB size");
        }
        file
    }

    pub fn open_fake() -> Self {
        Self {
            state_root: "NOT_USED".into(),
            meta: StateMeta::default(),
            slot_mgr: Arc::new(RwLock::new(None)),
            _marker: PhantomData::<ReadWrite>,
        }
    }

    pub fn open(state_root: PathBuf) -> Self {
        let state_file = Self::open_state_file(&state_root);
        let mapping_db = state_root.join("slot_db");
        if !mapping_db.exists() {
            std::fs::create_dir_all(mapping_db.as_path()).expect("unable to create db directory");
        }

        let meta = Self::validate(state_file);
        Self {
            state_root,
            meta,
            slot_mgr: Arc::new(RwLock::new(None)),
            _marker: PhantomData::<ReadWrite>,
        }
    }
}

impl std::fmt::Debug for CowMemoryManagerCommon<ReadOnly> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CowMemoryManager<ReadOnly>::state_root {:?}",
            self.state_root
        )
    }
}

impl std::fmt::Debug for CowMemoryManagerCommon<ReadWrite> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CowMemoryManager<ReadWrite>::state_root {:?}",
            self.state_root
        )
    }
}

impl<T: AccessPolicy> CowMemoryManagerCommon<T> {
    fn get_contiguous(&self, mappings: &BTreeMap<u64, u64>) -> BTreeMap<u64, (u64, u64)> {
        let mut contig_mappings = BTreeMap::new();

        let mut start_logical = INVALID_SLOT;
        let mut start_physical = INVALID_SLOT;
        let mut map_len = 0;

        for (logical_slot, physical_slot) in mappings {
            if start_logical == INVALID_SLOT {
                start_logical = *logical_slot;
                start_physical = *physical_slot;
                map_len = 1;
            } else if *logical_slot == start_logical + map_len
                && *physical_slot == start_physical + map_len
            {
                map_len += 1;
            } else {
                contig_mappings.insert(start_logical, (start_physical, map_len));
                start_logical = *logical_slot;
                start_physical = *physical_slot;
                map_len = 1;
            }
        }

        if map_len > 0 {
            contig_mappings.insert(start_logical, (start_physical, map_len));
        }

        contig_mappings
    }

    fn get_slot_mgr(&self) -> Arc<SlotMgr> {
        // We open slot managers lazily intentionally.
        // This is efficient as for inactive canisters and
        // inactive canister states (loaded_older_checkpoints) we
        // dont need to have slot_mgr/lmdb handles open unless required.
        // For active canisters/states they are opened once and remain open
        // as those handles are created against the "tip" state
        let slot_mgr_guard = self.slot_mgr.read().unwrap();
        let slot_mgr_guard = if slot_mgr_guard.is_none() {
            // drop the read lock
            drop(slot_mgr_guard);

            let state_root = self.state_root.clone();
            let mapping_db = state_root.join("slot_db");

            // grab the write lock, we dont need to re check for none again
            let mut slot_mgr_rw = self.slot_mgr.write().unwrap();
            let slot_mgr = Arc::new(SlotMgr::new(mapping_db.as_path(), HEAP_LEN as u64));
            *slot_mgr_rw = Some(slot_mgr);

            // drop the write lock
            drop(slot_mgr_rw);

            self.slot_mgr.read().unwrap()
        } else {
            slot_mgr_guard
        };

        slot_mgr_guard.as_ref().unwrap().clone()
    }

    fn create_map(&self, state_file: File, round_to_use: Option<u64>) -> Result<MapInfo, CowError> {
        unsafe {
            assert_eq!(self.meta.magic, STATE_MAGIC);
        }

        let slot_mgr = self.get_slot_mgr();

        let current_mappings = match round_to_use {
            None => slot_mgr.get_current_round_mappings(),
            Some(round) => {
                // see if the round exists, else we will return
                // the current mappings
                let mut completed_rounds = slot_mgr.get_completed_rounds();
                completed_rounds.sort();
                let max_round = completed_rounds.pop();
                if max_round.is_some() && max_round.unwrap() <= round {
                    slot_mgr.get_mappings_for_round(round)?
                } else {
                    slot_mgr.get_current_round_mappings()
                }
            }
        };

        let state_raw_fd = state_file.as_raw_fd();

        let total_size =
            (self.meta.meta_len + self.meta.globals_len + self.meta.heap_len) * *PAGE_SIZE;

        // embedders make only required amount of memory accessible
        // to canisters during execution along with wasmtime.
        // Setting PROT_NONE ensures rest remains inaccessible.
        #[cfg(target_os = "macos")]
        let mapped_base = unsafe {
            mmap(
                ptr::null_mut(),
                total_size as usize,
                PROT_NONE,
                MAP_PRIVATE,
                state_raw_fd,
                0,
            )
        };

        #[cfg(not(target_os = "macos"))]
        let mapped_base = unsafe {
            mmap(
                ptr::null_mut(),
                total_size as usize,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };

        if mapped_base == MAP_FAILED {
            panic!("mmap failed: {}", Error::last_os_error());
        }

        let mapped_base = mapped_base as *mut u8;

        let contig = self.get_contiguous(&current_mappings);

        // overlay individual pieces
        for (logical_slot, (physical_slot, map_len)) in contig {
            unsafe {
                let where_to_map = mapped_base.add(logical_slot as usize * *PAGE_SIZE);
                let what_to_map = (SlotMgr::get_slot(physical_slot) + self.meta.meta_len as u64)
                    * *PAGE_SIZE as u64;

                let overlay_mem = mmap(
                    where_to_map as *mut c_void,
                    map_len as usize * *PAGE_SIZE,
                    PROT_NONE,
                    MAP_PRIVATE | MAP_NORESERVE | MAP_FIXED,
                    state_raw_fd,
                    what_to_map as i64,
                );

                if overlay_mem == MAP_FAILED {
                    panic!("mmap failed: {}", Error::last_os_error());
                }
                assert_eq!(overlay_mem as u64, where_to_map as u64);
            }
        }

        Ok(MapInfo {
            mapped_base: mapped_base as u64,
            mapped_len: total_size,
            file: state_file,
            slot_mgr,
            current_mappings,
        })
    }

    fn get_map_for_snapshot(
        &self,
        file: File,
        round_to_use: u64,
    ) -> Result<MappedStateImpl, CowError> {
        let MapInfo {
            mapped_base,
            mapped_len,
            file,
            slot_mgr,
            current_mappings,
        } = self.create_map(file, Some(round_to_use))?;

        let internal = MappedStateCommon::<ReadOnly> {
            mapped_base,
            mapped_len,
            meta: self.meta,
            file,
            slot_mgr,
            current_mappings,
            _marker: PhantomData::<ReadOnly>,
        };

        Ok(MappedStateImpl {
            mapped_state: MappedStates::ReadOnly(internal),
        })
    }
}

impl CowMemoryManager for CowMemoryManagerCommon<ReadOnly> {
    fn get_map_for_snapshot(&self, round_to_use: u64) -> Result<MappedStateImpl, CowError> {
        let file = Self::open_state_file(&self.state_root);
        let mapped_state = self.get_map_for_snapshot(file, round_to_use);

        // we drop the slot manager handle here
        // This ensures that once mapped state
        // is dropped, its corresponding
        // slot mgr handle is also dropped
        self.slot_mgr.write().unwrap().take();
        mapped_state
    }

    fn get_map(&self) -> MappedStateImpl {
        let file = Self::open_state_file(&self.state_root);
        let MapInfo {
            mapped_base,
            mapped_len,
            file,
            slot_mgr,
            current_mappings,
        } = self.create_map(file, None).unwrap();

        let internal = MappedStateCommon::<ReadOnly> {
            mapped_base,
            mapped_len,
            meta: self.meta,
            file,
            slot_mgr,
            current_mappings,
            _marker: PhantomData::<ReadOnly>,
        };

        // we drop the slot manager handle here
        // This ensures that once mapped state
        // is dropped, its corresponding
        // slot mgr handle is also dropped
        self.slot_mgr.write().unwrap().take();

        MappedStateImpl {
            mapped_state: MappedStates::ReadOnly(internal),
        }
    }
}

impl CowMemoryManager for CowMemoryManagerCommon<ReadWrite> {
    fn get_map(&self) -> MappedStateImpl {
        let file = Self::open_state_file(&self.state_root);
        let MapInfo {
            mapped_base,
            mapped_len,
            file,
            slot_mgr,
            current_mappings,
        } = self.create_map(file, None).unwrap();

        let internal = MappedStateCommon::<ReadWrite> {
            mapped_base,
            mapped_len,
            meta: self.meta,
            file,
            slot_mgr,
            current_mappings,
            _marker: PhantomData::<ReadWrite>,
        };

        MappedStateImpl {
            mapped_state: MappedStates::ReadWrite(internal),
        }
    }

    fn get_map_for_snapshot(&self, round_to_use: u64) -> Result<MappedStateImpl, CowError> {
        let file = Self::open_state_file(&self.state_root);
        self.get_map_for_snapshot(file, round_to_use)
    }

    fn create_snapshot(&self, round: u64) {
        let slot_mgr_ro = self.slot_mgr.read().unwrap();
        if slot_mgr_ro.is_some() {
            slot_mgr_ro.as_ref().unwrap().end_round(round);
        } else {
            drop(slot_mgr_ro);
            let slot_mgr = self.get_slot_mgr();
            slot_mgr.as_ref().end_round(round);
        }
    }

    fn checkpoint(&self) {
        let mut slot_mgr_rw = self.slot_mgr.write().unwrap();
        if slot_mgr_rw.is_some() {
            slot_mgr_rw.as_ref().unwrap().checkpoint();
            // we drop the slot managers at the end
            // of checkpoint so if the canisters
            // become inactive there wont be any open
            // lmdb handles
            *slot_mgr_rw = None;
        }
    }

    fn upgrade(&self) {
        if cow_state_feature::is_enabled(cow_state_feature::cow_state) {
            let mapped_state = self.get_map();
            mapped_state.clear();
        }
    }
}
impl fmt::Debug for MappedStateImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let is_readonly = match self.mapped_state {
            MappedStates::ReadOnly(_) => true,
            MappedStates::ReadWrite(_) => false,
        };
        write!(
            f,
            "is_readonly {} base {:?}",
            is_readonly,
            self.get_heap_base()
        )
    }
}
