/// Slot manager is a "persistent" generic implementation to manage free
/// regions, allocations, mappings, snapshots and checkpointing for any
/// arbitrary object which can be viewed as a collection of slots.
/// A slot can be anything for example a block within a file, index in an array,
/// pages within memory region where the object is file, array and memory
/// respectively.
///
/// Internally slot manager keeps track of unused slots and provides allocator
/// to allocate them. It also provides mechanism to persist arbitrary mappings
/// between slots and any u64 number. Mappings can be used, for example, to
/// implement a virtual addressing where discontiguous slots can be a part of
/// contiguous virtual address range.
///
/// Lastly slot manager also supports rounds (snapshots) for mapping with
/// sharing of slots between multiple rounds. Also multiple rounds can be folded
/// into a single checkpoint freeing all overwritten slots.   
use lmdb::{Cursor, DatabaseFlags, EnvironmentFlags, Transaction, WriteFlags};
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryInto;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct SlotMgr {
    env: Arc<Box<lmdb::Environment>>,
    default_table: Arc<Box<lmdb::Database>>,
    meta_table: Arc<Box<lmdb::Database>>,
    free_list_table: Arc<Box<lmdb::Database>>,
    completed_rounds: Arc<Box<lmdb::Database>>,
    current_round_table: Arc<Box<lmdb::Database>>,
    slots_to_gc: Arc<Box<lmdb::Database>>,
    last_executed_round: Arc<AtomicU64>,
    nr_slots: u64,
    last_checkpointed_round: u64,
}
const KB: u64 = 1024;
const MB: u64 = KB * KB;
const GB: u64 = MB * KB;

// invalid slots are also treated as shared in mappings
pub const INVALID_SLOT: u64 = std::u64::MAX;
const MAX_ROUNDS: u32 = 120;
const SLOT_NR_VALID_BITS: u32 = 63;
const SHARED_MASK: u64 = 0x7FFF_FFFF_FFFF_FFFF;

// 1G initial size is a good starting point for
// the initial mapsize based on how we are storing
// the mappings. We need to revisit this if we end up
// expanding the maps often
const INITIAL_MAP_SIZE: usize = 2 * GB as usize;

impl SlotMgr {
    pub fn is_shared(slot_nr: u64) -> bool {
        slot_nr == INVALID_SLOT || (slot_nr >> SLOT_NR_VALID_BITS) & 1 == 0
    }

    // returns the actual slot number removing any private
    // indication so it can be used for writes
    pub fn get_slot(slot_nr: u64) -> u64 {
        assert_ne!(slot_nr, INVALID_SLOT);
        slot_nr & SHARED_MASK
    }

    pub fn new(db_base: &Path, max_slots: u64) -> Self {
        let mut env_builder = lmdb::Environment::new();
        env_builder.set_max_dbs(MAX_ROUNDS);

        env_builder.set_map_size(INITIAL_MAP_SIZE);

        let data_mdb = db_base.join("data.mdb");
        let read_only = data_mdb.exists() && data_mdb.metadata().unwrap().permissions().readonly();
        let mut slot_mgr = if read_only {
            // FixME in next restructure handle readonly vs readwrite in a cleaner
            // fashion with static polymorphism
            env_builder.set_flags(
                EnvironmentFlags::NO_LOCK
                    | EnvironmentFlags::NO_TLS
                    | EnvironmentFlags::NO_MEM_INIT
                    | EnvironmentFlags::READ_ONLY,
            );
            let env = env_builder
                .open_with_permissions(db_base, 0o400)
                .expect("Unable to open db");
            Self::open_db(env)
        } else {
            // DB syncing is dependant on external events and hence
            // no_sync is sufficient here.
            env_builder.set_flags(
                EnvironmentFlags::NO_SYNC
                    | EnvironmentFlags::NO_TLS
                    | EnvironmentFlags::NO_META_SYNC
                    | EnvironmentFlags::NO_MEM_INIT
                    | EnvironmentFlags::WRITE_MAP,
            );
            let env = env_builder.open(db_base).expect("Unable to open db");
            Self::create_db(env, max_slots)
        };

        slot_mgr.recover();
        slot_mgr
    }

    fn open_db(env: lmdb::Environment) -> SlotMgr {
        let default_table = env.open_db(None).expect("default_table created");

        let meta_table = env.open_db(Some("MetaTable")).expect("meta_table created");

        let free_list_table = env
            .open_db(Some("FreeList"))
            .expect("free_list_table created");

        let completed_rounds = env
            .open_db(Some("CompletedRounds"))
            .expect("completed_rounds created");

        let current_round_table = env
            .open_db(Some(&"Current".to_string().as_str()))
            .expect("current_round_table created");

        let slots_to_gc = env
            .open_db(Some(&"CurrentRoundOverwritten".to_string().as_str()))
            .expect("current_round_table created");

        SlotMgr {
            env: Arc::new(Box::new(env)),
            default_table: Arc::new(Box::new(default_table)),
            meta_table: Arc::new(Box::new(meta_table)),
            free_list_table: Arc::new(Box::new(free_list_table)),
            completed_rounds: Arc::new(Box::new(completed_rounds)),
            current_round_table: Arc::new(Box::new(current_round_table)),
            slots_to_gc: Arc::new(Box::new(slots_to_gc)),
            last_executed_round: Arc::new(AtomicU64::new(0)),
            nr_slots: 0,
            last_checkpointed_round: 0,
        }
    }

    fn create_db(env: lmdb::Environment, nr_slots: u64) -> SlotMgr {
        let rw_txn = env.begin_rw_txn().unwrap();
        let default_table = unsafe {
            rw_txn
                .create_db(None, DatabaseFlags::empty())
                .expect("default_table created")
        };
        let meta_table = unsafe {
            rw_txn
                .create_db(Some("MetaTable"), DatabaseFlags::empty())
                .expect("meta_table created")
        };
        let free_list_table = unsafe {
            rw_txn
                .create_db(Some("FreeList"), DatabaseFlags::INTEGER_KEY)
                .expect("free_list_table created")
        };
        let completed_rounds = unsafe {
            rw_txn
                .create_db(Some("CompletedRounds"), DatabaseFlags::INTEGER_KEY)
                .expect("completed_rounds created")
        };
        let current_round_table = unsafe {
            rw_txn
                .create_db(
                    Some(&"Current".to_string().as_str()),
                    DatabaseFlags::INTEGER_KEY,
                )
                .expect("current_round_table created")
        };
        let slots_to_gc = unsafe {
            rw_txn
                .create_db(
                    Some(&"CurrentRoundOverwritten".to_string().as_str()),
                    DatabaseFlags::INTEGER_KEY,
                )
                .expect("current_round_table created")
        };
        rw_txn.commit().expect("all dbs created successful");

        SlotMgr {
            env: Arc::new(Box::new(env)),
            default_table: Arc::new(Box::new(default_table)),
            meta_table: Arc::new(Box::new(meta_table)),
            free_list_table: Arc::new(Box::new(free_list_table)),
            completed_rounds: Arc::new(Box::new(completed_rounds)),
            current_round_table: Arc::new(Box::new(current_round_table)),
            slots_to_gc: Arc::new(Box::new(slots_to_gc)),
            last_executed_round: Arc::new(AtomicU64::new(0)),
            nr_slots,
            last_checkpointed_round: 0,
        }
    }

    fn first_init(&self) {
        let nr_slots = self.nr_slots;
        let canid: u64 = 111;
        let last_checkpointed_round: u64 = 0;

        let mut rw_txn = self.env.begin_rw_txn().unwrap();
        rw_txn
            .put(
                **self.meta_table,
                &b"NrSlots",
                &nr_slots.to_le_bytes(),
                WriteFlags::NO_DUP_DATA,
            )
            .expect("put is successful");
        rw_txn
            .put(
                **self.meta_table,
                &b"CanisterID",
                &canid.to_le_bytes(),
                WriteFlags::NO_DUP_DATA,
            )
            .expect("put is successful");
        rw_txn
            .put(
                **self.meta_table,
                &b"LastCheckpointedRound",
                &last_checkpointed_round.to_le_bytes(),
                WriteFlags::NO_DUP_DATA,
            )
            .expect("put is successful");
        rw_txn.commit().expect("Meta table completed successfully");

        self.init_free_list();
    }

    fn init_free_list(&self) {
        let mut rw_txn = self.env.begin_rw_txn().unwrap();
        for page_nr in 0..self.nr_slots {
            // Initially insert all pages to the free list
            rw_txn
                .put(
                    **self.free_list_table,
                    &page_nr.to_le_bytes(),
                    &[],
                    WriteFlags::NO_DUP_DATA,
                )
                .expect("put is successful");
        }
        rw_txn.commit().expect("commit successful");
    }

    fn recover(&mut self) {
        let ro_txn = self.env.begin_ro_txn().unwrap();
        let mut ro_cursor = ro_txn
            .open_ro_cursor(**self.meta_table)
            .expect("default table cursor");
        if ro_cursor.iter().peekable().peek().is_none() {
            drop(ro_cursor);
            // Table has not been initialized. Lets create now
            self.first_init();
            return;
        }

        for (k, v) in ro_cursor.iter().map(|x| x.unwrap()).map(|(k, v)| (k, v)) {
            let s = String::from_utf8(k.to_vec()).unwrap();
            match s.as_str() {
                "NrSlots" => self.nr_slots = Self::decode_key(v),
                "LastCheckpointedRound" => self.last_checkpointed_round = Self::decode_key(v),
                _ => panic!(format!("Unknow table found {}", s)),
            }
        }

        drop(ro_cursor);
        let _res = ro_txn.commit();

        self.last_executed_round
            .store(self.last_checkpointed_round, Ordering::Relaxed);

        // recover the current mapping table
        let ro_txn = self.env.begin_ro_txn().unwrap();
        let current_round = unsafe {
            ro_txn
                .open_db(Some("Current"))
                .expect("current_round_table created")
        };
        let _res = ro_txn.commit();
        self.current_round_table = Arc::new(Box::new(current_round));
    }

    // To clear current we need to make sure all private mappings that belong
    // to current round are returned to the free list. We can safely ignore
    // all shared mappings as they will be garbage collected once their
    // respective rounds are cleared
    pub fn clear_current(&self) {
        let mut rw_txn = self.env.begin_rw_txn().unwrap();

        let ro_txn = self.env.begin_ro_txn().unwrap();
        let mut ro_cursor = ro_txn.open_ro_cursor(**self.current_round_table).unwrap();

        for (_rawk, rawv) in ro_cursor.iter().map(|x| x.unwrap()).map(|(_k, v)| (_k, v)) {
            let val = Self::decode_key(rawv);

            // add all non shared slots to free list as they wont be required
            // anymore
            if !Self::is_shared(val) {
                rw_txn
                    .put(
                        **self.free_list_table,
                        &val.to_le_bytes(),
                        &[],
                        WriteFlags::NO_DUP_DATA,
                    )
                    .expect("copy should succeed");
            }
        }

        rw_txn.clear_db(**self.current_round_table).unwrap();
        rw_txn.commit().expect("unable to clear db");
    }

    pub fn end_round(&self, round: u64) {
        // create a new round db and inherit mappingss from previous round
        let mut rw_txn = self.env.begin_rw_txn().unwrap();
        let end_round = unsafe {
            rw_txn
                .create_db(
                    Some(&format!("round-{}", round).as_str()),
                    DatabaseFlags::INTEGER_KEY,
                )
                .expect("current_round_table created")
        };

        let ro_txn = self.env.begin_ro_txn().unwrap();
        let mut ro_cursor = ro_txn.open_ro_cursor(**self.current_round_table).unwrap();
        for (rawk, rawv) in ro_cursor.iter().map(|x| x.unwrap()).map(|(k, v)| (k, v)) {
            let key = Self::decode_key(rawk);
            let mut val = Self::decode_key(rawv);

            // covert all private mappings as shared when we create a new mappings
            // This will help us distinguish when we need a allocation and what
            // allocations can be reused
            if !Self::is_shared(val) {
                val &= SHARED_MASK;
                rw_txn
                    .put(
                        **self.current_round_table,
                        &key.to_le_bytes(),
                        &val.to_le_bytes(),
                        WriteFlags::NO_DUP_DATA,
                    )
                    .expect("copy should succeed");
            }
            rw_txn
                .put(
                    end_round,
                    &key.to_le_bytes(),
                    &val.to_le_bytes(),
                    WriteFlags::NO_DUP_DATA,
                )
                .expect("copy should succeed");
        }

        rw_txn
            .put(
                **self.completed_rounds,
                &round.to_le_bytes(),
                &[],
                WriteFlags::NO_DUP_DATA,
            )
            .expect("put is successful");
        rw_txn
            .commit()
            .expect("ending and creation of new round failed");

        self.last_executed_round.store(round, Ordering::Relaxed);
    }

    // Checkpoint accomplishes freeing of slots that are no longer required.
    // All the slots that ever were overwritten are tracked in the gc lists.
    // These slots cannot be unilaterally freed as they might still be
    // referred by older rounds. Current implementation just deletes all
    // previous rounds there by keeping the problem simple.
    // Alternatively we can find out the oldest round on which query might be
    // progressing All rounds older than that can free all the slots that were
    // overwritten in the later rounds. Find such slots and then mark them as
    // free. If all slots from the gc table are freed in such a way empty that
    // table.
    pub fn checkpoint(&self) {
        let mut free_slot_list = HashSet::new();

        let mut rounds = Vec::new();

        // Find out completed rounds
        let ro_txn = self.env.begin_ro_txn().unwrap();
        let mut ro_cursor = ro_txn.open_ro_cursor(**self.completed_rounds).unwrap();

        for round in ro_cursor.iter().map(|x| x.unwrap()).map(|(k, _)| k) {
            let round = Self::decode_key(round);
            rounds.push(round);
        }

        // Retain the highest round state and garbage collect
        // the rest
        rounds.sort();
        rounds.pop();

        // Get all the slots that can be gced
        let mut ro_cursor = ro_txn.open_ro_cursor(**self.slots_to_gc).unwrap();
        for rawk in ro_cursor.iter().map(|x| x.unwrap()).map(|(k, _)| k) {
            let slot = Self::decode_key(rawk);
            free_slot_list.insert(slot);
        }

        // Add the gc candidate slots to the free list for future allocation
        let mut rw_txn = self.env.begin_rw_txn().unwrap();
        for free_blk in free_slot_list {
            rw_txn
                .put(
                    **self.free_list_table,
                    &free_blk.to_le_bytes(),
                    &[],
                    WriteFlags::NO_DUP_DATA,
                )
                .expect("put is successful");
        }

        // drop the round specific mappings
        for round in rounds {
            let roundb = unsafe {
                rw_txn
                    .open_db(Some(&format!("round-{}", round).as_str()))
                    .expect("Opening old round db failed")
            };
            unsafe { rw_txn.drop_db(roundb).expect("dropping db failed") };

            rw_txn
                .del(**self.completed_rounds, &round.to_le_bytes(), None)
                .expect("deleting from the completed rounds")
        }
        rw_txn.clear_db(**self.slots_to_gc).expect("gc db cleared");

        // update the last checkpointed round to the current one
        let last_executed_round = self.last_executed_round.load(Ordering::Relaxed);
        rw_txn
            .put(
                **self.meta_table,
                &b"LastCheckpointedRound",
                &last_executed_round.to_le_bytes(),
                WriteFlags::NO_DUP_DATA,
            )
            .expect("unable to set last checkpointed round");
        rw_txn.commit().expect("commit successful");

        // Flush everything out that was lying around in memory is flushed to disk
        self.sync();
    }

    pub fn get_current_round_mappings(&self) -> HashMap<u64, u64> {
        let mut mappings = HashMap::new();
        let ro_txn = self.env.begin_ro_txn().unwrap();
        let mut ro_cursor = ro_txn.open_ro_cursor(**self.current_round_table).unwrap();
        for (rawk, rawv) in ro_cursor.iter().map(|x| x.unwrap()).map(|(k, v)| (k, v)) {
            let key = Self::decode_key(rawk);
            let val = Self::decode_key(rawv);
            mappings.insert(key, val);
        }
        mappings
    }

    pub fn get_mappings_for_round(&self, round: u64) -> HashMap<u64, u64> {
        let mut mappings = HashMap::new();
        let ro_txn = self.env.begin_ro_txn().unwrap();
        let roundb = unsafe {
            ro_txn
                .open_db(Some(&format!("round-{}", round).as_str()))
                .unwrap_or_else(|_| panic!("Opening old round db failed {}", round))
        };
        let mut ro_cursor = ro_txn.open_ro_cursor(roundb).unwrap();
        for (rawk, rawv) in ro_cursor.iter().map(|x| x.unwrap()).map(|(k, v)| (k, v)) {
            let key = Self::decode_key(rawk);
            let val = Self::decode_key(rawv);
            mappings.insert(key, val);
        }
        mappings
    }

    pub fn get_completed_rounds(&self) -> Vec<u64> {
        let mut rounds = Vec::new();
        let ro_txn = self.env.begin_ro_txn().unwrap();
        let mut ro_cursor = ro_txn.open_ro_cursor(**self.completed_rounds).unwrap();
        for rawk in ro_cursor.iter().map(|x| x.unwrap()).map(|(k, _)| k) {
            rounds.push(Self::decode_key(rawk));
        }
        rounds
    }

    #[allow(dead_code)]
    pub fn get_free_slot(&self) -> u64 {
        self.alloc_free_slots(1)[0]
    }

    pub fn alloc_free_slots(&self, count: u32) -> Vec<u64> {
        let mut allocated_slots = Vec::new();

        let ro_txn = self.env.begin_rw_txn().unwrap();
        let mut ro_cursor = ro_txn.open_ro_cursor(**self.free_list_table).unwrap();
        for _ in 0..count {
            let key = ro_cursor
                .iter()
                .next()
                .map(|x| x.unwrap())
                .map(|(k, _)| k)
                .unwrap();
            let allocated_physical_slot = Self::decode_key(key);
            allocated_slots.push(allocated_physical_slot);
        }

        //required so that we can begin a write txn immediately after
        drop(ro_cursor);
        let _res = ro_txn.commit();

        let mut rw_txn = self.env.begin_rw_txn().unwrap();
        for allocated_physical_slot in allocated_slots.clone() {
            rw_txn
                .del(
                    **self.free_list_table,
                    &allocated_physical_slot.to_le_bytes(),
                    None,
                )
                .expect("Remove slot from the free list");
        }

        let _res = rw_txn.commit();
        allocated_slots

        // FixME: handle issue where we can run out of free slots.
    }

    pub fn free_unused_slots(&self, slots_to_free: Vec<u64>) {
        if !slots_to_free.is_empty() {
            let mut rw_txn = self.env.begin_rw_txn().unwrap();
            for slot in slots_to_free {
                rw_txn
                    .put(
                        **self.free_list_table,
                        &slot.to_le_bytes(),
                        &[],
                        WriteFlags::NO_DUP_DATA,
                    )
                    .expect("Remove slot from the free list");
            }
            let _res = rw_txn.commit();
        }
    }

    fn update_mappings(
        &self,
        rw_txn: &mut lmdb::RwTransaction<'_>,
        virtual_slot: u64,
        physical_slot: u64,
        overwritten_physical_slot: u64,
    ) {
        if overwritten_physical_slot != INVALID_SLOT {
            // FixME: Add some slot number validation here
            // the overwritten slot is valid and shared then add it to the free list
            // println!("Adding {} to gc list", overwritten_physical_slot);
            rw_txn
                .put(
                    **self.slots_to_gc,
                    &overwritten_physical_slot.to_le_bytes(),
                    &[],
                    WriteFlags::NO_DUP_DATA,
                )
                .expect("Remove slot from the free list");
        }

        // mark the current mapping as private so subsequent overwrites to the slots can
        // be handled in place
        let physical_slot = 1 << SLOT_NR_VALID_BITS | physical_slot;
        rw_txn
            .put(
                **self.current_round_table,
                &virtual_slot.to_le_bytes(),
                &physical_slot.to_le_bytes(),
                WriteFlags::NO_DUP_DATA,
            )
            .expect("Remove slot from the free list");
    }

    #[allow(dead_code)]
    pub fn put_mapping(
        &self,
        virtual_slot: u64,
        physical_slot: u64,
        overwritten_physical_slot: u64,
    ) {
        let mut rw_txn = self.env.begin_rw_txn().unwrap();
        self.update_mappings(
            &mut rw_txn,
            virtual_slot,
            physical_slot,
            overwritten_physical_slot,
        );
        rw_txn.commit().expect("mapping update failed");
    }

    pub fn put_all_mappings(&self, mappings: HashMap<u64, (u64, u64)>) {
        let mut rw_txn = self.env.begin_rw_txn().unwrap();
        for (virtual_slot, (physical_slot, overwritten_physical_slot)) in mappings {
            self.update_mappings(
                &mut rw_txn,
                virtual_slot,
                physical_slot,
                overwritten_physical_slot,
            );
        }
        rw_txn.commit().expect("mapping update failed");
    }

    pub fn sync(&self) {
        let _res = self.env.sync(true);
    }

    fn decode_key(key: &[u8]) -> u64 {
        let (raw_bytes, _) = key.split_at(std::mem::size_of::<u64>());
        u64::from_ne_bytes(raw_bytes.try_into().unwrap())
    }

    #[allow(dead_code)]
    pub fn dump_db(&self) {
        let ro_txn = self.env.begin_ro_txn().unwrap();
        let mut ro_cursor = ro_txn
            .open_ro_cursor(**self.default_table)
            .expect("default table cursor");
        for i in ro_cursor.iter().map(|x| x.unwrap()).map(|(k, _)| k) {
            let s = String::from_utf8(i.to_vec());
            println!("{}", s.unwrap());
        }
    }
}
