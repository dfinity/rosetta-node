mod proto;

use candid::Decode;
use ic_base_types::{CanisterId, SubnetId};
use ic_ic00_types::{
    CanisterIdRecord, DevSetFundsArgs, InstallCodeArgs, Method as Ic00Method, Payload,
    ProvisionalTopUpCanisterArgs, SetControllerArgs,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, str::FromStr, sync::Arc};

pub enum ResolveDestinationError {
    CandidError(candid::Error),
    MethodNotFound(String),
    SubnetNotFound(CanisterId, Ic00Method),
}

impl From<candid::Error> for ResolveDestinationError {
    fn from(err: candid::Error) -> Self {
        ResolveDestinationError::CandidError(err)
    }
}

/// Inspect the method name and payload of a request to ic:00 to figure out to
/// which subnet it should be sent to.
pub fn resolve_destination(
    routing_table: Arc<RoutingTable>,
    method_name: &str,
    payload: &[u8],
    own_subnet: SubnetId,
) -> Result<SubnetId, ResolveDestinationError> {
    // Figure out the destination subnet based on the method and the payload.
    match Ic00Method::from_str(method_name) {
        Ok(Ic00Method::CreateCanister)
        | Ok(Ic00Method::RawRand)
        | Ok(Ic00Method::DevCreateCanisterWithFunds)
        | Ok(Ic00Method::ProvisionalCreateCanisterWithCycles)
        | Ok(Ic00Method::ConvertIcptToCycles)
        | Ok(Ic00Method::SetupInitialDKG) => Ok(own_subnet),
        Ok(Ic00Method::InstallCode) => {
            // Find the destination canister from the payload.
            let args = Decode!(payload, InstallCodeArgs)?;
            let canister_id = args.get_canister_id();
            routing_table.route(canister_id).ok_or({
                ResolveDestinationError::SubnetNotFound(canister_id, Ic00Method::InstallCode)
            })
        }
        Ok(Ic00Method::SetController) => {
            let args = Decode!(payload, SetControllerArgs)?;
            let canister_id = args.get_canister_id();
            routing_table.route(canister_id).ok_or({
                ResolveDestinationError::SubnetNotFound(canister_id, Ic00Method::SetController)
            })
        }
        Ok(Ic00Method::CanisterStatus)
        | Ok(Ic00Method::StartCanister)
        | Ok(Ic00Method::StopCanister)
        | Ok(Ic00Method::DeleteCanister)
        | Ok(Ic00Method::DepositFunds) => {
            let args = Decode!(payload, CanisterIdRecord)?;
            let canister_id = args.get_canister_id();
            routing_table.route(canister_id).ok_or({
                ResolveDestinationError::SubnetNotFound(canister_id, Ic00Method::DepositFunds)
            })
        }
        Ok(Ic00Method::DevSetFunds) => {
            let args = DevSetFundsArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            routing_table.route(canister_id).ok_or({
                ResolveDestinationError::SubnetNotFound(canister_id, Ic00Method::DevSetFunds)
            })
        }
        Ok(Ic00Method::ProvisionalTopUpCanister) => {
            let args = ProvisionalTopUpCanisterArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            routing_table.route(canister_id).ok_or({
                ResolveDestinationError::SubnetNotFound(
                    canister_id,
                    Ic00Method::ProvisionalTopUpCanister,
                )
            })
        }
        Err(_) => Err(ResolveDestinationError::MethodNotFound(
            method_name.to_string(),
        )),
    }
}

pub fn canister_id_into_u64(canister_id: CanisterId) -> u64 {
    const LENGTH: usize = std::mem::size_of::<u64>();
    let principal_id = canister_id.get();
    let bytes = principal_id.as_slice();
    // the +2 accounts for the two sentinel bytes that are added to the end of
    // the array
    assert_eq!(
        bytes.len(),
        LENGTH + 2,
        "canister_id: {}; raw {:?}",
        canister_id,
        canister_id
    );
    let mut array = [0; LENGTH];
    array[..LENGTH].copy_from_slice(&bytes[..LENGTH]);
    u64::from_be_bytes(array)
}

fn canister_id_into_u128(canister_id: CanisterId) -> u128 {
    canister_id_into_u64(canister_id) as u128
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct CanisterIdRange {
    pub start: CanisterId,
    pub end: CanisterId,
}

// EXE-96: Currently the `String`s just offer informative messages about the
// error.  This could be further improved.
#[derive(Debug, Eq, PartialEq)]
pub enum WellFormedError {
    CanisterIdRangeNonClosedRange(String),
    CanisterIdRangeAppGroupSplit(String),
    CanisterIdRangeNotSortedOrNotDisjoint(String),
    RoutingTableNonEmptyRange(String),
    RoutingTableAppGroupSplit(String),
    RoutingTableNotDisjoint(String),
}

/// A list of closed `CanisterId` ranges that are present in the `RoutingTable`
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanisterIdRanges(Vec<CanisterIdRange>);

impl CanisterIdRanges {
    /// Returns true if this collection of canister ID ranges is well-formed.
    fn well_formed(&self) -> Result<(), WellFormedError> {
        use WellFormedError::*;

        // Ranges are non-empty (ranges are closed).
        for range in self.0.iter() {
            if range.start > range.end {
                return Err(CanisterIdRangeNonClosedRange(format!(
                    "start {} is greater than end {}",
                    range.start, range.end,
                )));
            }
        }

        // Ranges do not split application groups.
        for range in self.0.iter() {
            if canister_id_into_u64(range.start) & 0xff != 0 {
                return Err(CanisterIdRangeAppGroupSplit(format!(
                    "Start {} ({}) & 0xff != 0",
                    range.start,
                    canister_id_into_u64(range.start)
                )));
            }
            if canister_id_into_u64(range.end) & 0xff != 0xff {
                return Err(CanisterIdRangeAppGroupSplit(format!(
                    "end {} ({}) & 0xff != 0xff",
                    range.end,
                    canister_id_into_u64(range.end)
                )));
            }
        }

        // Ranges are sorted and disjoint.
        for i in 1..self.0.len() {
            let current_start = self.0[i].start;
            let previous_end = self.0[i - 1].end;
            if previous_end >= current_start {
                return Err(CanisterIdRangeNotSortedOrNotDisjoint(format!(
                    "previous_end {} >= current_start {}",
                    previous_end, current_start
                )));
            }
        }

        // TODO: we could (and probably should) also require that the
        // sequence is gap free.
        Ok(())
    }

    /// Total sum of the lengths of all ranges, i.e., the total number of
    /// canister IDs that are included in the ranges.  Note that the entire
    /// valid space of canister ids is exactly (1<<64) which cannot be
    /// represented in a u64, therefore this function returns a u128.
    pub fn total_count(&self) -> u128 {
        let mut sum = 0;
        for range in self.0.iter() {
            sum +=
                1 as u128 + canister_id_into_u128(range.end) - canister_id_into_u128(range.start);
        }
        sum
    }

    /// Given location 'loc' in the range [0, total_count()), select a Canister
    /// ID that falls into the Canister ID ranges.
    pub fn locate(&self, loc: u64) -> CanisterId {
        let mut loc = loc as u128;
        assert!(loc < self.total_count());
        for range in self.0.iter() {
            let len =
                1 as u128 + canister_id_into_u128(range.end) - canister_id_into_u128(range.start);
            if loc < len {
                return CanisterId::from(canister_id_into_u64(range.start) + loc as u64);
            }
            loc -= len;
        }
        unreachable!(
            "We asserted that loc {} is less than total_count {} so should not get here.",
            loc,
            self.total_count()
        );
    }
}

/// Stores an ordered map mapping CanisterId ranges to SubnetIds.  The ranges
/// tracked are inclusive of start and end i.e. can be denoted as [a, b].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingTable(BTreeMap<CanisterIdRange, SubnetId>);

impl RoutingTable {
    pub fn new(map: BTreeMap<CanisterIdRange, SubnetId>) -> Self {
        let ret = Self(map);
        // TODO(akhi): return error instead of panicking.
        assert_eq!(ret.well_formed(), Ok(()));
        ret
    }

    pub fn insert(
        &mut self,
        canister_id_range: CanisterIdRange,
        subnet_id: SubnetId,
    ) -> Result<(), WellFormedError> {
        self.0.insert(canister_id_range, subnet_id);
        self.well_formed()
    }

    pub fn iter(&self) -> impl std::iter::Iterator<Item = (&CanisterIdRange, &SubnetId)> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns true if the routing table is well-formed.
    fn well_formed(&self) -> Result<(), WellFormedError> {
        use WellFormedError::*;

        // Used to track the end of the previous end used to check that the
        // ranges are disjoint.
        let mut previous_end: Option<CanisterId> = None;
        for range in self.0.keys() {
            // Check that ranges are non-empty (ranges are closed).
            if range.start > range.end {
                return Err(RoutingTableNonEmptyRange(format!(
                    "start {} is greater than end {}",
                    range.start, range.end
                )));
            }
            // Check that ranges do not split application groups.
            if canister_id_into_u64(range.start) & 0xff != 0 {
                return Err(RoutingTableAppGroupSplit(format!(
                    "Start {} ({}) & 0xff != 0",
                    range.start,
                    canister_id_into_u64(range.start)
                )));
            }
            if canister_id_into_u64(range.end) & 0xff != 0xff {
                return Err(RoutingTableAppGroupSplit(format!(
                    "End {} ({}) & 0xff != 0xff",
                    range.end,
                    canister_id_into_u64(range.end)
                )));
            }

            // Check that this range starts strictly after the
            // previous range (remember that the endpoints of ranges
            // are inclusive).
            if previous_end >= Some(range.start) {
                return Err(RoutingTableNotDisjoint(format!(
                    "Previous end {:?} >= current start {}",
                    previous_end, range.start
                )));
            }
            previous_end = Some(range.end);
        }

        // TODO: we could (and probably should) also require that
        // adjacent ranges don't specify the same subnet ID, as the
        // ranges ought to be merged in this case.
        Ok(())
    }

    /// Find the subnetwork that `canister_id` is assigned to.
    pub fn route(&self, canister_id: CanisterId) -> Option<SubnetId> {
        // In simple terms, we need to do a binary search of all the interval
        // ranges tracked in self to see if `canister_id` in included in any of
        // them.  BTreeMap offers this functionality in the form of the
        // `range()` function.  In particular, assume self is [a1, b1] ... [an,
        // bn].  Pretend to insert [canister_id, u64::MAX] into this sequence.
        // We look for the interval [i1, i2] that is before (or equal to) the
        // position where [caniter_id, u64::MAX] would be inserted.
        let before = self
            .0
            .range(
                ..=(CanisterIdRange {
                    start: canister_id,
                    end: CanisterId::from(u64::MAX),
                }),
            )
            .next_back();
        if let Some((interval, subnet_id)) = before {
            // We found an interval [star, end], it must be the case that
            // [start, end]<=[canister_id, u64::MAX] lexicographically, whence
            // start <= canister_id.
            assert!(interval.start <= canister_id);
            // If canister_id is in the interval then we found our answer.
            if canister_id <= interval.end {
                Some(*subnet_id)
            } else {
                // In this case, either [start, end] is the last interval in the
                // map and c comes after end, or there is an interval [a,b] in
                // the map such that lexicographically [start, end] <= [c,
                // u64::MAX] < [a, b]. This means that canister_id < a so
                // canister_id is not assigned to any subnetwork. Because if
                // canister_id == a, then u64::MAX < b which is impossible.
                None
            }
        } else {
            // All intervals [a,b] of the map are lexicographically > than
            // [canister_id, u64::MAX]. But if [a, b] > [canister_id, u64::MAX]
            // then a > canister_id, which means that canister_id is unassigned
            // (or a == b and b > u64::MAX which is impossible).
            None
        }
    }

    /// Find all canister ranges that are assigned to subnet_id.
    pub fn ranges(&self, subnet_id: SubnetId) -> CanisterIdRanges {
        let mut ranges = Vec::new();
        for (range, range_subnet_id) in self.0.iter() {
            if subnet_id == *range_subnet_id {
                ranges.push(*range);
            }
        }
        let res = CanisterIdRanges(ranges);
        assert_eq!(res.well_formed(), Ok(()));
        res
    }
}

impl IntoIterator for RoutingTable {
    type Item = (CanisterIdRange, SubnetId);
    type IntoIter = std::collections::btree_map::IntoIter<CanisterIdRange, SubnetId>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;
    use ic_test_utilities::types::ids::subnet_test_id;
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    fn hash(seed: u64, counter: u32) -> u64 {
        let mut s = DefaultHasher::new();
        seed.hash(&mut s);
        counter.hash(&mut s);
        s.finish()
    }

    fn allocate_canister_id(
        rt: &RoutingTable,
        me: SubnetId,
        seed: u64,
        seq_no: &mut u32,
        canister_find: &dyn Fn(CanisterId) -> bool,
    ) -> CanisterId {
        let ranges: CanisterIdRanges = rt.ranges(me);
        // The sum of the length of all ranges.
        let r = ranges.total_count();
        assert!(r > 0x100);
        // Try 1000 times
        for _ in 0..1000 {
            // Compute a random Canister ID h in the current range of the subnet's
            // allocation.
            let h = 0x100 * (hash(seed, *seq_no) as u128 % (r / 0x100));
            // Increase the sequence number.
            *seq_no += 1;
            // .locate() returns the h'th Canister ID across all the ranges
            let cid = ranges.locate(h as u64);
            // Check that we got an application group ID.
            assert!(canister_id_into_u64(cid).trailing_zeros() >= 8);
            // Sanity check: the Canister ID routes to our SN.
            assert_eq!(rt.route(cid), Some(me));
            // Check in our canister map if the Canister ID is already
            // mapped to a canister.
            if canister_find(cid) {
                println!("Very unlikely event happened: a Canister ID clash for 0x{:x?} at sequence number {}!",
                     cid, *seq_no);
                continue;
            }
            return cid;
        }
        // Then panic.
        panic!();
    }

    fn new_canister_id_ranges(ranges: Vec<(u64, u64)>) -> CanisterIdRanges {
        let ranges = ranges
            .into_iter()
            .map(|(start, end)| CanisterIdRange {
                start: CanisterId::from(start),
                end: CanisterId::from(end),
            })
            .collect();
        CanisterIdRanges(ranges)
    }

    fn new_routing_table(ranges: Vec<((u64, u64), u64)>) -> RoutingTable {
        let mut map = BTreeMap::new();
        for ((start, end), subnet_id) in ranges {
            let range = CanisterIdRange {
                start: CanisterId::from(start),
                end: CanisterId::from(end),
            };
            map.insert(range, subnet_test_id(subnet_id));
        }
        RoutingTable(map)
    }

    #[test]
    fn invalid_canister_id_ranges() {
        let ranges = CanisterIdRanges(vec![CanisterIdRange {
            start: CanisterId::from(1),
            end: CanisterId::from(0),
        }]);
        assert_matches!(
            ranges.well_formed(),
            Err(WellFormedError::CanisterIdRangeNonClosedRange(_))
        );

        let ranges = CanisterIdRanges(vec![CanisterIdRange {
            start: CanisterId::from(1),
            end: CanisterId::from(0xff),
        }]);
        assert_matches!(
            ranges.well_formed(),
            Err(WellFormedError::CanisterIdRangeAppGroupSplit(_))
        );

        let ranges = CanisterIdRanges(vec![CanisterIdRange {
            start: CanisterId::from(0),
            end: CanisterId::from(0xfe),
        }]);
        assert_matches!(
            ranges.well_formed(),
            Err(WellFormedError::CanisterIdRangeAppGroupSplit(_))
        );

        let ranges = CanisterIdRanges(vec![
            CanisterIdRange {
                start: CanisterId::from(0),
                end: CanisterId::from(0xff),
            },
            CanisterIdRange {
                start: CanisterId::from(0),
                end: CanisterId::from(0xff),
            },
        ]);
        assert_matches!(
            ranges.well_formed(),
            Err(WellFormedError::CanisterIdRangeNotSortedOrNotDisjoint(_))
        );
    }

    #[test]
    fn invalid_routing_table() {
        // empty range
        let rt = new_routing_table([((0x1000, 0x1ff), 0)].to_vec());
        assert_matches!(
            rt.well_formed(),
            Err(WellFormedError::RoutingTableNonEmptyRange(_))
        );

        // not respecting application groups
        let rt = new_routing_table([((0x1, 0x10fe), 0)].to_vec());
        assert_matches!(
            rt.well_formed(),
            Err(WellFormedError::RoutingTableAppGroupSplit(_))
        );

        // not respecting application groups
        let rt = new_routing_table([((0x1000, 0x10fe), 0)].to_vec());
        assert_matches!(
            rt.well_formed(),
            Err(WellFormedError::RoutingTableAppGroupSplit(_))
        );

        // overlaping ranges.
        let rt = new_routing_table([((0, 0x100ff), 123), ((0x10000, 0x200ff), 7)].to_vec());
        assert_matches!(
            rt.well_formed(),
            Err(WellFormedError::RoutingTableNotDisjoint(_))
        );
    }

    #[test]
    fn valid_example() {
        // Valid example
        let rt = new_routing_table(
            [
                ((0x100, 0x100ff), 1),
                ((0x20000, 0x2ffff), 2),
                ((0x50000, 0x50fff), 1),
                ((0x80000, 0x8ffff), 8),
                ((0x90000, 0xfffff), 9),
                ((0x1000000000000000, 0xffffffffffffffff), 0xf),
            ]
            .to_vec(),
        );
        assert_eq!(rt.well_formed(), Ok(()));
        assert!(rt.route(CanisterId::from(0)) == None);
        assert!(rt.route(CanisterId::from(0x99)) == None);
        assert!(rt.route(CanisterId::from(0x100)) == Some(subnet_test_id(1)));
        assert!(rt.route(CanisterId::from(0x10000)) == Some(subnet_test_id(1)));
        assert!(rt.route(CanisterId::from(0x100ff)) == Some(subnet_test_id(1)));
        assert!(rt.route(CanisterId::from(0x10100)) == None);
        assert!(rt.route(CanisterId::from(0x20500)) == Some(subnet_test_id(2)));
        assert!(rt.route(CanisterId::from(0x50050)) == Some(subnet_test_id(1)));
        assert!(rt.route(CanisterId::from(0x100000)) == None);
        assert!(rt.route(CanisterId::from(0x80500)) == Some(subnet_test_id(8)));
        assert!(rt.route(CanisterId::from(0x8ffff)) == Some(subnet_test_id(8)));
        assert!(rt.route(CanisterId::from(0x90000)) == Some(subnet_test_id(9)));
        assert!(rt.route(CanisterId::from(0xffffffffffffffff)) == Some(subnet_test_id(0xf)));
        assert_eq!(rt.ranges(subnet_test_id(1)).well_formed(), Ok(()));
        assert!(
            rt.ranges(subnet_test_id(1)).0
                == new_canister_id_ranges(vec![(0x100, 0x100ff), (0x50000, 0x50fff)]).0
        );
        let mut seq_no = 0;
        let cid = allocate_canister_id(
            &rt,
            subnet_test_id(1),
            17,
            &mut seq_no,
            &(|x| x <= CanisterId::from(0x100ff)),
        );
        println!("CID 0x{:x?}, seq_no {}", cid, seq_no);
        assert!(cid > CanisterId::from(0x10000));
    }
}
