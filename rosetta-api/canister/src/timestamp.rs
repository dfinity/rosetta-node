use candid::CandidType;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

#[derive(
    Serialize, Deserialize, CandidType, Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Timestamp {
    pub secs: u64,
    pub nanos: u32,
}

impl Timestamp {
    pub fn new(secs: u64, nanos: u32) -> Self {
        assert!(nanos < 1_000_000_000);
        Self { secs, nanos }
    }
}

impl From<SystemTime> for Timestamp {
    fn from(t: SystemTime) -> Self {
        let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        Self::new(d.as_secs(), d.subsec_nanos())
    }
}

impl From<Timestamp> for SystemTime {
    fn from(t: Timestamp) -> Self {
        SystemTime::UNIX_EPOCH + Duration::new(t.secs, t.nanos)
    }
}
