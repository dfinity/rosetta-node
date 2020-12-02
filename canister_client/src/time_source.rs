use ic_interfaces::time_source::TimeSource;
use ic_types::time::{Time, UNIX_EPOCH};
use std::time::SystemTime;

/// Time source using the system time that automatically reflects the most
/// current system time. Not for use in canisters.
pub(crate) struct SystemTimeTimeSource();

#[allow(clippy::new_without_default)]
impl SystemTimeTimeSource {
    pub fn new() -> Self {
        Self()
    }
}

impl TimeSource for SystemTimeTimeSource {
    fn get_relative_time(&self) -> Time {
        UNIX_EPOCH
            + SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("SystemTime is before UNIX EPOCH!")
    }
}
