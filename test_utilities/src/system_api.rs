use ic_system_api::PauseHandler;
use ic_types::NumInstructions;

/// Pause handler that does not return any new cycles (and hence causes
/// calling canister execution to abort).
struct DummyPauseHandler {}
impl PauseHandler for DummyPauseHandler {
    fn pause(&self) -> NumInstructions {
        NumInstructions::from(0)
    }
}

pub fn dummy_pause_handler() -> Box<dyn PauseHandler> {
    Box::new(DummyPauseHandler {})
}
