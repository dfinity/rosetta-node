use actix::{System, SystemRunner};
use core::future::Future;
use std::cell::Cell;

#[cfg(test)]
mod tests;

/// Wrapper around an `actix::System` that ensures it (and all its arbiters) are
/// stopped when this wrapper goes out of scope.
pub struct ScopedSystem {
    runner: Cell<Option<SystemRunner>>,
    system: System,
}

impl ScopedSystem {
    /// Creates a new wrapped `actix::System`.
    pub fn new(name: &str) -> Self {
        let runner = Cell::new(Some(System::new(name)));
        let system = System::current();

        Self { runner, system }
    }

    /// Executes a future and waits for the result.
    pub fn block_on<F, O>(&mut self, fut: F) -> O
    where
        F: Future<Output = O> + 'static,
    {
        self.runner.get_mut().as_mut().unwrap().block_on(fut)
    }

    /// Stops the system, including all arbiters.
    ///
    /// Note that the event loop must be running during or be started after this
    /// invocation (via `run()`) in order for the stop command to be processed.
    pub fn stop(&self) {
        self.system.stop();
    }

    /// Starts event loop, finishing once `ScopedSystem::stop()` is called.
    pub fn run(self) -> std::io::Result<()> {
        self.runner.take().unwrap().run()
    }
}

impl Drop for ScopedSystem {
    fn drop(&mut self) {
        self.system.stop();
        if let Some(runner) = self.runner.take() {
            runner.run().expect("Failed to stop actix::System")
        };
    }
}
