use crossbeam_channel::{bounded, tick, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

/// The struct implements an abstraction for running periodically a closure at
/// fixed period - 'P'. The first call happens after duration of 'P' when
/// 'start' is called. If the closure runs longer than the period then
/// consequtive calls to the closure will be collapsed guaranteeing that we
/// don't call the closure more than once for any interval of duration 'P'.
/// The closure is stopped when the object is dropped.
pub struct PeriodicClosure {
    join_handle: Option<JoinHandle<()>>,
    canceller: Sender<()>,
}

impl PeriodicClosure {
    pub fn start<F: FnMut() + Send + Sync + 'static>(period: Duration, mut func: F) -> Self {
        let ticker = tick(period);
        let (canceller, cancelled) = bounded(1);
        let join_handle = std::thread::spawn(move || {
            loop {
                // The cancel signal takes precedence over a tick. In case we have a message in
                // both receivers we don't know what the select will return. It may happen that
                // the select keeps returning ticks although there is a cancellation signal.
                if cancelled.try_recv().is_ok() {
                    break;
                }
                // The ticker is collapsing ticks for us since it is a channel with size 1.
                crossbeam::channel::select! {
                    recv(cancelled) -> _ => break,
                    recv(ticker) -> _ => func(),
                }
            }
        });
        Self {
            join_handle: Some(join_handle),
            canceller,
        }
    }
}

impl Drop for PeriodicClosure {
    fn drop(&mut self) {
        if let Some(join_handle) = self.join_handle.take() {
            self.canceller
                .send(())
                .expect("The receiver must exists in detached thread.");
            join_handle.join().unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test() {
        let i = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let j = Arc::clone(&i);
        let p = PeriodicClosure::start(Duration::from_millis(100), move || {
            j.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });
        std::thread::sleep(Duration::from_millis(1050));
        std::mem::drop(p);
        // We should have exactly 10 increments.
        assert_eq!(i.load(std::sync::atomic::Ordering::Relaxed), 10);
    }

    #[test]
    fn test_collapsed() {
        let i = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let j = Arc::clone(&i);
        let p = PeriodicClosure::start(Duration::from_millis(1), move || {
            j.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(100));
        });
        std::thread::sleep(Duration::from_millis(950));
        std::mem::drop(p);
        // We should have exactly 10 increments. The first closure runs for
        // [1ms...101ms], the last closure will run, in theory, for
        // [901ms...1001ms].
        assert_eq!(i.load(std::sync::atomic::Ordering::Relaxed), 10);
    }
}
