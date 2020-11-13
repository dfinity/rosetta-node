use super::*;
use actix::Arbiter;
use core::future::Future;
use std::sync::mpsc::{channel, Receiver, Sender};

/// Creates an arbiter running a ticker on a `ScopedSystem` and ensures the
/// arbiter is stopped when the `ScopedSystem` goes out of scope.
#[test]
fn system_stops() {
    let (mut arbiter, rx) = {
        let _system = ScopedSystem::new("system_stops");

        arbiter_with_ticker()
    };

    // Assert that the ticker future stops.
    for i in rx.iter() {
        assert_eq!(1, i);
    }

    // Ensure the arbiter thread terminated.
    arbiter.join().unwrap();
}

/// Creates an arbiter running a ticker on a `ScopedSystem` and ensures the
/// arbiter is stopped when the `ScopedSystem` goes out of scope due to a panic.
#[test]
fn system_stops_on_panic() {
    use std::sync::{Arc, Mutex};

    #[allow(clippy::type_complexity)]
    let m: Arc<Mutex<Option<(Arbiter, Receiver<i32>)>>> = Arc::new(Mutex::new(None));

    let m_clone = m.clone();
    std::thread::spawn(move || {
        let _system = ScopedSystem::new("system_stops");

        m_clone.lock().unwrap().replace(arbiter_with_ticker());

        panic!("Oops");
    })
    .join()
    .unwrap_err();

    let (mut arbiter, rx) = Arc::try_unwrap(m).unwrap().into_inner().unwrap().unwrap();

    // Assert that the timer terminates.
    for i in rx.iter() {
        assert_eq!(1, i);
    }

    // And ensure we can join the arbiter thread.
    arbiter.join().unwrap();
}

// Returns an arbiter running a ticker and the receiver for the generated ticks.
fn arbiter_with_ticker() -> (Arbiter, Receiver<i32>) {
    let arbiter = Arbiter::new();

    let (tx, rx) = channel();
    let ticker = ticker_future(tx);
    arbiter.send(ticker);

    // Wait for the ticker to go live.
    assert_eq!(0, rx.recv().unwrap());
    assert_eq!(1, rx.recv().unwrap());

    (arbiter, rx)
}

// Returns a future that send ticks indefinitely over the provided sender.
fn ticker_future(tx: Sender<i32>) -> std::pin::Pin<Box<impl Future<Output = ()>>> {
    Box::pin(async move {
        tx.send(0).unwrap();

        let mut interval = actix::clock::interval_at(
            tokio::time::Instant::now(),
            std::time::Duration::from_millis(100),
        );
        loop {
            interval.tick().await;
            tx.send(1).unwrap();
            eprintln!("Tick");
        }
    })
}
