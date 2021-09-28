use prometheus::core::{Atomic, GenericGauge};
use std::sync::Arc;

///  Semaphore with integrated gauge that tracks the outstanding permits.
///
///  This is useful pattern if you want to have a limit on the number of events
///  and track how many permits are consumed.
///
///  You must be within a Tokio runtime. The type is thread-safe.
///
///  Examples:
///```
///     // If you want to execute particular task with limited concurrency but
///     // you also want to see how much flow control happens in Prometheus.
///     // This is particular useful for servers that want to implement some
///     // type of flow control.
///     use std::sync::Arc;
///
///     async fn example() {
///         let gauge = prometheus::IntGauge::new("name", "help").unwrap();
///         let sem =
///             ic_base_thread::ObservableCountingSemaphore::new(2, gauge);
///         let mut jhs = Vec::new();
///         for _i in 1..10 {
///             let _permit = sem.acquire().await;
///             jhs.push(tokio::spawn(async move {
///                 let _permit_deleter = _permit;
///                 // do work
///             }));
///         }
///         // do work
///         for jh in jhs {
///             jh.await.unwrap();
///         }
///     }
/// ```
pub struct ObservableCountingSemaphore<P: Atomic> {
    semaphore: Arc<tokio::sync::Semaphore>,
    gauge: GenericGauge<P>,
}

impl<P: Atomic> ObservableCountingSemaphore<P> {
    pub fn new(permits: usize, gauge: GenericGauge<P>) -> Self {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(permits));
        Self { semaphore, gauge }
    }

    /// A call to acquire will return a permit that will be valid until being
    /// dropped. Please note the semantics of acquire is different from the
    /// semantics of `tokio::sync::Semaphore::{acquire,acquire_owned}`.
    ///
    /// 1. Unlike in Tokio when acquire_owned is used, the
    /// `ObservableCountingSemaphore` doesn't need to be wrapped in Arc.
    /// Furthermore, if you want to reuse the semaphore you don't need to clone
    /// it before hand in order to retain ownership.
    ///
    /// 2. Unlike in Tokio when acquire is used, you can pass the
    /// permit across different threads without worrying about lifetimes.
    pub async fn acquire(&self) -> SemaphorePermit<P> {
        // We need to clone the underlying semaphore so it is both owned by the
        // current object and the Tokio permit. This way it is safe to drop the
        // ObservableCountingSemaphore object before the permit, although not
        // recommended.
        let sem_for_permit = Arc::clone(&self.semaphore);
        // Can't panic because the semaphore is never closed before this call.
        let permit = sem_for_permit
            .acquire_owned()
            .await
            .expect("Acquiring a permit on closed semaphore. This can't happen.");
        self.gauge.inc();
        SemaphorePermit {
            gauge: self.gauge.clone(),
            _permit: permit,
        }
    }
}

/// The semaphore permit type returned from the `ObservableCountingSemaphore`.
pub struct SemaphorePermit<P: Atomic> {
    gauge: GenericGauge<P>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl<P: Atomic> Drop for SemaphorePermit<P> {
    fn drop(&mut self) {
        self.gauge.dec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_concurrent_flow_control() {
        let gauge = prometheus::IntGauge::new("name", "help").unwrap();
        let sem = ObservableCountingSemaphore::new(2, gauge.clone());
        assert_eq!(gauge.get(), 0);
        let mut jhs = Vec::new();
        for _i in 1..10 {
            let permit = sem.acquire().await;
            jhs.push(tokio::task::spawn({
                let gauge = gauge.clone();
                async move {
                    assert!(gauge.get() > 0);
                    assert!(gauge.get() <= 2);
                    let _permit_deleter = permit;
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }));
        }
        for jh in jhs {
            assert!(jh.await.is_ok());
        }
        assert_eq!(gauge.get(), 0);
    }

    #[tokio::test]
    async fn test_sequencial_operations() {
        let gauge = prometheus::IntGauge::new("name", "help").unwrap();
        let sem = Arc::new(ObservableCountingSemaphore::new(3, gauge.clone()));
        assert_eq!(gauge.get(), 0);
        {
            let _permit1 = sem.acquire().await;
            assert_eq!(gauge.get(), 1);
            let _permit2 = sem.acquire().await;
            assert_eq!(gauge.get(), 2);
            let cloned_sem = Arc::clone(&sem);
            let _permit3 = cloned_sem.acquire().await;
            assert_eq!(gauge.get(), 3);
        }
        assert_eq!(gauge.get(), 0);
        {
            let _permit = sem.acquire().await;
            assert_eq!(gauge.get(), 1);
        }
        assert_eq!(gauge.get(), 0);
    }
}
