//! Metrics exported by crypto

use ic_metrics::MetricsRegistry;
use prometheus::HistogramVec;

pub struct Metrics {
    pub ic_crypto_lock_acquisition_duration_seconds: HistogramVec,
}

impl Metrics {
    pub fn new(r: &MetricsRegistry) -> Self {
        Self {
            /// Histogram of crypto lock acquisition times. The 'access' label
            /// is either 'read' or 'write'.
            ic_crypto_lock_acquisition_duration_seconds: r.histogram_vec(
                "ic_crypto_lock_acquisition_duration_seconds",
                "Histogram of crypto lock acquisition times",
                vec![0.00001, 0.0001, 0.001, 0.01, 0.1, 1.0, 10.0],
                &["name", "access"],
            ),
        }
    }
}
