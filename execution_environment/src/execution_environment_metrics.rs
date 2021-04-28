use ic_metrics::buckets::decimal_buckets;
use ic_metrics::{MetricsRegistry, Timer};
use ic_types::ic00;
use prometheus::HistogramVec;
use std::str::FromStr;

/// Metrics used to monitor the performance of the execution environment.
pub(crate) struct ExecutionEnvironmentMetrics {
    subnet_messages: HistogramVec,
}

impl ExecutionEnvironmentMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            subnet_messages: metrics_registry.histogram_vec(
                "execution_subnet_message_duration_seconds",
                "Duration of a executing subnet messages in seconds.",
                decimal_buckets(-3, 1),
                &["method_name", "outcome"],
            ),
        }
    }

    /// Observe the duration and count of subnet messages.
    ///
    /// The observation is divided by the name of the method as well as by the
    /// "outcome" (i.e. whether or not execution succeeded).
    ///
    /// Example 1: A successful call to ic00::create_canister is observed as:
    /// subnet_message(
    ///     { "method_name": "ic00_create_canister", "outcome": "success"})
    ///
    /// Example 2: An unsuccessful call to ic00::install_code is observed as:
    /// subnet_message(
    ///     { "method_name": "ic00_install_code", "outcome": "error"})
    ///
    /// Example 3: A call to a non-existing method is observed as:
    ///   subnet_message(
    ///     { "method_name": "unknown_method", "outcome": "error"})
    pub fn observe_subnet_message(&self, method_name: &str, timer: Timer, succeeded: bool) {
        let method_name_label = if let Ok(method_name) = ic00::Method::from_str(method_name) {
            format!("ic00_{}", method_name.to_string())
        } else {
            String::from("unknown_method")
        };
        let outcome_label = if succeeded { "success" } else { "error" };

        self.subnet_messages
            .with_label_values(&[method_name_label.as_str(), outcome_label])
            .observe(timer.elapsed());
    }
}
