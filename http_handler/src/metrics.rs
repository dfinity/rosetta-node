use crate::types::*;
use ic_metrics::{
    buckets::{add_bucket, decimal_buckets},
    MetricsRegistry,
};
use prometheus::{HistogramVec, IntCounterVec, IntGauge};
use std::sync::Arc;

// Struct holding only Prometheus metric objects. Hence, it is thread-safe iff
// the data members are thread-safe.
pub(crate) struct HttpHandlerMetrics {
    pub(crate) requests: Arc<HistogramVec>,
    pub(crate) inflight_requests: Arc<IntGauge>,
    requests_per_app_layer: Arc<IntCounterVec>,
    forbidden_requests: Arc<IntCounterVec>,
    connection_errors: Arc<IntCounterVec>,
    internal_errors: Arc<IntCounterVec>,
}

// There is a mismatch between the labels and the public spec.
// The `type` label corresponds to the `request type` in the public spec.
// The `request_type` label corresponds to the API endpoint.
// Naming conventions:
//   1. If you include the `type` label, prefix your metric name with
// `replica_http`.
impl HttpHandlerMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            requests: Arc::new(metrics_registry.histogram_vec(
                // This metric will contain durations of HTTPS requests as well. The naming is
                // unfortunate.
                "replica_http_request_duration_seconds",
                "The HTTP/HTTPS request latencies in seconds.",
                // We need more than what the default offers (max 10.0), so we
                // could better check the acceptance of our scenario tests. In
                // addition, this code uses decimal buckets just like all other
                // places that deal with request durations (for example, xnet
                // traffic). In addition, the buckets are extended by one more
                // value - 15s, needed for the scenario testcases.

                // NOTE: If you ever change this, consult and update scenario
                // tests in prod/tests/scenario_tests These tests assume there
                // MUST be a bucket at 15s, AND one bucket above it, that is not
                // +Inf.
                add_bucket(15.0, decimal_buckets(-3, 1)),
                // 1ms, 2ms, 5ms, 10ms, 20ms, ..., 10s, 15s, 20s, 50s
                &["type", "status", "request_type"],
            )),
            forbidden_requests: Arc::new(metrics_registry.int_counter_vec(
                "replica_http_forbidden_request_count",
                "The number of HTTP or HTTPS requests that were rejected with 403 code",
                &["type", "reason"],
            )),
            requests_per_app_layer: Arc::new(metrics_registry.int_counter_vec(
                "replica_http_requests_per_app_layer_protocol",
                "The number of HTTP or HTTPS streams per request type.",
                &["type", "app_layer_protocol"],
            )),
            internal_errors: Arc::new(metrics_registry.int_counter_vec(
                "replica_http_internal_errors",
                "The number of different internal errors. Those are errors that must not happen.",
                &["type", "reason"],
            )),
            inflight_requests: Arc::new(
                metrics_registry
                    .int_gauge("replica_inflight_requests", "Number of inflight requests"),
            ),
            connection_errors: Arc::new(metrics_registry.int_counter_vec(
                "replica_connection_errors",
                "The number of different connection errors.",
                &["reason"],
            )),
        }
    }

    pub(crate) fn observe_forbidden_request(&self, request_type: &RequestType, reason: &str) {
        self.forbidden_requests
            .with_label_values(&[&request_type.to_string(), reason])
            .inc();
    }

    pub(crate) fn observe_requests_per_app_layer(
        &self,
        request_type: &RequestType,
        app_layer: &AppLayer,
    ) {
        self.requests_per_app_layer
            .with_label_values(&[&request_type.to_string(), &app_layer.to_string()])
            .inc();
    }

    pub(crate) fn observe_connection_error(&self, error: ConnectionError) {
        self.connection_errors
            .with_label_values(&[&error.to_string()])
            .inc();
    }

    pub(crate) fn observe_internal_error(&self, request_type: &RequestType, error: InternalError) {
        self.internal_errors
            .with_label_values(&[&request_type.to_string(), &error.to_string()])
            .inc();
    }
}
