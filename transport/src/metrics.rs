//! Transport related metrics

use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use prometheus::{HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec};

#[derive(Clone)]
pub(crate) struct ControlPlaneMetrics {
    pub(crate) flow_state: IntGaugeVec,
    pub(crate) tcp_accept_conn_err: IntCounterVec,
    pub(crate) tcp_accept_conn_success: IntCounterVec,
    pub(crate) tcp_conn_to_server_err: IntCounterVec,
    pub(crate) tcp_conn_to_server_success: IntCounterVec,
    pub(crate) tcp_server_handshake_failed: IntCounterVec,
    pub(crate) tcp_server_handshake_success: IntCounterVec,
    pub(crate) tcp_client_handshake_failed: IntCounterVec,
    pub(crate) tcp_client_handshake_success: IntCounterVec,
    pub(crate) retry_connection: IntCounterVec,
}

impl ControlPlaneMetrics {
    pub(crate) fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            flow_state: metrics_registry.int_gauge_vec(
                "transport_flow_state",
                "Current state of the flow",
                &["flow_peer_id", "flow_tag"],
            ),
            tcp_accept_conn_err: metrics_registry.int_counter_vec(
                "transport_tcp_accept_conn_error",
                "Error connecting to incoming TcpStream in server mode",
                &["flow_tag"],
            ),
            tcp_accept_conn_success: metrics_registry.int_counter_vec(
                "transport_tcp_accept_conn_success",
                "Successfully connected to incoming TcpStream in server mode",
                &["flow_tag"],
            ),
            tcp_conn_to_server_err: metrics_registry.int_counter_vec(
                "transport_conn_to_server_error",
                "Error connecting to peer TCP server as client",
                &["flow_peer_id", "flow_tag"],
            ),
            tcp_conn_to_server_success: metrics_registry.int_counter_vec(
                "transport_conn_to_server_success",
                "Successfully connected to peer TCP server as client",
                &["flow_peer_id", "flow_tag"],
            ),
            tcp_server_handshake_failed: metrics_registry.int_counter_vec(
                "transport_tcp_server_handshake_failed",
                "Error completing handshake as peer server",
                &["flow_tag"],
            ),
            tcp_server_handshake_success: metrics_registry.int_counter_vec(
                "transport_tcp_server_handshake_success",
                "Successfully completed handshake as peer server",
                &["flow_tag"],
            ),
            tcp_client_handshake_failed: metrics_registry.int_counter_vec(
                "transport_tcp_client_handshake_failed",
                "Error completing handshake to peer as client",
                &["flow_tag"],
            ),
            tcp_client_handshake_success: metrics_registry.int_counter_vec(
                "transport_tcp_client_handshake_success",
                "Successfully completed handshake to peer as client",
                &["flow_tag"],
            ),
            retry_connection: metrics_registry.int_counter_vec(
                "transport_retry_connection",
                "Connection retries to reconnect to a peer from Transport",
                &["peer_id", "flow_tag"],
            ),
        }
    }
}

#[derive(Clone)]
pub(crate) struct DataPlaneMetrics {
    pub(crate) client_queue_full: IntCounter,
    pub(crate) client_send_fail: IntCounterVec,
    pub(crate) client_send_time_msec: HistogramVec,
    pub(crate) socket_write_bytes: IntCounterVec,
    pub(crate) socket_write_size: HistogramVec,
    pub(crate) socket_write_time_msec: HistogramVec,
    pub(crate) socket_read_bytes: IntCounterVec,
    pub(crate) socket_heart_beat_timeouts: IntCounterVec,
    pub(crate) heart_beats_sent: IntCounterVec,
    pub(crate) heart_beats_received: IntCounterVec,
    pub(crate) send_errors_received: IntCounterVec,
    pub(crate) write_tasks: IntGauge,
    pub(crate) read_tasks: IntGauge,
    pub(crate) write_task_overhead_time_msec: HistogramVec,
}

impl DataPlaneMetrics {
    pub(crate) fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            client_queue_full: metrics_registry
                .int_counter("transport_client_queue_full", "Client queue fulls"),
            client_send_fail: metrics_registry.int_counter_vec(
                "transport_client_send_fail",
                "Passing read payload to client failed",
                &["flow_peer_id", "flow_tag"],
            ),
            client_send_time_msec: metrics_registry.histogram_vec(
                "transport_client_send_time_msec",
                "Time spent in client message callback, in milliseconds",
                // 1ms, 2ms, 5ms - 100 sec, 200 sec, 500 sec
                decimal_buckets(0, 5),
                &["flow_peer_id", "flow_tag"],
            ),
            socket_write_bytes: metrics_registry.int_counter_vec(
                "transport_socket_write_bytes",
                "Bytes written to sockets",
                &["flow_peer_id", "flow_tag"],
            ),
            socket_write_size: metrics_registry.histogram_vec(
                "transport_socket_write_size",
                "Bytes written per socket write",
                // 1K, 2K, 5K - 1MB, 2MB, 5MB
                decimal_buckets(3, 6),
                &["flow_peer_id", "flow_tag"],
            ),
            socket_write_time_msec: metrics_registry.histogram_vec(
                "transport_socket_write_time_msec",
                "Socket write time, in milliseconds",
                // 1ms, 2ms, 5ms - 100 sec, 200 sec, 500 sec
                decimal_buckets(0, 5),
                &["flow_peer_id", "flow_tag"],
            ),
            socket_read_bytes: metrics_registry.int_counter_vec(
                "transport_socket_read_bytes",
                "Bytes read from sockets",
                &["flow_peer_id", "flow_tag"],
            ),
            socket_heart_beat_timeouts: metrics_registry.int_counter_vec(
                "transport_heart_beat_timeouts",
                "Number of times the heart beat timed out.",
                &["flow_peer_id", "flow_tag"],
            ),
            send_errors_received: metrics_registry.int_counter_vec(
                "transport_send_errors_received",
                "Number of peer send error notifications",
                &["flow_peer_id", "flow_tag"],
            ),
            heart_beats_received: metrics_registry.int_counter_vec(
                "transport_heart_beats_received",
                "Number of heart beats as seen by receiver",
                &["flow_peer_id", "flow_tag"],
            ),
            heart_beats_sent: metrics_registry.int_counter_vec(
                "transport_heart_beats_sent",
                "Number of heart beats sent by sender",
                &["flow_peer_id", "flow_tag"],
            ),
            write_tasks: metrics_registry
                .int_gauge("transport_write_tasks", "Active data plane write tasks"),
            read_tasks: metrics_registry
                .int_gauge("transport_read_tasks", "Active data plane read tasks"),
            write_task_overhead_time_msec: metrics_registry.histogram_vec(
                "transport_write_task_overhead_time_msec",
                "Time before socket write, in milliseconds",
                // 1ms, 2ms, 5ms - 100 sec, 200 sec, 500 sec
                decimal_buckets(0, 5),
                &["flow_peer_id", "flow_tag"],
            ),
        }
    }
}

/// Per send queue metrics
#[derive(Clone)]
pub(crate) struct SendQueueMetrics {
    pub(crate) add_count: IntCounterVec,
    pub(crate) add_bytes: IntCounterVec,
    pub(crate) remove_count: IntCounterVec,
    pub(crate) remove_bytes: IntCounterVec,
    pub(crate) queue_size: IntGaugeVec,
    pub(crate) queue_full: IntCounterVec,
    pub(crate) queue_clear: IntCounterVec,
    pub(crate) receive_end_updates: IntCounterVec,
    pub(crate) queue_time_msec: HistogramVec,
    pub(crate) no_receiver: IntCounterVec,
}

impl SendQueueMetrics {
    pub(crate) fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            add_count: metrics_registry.int_counter_vec(
                "transport_send_queue_add_count",
                "Enqueued messages",
                &["flow_peer_id", "flow_tag"],
            ),
            add_bytes: metrics_registry.int_counter_vec(
                "transport_send_queue_add_bytes",
                "Enqueued bytes",
                &["flow_peer_id", "flow_tag"],
            ),
            remove_count: metrics_registry.int_counter_vec(
                "transport_send_queue_remove_count",
                "Dequeued messages",
                &["flow_peer_id", "flow_tag"],
            ),
            remove_bytes: metrics_registry.int_counter_vec(
                "transport_send_queue_remove_bytes",
                "Dequeued bytes",
                &["flow_peer_id", "flow_tag"],
            ),
            queue_size: metrics_registry.int_gauge_vec(
                "transport_send_queue_size",
                "Queue size",
                &["flow_peer_id", "flow_tag"],
            ),
            queue_full: metrics_registry.int_counter_vec(
                "transport_send_queue_full",
                "Queue full count",
                &["flow_peer_id", "flow_tag"],
            ),
            queue_clear: metrics_registry.int_counter_vec(
                "transport_send_queue_clear",
                "Queue cleared count",
                &["flow_peer_id", "flow_tag"],
            ),
            receive_end_updates: metrics_registry.int_counter_vec(
                "transport_receive_end_updates",
                "Channel receive end update count",
                &["flow_peer_id", "flow_tag"],
            ),
            queue_time_msec: metrics_registry.histogram_vec(
                "transport_send_queue_time_msec",
                "Time spent in the send queue, in milliseconds",
                // 1ms, 2ms, 5ms - 100 sec, 200 sec, 500 sec
                decimal_buckets(0, 5),
                &["flow_peer_id", "flow_tag"],
            ),
            no_receiver: metrics_registry.int_counter_vec(
                "transport_send_no_receiver",
                "Message send failed as receive channel end closed",
                &["flow_peer_id", "flow_tag"],
            ),
        }
    }
}
