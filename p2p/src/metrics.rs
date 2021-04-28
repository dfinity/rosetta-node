use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use prometheus::{Histogram, HistogramVec, IntCounter, IntGauge};

#[derive(Debug, Clone)]
pub struct P2PMetrics {
    pub run_duration: Histogram,
    pub advert_queue_size: IntGauge,
    pub chunk_queue_size: IntGauge,
    pub request_queue_size: IntGauge,
    pub user_ingress_queue_size: IntGauge,
    pub sender_errors_reported: IntGauge,
}

impl P2PMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            run_duration: metrics_registry.histogram(
                "p2p_run_duration",
                "The time it takes to call P2PImpl.run, in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms
                decimal_buckets(-4, -1),
            ),
            advert_queue_size: metrics_registry.int_gauge(
                "gossip_advert_queue_size_deprecated",
                "adverts received by transport and not yet delivered to gossip",
            ),
            chunk_queue_size: metrics_registry.int_gauge(
                "gossip_chunk_queue_size_deprecated",
                "chunks received by transport and not yet delivered to gossip",
            ),
            request_queue_size: metrics_registry.int_gauge(
                "gossip_request_queue_size_deprecated",
                "requests received by transport but not yet delivered to gossip",
            ),
            user_ingress_queue_size: metrics_registry.int_gauge(
                "gossip_user_ingress_queue_size_deprecated",
                "user ingress messages received by P2P but not yet delivered to gossip",
            ),
            sender_errors_reported: metrics_registry.int_gauge(
                "gossip_sender_errors_reported",
                "Errors reported by sender and possibly caused a retransmission request",
            ),
        }
    }
}
#[derive(Debug, Clone)]
pub struct GossipMetrics {
    pub op_duration: HistogramVec,
    pub chunk_req_not_found: IntCounter,
    pub artifacts_dropped: IntCounter,
}

impl GossipMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            op_duration: metrics_registry.histogram_vec(
                "p2p_gossip_op_duration",
                "The time it took to execute the given op, in millseconds",
                vec![
                    1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 300.0, 400.0, 500.0, 600.0,
                    700.0, 800.0, 900.0, 1000.0, 1200.0, 1400.0, 1600.0, 1800.0, 2000.0, 2500.0,
                    3000.0, 4000.0, 5000.0, 7000.0, 10000.0, 20000.0,
                ],
                &["op"],
            ),
            chunk_req_not_found: metrics_registry
                .int_counter("chunk_req_not_found", "number of chunk request not found"),
            artifacts_dropped: metrics_registry.int_counter(
                "p2p_gossip_artifacts_dropped",
                "Number of artifacts dropped by Gossip",
            ),
        }
    }
}
#[derive(Debug)]
pub struct DownloadManagementMetrics {
    pub op_duration: HistogramVec,
    // artifact
    pub artifacts_received: IntCounter,
    pub artifact_timeouts: IntCounter,
    pub received_artifact_size: IntGauge,
    pub integrity_hash_check_failed: IntCounter,

    // chunking
    pub chunks_requested: IntCounter,
    pub chunk_request_send_failed: IntCounter,
    pub chunks_sent: IntCounter,
    pub chunk_send_failed: IntCounter,
    pub chunks_received: IntCounter,
    pub chunks_timedout: IntCounter,
    pub chunk_delivery_time: HistogramVec,
    pub chunks_download_failed: IntCounter,
    pub chunks_not_served_from_peer: IntCounter,
    pub chunks_download_retry_attempts: IntCounter,
    pub chunks_unsolicited_or_timedout: IntCounter,
    pub chunks_redundant_residue: IntCounter,
    pub chunks_verification_failed: IntCounter,

    // advert
    pub adverts_sent: IntCounter,
    pub adverts_send_failed: IntCounter,
    pub adverts_received: IntCounter,
    pub adverts_dropped: IntCounter,

    // retransmission
    pub retransmission_requests_sent: IntCounter,
    pub retransmission_request_send_failed: IntCounter,
    pub retransmission_request_time: Histogram,

    // connection
    pub connection_up_events: IntCounter,
    pub connection_down_events: IntCounter,

    // download next stats
    pub download_next_time: IntGauge,
    pub download_next_total_entries: IntGauge,
    pub download_next_visited: IntGauge,
    pub download_next_selected: IntGauge,
    pub download_next_calls: IntCounter,
    pub download_next_retrans_requests_sent: IntCounter,
}

impl DownloadManagementMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            op_duration: metrics_registry.histogram_vec(
                "p2p_peermgmt_op_duration",
                "The time it took to execute the given op, in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms
                decimal_buckets(-4, -1),
                &["op"],
            ),

            // artifact
            artifacts_received: metrics_registry
                .int_counter("gossip_artifacts_received", "number of artifact received"),
            artifact_timeouts: metrics_registry
                .int_counter("artifact_timeouts", "number of artifact timeouts"),
            received_artifact_size: metrics_registry
                .int_gauge("gossip_received_artifact_size", "size of received artifact"),
            integrity_hash_check_failed: metrics_registry.int_counter(
                "integrity_hash_check_failed",
                "Number of times the integrity check failed for artifacts",
            ),

            // Chunks
            chunks_requested: metrics_registry.int_counter(
                "gossip_chunks_requested",
                "number of chunks that were requested",
            ),
            chunk_request_send_failed: metrics_registry.int_counter(
                "chunk_request_send_failed",
                "Number of chunk request send failures",
            ),
            chunks_received: metrics_registry
                .int_counter("gossip_chunks_received", "number of chunks received"),
            chunk_delivery_time: metrics_registry.histogram_vec(
                "gossip_chunk_delivery_time",
                "time it took to deliver a chunk after it has been requested (in milliseconds)",
                vec![
                    1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 300.0, 400.0, 500.0, 600.0,
                    700.0, 800.0, 900.0, 1000.0, 1200.0, 1400.0, 1600.0, 1800.0, 2000.0, 2500.0,
                    3000.0, 4000.0, 5000.0, 7000.0, 10000.0, 20000.0,
                ],
                &["artifact_type"],
            ),
            chunks_sent: metrics_registry
                .int_counter("gossip_chunks_sent", "number of chunks sent"),
            chunk_send_failed: metrics_registry
                .int_counter("chunkd_send_failed", "Number of chunk send faiures"),
            chunks_timedout: metrics_registry
                .int_counter("gossip_chunks_timedout", "timedout chunks"),
            connection_up_events: metrics_registry.int_counter(
                "gossip_connection_up_event",
                "number of connection up events received",
            ),
            connection_down_events: metrics_registry.int_counter(
                "gossip_connection_down_event",
                "number of connection down events received",
            ),
            chunks_download_failed: metrics_registry.int_counter(
                "gossip_chunks_download_failed",
                "Number for failed chunk downloads (for various reasons)",
            ),
            chunks_not_served_from_peer: metrics_registry.int_counter(
                "gossip_chunks_not_served_from_peer",
                "Number for time peers failed to serve a chunk",
            ),
            chunks_download_retry_attempts: metrics_registry.int_counter(
                "gossip_chunks_download_retried",
                "Number for times chunk downloads were retried",
            ),
            chunks_unsolicited_or_timedout: metrics_registry.int_counter(
                "gossip_chunks_num_unsolicited",
                "Number for unsolicited chunks recieved",
            ),
            chunks_redundant_residue: metrics_registry.int_counter(
                "gossip_chunks_redundant_residue",
                "number of chunks that were downloaded after the artifact was marked complete",
            ),
            chunks_verification_failed: metrics_registry.int_counter(
                "gossip_chunk_verification_failed",
                "number of chunks that failed verification",
            ),

            // adverts
            adverts_sent: metrics_registry.int_counter(
                "gossip_adverts_sent",
                "number of artifact advertisements sent",
            ),
            adverts_send_failed: metrics_registry
                .int_counter("adverts_send_failed", "number of advert send failures"),
            adverts_received: metrics_registry.int_counter(
                "gossip_adverts_received",
                "number of adverts received from all peers",
            ),
            adverts_dropped: metrics_registry.int_counter(
                "gossip_adverts_ignored",
                "Number of adverts that were dropped",
            ),

            // retransmission
            retransmission_requests_sent: metrics_registry.int_counter(
                "retransmission_requests_sent",
                "Number of retransmission requests successfully sent",
            ),
            retransmission_request_send_failed: metrics_registry.int_counter(
                "retransmission_request_send_failed",
                "Critical error a lagging replica isn't able to send a retransmission request",
            ),
            retransmission_request_time: metrics_registry.histogram(
                "retransmission_request_time",
                "The time it took to send retransmission request, in milliseconds",
                vec![
                    1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 300.0, 400.0, 500.0, 600.0,
                    700.0, 800.0, 900.0, 1000.0, 1200.0, 1400.0, 1600.0, 1800.0, 2000.0, 2500.0,
                    3000.0, 4000.0, 5000.0, 7000.0, 10000.0, 20000.0,
                ],
            ),

            // download next stats
            download_next_time: metrics_registry
                .int_gauge("download_next_time", "Time spent in download_next()"),
            download_next_total_entries: metrics_registry.int_gauge(
                "download_next_total_entries",
                "Total entries returned by get_peer_priority_queues()",
            ),
            download_next_visited: metrics_registry.int_gauge(
                "download_next_visited",
                "Entries checked by download_next()",
            ),
            download_next_selected: metrics_registry.int_gauge(
                "download_next_selected",
                "Entries selected for download by download_next()",
            ),
            download_next_calls: metrics_registry
                .int_counter("download_next_calls", "Num calls to download_next()"),
            download_next_retrans_requests_sent: metrics_registry.int_counter(
                "download_next_retrans_requests_sent",
                "Num of retrans requests sent",
            ),
        }
    }
}

pub struct DownloadPrioritizerMetrics {
    pub adverts_deleted_from_peer: IntCounter,
    pub priority_adverts_dropped: IntCounter,
    pub priority_fn_updates: IntCounter,
    pub priority_fn_timer: Histogram,
}

impl DownloadPrioritizerMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            adverts_deleted_from_peer: metrics_registry.int_counter(
                "priority_adverts_deleted",
                "number of adverts deleted from peer",
            ),
            priority_adverts_dropped: metrics_registry
                .int_counter("priority_adverts_dropped", "number of adverts dropped"),
            priority_fn_updates: metrics_registry.int_counter(
                "priority_fn_updates",
                "number of times priority function was updated",
            ),
            priority_fn_timer: metrics_registry.histogram(
                "priority_fn_time",
                "The time it took to update priorities with priority fns, in seconds",
                // 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0
                decimal_buckets(-1, 1),
            ),
        }
    }
}

pub struct EventHandlerMetrics {
    pub send_message_duration_msec: HistogramVec,
    pub adverts_blocked: IntCounter,
    pub requests_blocked: IntCounter,
    pub chunks_blocked: IntCounter,
    pub retransmissions_blocked: IntCounter,
}

impl EventHandlerMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            send_message_duration_msec: metrics_registry.histogram_vec(
                "send_message_duration_msec",
                "Time taken by event handler send message call, in milliseconds",
                // 1ms, 2ms, 5ms - 100 sec, 200 sec, 500 sec
                decimal_buckets(0, 5),
                &["msg_type"],
            ),
            adverts_blocked: metrics_registry
                .int_counter("adverts_blocked", "number of times advert delivery blocked"),
            chunks_blocked: metrics_registry
                .int_counter("chunks_blocked", "number of times chunks delivery blocked"),
            requests_blocked: metrics_registry
                .int_counter("requests_blocked", "number of requests delivery blocked"),
            retransmissions_blocked: metrics_registry.int_counter(
                "retransmissions_blocked",
                "number of times retransmissions delivery blocked",
            ),
        }
    }
}
