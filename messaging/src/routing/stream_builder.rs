use crate::message_routing::LatencyMetrics;
use ic_logger::{error, trace, warn, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_replicated_state::{canister_state::QUEUE_INDEX_NONE, ReplicatedState};
use ic_types::{
    messages::{Payload, RejectContext, Request, RequestOrResponse, Response},
    user_error::RejectCode,
    xnet::QueueId,
    CanisterId, QueueIndex, SubnetId,
};
#[cfg(test)]
use mockall::automock;
use prometheus::{Histogram, IntCounterVec, IntGaugeVec};
use std::sync::{Arc, Mutex};

#[cfg(test)]
mod tests;

struct StreamBuilderMetrics {
    /// Messages currently enqueued in streams, by destination subnet.
    pub stream_messages: IntGaugeVec,
    /// Routed XNet messages, by type and status.
    pub routed_messages: IntCounterVec,
    /// Successfully routed XNet messages' total payload size.
    pub routed_payload_sizes: Histogram,
}

const METRIC_STREAM_MESSAGES: &str = "mr_stream_messages";
const METRIC_ROUTED_MESSAGES: &str = "mr_routed_message_count";
const METRIC_ROUTED_PAYLOAD_SIZES: &str = "mr_routed_payload_size_bytes";

const LABEL_TYPE: &str = "type";
const LABEL_STATUS: &str = "status";
const LABEL_DESTINATION: &str = "destination";

const LABEL_VALUE_TYPE_REQUEST: &str = "request";
const LABEL_VALUE_TYPE_RESPONSE: &str = "response";
const LABEL_VALUE_STATUS_SUCCESS: &str = "success";
const LABEL_VALUE_STATUS_CANISTER_NOT_FOUND: &str = "canister_not_found";

impl StreamBuilderMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        let stream_messages = metrics_registry.int_gauge_vec(
            METRIC_STREAM_MESSAGES,
            "Messages currently enqueued in streams, by destination subnet.",
            &[LABEL_DESTINATION],
        );
        let routed_messages = metrics_registry.int_counter_vec(
            METRIC_ROUTED_MESSAGES,
            "Routed XNet messages, by type and status.",
            &[LABEL_TYPE, LABEL_STATUS],
        );
        let routed_payload_sizes = metrics_registry.histogram(
            METRIC_ROUTED_PAYLOAD_SIZES,
            "Successfully routed XNet messages' total payload size.",
            // 10 B - 5 MB
            decimal_buckets(1, 6),
        );

        // Initialize all `routed_messages` counters with zero, so they are all exported
        // from process start (`IntCounterVec` is really a map).
        for (msg_type, status) in &[
            (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_STATUS_SUCCESS),
            (
                LABEL_VALUE_TYPE_REQUEST,
                LABEL_VALUE_STATUS_CANISTER_NOT_FOUND,
            ),
            (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_STATUS_SUCCESS),
            (
                LABEL_VALUE_TYPE_RESPONSE,
                LABEL_VALUE_STATUS_CANISTER_NOT_FOUND,
            ),
        ] {
            routed_messages.with_label_values(&[msg_type, status]);
        }

        Self {
            stream_messages,
            routed_messages,
            routed_payload_sizes,
        }
    }
}

/// Interface for the StreamBuilder sub-component.  Invoked by the
/// Coordinator.
#[cfg_attr(test, automock)]
pub(crate) trait StreamBuilder: Send {
    /// Build all streams from the messages and signals that are pending (i.e.,
    /// have been added but not yet moved into a stream.
    fn build_streams(&self, state: ReplicatedState) -> ReplicatedState;
}

pub(crate) struct StreamBuilderImpl {
    subnet_id: SubnetId,
    metrics: StreamBuilderMetrics,
    time_in_stream_metrics: Arc<Mutex<LatencyMetrics>>,
    log: ReplicaLogger,
}

impl StreamBuilderImpl {
    pub(crate) fn new(
        subnet_id: SubnetId,
        metrics_registry: &MetricsRegistry,
        time_in_stream_metrics: Arc<Mutex<LatencyMetrics>>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            subnet_id,
            metrics: StreamBuilderMetrics::new(metrics_registry),
            time_in_stream_metrics,
            log,
        }
    }

    /// Enqueues a reject Response to a request from a local canister into the
    /// canister's input queue.
    fn reject_local_request(
        &self,
        state: &mut ReplicatedState,
        req: Request,
        reject_code: RejectCode,
        reject_message: String,
    ) {
        state
            .push_input(
                QUEUE_INDEX_NONE,
                Response {
                    originator: req.sender,
                    respondent: req.receiver,
                    originator_reply_callback: req.sender_reply_callback,
                    refund: req.payment,
                    response_payload: Payload::Reject(RejectContext {
                        code: reject_code,
                        message: reject_message,
                    }),
                }
                .into(),
            )
            .unwrap();
    }

    /// Records the result of routing an XNet message.
    fn observe_message_status(&self, msg: &RequestOrResponse, status: &str) {
        let msg_type = match msg {
            RequestOrResponse::Request(_) => LABEL_VALUE_TYPE_REQUEST,
            RequestOrResponse::Response(_) => LABEL_VALUE_TYPE_RESPONSE,
        };
        self.metrics
            .routed_messages
            .with_label_values(&[msg_type, status])
            .inc();
    }

    /// Records the size of a successfully routed XNet message payload.
    fn observe_payload_size(&self, msg: &RequestOrResponse) {
        let payload_size = match msg {
            RequestOrResponse::Request(req) => req.method_payload.len() as u64,
            RequestOrResponse::Response(res) => res.response_payload.size_of().get(),
        };
        self.metrics
            .routed_payload_sizes
            .observe(payload_size as f64);
    }
}

impl StreamBuilder for StreamBuilderImpl {
    fn build_streams(&self, mut state: ReplicatedState) -> ReplicatedState {
        trace!(self.log, "Building streams");
        let mut streams = state.take_streams();

        // Extract all of the outgoing messages from the output queues into a
        // collection.
        let mut msg_set: Vec<(QueueId, QueueIndex, RequestOrResponse)> = state
            .canisters_iter_mut()
            .flat_map(|canister| canister.output_into_iter())
            .collect();

        for subnet_msg in state
            .subnet_queues
            .output_into_iter(CanisterId::from(self.subnet_id))
        {
            msg_set.push(subnet_msg);
        }

        // Place all messages into the appropriate stream or generate reject Responses
        // when unable to (canister not found).
        for (queue_id, _queue_index, msg) in msg_set {
            let src_canister_id = queue_id.src_canister;
            let dst_canister_id = queue_id.dst_canister;

            match state
                .metadata
                .network_topology
                .routing_table
                .route(dst_canister_id.get())
            {
                // Destination subnet found.
                Some(dst_net_id) => {
                    // Insert the message into the stream.
                    self.observe_message_status(&msg, LABEL_VALUE_STATUS_SUCCESS);
                    self.observe_payload_size(&msg);
                    streams.entry(dst_net_id).or_default().messages.push(msg);
                }

                // Destination subnet not found.
                None => {
                    warn!(self.log, "Canister {} not found", dst_canister_id);
                    self.observe_message_status(&msg, LABEL_VALUE_STATUS_CANISTER_NOT_FOUND);
                    match msg {
                        // A Request: generate a reject Response.
                        RequestOrResponse::Request(req) => {
                            self.reject_local_request(
                                &mut state,
                                req,
                                RejectCode::DestinationInvalid,
                                format!("Canister {} does not exist", dst_canister_id),
                            );
                        }

                        RequestOrResponse::Response(_) => {
                            // A Response: discard it.
                            error!(
                                self.log,
                                "Discarding response from canister {}.", src_canister_id
                            );
                        }
                    }
                }
            };
        }

        // Export the total number of enqueued messages.
        streams
            .iter()
            .map(|(subnet, stream)| (subnet, stream.messages.len()))
            .for_each(|(subnet, len)| {
                self.metrics
                    .stream_messages
                    .with_label_values(&[&subnet.to_string()])
                    .set(len as i64);
            });

        {
            let mut time_in_stream_metrics = self.time_in_stream_metrics.lock().unwrap();
            for (subnet_id, stream) in &streams {
                if *subnet_id == self.subnet_id {
                    continue;
                }
                time_in_stream_metrics.observe_header(*subnet_id, &stream.header());
            }
        }

        // Put the updated CanisterStates (outgoing messages removed) and Streams
        // (messages added) into the ReplicatedState to be returned.
        state.put_streams(streams);
        state
    }
}
