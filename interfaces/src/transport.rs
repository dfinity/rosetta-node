//! Transport layer public interface.

use std::sync::Arc;

use ic_protobuf::registry::node::v1::NodeRecord;
use ic_types::transport::{
    FlowId, FlowTag, TransportClientContext, TransportClientType, TransportErrorCode,
    TransportPayload, TransportStateChange,
};
use ic_types::{NodeId, RegistryVersion};

/// Transport layer APIs.
pub trait Transport: Send + Sync {
    /// Register the transport client of the specified type. No more than one
    /// module can register against a particular client type. This returns a
    /// handle to the client's context, which should be supplied in all the
    /// future interactions with the transport layer.
    fn register_client(
        &self,
        client_type: TransportClientType,
        event_handler: Arc<dyn TransportEventHandler>,
    ) -> Result<TransportClientContext, TransportErrorCode>;

    /// Mark the peer as valid neighbor, and set up the transport layer to
    /// exchange messages with the peer. This call would create the
    /// necessary wiring in the transport layer for the peer:
    /// - 1. Set up the Tx/Rx queueing, based on TransportQueueConfig.
    /// - 2. If the peer is the server, initiate connection requests to the peer
    ///   server ports.
    /// - 3. If the peer is the client, set up the connection state to accept
    ///   connection requests from the peer.
    fn start_connections(
        &self,
        client_context: &TransportClientContext,
        peer: &NodeId,
        node_record: &NodeRecord,
        registry_version: RegistryVersion,
    ) -> Result<(), TransportErrorCode>;

    /// Remove the peer from the set of valid neighbors, and tear down the
    /// queues and connections for the peer. Any messages in the Tx and Rx
    /// queues for the peer will be discarded.
    fn stop_connections(
        &self,
        client_context: &TransportClientContext,
        peer_id: &NodeId,
        registry_version: RegistryVersion,
    ) -> Result<(), TransportErrorCode>;

    /// Send the message to the specified peer. The message will be enqueued
    /// into the appropriate TxQ based on the TransportQueueConfig.
    fn send(
        &self,
        client_context: &TransportClientContext,
        peer_id: &NodeId,
        flow_tag: FlowTag,
        message: TransportPayload,
    ) -> Result<(), TransportErrorCode>;

    /// Clear any unsent messages in all the send queues for the peer.
    /// TODO: add a per-flow equivalent
    fn clear_send_queues(
        &self,
        client_context: &TransportClientContext,
        peer_id: &NodeId,
    ) -> Result<(), TransportErrorCode>;
}

pub trait TransportEventHandler: Send + Sync {
    /// Invoked by the transport layer when a message is received from the
    /// network. This is implemented by the transport clients to
    /// receive/process the messages.
    /// Returns the message back if it was not accepted.
    fn on_message(&self, flow: FlowId, message: TransportPayload) -> Option<TransportPayload>;

    /// Invoked by the transport layer to notify of any changes in the state.
    fn on_state_change(&self, state_change: TransportStateChange);
}
