use async_trait::async_trait;
use ic_types::messages::SignedIngress;

pub type IngressError = String;

/// This is an event handler that can be used to submit an
/// Ingress Message to P2P events channel for processing. It encapsulates the
/// given ingress message in a GossipArtifact and sends it to P2P GossipArtifact
/// channel. It is mainly to be used by HttpHandler to submit ingress messages.
/// TODO: Make it such that it does not need to wrapped into a GossipArtifact
pub trait IngressEventHandler: Send + Sync {
    fn on_ingress_message(&self, message: SignedIngress) -> Result<(), IngressError>;

    /// Checks if the user message can be accepted for processing or if it
    /// should rejected/throttled
    fn can_accept_user_request(&self) -> bool;
}

// Async version of the ingress event handler
#[async_trait]
pub trait AsyncIngressEventHandler: Send + Sync {
    async fn send_ingress_message(&mut self, message: SignedIngress) -> Result<(), IngressError>;
}

/// P2P exposes channels which are used to hold artifacts sent by
/// Transport or HttpHandler. These channels also hold any errors/notification
/// send by the Transport layer (ex. connection/disconnection with a peer).
/// P2PRunner provides the run interface which is used by replica to start
/// reading from these channels. The artifacts or notifications received from
/// these channels are sent to Gossip for processing.
#[async_trait]
pub trait P2PRunner: Send {
    fn run(&mut self);
    async fn stop(&mut self);
    /// This is required for tests that cannot call the async stop().
    /// Example: replica tests that expect a panic need to do the clean up
    /// from Drop::drop(). Drop is sync and hence can't use the async version.
    fn stop_blocking(&mut self);
}
