use ic_types::messages::SignedIngress;

pub type IngressError = String;

/// This is an event handler that can be used to submit an
/// Ingress Message to P2P events channel for processing. It encapsulates the
/// given ingress message in a GossipArtifact and sends it to P2P GossipArtifact
/// channel. It is mainly to be used by HttpHandler to submit ingress messages.
/// TODO: Make it such that it does not need to wrapped into a GossipArtifact
pub trait IngressEventHandler: Send + Sync {
    fn on_ingress_message(&self, message: SignedIngress) -> Result<(), IngressError>;
}

/// P2P exposes channels which are used to hold artifacts sent by
/// Transport or HttpHandler. These channels also hold any errors/notification
/// send by the Transport layer (ex. connection/disconnection with a peer).
/// P2PRunner provides the run interface which is used by replica to start
/// reading from these channels. The artifacts or notifications received from
/// these channels are sent to Gossip for processing.
pub trait P2PRunner {
    fn run(&self);
    fn stop(&mut self);
}
