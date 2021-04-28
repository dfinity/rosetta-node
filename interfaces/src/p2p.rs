//! The P2P public interface.
use ic_types::{artifact::Artifact, messages::SignedIngress};

use crate::artifact_manager::OnArtifactError;

/// This is an event handler that can be used to submit an
/// Ingress Message to P2P events channel for processing. It encapsulates the
/// given ingress message in a GossipArtifact and sends it to P2P GossipArtifact
/// channel. It is mainly to be used by HttpHandler to submit ingress messages.
pub trait IngressEventHandler: Send + Sync {
    fn on_ingress_message(&self, message: SignedIngress) -> Result<(), OnArtifactError<Artifact>>;

    /// Checks if the user message can be accepted for processing or if it
    /// should rejected/throttled
    fn can_accept_user_request(&self) -> bool;
}

/// P2P exposes channels which are used to hold artifacts sent by
/// Transport or HttpHandler. These channels also hold any errors/notification
/// send by the Transport layer (ex. connection/disconnection with a peer).
/// P2PRunner provides the run interface which is used by replica to start
/// reading from these channels. The artifacts or notifications received from
/// these channels are sent to Gossip for processing.
pub trait P2PRunner: Send {
    fn run(&mut self);
}
