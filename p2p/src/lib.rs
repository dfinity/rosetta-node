//! <h1>Overview</h1>
//!
//! The peer-to-peer (P2P) component implements a gossiping mechanism for
//! subnets and creates and validates ingress message payloads for the
//! *Consensus* layer. It contains the following sub-components:

//!
//! * *Gossip*: Disseminate artifacts to other nodes in the same subnet. This is
//!   achieved by an advertise-request-response mechanism, taking priorities
//!   into account.
//! * *Artifact Manager*: Store artifacts to be used by this and other nodes in
//!  the same subnet in the artifact pool. The artifact manager interacts with
//! *Gossip* and its application components:
//!     * *Consensus*
//!     * *Distributed Key Generation*
//!     * *Certification*
//!     * *Ingress Manager*
//!     * *State Sync*
//! * *Ingress Manager*: Processes ingress messages, providing the following
//!   functionality:
//!     * Check ingress message validity of messages received from other nodes
//!       and broadcast valid ingress messages
//!     * Select ingress message to form *Consensus* payloads
//!     * Validate such payloads

//! <h1>Bounded-time/Eventual Delivery</h1>
//!
//! * P2P guarantees that, up to a certain maximum volume, valid artifacts reach
//!   all nodes subject to constraints due to prioritisation and the
//!   applications' validation policies. More precisely, *Gossip* guarantees the
//!   delivery of artifacts of a bounded aggregate size within bounded
//!   time/eventually under certain network assumptions and provided that the
//!   rules and validity conditions specified by the application components are
//!   satisfied. Thus, valid artifacts that are of high priority for all nodes
//!   will reach all honest nodes in bounded time/eventually, despite attacks
//!   (under certain network assumptions). In other words, the priority function
//!   ensures that relevant valid artifacts reach enough nodes in the subnet,
//!   while artifacts that violate the policy or are of low priority may not
//!   reach all other nodes in the subnet.
//! * Eventual delivery differs from eventual consistency. Consistency models
//!   describe the contract between users and a system offering reading and
//!   writing to replicated state. Informally, eventual consistency guarantees
//!   that if no write occurs for a long time, all replicas return the same
//!   value for reads. *Consensus* does **not** require eventual consistency for
//!   the artifact pool: the priority function can drop adverts without
//!   requesting the artifact and different (valid) artifacts with the same
//!   identifier may exist in the system and *Consensus* often only needs at
//!   most one of them. Moreover, the offered guarantees are subject to
//!   bandwidth restrictions on all honest peers.

//! <h1>Performance</h1>
//!
//! * Low number of open connections: An overlay topology defines which nodes
//!   exchange artifacts directly with each other. Together with the
//!   bounded-time/eventual delivery guarantee mentioned above, the topology
//!   ensures that enough honest nodes receive artifacts to make progress. Since
//!   the overlay topology describes which connections are established and
//!   maintained, it enables the broadcast protocol to trade off bandwidth
//!   consumption with latency.
//! * High throughput and predictability: Bandwidth must not be wasted on
//!   sending/receiving the same artifact twice. The behavior under load must be
//!   predictable (memory/bandwidth/CPU guarantees for different peers and for
//!   different components using gossip).
//! * Prioritization: Different artifacts are transferred with different
//!   priorities, and priorities change over time.

//! <h1>Ingress Manager</h1>
//!
//! * Validity: ingress messages are broadcast to other peers only if they are
//!   valid.
//! * At-most-once semantics: an ingress message is selected to be in a
//!   *Consensus* payload at most once before its expiry time and only if it is
//!   valid (even if a node restarts).

//! <h1>Dependencies</h1>
//! P2P relies on the following components:
//!
//! * *Transport* for node-to-node communication.
//! * *HTTP handler* to submit validated ingress messages.
//! * *Consensus* to pass the Internet Computer time as well as finalized
//!   payloads and non-finalized payloads since the last executed height in the
//!   chain.
//! * *Registry* to look up subnet IDs, node IDs, and configuration values.
//! * *Crypto* to verify signatures in the *Ingress Manager*.
//! * *Ingress History Reader* to prevent duplicate Ingress Messages in blocks

//! <h1>Component Diagram</h1>
//!
//! The following diagram depicts the interfaces between the P2P components and
//! other components. The interaction with the *Registry* is omitted for
//! simplicity's sake as all components rely on it.
//!
//! <div>
//! <img src="../../../../../docs/assets/p2p.png" height="960"
//! width="540"/> </div> <hr/>

use serde::{Deserialize, Serialize};
use std::{
    error,
    fmt::{Display, Formatter, Result as FmtResult},
};

mod artifact_download_list;
mod download_management;
mod download_prioritization;
mod event_handler;
mod gossip_protocol;
mod malicious_gossip;
mod metrics;
pub mod p2p;

/// Custom P2P result type returning a P2P error in case of error.
pub(crate) type P2PResult<T> = std::result::Result<T, P2PError>;

pub(crate) mod utils {
    //! The utils module provides a mapping from a gossip message to the
    //! corresponding flow tag.
    use ic_types::transport::FlowTag;

    use crate::gossip_protocol::GossipMessage;

    /// The FlowMapper struct holds a vector of flow tags.
    pub(crate) struct FlowMapper {
        flow_tags: Vec<FlowTag>,
    }

    impl FlowMapper {
        /// The function creates a new FlowMapper instance.
        pub(crate) fn new(flow_tags: Vec<FlowTag>) -> Self {
            assert_eq!(flow_tags.len(), 1);
            Self { flow_tags }
        }

        /// The function returns the flow tag of the flow the message maps to.
        pub(crate) fn map(&self, _msg: &GossipMessage) -> FlowTag {
            self.flow_tags[0]
        }
    }
}

/// Generic P2P Error codes.
///
/// Some error codes are serialized over the wire to convey
/// protocol results. Some results are also used for internal
/// operation, i.e., they are not represented in the on-wire protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum P2PErrorCode {
    /// The requested entity artifact/chunk/server/client was not found
    NotFound = 1,
    /// An artifact (chunk) was received that already exists.
    Exists,
    /// An internal operation failed.
    Failed,
    /// The operation cannot be performed at this time.
    Busy,
    /// P2P initialization failed.
    InitFailed,
    /// Send/receive failed because the channel was disconnected.
    ChannelShutDown,
}

/// Wrapper over a P2P error code.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct P2PError {
    /// The P2P error code.
    p2p_error_code: P2PErrorCode,
}

/// Implement the `Display` trait to print/display P2P error codes.
impl Display for P2PError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "P2PErrorCode: {:?}", self.p2p_error_code)
    }
}

/// Implement the `Error` trait to wrap P2P errors.
impl error::Error for P2PError {
    /// The function returns `None` as the underlying cause is not tracked.
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

/// A P2P error code can be converted into a P2P result.
impl<T> From<P2PErrorCode> for P2PResult<T> {
    /// The function converts a P2P error code to a P2P result.
    fn from(p2p_error_code: P2PErrorCode) -> P2PResult<T> {
        Err(P2PError { p2p_error_code })
    }
}
