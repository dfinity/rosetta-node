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
pub(crate) type P2PResult<T> = std::result::Result<T, P2PError>;

pub(crate) mod utils {
    use ic_types::transport::FlowTag;

    use crate::gossip_protocol::GossipMessage;

    pub(crate) struct FlowMapper {
        flow_tags: Vec<FlowTag>,
    }

    impl FlowMapper {
        pub(crate) fn new(flow_tags: Vec<FlowTag>) -> Self {
            assert_eq!(flow_tags.len(), 1);
            Self { flow_tags }
        }

        // Returns the flow tag of the flow the message maps to
        pub(crate) fn map(&self, _msg: &GossipMessage) -> FlowTag {
            self.flow_tags[0]
        }
    }
}

/// Generic P2P Error codes.
///
///
/// some error codes are also serialized over the wire to convey
/// protocol results. Some results are also used for internal
/// operation i.e. the are not represented in the on-wire protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum P2PErrorCode {
    NotFound = 1,    // Protocol: Requested entity artifact/chunk/server/client not found
    Exists,          // Protocol: Received a artifact/chunk that already exists
    Failed,          // Internal operation failed
    Busy,            // Cannot perform operation at this time
    InitFailed,      // P2P Initialization failed
    ChannelShutDown, // Send/receive failed as channel was disconnected
}

/// Wrapper over the P2P Error code.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct P2PError {
    p2p_error_code: P2PErrorCode,
}

/// Print/display P2PError code
impl Display for P2PError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "P2PErrorCode: {:?}", self.p2p_error_code)
    }
}

// This is important for other errors to wrap this one.
impl error::Error for P2PError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl<T> From<P2PErrorCode> for P2PResult<T> {
    fn from(p2p_error_code: P2PErrorCode) -> P2PResult<T> {
        Err(P2PError { p2p_error_code })
    }
}
