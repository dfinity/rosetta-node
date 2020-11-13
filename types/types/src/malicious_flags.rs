// This file defines a global struct to control which
// malicious behavior to enable in different components
// Both struct and fields have to be public

// Introducing a new malicious behavior starts with extanding
// this component struct with a new flag
//

// It is desirable to have a description for each flag in this file

use serde::{Deserialize, Serialize};

//
//
//
#[derive(Clone, Default, Deserialize, Debug, PartialEq, Eq, Serialize)]
pub struct MaliciousFlagsStruct {
    // malicious gossip does not send requested artifacts
    pub maliciously_gossip_drop_requests: bool,
    pub maliciously_gossip_artifact_not_found: bool,
    pub maliciously_gossip_send_many_artifacts: bool,
    pub maliciously_gossip_send_invalid_artifacts: bool,
    pub maliciously_gossip_send_late_artifacts: bool,
    pub maliciously_equivocation_blockmaker: bool,
    pub maliciously_notary: bool,
    pub maliciously_dkg: bool,
    pub maliciously_certification: bool,
    pub maliciously_malfunctioning_xnet_endpoint: bool,
    pub maliciously_disable_execution: bool,
}
