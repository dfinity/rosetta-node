use candid::CandidType;
use ic_protobuf::{proxy::ProxyDecodeError, registry::subnet::v1 as pb};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use strum_macros::EnumString;

#[derive(CandidType, Clone, Copy, Deserialize, Debug, Eq, EnumString, PartialEq, Serialize)]
pub enum SubnetType {
    #[strum(serialize = "application")]
    #[serde(rename = "application")]
    Application,
    #[strum(serialize = "system")]
    #[serde(rename = "system")]
    System,
}

impl Default for SubnetType {
    fn default() -> Self {
        SubnetType::Application
    }
}

impl From<SubnetType> for i32 {
    fn from(subnet_type: SubnetType) -> i32 {
        match subnet_type {
            SubnetType::Application => 1,
            SubnetType::System => 2,
        }
    }
}

impl TryFrom<i32> for SubnetType {
    type Error = String;

    fn try_from(input: i32) -> Result<Self, Self::Error> {
        if input == 1 {
            Ok(SubnetType::Application)
        } else if input == 2 {
            Ok(SubnetType::System)
        } else {
            Err(format!(
                "Unknown subnet type {}. Expected 1 (application) or 2 (system).",
                input
            ))
        }
    }
}

impl From<SubnetType> for pb::SubnetType {
    fn from(subnet_type: SubnetType) -> Self {
        match subnet_type {
            SubnetType::Application => Self::Application,
            SubnetType::System => Self::System,
        }
    }
}

impl TryFrom<pb::SubnetType> for SubnetType {
    type Error = ProxyDecodeError;

    fn try_from(src: pb::SubnetType) -> Result<Self, Self::Error> {
        match src {
            pb::SubnetType::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "SubnetType",
                err: format!(
                    "{:?} is not one of the expected variants of SubnetType.",
                    src,
                ),
            }),
            pb::SubnetType::Application => Ok(SubnetType::Application),
            pb::SubnetType::System => Ok(SubnetType::System),
        }
    }
}
