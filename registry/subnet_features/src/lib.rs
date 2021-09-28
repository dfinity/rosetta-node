use candid::CandidType;
use ic_protobuf::registry::subnet::v1 as pb;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// List of features that are enabled on the given subnet.
#[derive(CandidType, Clone, Copy, Default, Deserialize, Debug, Eq, PartialEq, Serialize)]
pub struct SubnetFeatures {
    pub ecdsa_signatures: bool,
}

impl From<SubnetFeatures> for pb::SubnetFeatures {
    fn from(features: SubnetFeatures) -> pb::SubnetFeatures {
        Self {
            ecdsa_signatures: features.ecdsa_signatures,
        }
    }
}

impl From<pb::SubnetFeatures> for SubnetFeatures {
    fn from(features: pb::SubnetFeatures) -> SubnetFeatures {
        Self {
            ecdsa_signatures: features.ecdsa_signatures,
        }
    }
}

impl FromStr for SubnetFeatures {
    type Err = String;

    fn from_str(string: &str) -> Result<Self, <Self as FromStr>::Err> {
        // Default value for bools is 'false'.
        let mut features = Self::default();

        if string.eq("None") {
            return Ok(features);
        }

        for feature in string.split(',') {
            match feature {
                "ecdsa_signatures" => features.ecdsa_signatures = true,
                _ => return Err(format!("Unknown feature {:?} in {:?}", feature, string)),
            }
        }

        Ok(features)
    }
}

#[cfg(test)]
mod tests {
    use crate::SubnetFeatures;
    use std::str::FromStr;

    #[test]
    fn test_none_is_accepted() {
        let result = SubnetFeatures::from_str("None").unwrap();
        assert_eq!(result, SubnetFeatures::default());
    }

    #[test]
    fn test_double_entries_are_handled() {
        let result = SubnetFeatures::from_str("ecdsa_signatures,ecdsa_signatures").unwrap();
        assert_eq!(
            result,
            SubnetFeatures {
                ecdsa_signatures: true,
            }
        );
    }

    #[test]
    fn test_all_can_be_set_true() {
        let result = SubnetFeatures::from_str("ecdsa_signatures").unwrap();
        assert_eq!(
            result,
            SubnetFeatures {
                ecdsa_signatures: true,
            }
        );
    }
}
