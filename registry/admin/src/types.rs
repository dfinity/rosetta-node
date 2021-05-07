use ic_protobuf::registry::{
    provisional_whitelist::v1::ProvisionalWhitelist as ProvisionalWhitelistProto,
    subnet::v1::{
        GossipConfig as GossipConfigProto,
        InitialDkgTranscriptRecord as InitialDkgTranscriptRecordProto,
        SubnetRecord as SubnetRecordProto,
    },
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_types::{NodeId, PrincipalId};
use serde::Serialize;
use std::convert::{From, TryFrom};

/// All or part of the registry
#[derive(Default, Serialize)]
pub(crate) struct Registry {
    /// The registry version being shown
    pub version: u64, //RegistryVersion,

    /// 0 or more RegistryRecord, depending on what was requested
    pub records: Vec<RegistryRecord>,
}

/// The contents of a single record
#[derive(Default, Serialize)]
pub(crate) struct RegistryRecord {
    pub key: String,
    pub version: u64,
    pub value: RegistryValue,
}

/// The types of RegistryRecorsds that can be serialized to user friendly JSON
#[derive(Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum RegistryValue {
    Unknown,
    SubnetRecord(SubnetRecord),
    ProvisionalWhitelistRecord(ProvisionalWhitelistRecord),
}

impl Default for RegistryValue {
    fn default() -> Self {
        RegistryValue::Unknown
    }
}

/// User-friendly representation of a v1::SubnetRecord. Only difference is that
/// the `membership` field is a `Vec<String>` to pretty-print the node IDs.
#[derive(Default, Serialize)]
pub(crate) struct SubnetRecord {
    pub membership: Vec<String>,
    pub initial_dkg_transcript: Option<InitialDkgTranscriptRecordProto>,
    pub ingress_bytes_per_block_soft_cap: u64,
    pub max_ingress_bytes_per_message: u64,
    pub unit_delay_millis: u64,
    pub initial_notary_delay_mills: u64,
    pub replica_version_id: String,
    pub dkg_interval_length: u64,
    pub gossip_config: Option<GossipConfigProto>,
    pub start_as_nns: bool,
    pub subnet_type: SubnetType,
}

impl From<&SubnetRecordProto> for SubnetRecord {
    /// Convert a v1::SubnetRecord to a SubnetRecord. Most data is passed
    /// through unchanged, except the `membership` list, which is converted
    /// to a `Vec<String>` for nicer display.
    fn from(value: &SubnetRecordProto) -> Self {
        Self {
            membership: value
                .membership
                .iter()
                .map(|n| {
                    NodeId::from(
                        PrincipalId::try_from(&n[..])
                            .expect("could not create PrincipalId from membership entry"),
                    )
                    .to_string()
                })
                .collect(),
            initial_dkg_transcript: value.initial_dkg_transcript.clone(),
            ingress_bytes_per_block_soft_cap: value.ingress_bytes_per_block_soft_cap,
            max_ingress_bytes_per_message: value.max_ingress_bytes_per_message,
            unit_delay_millis: value.unit_delay_millis,
            initial_notary_delay_mills: value.initial_notary_delay_millis,
            replica_version_id: value.replica_version_id.clone(),
            dkg_interval_length: value.dkg_interval_length,
            gossip_config: value.gossip_config.clone(),
            start_as_nns: value.start_as_nns,
            subnet_type: SubnetType::try_from(value.subnet_type).unwrap(),
        }
    }
}

/// User-friendly representation of a v1::ProvisionalWhitelist.
/// The principal IDs are parsed into their text representations.
#[derive(Serialize)]
pub(crate) enum ProvisionalWhitelistRecord {
    Set(Vec<String>),
    All,
}

impl From<ProvisionalWhitelistProto> for ProvisionalWhitelistRecord {
    fn from(value: ProvisionalWhitelistProto) -> Self {
        match ProvisionalWhitelist::try_from(value).unwrap() {
            ProvisionalWhitelist::All => Self::All,
            ProvisionalWhitelist::Set(set) => Self::Set(
                set.into_iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<String>>(),
            ),
        }
    }
}
