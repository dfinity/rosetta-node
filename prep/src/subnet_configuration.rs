use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Result;
use thiserror::Error;

use ic_crypto::{
    threshold_sig_public_key_to_der,
    utils::ni_dkg::{self, initial_ni_dkg_transcript_record_from_transcript, InitialNiDkgConfig},
};
use ic_protobuf::registry::{
    crypto::v1::PublicKey,
    subnet::v1::{CatchUpPackageContents, SubnetRecord},
};
use ic_registry_common::bootstrap_registry_data_provider::INITIAL_REGISTRY_VERSION;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    crypto::{
        threshold_sig::{
            ni_dkg::{NiDkgTag, NiDkgTargetId},
            ThresholdSigPublicKey, ThresholdSigPublicKeyBytesConversionError,
        },
        CryptoError,
    },
    p2p, Height, NodeId, PrincipalId, ReplicaVersion, SubnetId,
};

use crate::node::{InitializedNode, NodeConfiguration, NodeConfigurationTryFromError, NodeIndex};
use crate::{initialized_subnet::InitializedSubnet, node::InitializeNodeError};

const UNIT_DELAY: Duration = Duration::from_millis(2000);
const INITIAL_NOTARY_DELAY: Duration = Duration::from_millis(2500);
const INGRESS_BYTES_PER_BLOCK_SOFT_CAP: u64 = 2 * 1024 * 1024;
const MAX_INGRESS_MESSAGES_PER_BLOCK: u64 = 1000;

pub type SubnetIndex = u64;

/// This sets the upper bound on how big a single ingress message can be, as
/// allowing messages larger than around 3MB has various security and
/// performance impacts on the network.  More specifically, large messages can
/// allow dishonest block makers to always manage to get their blocks notarized;
/// and when the consensus protocol is configured for smaller messages, a large
/// message in the network can cause the finalization rate to drop.
const MAX_INGRESS_BYTES_PER_MESSAGE: u64 = 3 * 1024 * 1024;

/// The default length for a DKG interval. This is the number of rounds we would
/// have after a DKG summary block, making the total length
/// `DKG_INTERVAL_LENGTH` + 1.
const DKG_INTERVAL_LENGTH: Height = Height::new(99);

/// The default upper bound for the number of allowed dkg dealings in a block.
const DKG_DEALINGS_PER_BLOCK: usize = 1;

/// This represents the initial configuration of an NNS subnetwork of an IC
/// instance.
#[derive(Clone, Debug, Default)]
pub struct SubnetConfig {
    /// The subnet id of this subnetwork.
    pub subnet_index: u64,

    /// The node ids that belong to this subnetwork.
    pub membership: BTreeMap<NodeIndex, NodeConfiguration>,

    /// soft cap on the maximum size of a block, i.e. if the total size of a
    /// block exceeds `max_ingress_bytes_per_block`, no more messages can be
    /// added.
    pub ingress_bytes_per_block_soft_cap: u64,

    /// maximum size of an ingress message
    pub max_ingress_bytes_per_message: u64,

    /// maximum number of ingress message per block
    pub max_ingress_messages_per_block: u64,

    /// Notarization delay parameters.
    pub unit_delay: Duration,
    pub initial_notary_delay: Duration,

    /// The length of a DKG interval.
    pub dkg_interval_length: Height,

    /// The upper bound for the number of dealings we allow in a block.
    pub dkg_dealings_per_block: usize,

    /// The version of the replica binary
    pub replica_version_id: ReplicaVersion,

    /// The type of the subnet
    pub subnet_type: SubnetType,
}

#[derive(Error, Debug)]
pub enum InitializeSubnetError {
    #[error("converting node to proto failed: {source}")]
    TryFrom {
        #[from]
        source: NodeConfigurationTryFromError,
    },

    #[error("threshold signature public key: {source}")]
    ThresholdSigPublicKey {
        #[from]
        source: ThresholdSigPublicKeyBytesConversionError,
    },

    #[error("crypto error: {source}")]
    Crypto {
        #[from]
        source: CryptoError,
    },

    #[error("saving node id to {path:?} failed: {source}")]
    SavingNodeId { source: io::Error, path: PathBuf },

    #[error("initializing node failed: {source}")]
    InitializeNode {
        #[from]
        source: InitializeNodeError,
    },
}

impl SubnetConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subnet_index: u64,
        membership: BTreeMap<NodeIndex, NodeConfiguration>,
        replica_version_id: Option<ReplicaVersion>,
        ingress_bytes_per_block_soft_cap: Option<u64>,
        max_ingress_bytes_per_message: Option<u64>,
        max_ingress_messages_per_block: Option<u64>,
        unit_delay: Option<Duration>,
        initial_notary_delay: Option<Duration>,
        dkg_interval_length: Option<Height>,
        dkg_dealings_per_block: Option<usize>,
        subnet_type: SubnetType,
    ) -> Self {
        Self {
            subnet_index,
            membership,
            replica_version_id: replica_version_id.unwrap_or_else(ReplicaVersion::default),
            ingress_bytes_per_block_soft_cap: ingress_bytes_per_block_soft_cap
                .unwrap_or(INGRESS_BYTES_PER_BLOCK_SOFT_CAP),
            max_ingress_bytes_per_message: max_ingress_bytes_per_message
                .unwrap_or(MAX_INGRESS_BYTES_PER_MESSAGE),
            max_ingress_messages_per_block: max_ingress_messages_per_block
                .unwrap_or(MAX_INGRESS_MESSAGES_PER_BLOCK),
            unit_delay: unit_delay.unwrap_or(UNIT_DELAY),
            initial_notary_delay: initial_notary_delay.unwrap_or(INITIAL_NOTARY_DELAY),
            dkg_interval_length: dkg_interval_length.unwrap_or(DKG_INTERVAL_LENGTH),
            dkg_dealings_per_block: dkg_dealings_per_block.unwrap_or(DKG_DEALINGS_PER_BLOCK),
            subnet_type,
        }
    }

    pub fn initialize<P: AsRef<Path>>(
        self,
        subnet_path: P,
    ) -> Result<InitializedSubnet, InitializeSubnetError> {
        let subnet_config = self.clone();
        let subnet_path = PathBuf::from(subnet_path.as_ref());
        let subnet_index = self.subnet_index;
        let mut initialized_nodes: BTreeMap<NodeIndex, InitializedNode> = BTreeMap::new();

        for (node_index, node_config) in self.membership {
            let node_path = InitializedSubnet::build_node_path(subnet_path.as_path(), node_index);
            let initialized_node = node_config.initialize(node_path.as_path())?;
            initialized_nodes.insert(node_index, initialized_node);
        }

        let nodes_in_subnet: BTreeSet<NodeId> = initialized_nodes
            .values()
            .map(|initalized_node| initalized_node.node_id)
            .collect();

        let membership_nodes: Vec<Vec<u8>> = nodes_in_subnet
            .iter()
            .map(|node_id| node_id.clone().get().into_vec())
            .collect();

        let subnet_record = SubnetRecord {
            membership: membership_nodes,
            initial_dkg_transcript: None,
            ingress_bytes_per_block_soft_cap: self.ingress_bytes_per_block_soft_cap,
            max_ingress_bytes_per_message: self.max_ingress_bytes_per_message,
            max_ingress_messages_per_block: self.max_ingress_messages_per_block,
            unit_delay_millis: self.unit_delay.as_millis() as u64,
            initial_notary_delay_millis: self.initial_notary_delay.as_millis() as u64,
            replica_version_id: self.replica_version_id.to_string(),
            dkg_interval_length: self.dkg_interval_length.get(),
            dkg_dealings_per_block: self.dkg_dealings_per_block as u64,
            gossip_config: Some(p2p::build_default_gossip_config()),
            // This is not something ic-prep will participate in, so it is safe
            // to set it to false. ic-admin can set it to true when adding a
            // subnet via NNS.
            start_as_nns: false,
            subnet_type: self.subnet_type.into(),
            is_halted: false,
        };

        let dkg_dealing_encryption_pubkeys: BTreeMap<_, _> = initialized_nodes
            .values()
            .map(|initialized_node| {
                (
                    initialized_node.node_id,
                    initialized_node.dkg_dealing_encryption_pubkey.clone(),
                )
            })
            .collect();
        let random_ni_dkg_target_id = NiDkgTargetId::new(rand::random::<[u8; 32]>());
        let ni_dkg_transcript_low_threshold = ni_dkg::initial_dkg_transcript(
            InitialNiDkgConfig::new(
                &nodes_in_subnet,
                SubnetId::from(PrincipalId::new_subnet_test_id(subnet_index)),
                NiDkgTag::LowThreshold,
                random_ni_dkg_target_id,
                INITIAL_REGISTRY_VERSION,
            ),
            &dkg_dealing_encryption_pubkeys,
        );
        let ni_dkg_transcript_high_threshold = ni_dkg::initial_dkg_transcript(
            InitialNiDkgConfig::new(
                &nodes_in_subnet,
                SubnetId::from(PrincipalId::new_subnet_test_id(subnet_index)),
                NiDkgTag::HighThreshold,
                random_ni_dkg_target_id,
                INITIAL_REGISTRY_VERSION,
            ),
            &dkg_dealing_encryption_pubkeys,
        );
        let subnet_threshold_signing_public_key = PublicKey::from(ThresholdSigPublicKey::from(
            &ni_dkg_transcript_high_threshold,
        ));

        let subnet_dkg = CatchUpPackageContents {
            initial_ni_dkg_transcript_low_threshold: Some(
                initial_ni_dkg_transcript_record_from_transcript(ni_dkg_transcript_low_threshold),
            ),
            initial_ni_dkg_transcript_high_threshold: Some(
                initial_ni_dkg_transcript_record_from_transcript(ni_dkg_transcript_high_threshold),
            ),
            ..Default::default()
        };

        let pk = ThresholdSigPublicKey::try_from(subnet_threshold_signing_public_key.clone())?;
        let der_pk = threshold_sig_public_key_to_der(pk)?;
        let subnet_id = SubnetId::from(PrincipalId::new_self_authenticating(&der_pk[..]));

        Ok(InitializedSubnet {
            subnet_index,
            subnet_id,
            initialized_nodes,
            subnet_record,
            subnet_dkg,
            subnet_threshold_signing_public_key,
            subnet_path,
            subnet_config,
        })
    }
}
