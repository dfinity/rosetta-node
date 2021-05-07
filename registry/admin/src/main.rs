mod authz;
mod routing_table;
mod types;

extern crate chrono;
use candid::{CandidType, Decode, Encode};
use chrono::prelude::{DateTime, NaiveDateTime, Utc};
use clap::Clap;
use ed25519_dalek::Keypair;
use futures::future::join_all;
use ic_canister_client::{Agent, Sender};
use ic_crypto::threshold_sig_public_key_to_der;
use ic_crypto_utils_basic_sig::conversions::Ed25519SecretKeyConversions;
use ic_http_utils::file_downloader::{compute_sha256_hex, FileDownloader};

use authz::AuthzDeltaArg;
use ic_consensus::dkg::make_registry_cup;
use ic_interfaces::registry::RegistryClient;
use ic_nns_common::types::{AuthzChangeOp, MethodAuthzChange};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::{
    ids::TEST_NEURON_1_OWNER_KEYPAIR, GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID,
};
use ic_nns_governance::pb::v1::ManageNeuron;
use ic_nns_governance::proposal_submission::create_external_update_proposal_binary;
use ic_nns_governance::{
    pb::v1::{
        manage_neuron_response::Command as CommandResponse, ManageNeuronResponse, NnsFunction, Vote,
    },
    proposal_submission::{
        create_external_update_proposal_candid, create_make_proposal_payload,
        decode_make_proposal_response,
    },
};
use ic_nns_handler_root::common::{
    AddNnsCanisterProposalPayload, ChangeNnsCanisterProposalPayload,
};
use ic_nns_init::{make_hsm_sender, read_initial_registry_mutations};
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use ic_protobuf::registry::{
    conversion_rate::v1::IcpXdrConversionRateRecord,
    crypto::v1::{PublicKey, X509PublicKeyCert},
    node::v1::NodeRecord,
    node_operator::v1::NodeOperatorRecord,
    provisional_whitelist::v1::ProvisionalWhitelist as ProvisionalWhitelistProto,
    replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    routing_table::v1::RoutingTable,
    subnet::v1::{CatchUpPackageContents, SubnetListRecord, SubnetRecord as SubnetRecordProto},
};
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client::helper::{crypto::CryptoRegistry, subnet::SubnetRegistry};
use ic_registry_common::data_provider::NnsDataProvider;
use ic_registry_common::local_store::{
    Changelog, ChangelogEntry, KeyMutation, LocalStoreImpl, LocalStoreWriter,
};
use ic_registry_common::registry::RegistryCanister;
use ic_registry_keys::{
    get_node_record_node_id, is_node_record_key, make_blessed_replica_version_key,
    make_catch_up_package_contents_key, make_crypto_node_key,
    make_crypto_threshold_signing_pubkey_key, make_crypto_tls_cert_key,
    make_node_operator_record_key, make_node_record_key, make_provisional_whitelist_record_key,
    make_replica_version_key, make_routing_table_record_key, make_subnet_record_key,
    NODE_OPERATOR_RECORD_KEY_PREFIX, SUBNET_LIST_KEY, XDR_PER_ICP_KEY,
};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{
    pb::v1::{registry_mutation, Precondition, RegistryMutation},
    update, Error,
};
use ic_types::{
    consensus::{catchup::CUPWithOriginalProtobuf, HasHeight},
    crypto::{
        threshold_sig::{
            ni_dkg::{
                config::{receivers::NiDkgReceivers, NiDkgThreshold},
                NiDkgId, NiDkgTranscript,
            },
            ThresholdSigPublicKey,
        },
        KeyPurpose,
    },
    messages::CanisterInstallMode,
    CanisterId, NodeId, NumberOfNodes, PrincipalId, RegistryVersion, ReplicaVersion, SubnetId,
};
use prost::Message;
use registry_canister::mutations::do_set_firewall_config::SetFirewallConfigPayload;
use registry_canister::mutations::{
    do_add_node::AddNodePayload, do_add_node_operator::AddNodeOperatorPayload,
    do_add_nodes_to_subnet::AddNodesToSubnetPayload,
    do_bless_replica_version::BlessReplicaVersionPayload, do_create_subnet::CreateSubnetPayload,
    do_recover_subnet::RecoverSubnetPayload, do_remove_node::RemoveNodePayload,
    do_remove_nodes_from_subnet::RemoveNodesFromSubnetPayload,
    do_update_node_operator_config::UpdateNodeOperatorConfigPayload,
    do_update_subnet::UpdateSubnetPayload,
    do_update_subnet_replica::UpdateSubnetReplicaVersionPayload,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::sync::Arc;
use std::{
    collections::BTreeSet,
    convert::TryFrom,
    fs::{metadata, read_to_string, File},
    io::Read,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    str::FromStr,
    time::SystemTime,
};
use types::{ProvisionalWhitelistRecord, Registry, RegistryRecord, RegistryValue, SubnetRecord};
use url::Url;
use walkdir::{DirEntry, WalkDir};

#[derive(Clap)]
#[clap(version = "1.0")]
struct Opts {
    #[clap(short = 'r', long, alias = "registry-url")]
    /// The URL of an NNS entry point. That is, the URL of any replica on the
    /// NNS subnet.
    nns_url: Url,

    #[clap(short = 's', long)]
    /// The pem file containing a secret key to use while authenticating with
    /// the NNS.
    secret_key_pem: Option<PathBuf>,

    #[clap(subcommand)]
    subcmd: SubCommand,

    /// Use an HSM to sign calls.
    #[clap(long)]
    use_hsm: bool,

    /// The slot related to the HSM key that shall be used.
    #[clap(
        long = "slot",
        about = "Only required if use-hsm is set. Ignored otherwise."
    )]
    hsm_slot: Option<String>,

    /// The id of the key on the HSM that shall be used.
    #[clap(
        long = "key-id",
        about = "Only required if use-hsm is set. Ignored otherwise."
    )]
    key_id: Option<String>,

    /// The PIN used to unlock the HSM.
    #[clap(
        long = "pin",
        about = "Only required if use-hsm is set. Ignored otherwise."
    )]
    pin: Option<String>,
}

#[derive(Clap)]
enum SubCommand {
    /// Add all entries within a directory tree to the registry
    /// as a single mutation.
    AddAllPBFilesInPath(AddAllPBFilesInPathCmd),
    /// Add an entry to the registry, from a file generated by ic-prep. The name
    /// of the file is taken to be the key, and the contents the value.
    AddICPrepPBFile(AddICPrepPBFileCmd),
    /// Add a node's public key to the registry.
    AddPublicKey(AddPublicKeyCmd),
    /// Delete a node's public key from the registry.
    DeletePublicKey(DeletePublicKeyCmd),
    /// Get the last version of a node's public key from the registry.
    GetPublicKey(GetPublicKeyCmd),
    /// Add a node's TLS certificate to the registry.
    AddTlsCertificate(AddTlsCertificateCmd),
    /// Delete a node's TLS certificate from the registry.
    DeleteTlsCertificate(DeleteTlsCertificateCmd),
    /// Get the last version of a node's TLS certificate key from the registry.
    GetTlsCertificate(GetTlsCertificateCmd),
    /// Add a node to the registry.
    AddNode(AddNodeCmd),
    /// Remove a node from the registry.
    RemoveNode(RemoveNodeCmd),
    /// Add registered nodes to the subnet.
    AddNodesToSubnet(AddNodesToSubnetCmd),
    /// Remove a node from the registry.
    ProposeToRemoveNodesFromSubnet(ProposeToRemoveNodesFromSubnetCmd),
    /// Delete a node from the registry.
    DeleteNode(DeleteNodeCmd),
    /// Get the last version of a node from the registry.
    GetNode(GetNodeCmd),
    /// Get the nodes added since a given version (exclusive).
    GetNodeListSince(GetNodeListSinceCmd),
    /// Get the topology of the system as described in the registry, in JSON
    /// format.
    GetTopology,
    /// Add a new subnet to the registry.
    AddSubnet(AddSubnetCmd),
    /// Delete a subnet from the registry.
    DeleteSubnet(DeleteSubnetCmd),
    /// Delete the threshold signing public key of a subnet from the registry.
    DeleteSubnetThresholdSigningPublicKey(DeleteSubnetThresholdSigningPublicKeyCmd),
    /// Get the last version of a subnet from the registry.
    GetSubnet(GetSubnetCmd),
    /// Get the last version of the subnet list from the registry.
    GetSubnetList,
    /// Submit the initial registry.
    SubmitInitialRegistry(SubmitInitialRegistry),
    /// Add a new version of the Replica binary to the registry.
    AddReplicaVersion(AddReplicaVersionCmd),
    /// Get info about a Replica version
    GetReplicaVersion(GetReplicaVersionCmd),
    /// Get the ICP/XDR conversion rate (the value of 1 ICP measured in XDR).
    GetIcpXdrConversionRate,
    /// Update a subnet's Replica version, bypassing the Upgrades handler. This
    /// does NOT verify that the version is blessed.
    UpdateSubnetReplicaVersionBypassingHandler(UpdateSubnetReplicaVersionBypassingHandlerCmd),
    /// Propose updating a subnet's Replica version
    ProposeToUpdateSubnetReplicaVersion(ProposeToUpdateSubnetReplicaVersionCmd),
    /// Get the list of blessed Replica versions.
    GetBlessedReplicaVersions,
    /// Get the latest routing table.
    GetRoutingTable,
    /// Submits a proposal to get a given replica version, to be downloaded from
    /// download.dfinity.systems, blessed. For details about the lifecycle of
    /// replica versions, see https://github.com/dfinity-lab/dfinity/blob/master/rs/nns/handlers/upgrades/README.adoc
    ProposeToBlessReplicaVersion(ProposeToBlessReplicaVersionCmd),
    /// Submits a proposal to get the given replica version blessed. This
    /// command gives you maximum flexibility for specifying the download
    /// locations. It is usually preferable to use
    /// --propose-to-bless-replica-version instead, which is less flexible, but
    /// easier to use.
    ProposeToBlessReplicaVersionFlexible(ProposeToBlessReplicaVersionFlexibleCmd),
    /// Submits a proposal to create a new subnet.
    ProposeToCreateSubnet(ProposeToCreateSubnetCmd),
    /// Submits a proposal to update an existing subnet.
    ProposeToAddNodesToSubnet(ProposeToAddNodesToSubnetCmd),
    /// Submits a proposal to update a subnet's recovery CUP
    ProposeToUpdateRecoveryCup(ProposeToUpdateRecoveryCupCmd),
    /// Submits a proposal to update an existing subnet's configuration.
    ProposeToUpdateSubnet(ProposeToUpdateSubnetCmd),
    /// Submits a proposal to change an existing canister on NNS.
    ProposeToChangeNnsCanister(ProposeToChangeNnsCanisterCmd),
    /// Submits a proposal to set authorized subnetworks that the cycles minting
    /// canister can use.
    ProposeToSetAuthorizedSubnetworks(ProposeToSetAuthorizedSubnetworksCmd),
    /// Submits a proposal to add a new canister on NNS.
    ProposeToAddNnsCanister(ProposeToAddNnsCanisterCmd),
    /// Submits a proposal to add a new node.
    AddNodeViaNns(AddNodeViaNnsCmd),
    /// Convert the integer node ID into Principal Id
    ConvertNumericNodeIdToPrincipalId(ConvertNumericNodeIdtoPrincipalIdCmd),
    /// Votes on a proposal on behalf of a test neuron
    ForwardTestNeuronVote(ForwardTestNeuronVoteCmd),
    /// Execute all eligible proposals
    ExecuteEligibleProposals,
    /// Get whitelist of principals that can access the provisional_* APIs in
    /// the management canister.
    GetProvisionalWhitelist,
    /// Get the public of the subnet.
    GetSubnetPublicKey(SubnetPublicKeyCmd),
    /// Get the recovery CUP fields of a subnet
    GetRecoveryCup(GetRecoveryCupCmd),
    /// Propose to add a new node operator to the registry.
    ProposeToAddNodeOperator(ProposeToAddNodeOperatorCmd),
    /// Get a node operator's record
    GetNodeOperator(GetNodeOperatorCmd),
    /// Get the list of all node operators
    GetNodeOperatorList,
    /// Update local registry store by pulling from remote URL
    UpdateRegistryLocalStore(UpdateRegistryLocalStoreCmd),
    /// Update the whitelist of principals that can access the provisional_*
    /// APIs in the management canister.
    ProposeToClearProvisionalWhitelist(ProposeToClearProvisionalWhitelistCmd),
    /// Update the Node Operator's specified parameters
    ProposeToUpdateNodeOperatorConfig(ProposeToUpdateNodeOperatorConfigCmd),
    /// Propose to set the firewall config
    ProposeToSetFirewallConfig(ProposeToSetFirewallConfigCmd),
}

#[derive(Clap, Clone)]
enum ValueFormat {
    /// Whether the value to add is a JSON string
    Json,
    /// Whether the value to add is a path to a PB.
    PBFile,
}

impl FromStr for ValueFormat {
    type Err = String;

    fn from_str(string: &str) -> Result<Self, <Self as FromStr>::Err> {
        match string {
            "json" => Ok(ValueFormat::Json),
            "pb_file" => Ok(ValueFormat::PBFile),
            &_ => Err(format!("Unknown value format: {:?}", string)),
        }
    }
}

#[derive(Clap)]
struct AddAllPBFilesInPathCmd {
    /// The path of the directory containing the entries to add.
    file_path: PathBuf,
    #[clap(short, long)]
    /// Add only the pub key and node information. Ignore subnet records and
    /// subnet-list updates
    nodes_only: bool,
}

#[derive(Clap)]
struct AddICPrepPBFileCmd {
    /// The path of the file containing the entry to add to the registry.
    file_path: PathBuf,
}

#[derive(Clap)]
struct AddPublicKeyCmd {
    /// The node id to which the key belongs.
    node_id: PrincipalId,
    /// The purpose of the key. See ic::types::crypto::KeyPurpose.
    key_purpose: KeyPurpose,
    /// The format of the value (json or pb_file).
    value_format: ValueFormat,
    /// The value to add (or a path to a file with the value, depending on
    /// format).
    value: String,
}

#[derive(Clap)]
struct DeletePublicKeyCmd {
    /// The node id to which the key belongs.
    node_id: PrincipalId,
    /// The purpose of the key. See ic::types::crypto::KeyPurpose.
    key_purpose: KeyPurpose,
}

#[derive(Clap)]
struct GetPublicKeyCmd {
    /// The node id to which the key belongs.
    node_id: PrincipalId,
    /// The purpose of the key. See ic::types::crypto::KeyPurpose.
    key_purpose: KeyPurpose,
}

#[derive(Clap)]
struct AddTlsCertificateCmd {
    /// The node id to which the TLS certificate belongs.
    node_id: PrincipalId,
    /// The format of the value (json or pb_file).
    value_format: ValueFormat,
    /// The value to add (or a path to a file with the value, depending on
    /// format).
    value: String,
}

#[derive(Clap)]
struct DeleteTlsCertificateCmd {
    /// The node id to which the TLS certificate belongs.
    node_id: PrincipalId,
}

#[derive(Clap)]
struct GetTlsCertificateCmd {
    /// The node id to which the TLS certificate belongs.
    node_id: PrincipalId,
}

#[derive(Clap)]
struct AddNodeCmd {
    /// The id of the node to add.
    node_id: PrincipalId,
    /// The subnet to add the node to.
    subnet: SubnetDescriptor,
    /// The format of the value (json or pb_file).
    value_format: ValueFormat,
    /// The value to add (or a path to a file with the value, depending on
    /// format).
    value: String,
    #[clap(short, long)]
    /// Do not add the node to subnet. Value for subnet_id will be ignored.
    without_subnet: bool,
}

#[derive(Clap)]
struct RemoveNodeCmd {
    /// The id of the node to remove.
    node_id: PrincipalId,
}

#[derive(Clap)]
struct AddNodesToSubnetCmd {
    /// The subnet to add the nodes to.
    subnet: SubnetDescriptor,
    #[clap(name = "NODE_ID", required = true)]
    /// The node IDs (strings) of the nodes that will join the subnet.
    pub node_ids: Vec<PrincipalId>,
}

#[derive(Clap)]
struct ProposeToRemoveNodesFromSubnetCmd {
    #[clap(name = "NODE_ID", required = true)]
    /// The node IDs of the nodes that will leave the subnet.
    pub node_ids: Vec<PrincipalId>,

    #[clap(long)]
    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister. Ignored if 'proposer' is set.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct DeleteNodeCmd {
    /// The id of the node to delete.
    node_id: PrincipalId,
}

#[derive(Clap)]
struct GetNodeCmd {
    /// The id of the node to get.
    node_id: PrincipalId,
}

#[derive(Clap)]
struct ConvertNumericNodeIdtoPrincipalIdCmd {
    /// The integer Id of the node to convert to actual node id.
    node_id: u64,
}

#[derive(Clap)]
struct AddSubnetCmd {
    /// The format of the value (json or pb_file).
    value_format: ValueFormat,
    /// The value to add (or a path to a file with the value, depending on
    /// format).
    value: String,
    /// The path to the protobuf file with the initial DKG transcripts.
    dkg_pb_path: String,
}

#[derive(Clap)]
struct DeleteSubnetCmd {
    /// The subnet to delete.
    subnet: SubnetDescriptor,
}

#[derive(Clap)]
struct DeleteSubnetThresholdSigningPublicKeyCmd {
    /// The subnet to which the threshold signing public key belongs.
    subnet: SubnetDescriptor,
}

#[derive(Clap)]
struct GetSubnetCmd {
    /// The subnet to get.
    subnet: SubnetDescriptor,
}

#[derive(Clap)]
struct GetNodeListSinceCmd {
    /// Returns the most recent node records added since this given version,
    /// exclusive.
    version: u64,
}

#[derive(Clap)]
struct SubmitInitialRegistry {
    /// Path to the file containing the initial registry required for NNS
    /// Bootstrap.
    initial_registry: PathBuf,
}

#[derive(Clap)]
struct AddReplicaVersionCmd {
    /// The Replica version ID
    replica_version_id: String,
    /// The format of the value (json or pb_file).
    value_format: ValueFormat,
    /// The value to add (or a path to a file with the value, depending on
    /// format).
    value: String,
}

#[derive(Clap)]
struct GetReplicaVersionCmd {
    /// The Replica version to query
    replica_version_id: String,
}

#[derive(Clap)]
struct UpdateSubnetReplicaVersionBypassingHandlerCmd {
    /// The subnet to update.
    subnet: SubnetDescriptor,
    /// The new Replica version to use.
    replica_version_id: String,
}

#[derive(Clap)]
struct ProposeToUpdateSubnetReplicaVersionCmd {
    /// The subnet to update.
    subnet: SubnetDescriptor,
    /// The new Replica version to use.
    replica_version_id: String,

    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct ProposeToBlessReplicaVersionCmd {
    /// The hash of the commit to propose
    pub commit_hash: String,

    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct ProposeToBlessReplicaVersionFlexibleCmd {
    /// Version ID. This can be anything, it has no semantics. The reason it is
    /// part of the payload is that it will be needed in the subsequent step
    /// of upgrading individual subnets.
    pub replica_version_id: String,

    /// The URL against which a HTTP GET request will return a replica binary
    /// that corresponds to this version.
    pub replica_url: Option<String>,

    /// The hex-formatted SHA-256 hash of the binary served by 'replica_url'
    replica_sha256_hex: Option<String>,

    /// The URL against which a HTTP GET request will return a node manager
    /// binary that corresponds to this version. If unset, then only the
    /// replica will be updated when a subnet is updated to that version.
    pub node_manager_url: Option<String>,

    /// The hex-formatted SHA-256 hash of the binary served by
    /// 'node_manager_url'. Must be present if and only if the node manager
    /// url is present.
    node_manager_sha256_hex: Option<String>,

    /// The URL against which a HTTP GET request will return a release
    /// package that corresponds to this version. If set,
    /// {replica, node_manager}_{url, sha256_hex} will be ignored
    pub release_package_url: Option<String>,

    /// The hex-formatted SHA-256 hash of the archive served by
    /// 'release_package_url'. Must be present if release_package_url is
    /// present.
    release_package_sha256_hex: Option<String>,

    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct ProposeToCreateSubnetCmd {
    #[clap(long)]
    #[allow(dead_code)]
    /// Obsolete. Does nothing. Exists for compatibility with legacy scripts.
    subnet_handler_id: Option<String>,

    #[clap(name = "NODE_ID", required = true)]
    /// The node IDs (strings) of the nodes that will be part of the new subnet.
    pub node_ids: Vec<String>,

    #[clap(long)]
    // Assigns this subnet ID to the newly created subnet
    pub subnet_id_override: Option<PrincipalId>,

    #[clap(long, required = true)]
    /// Maximum amount of bytes per block. This is a soft cap.
    pub ingress_bytes_per_block_soft_cap: u64,

    #[clap(long, required = true)]
    /// Maximum amount of bytes per message. This is a hard cap.
    pub max_ingress_bytes_per_message: u64,

    #[clap(long, required = true)]
    /// Maximum number of ingress messages per block. This is a hard cap.
    pub max_ingress_messages_per_block: u64,

    // the default is from subnet_configuration.rs from ic-prep
    #[clap(long, required = true)]
    ///  Unit delay for blockmaker (in milliseconds).
    pub unit_delay_millis: u64,

    #[clap(long, required = true)]
    /// Initial delay for notary (in milliseconds), to give time to rank-0 block
    /// propagation.
    pub initial_notary_delay_millis: u64,

    #[clap(long, parse(try_from_str = ReplicaVersion::try_from))]
    /// ID of the Replica version to run.
    pub replica_version_id: Option<ReplicaVersion>,

    #[clap(long, required = true)]
    /// The length of all DKG intervals. The DKG interval length is the number
    /// of rounds following the DKG summary.
    pub dkg_interval_length: u64,

    #[clap(long, required = false, default_value = "1")]
    /// The upper bound for the number of allowed DKG dealings in a block.
    pub dkg_dealings_per_block: u64,

    // These are for the GossipConfig sub-struct
    #[clap(long, required = true)]
    /// max outstanding request per peer MIN/DEFAULT/MAX.
    pub gossip_max_artifact_streams_per_peer: u32,

    #[clap(long, required = true)]
    /// timeout for a outstanding request.
    pub gossip_max_chunk_wait_ms: u32,

    #[clap(long, required = true)]
    /// max duplicate requests in underutilized networks.
    pub gossip_max_duplicity: u32,

    #[clap(long, required = true)]
    /// maximum chunk size supported on this subnet.
    pub gossip_max_chunk_size: u32,

    #[clap(long, required = true)]
    /// history size for receive check.
    pub gossip_receive_check_cache_size: u32,

    #[clap(long, required = true)]
    /// period for re evaluating the priority function.
    pub gossip_pfn_evaluation_period_ms: u32,

    #[clap(long, required = true)]
    /// period for polling the registry for updates.
    pub gossip_registry_poll_period_ms: u32,

    #[clap(long, required = true)]
    /// period for sending retransmission request.
    pub gossip_retransmission_request_ms: u32,

    #[clap(long)]
    /// if set, the subnet will start as (new) NNS.
    pub start_as_nns: bool,

    #[clap(long)]
    /// The type of the subnet.
    /// Can be either "application" or "system".
    pub subnet_type: SubnetType,

    #[clap(long)]
    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister. Ignored if 'proposer' is set.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// If set, the created subnet will be halted: it will not create or execute
    /// blocks
    #[clap(long)]
    pub is_halted: bool,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct ProposeToAddNodesToSubnetCmd {
    #[clap(long)]
    #[allow(dead_code)]
    /// Obsolete. Does nothing
    subnet_handler_id: Option<String>,

    #[clap(long, required = true, alias = "subnet-id")]
    /// The subnet to modify
    subnet: SubnetDescriptor,

    #[clap(name = "NODE_ID", required = true)]
    /// The node IDs of the nodes that will be part of the new subnet.
    pub node_ids: Vec<PrincipalId>,

    #[clap(long)]
    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister. Ignored if 'proposer' is set.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct ProposeToUpdateRecoveryCupCmd {
    #[clap(long, required = true, alias = "subnet-index")]
    /// The targetted subnet.
    subnet: SubnetDescriptor,

    #[clap(long, required = true)]
    /// The height of the CUP
    pub height: u64,

    #[clap(long, required = true)]
    /// The block time to start from (nanoseconds from Epoch)
    pub time_ns: u64,

    #[clap(long, required = true)]
    /// The hash of the state
    pub state_hash: String,

    #[clap(long)]
    /// Replace the members of the given subnet with these nodes
    pub replacement_nodes: Option<Vec<PrincipalId>>,

    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister.  Ignored if 'proposer' is set.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// A uri from which data to replace the registry local store should be
    /// downloaded
    #[clap(long)]
    pub registry_store_uri: Option<String>,

    /// The hash of the data that is to be retrieved at the registry store URI
    #[clap(long)]
    pub registry_store_hash: Option<String>,

    /// The registry version that should be used for the recovery cup
    #[clap(long)]
    pub registry_version: Option<u64>,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct ProposeToUpdateSubnetCmd {
    /// The subnet that should be updated.
    #[clap(long, required = true, alias = "subnet-id")]
    subnet: SubnetDescriptor,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub ingress_bytes_per_block_soft_cap: Option<u64>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub max_ingress_bytes_per_message: Option<u64>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub unit_delay_millis: Option<u64>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub initial_notary_delay_millis: Option<u64>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub dkg_interval_length: Option<u64>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub dkg_dealings_per_block: Option<u64>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_max_artifact_streams_per_peer: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_max_chunk_wait_ms: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_max_duplicity: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_max_chunk_size: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_receive_check_cache_size: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_pfn_evaluation_period_ms: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_registry_poll_period_ms: Option<u32>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub gossip_retransmission_request_ms: Option<u32>,

    #[clap(long)]
    /// If set, it will set a default value for the entire gossip config. Useful
    /// when you want to only set some fields for the gossip config and there's
    /// currently none set.
    pub set_gossip_config_to_default: bool,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub start_as_nns: Option<bool>,

    #[clap(long)]
    /// If set, the created proposal will contain a desired override of that
    /// field to the value set. See `ProposeToCreateSubnetCmd` for the semantic
    /// of this field.
    pub subnet_type: Option<SubnetType>,

    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister. Ignored if 'proposer' is set.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// If set, the subnet will be halted: it will no longer create or execute
    /// blocks
    #[clap(long)]
    pub is_halted: Option<bool>,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct ProposeToChangeNnsCanisterCmd {
    #[clap(long)]
    /// Whether to skip stopping the canister before installing. Generally,
    /// recommended to stop your canister but you can skip if you are sure there
    /// are no outstanding callbacks that could put it in undefined state after
    /// the upgrade.
    skip_stopping_before_installing: bool,

    #[clap(long, required = true)]
    /// The mode to use when updating the canister.
    mode: CanisterInstallMode,

    #[clap(long, required = true)]
    /// The ID of the canister to modify
    canister_id: CanisterId,

    #[clap(long, required = true)]
    /// The path to the new wasm module to ship.
    pub wasm_module_path: PathBuf,

    #[clap(long)]
    /// The path to a binary file containing the initialization args of the
    /// canister.
    arg: Option<PathBuf>,

    #[clap(long)]
    /// Change to the authz of the canisters being changed or other canisters.
    /// Format is: <canister>?:<method_name>[><]<caller>?
    ///
    /// <canister> is the canister that is affected by the change. If
    /// unspecified, it is the one being specified by --canister-id.
    ///
    /// <method_name> is the method for which the authorization is being
    /// changed.
    ///
    /// '>' is for removing a caller from the authorization list, and '<' to add
    /// a caller to the authorization list.
    ///
    /// <caller> is the caller being authorized or deauthorized. If unspecified,
    /// it is the same as --canister-id.
    ///
    /// Example: ':foo>2vxsx-fae' means: "After upgrading/reinstalling this
    /// canister, change remove '2vxsx-fae' from the list of identities
    /// authorized to call its "foo" method.
    authz_changes: Vec<AuthzDeltaArg>,

    #[clap(long)]
    /// If set, it will update the canister's compute allocation to this value.
    /// See `ComputeAllocation` for the semantics of this field.
    compute_allocation: Option<u64>,
    #[clap(long)]
    /// If set, it will update the canister's memory allocation to this value.
    /// See `MemoryAllocation` for the semantics of this field.
    memory_allocation: Option<u64>,
    #[clap(long)]
    /// If set, it will update the canister's query allocation to this value.
    /// See `QueryAllocation` for the semantics of this field.
    query_allocation: Option<u64>,

    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister. Ignored if 'proposer' is set.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct ProposeToAddNnsCanisterCmd {
    #[clap(long, required = true)]
    /// A unique name for the canister.
    name: String,

    #[clap(long, required = true)]
    /// The path to the new wasm module to ship.
    pub wasm_module_path: PathBuf,

    #[clap(long)]
    /// The path to a binary file containing the initialization args of the
    /// canister.
    arg: Option<PathBuf>,

    #[clap(long)]
    /// If set, it will update the canister's compute allocation to this value.
    /// See `ComputeAllocation` for the semantics of this field.
    compute_allocation: Option<u64>,
    #[clap(long)]
    /// If set, it will update the canister's memory allocation to this value.
    /// See `MemoryAllocation` for the semantics of this field.
    memory_allocation: Option<u64>,
    #[clap(long)]
    /// If set, it will update the canister's query allocation to this value.
    /// See `QueryAllocation` for the semantics of this field.
    query_allocation: Option<u64>,

    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister. Ignored if 'proposer' is set.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct AddNodeViaNnsCmd {
    #[clap(long)]
    #[allow(dead_code)]
    /// Obsolete. Does nothing.
    node_handler_id: Option<String>,

    #[clap(long, required = true)]
    /// The path to the file containing node's signing key (PublicKey) in
    /// Protobuf format.
    pub node_signing_pk_path: PathBuf,

    #[clap(long, required = true)]
    /// The path to the file containing node's committee signing key (PublicKey)
    /// in Protobuf format.
    pub committee_signing_pk_path: PathBuf,

    #[clap(long, required = true)]
    /// The path to the file containing node's NI-DKG dealing encryption key
    /// (PublicKey) in Protobuf format.
    pub ni_dkg_dealing_encryption_pk_path: PathBuf,

    #[clap(long, required = true)]
    /// The path to the file containing the node's transport TLS certificate
    /// (X509PublicKeyCert) in Protobuf format.
    pub transport_tls_certificate_path: PathBuf,

    #[clap(long, required = true)]
    /// The endpoint (ipv4_addr:port or [ipv6_addr]:port) where this node
    /// receives xnet messages.
    xnet_endpoint: String,

    #[clap(long, required = true)]
    /// The http endpoint (ipv4_addr:port or [ipv6_addr]:port) for this node.
    http_endpoint: String,

    #[clap(long, required = true, takes_value = true)]
    /// The p2p flow endpoint (in format: 'flow,ipv4_addr:port' or
    /// 'flow,[ipv6_addr]:port') for this node. Multiple values are allowed.
    p2p_flow_endpoint: Vec<String>,

    #[clap(long, required = true)]
    /// The Prometheus metrics http endpoint (ipv4_addr:port or
    /// [ipv6_addr]:port) for this node.
    prometheus_metrics_endpoint: String,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct ProposeToClearProvisionalWhitelistCmd {
    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister. Ignored if 'proposer' is set.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct ProposeToSetAuthorizedSubnetworksCmd {
    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister. Ignored if 'proposer' is set.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// The principal to be authorized to create canisters using ICPTs.
    /// If who is `None`, then the proposal will set the default list of subnets
    /// onto which everyone is authorized to create canisters to `subnets`
    /// (except those who have a custom list).
    #[clap(long)]
    pub who: Option<PrincipalId>,

    /// The list of subnets that `who` would be authorized to create subnets on.
    /// If `subnets` is `None`, then `who` is removed from the list of
    /// authorized users.
    #[clap(long)]
    pub subnets: Option<Vec<PrincipalId>>,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct ForwardTestNeuronVoteCmd {
    /// The ID of the proposal to execute
    proposal_id: u64,
}

#[derive(Clap)]
struct SubnetPublicKeyCmd {
    /// The subnet.
    subnet: SubnetDescriptor,

    /// Target path where the PEM is stored.
    target_path: PathBuf,
}

#[derive(Clap)]
struct GetRecoveryCupCmd {
    /// The subnet
    subnet: SubnetDescriptor,

    #[clap(long, required = false)]
    output_file: PathBuf,
}

#[derive(Clap)]
struct ProposeToAddNodeOperatorCmd {
    #[clap(long, required = true)]
    /// The principal id of the node operator
    pub node_operator_principal_id: PrincipalId,

    #[clap(long, required = true)]
    /// The remaining number of nodes that could be added by this node operator
    pub node_allowance: u64,

    //// The principal id of this node operator's provider
    pub node_provider_principal_id: PrincipalId,

    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister. Ignored if 'proposer' is set.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct ProposeToUpdateNodeOperatorConfigCmd {
    #[clap(long, required = true)]
    /// The principal id of the node operator
    pub node_operator_id: PrincipalId,

    /// The remaining number of nodes that could be added by this node operator
    pub node_allowance: Option<u64>,

    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister. Ignored if 'proposer' is set.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

#[derive(Clap)]
struct GetNodeOperatorCmd {
    #[clap(long, required = true)]
    /// The principal id of the node operator
    pub node_operator_principal_id: PrincipalId,
}

#[derive(Clap)]
struct UpdateRegistryLocalStoreCmd {
    /// The path of the directory of registry local store.
    local_store_path: PathBuf,
    #[clap(long)]
    /// Option to disable certificate validation, useful for emergency
    /// recovery.
    disable_certificate_validation: bool,
}

#[derive(Clap)]
struct ProposeToSetFirewallConfigCmd {
    /// File with the firewall configuration content
    pub firewall_config_file: PathBuf,
    /// List of allowed IPv4 prefixes, comma separated, or "-" (for empty list)
    pub ipv4_prefixes: String,
    /// List of allowed IPv6 prefixes, comma separated, or "-" (for empty list)
    pub ipv6_prefixes: String,

    /// The id of the neuron on behalf of which the proposal will be submitted.
    pub proposer: Option<NeuronId>,

    /// If set, the proposal will use a test proposer neuron, which must exist
    /// in the governance canister. Ignored if 'proposer' is set.
    #[clap(long)]
    pub test_neuron_proposer: bool,

    /// A url pointing to additional content required to evaluate the
    /// proposal, specified using HTTPS.
    #[clap(long)]
    pub proposal_url: Option<Url>,
}

/// A description of a subnet, either by index, or by id.
#[derive(Clone, Copy)]
enum SubnetDescriptor {
    Id(PrincipalId),
    Index(usize),
}

impl FromStr for SubnetDescriptor {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let maybe_index = usize::from_str(s);
        let maybe_principal = PrincipalId::from_str(s);
        match (maybe_index, maybe_principal) {
            (Err(e1), Err(e2)) => Err(format!(
                "Cannot parse argument '{}' as a subnet descriptor. \
                 It is not an index because {}. It is not a principal because {}.",
                s, e1, e2
            )),
            (Ok(i), Err(_)) => Ok(Self::Index(i)),
            (Err(_), Ok(id)) => Ok(Self::Id(id)),
            (Ok(_), Ok(_)) => Err(format!(
                "Well that's embarrassing. {} can be interpreted both as an index and as a \
                 principal. I did not think this was possible!",
                s
            )),
        }
    }
}

impl SubnetDescriptor {
    async fn get_id(&self, registry_canister: &RegistryCanister) -> SubnetId {
        match self {
            Self::Id(p) => SubnetId::new(*p),
            Self::Index(i) => {
                let subnets = get_subnet_ids(registry_canister).await;
                *(subnets.get(*i)
                    .unwrap_or_else(|| panic!("Tried to get subnet of index {}, but there are only {} subnets according to the registry", i, subnets.len())))
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let opts: Opts = Opts::parse();
    let registry_canister = RegistryCanister::new(vec![opts.nns_url.clone()]);

    let sender = if opts.secret_key_pem.is_some() || opts.use_hsm {
        // Make sure to let the user know that we only actually use the sender
        // in methods that go through the NNS handlers and not for other methods.
        //
        // TODO(NNS1-486): Remove ic-admin command whitelist for sender
        match opts.subcmd {
            SubCommand::ProposeToUpdateSubnetReplicaVersion(_) => (),
            SubCommand::ProposeToCreateSubnet(_) => (),
            SubCommand::ProposeToAddNodesToSubnet(_) => (),
            SubCommand::ProposeToRemoveNodesFromSubnet(_) => (),
            SubCommand::ProposeToChangeNnsCanister(_) => (),
            SubCommand::ProposeToAddNnsCanister(_) => (),
            SubCommand::ProposeToBlessReplicaVersion(_) => (),
            SubCommand::ProposeToBlessReplicaVersionFlexible(_) => (),
            SubCommand::ProposeToUpdateSubnet(_) => (),
            SubCommand::ProposeToClearProvisionalWhitelist(_) => (),
            SubCommand::ProposeToUpdateRecoveryCup(_) => (),
            SubCommand::AddNodeViaNns(_) => (),
            SubCommand::ProposeToUpdateNodeOperatorConfig(_) => (),
            SubCommand::ProposeToSetFirewallConfig(_) => (),
            SubCommand::ProposeToSetAuthorizedSubnetworks(_) => (),
            _ => panic!(
                "Specifying a secret key or HSM is only supported for\
                     methods that interact with NNS handlers."
            ),
        }

        if opts.secret_key_pem.is_some() {
            let secret_key_path = opts.secret_key_pem.unwrap();
            use ic_crypto_internal_types::sign::eddsa::ed25519::SecretKey;
            let contents = read_to_string(secret_key_path).expect("Could not read key file.");
            let (secret_key, public_key) =
                SecretKey::from_pem(&contents).expect("Invalid secret key.");
            let mut buf = Vec::new();
            buf.extend(secret_key.as_bytes());
            buf.extend(public_key.as_bytes());
            let keypair = Keypair::from_bytes(&buf).expect("Invalid secret key.");
            Sender::from_keypair(&keypair)
        } else if opts.use_hsm {
            make_hsm_sender(
                &opts.hsm_slot.unwrap(),
                &opts.key_id.unwrap(),
                &opts.pin.unwrap(),
            )
        } else {
            Sender::Anonymous
        }
    } else {
        Sender::Anonymous
    };

    match opts.subcmd {
        SubCommand::AddAllPBFilesInPath(add_all_files_in_path_cmd) => {
            add_all_files_in_path(
                &add_all_files_in_path_cmd.file_path,
                add_all_files_in_path_cmd.nodes_only,
                &registry_canister,
            )
            .await;
        }
        SubCommand::AddICPrepPBFile(add_ic_prep_pb_file) => {
            add_pb_file_entry(&add_ic_prep_pb_file.file_path, &registry_canister).await;
        }
        SubCommand::AddPublicKey(add_pk_cmd) => {
            let public_key = parse_json_or_load_pb::<PublicKey>(
                add_pk_cmd.value_format.clone(),
                &add_pk_cmd.value,
            );
            let node_id = NodeId::from(add_pk_cmd.node_id);
            add_public_key(
                node_id,
                add_pk_cmd.key_purpose,
                public_key,
                &registry_canister,
            )
            .await;
        }
        SubCommand::DeletePublicKey(delete_pk_cmd) => {
            let node_id = NodeId::from(delete_pk_cmd.node_id);
            delete_public_key(node_id, delete_pk_cmd.key_purpose, &registry_canister).await;
        }
        SubCommand::GetPublicKey(get_pk_cmd) => {
            let node_id = NodeId::from(get_pk_cmd.node_id);
            print_and_get_last_value::<PublicKey>(
                make_crypto_node_key(node_id, get_pk_cmd.key_purpose)
                    .as_bytes()
                    .to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::AddTlsCertificate(add_cert_cmd) => {
            let tls_certificate = parse_json_or_load_pb::<X509PublicKeyCert>(
                add_cert_cmd.value_format.clone(),
                &add_cert_cmd.value,
            );
            let node_id = NodeId::from(add_cert_cmd.node_id);
            add_tls_certificate(node_id, tls_certificate, &registry_canister).await;
        }
        SubCommand::DeleteTlsCertificate(delete_cert_cmd) => {
            let node_id = NodeId::from(delete_cert_cmd.node_id);
            delete_tls_certificate(node_id, &registry_canister).await;
        }
        SubCommand::GetTlsCertificate(get_cert_cmd) => {
            let node_id = NodeId::from(get_cert_cmd.node_id);
            print_and_get_last_value::<X509PublicKeyCert>(
                make_crypto_tls_cert_key(node_id).as_bytes().to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::AddNode(add_node_cmd) => {
            let node_record = parse_json_or_load_pb::<NodeRecord>(
                add_node_cmd.value_format.clone(),
                &add_node_cmd.value,
            );
            let node_id = NodeId::from(add_node_cmd.node_id);
            if add_node_cmd.without_subnet {
                just_add_node(node_id, node_record, &registry_canister).await;
            } else {
                let subnet_id = add_node_cmd.subnet.get_id(&registry_canister).await;
                add_node(node_id, subnet_id, node_record, &registry_canister).await;
            }
        }
        SubCommand::RemoveNode(cmd) => {
            remove_node(cmd, opts.nns_url, sender).await;
        }
        SubCommand::AddNodesToSubnet(args) => {
            let subnet_id = args.subnet.get_id(&registry_canister).await;
            let node_ids = args.node_ids.into_iter().map(NodeId::from).collect();
            add_nodes_to_subnet(node_ids, subnet_id, &registry_canister).await;
        }
        SubCommand::ProposeToRemoveNodesFromSubnet(cmd) => {
            propose_to_remove_nodes_from_subnet(cmd, opts.nns_url, sender).await;
        }
        SubCommand::DeleteNode(delete_node_cmd) => {
            let node_id = NodeId::from(delete_node_cmd.node_id);
            delete_node(node_id, &registry_canister).await;
        }
        SubCommand::GetNode(get_node_cmd) => {
            let node_id = NodeId::from(get_node_cmd.node_id);
            print_and_get_last_value::<NodeRecord>(
                make_node_record_key(node_id).as_bytes().to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::GetNodeListSince(cmd) => {
            let node_records = get_node_list_since(cmd.version, &registry_canister).await;

            let res = serde_json::to_string(&node_records)
                .unwrap_or_else(|_| "Could not serialize node_records".to_string());
            println!("{}", res);
        }
        SubCommand::GetTopology => {
            // Because ic-admin codebase is riddled with bad patterns -- most notably, all
            // get/fetch methods also print out the representation of the
            // data, there is no nice way to print the whole topology.
            // Instead, we print the surrounding structure in a not so nice way
            // and delegate pretty-printing to jq or other consumers.
            // Also, this method is slow, as each fetch needs to happen in sequence (due to
            // printing from it).
            let subnet_ids = get_subnet_ids(&registry_canister).await;
            let subnet_count = subnet_ids.len();
            let mut seen: HashSet<NodeId> = HashSet::new();
            println!("{{ \"topology\": {{");
            println!("\"subnets\": {{");
            for (i, subnet_id) in subnet_ids.iter().enumerate() {
                println!("\"{}\": ", subnet_id);
                let record = print_and_get_last_value::<SubnetRecordProto>(
                    make_subnet_record_key(*subnet_id).as_bytes().to_vec(),
                    &registry_canister,
                )
                .await;
                if i + 1 != subnet_count {
                    println!(",")
                }

                for node in record
                    .membership
                    .iter()
                    .map(|n| NodeId::from(PrincipalId::try_from(&n[..]).unwrap()))
                {
                    seen.insert(node);
                }
            }
            println!("}}");
            let node_ids = get_node_list_since(0, &registry_canister)
                .await
                .into_iter()
                .filter(|record| {
                    let node_id = NodeId::from(PrincipalId::from_str(&record.node_id).unwrap());
                    !seen.contains(&node_id)
                })
                .collect::<Vec<_>>();
            println!(
                ",\"unassigned_nodes\": {}",
                serde_json::to_string_pretty(&node_ids).unwrap()
            );
            println!("}}}}");
        }
        SubCommand::ConvertNumericNodeIdToPrincipalId(
            convert_numeric_node_id_to_principal_id_cmd,
        ) => {
            let node_id = NodeId::from(PrincipalId::new_node_test_id(
                convert_numeric_node_id_to_principal_id_cmd.node_id,
            ));
            println!("{}", node_id);
        }
        SubCommand::AddSubnet(add_subnet_cmd) => {
            let subnet_record = parse_json_or_load_pb::<SubnetRecordProto>(
                add_subnet_cmd.value_format.clone(),
                &add_subnet_cmd.value,
            );
            let cup_contents = parse_json_or_load_pb::<CatchUpPackageContents>(
                ValueFormat::PBFile,
                &add_subnet_cmd.dkg_pb_path,
            );
            add_subnet(subnet_record, cup_contents, &registry_canister).await;
        }
        SubCommand::DeleteSubnet(delete_subnet_cmd) => {
            let subnet_id = delete_subnet_cmd.subnet.get_id(&registry_canister).await;
            delete_subnet(subnet_id, &registry_canister).await;
        }
        SubCommand::DeleteSubnetThresholdSigningPublicKey(delete_threshold_sig_pubkey_cmd) => {
            let subnet_id = delete_threshold_sig_pubkey_cmd
                .subnet
                .get_id(&registry_canister)
                .await;
            delete_subnet_threshold_signing_public_key(subnet_id, &registry_canister).await;
        }
        SubCommand::GetSubnet(get_subnet_cmd) => {
            let subnet_id = get_subnet_cmd.subnet.get_id(&registry_canister).await;
            print_and_get_last_value::<SubnetRecordProto>(
                make_subnet_record_key(subnet_id).as_bytes().to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::GetSubnetList => {
            let value: Vec<_> = registry_canister
                .get_value(SUBNET_LIST_KEY.as_bytes().to_vec(), None)
                .await
                .map(|(bytes, _version)| SubnetListRecord::decode(&bytes[..]).unwrap())
                .unwrap()
                .subnets
                .into_iter()
                .map(|id_vec| format!("{:?}", PrincipalId::try_from(id_vec).unwrap()))
                .collect();
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
        }
        SubCommand::SubmitInitialRegistry(arg) => {
            submit_initial_registry_version(arg.initial_registry.as_path(), &registry_canister)
                .await
        }
        SubCommand::AddReplicaVersion(add_replica_version_cmd) => {
            let replica_version_id = add_replica_version_cmd.replica_version_id.clone();
            let replica_version_record = parse_json_or_load_pb::<ReplicaVersionRecord>(
                add_replica_version_cmd.value_format.clone(),
                &add_replica_version_cmd.value,
            );
            add_replica_version(
                replica_version_id,
                replica_version_record,
                &registry_canister,
            )
            .await;
        }
        SubCommand::GetReplicaVersion(get_replica_version_cmd) => {
            let key = make_replica_version_key(get_replica_version_cmd.replica_version_id)
                .as_bytes()
                .to_vec();
            print_and_get_last_value::<ReplicaVersionRecord>(key, &registry_canister).await;
        }
        SubCommand::UpdateSubnetReplicaVersionBypassingHandler(
            update_subnet_replica_version_cmd,
        ) => {
            update_subnet_replica_version_bypassing_handler(
                update_subnet_replica_version_cmd
                    .subnet
                    .get_id(&registry_canister)
                    .await,
                update_subnet_replica_version_cmd.replica_version_id,
                &registry_canister,
            )
            .await;
        }
        SubCommand::GetIcpXdrConversionRate => {
            let key = XDR_PER_ICP_KEY;
            let key = key.as_bytes().to_vec();
            let value = registry_canister.get_value(key.clone(), None).await;
            if let Ok((bytes, _version)) = value {
                let value = IcpXdrConversionRateRecord::decode(&bytes[..])
                    .expect("Error decoding conversion rate from registry.");
                // Convert the UNIX epoch timestamp to date and (UTC) time:
                let date_time = NaiveDateTime::from_timestamp(value.timestamp_seconds as i64, 0);
                let date_time: DateTime<Utc> = DateTime::from_utc(date_time, Utc);
                println!(
                    "ICP/XDR conversion rate at {}: {}",
                    date_time,
                    value.xdr_permyriad_per_icp as f64 / 10_000.
                );
            }
        }
        SubCommand::ProposeToUpdateSubnetReplicaVersion(cmd) => {
            propose_update_subnet_replica_version(cmd, opts.nns_url, &registry_canister, sender)
                .await;
        }
        SubCommand::GetBlessedReplicaVersions => {
            print_and_get_last_value::<BlessedReplicaVersions>(
                make_blessed_replica_version_key().as_bytes().to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::GetRoutingTable => {
            print_and_get_last_value::<RoutingTable>(
                make_routing_table_record_key().as_bytes().to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::ProposeToBlessReplicaVersion(cmd) => {
            propose_to_bless_replica_version(cmd, opts.nns_url, sender).await
        }
        SubCommand::ProposeToBlessReplicaVersionFlexible(cmd) => {
            propose_to_bless_replica_version_flexible(cmd, opts.nns_url, sender).await
        }
        SubCommand::ProposeToCreateSubnet(cmd) => {
            propose_to_create_subnet(cmd, opts.nns_url, sender).await
        }
        SubCommand::ProposeToAddNodesToSubnet(cmd) => {
            propose_to_add_nodes_to_subnet(&registry_canister, cmd, opts.nns_url, sender).await
        }
        SubCommand::ProposeToUpdateRecoveryCup(cmd) => {
            let subnet_id = cmd.subnet.get_id(&registry_canister).await.get();
            propose_to_recover_subnet(cmd, opts.nns_url, sender, subnet_id).await
        }
        SubCommand::ProposeToUpdateSubnet(cmd) => {
            propose_to_update_subnet(&registry_canister, cmd, opts.nns_url, sender).await
        }
        SubCommand::ProposeToAddNnsCanister(cmd) => {
            propose_to_add_nns_canister(cmd, opts.nns_url, sender).await
        }
        SubCommand::ProposeToChangeNnsCanister(cmd) => {
            propose_to_change_nns_canister(cmd, opts.nns_url, sender).await
        }
        SubCommand::ProposeToClearProvisionalWhitelist(cmd) => {
            propose_to_clear_provisional_whitelist(cmd, opts.nns_url, sender).await
        }
        SubCommand::ProposeToSetAuthorizedSubnetworks(cmd) => {
            propose_to_set_authorized_subnetworks(cmd, opts.nns_url, sender).await
        }
        SubCommand::AddNodeViaNns(cmd) => add_node_via_nns(cmd, opts.nns_url, sender).await,
        SubCommand::ForwardTestNeuronVote(cmd) => forward_test_neuron_vote(cmd, opts.nns_url).await,
        SubCommand::ExecuteEligibleProposals => execute_eligible_proposals(opts.nns_url).await,
        SubCommand::GetProvisionalWhitelist => {
            print_and_get_last_value::<ProvisionalWhitelistProto>(
                make_provisional_whitelist_record_key().as_bytes().to_vec(),
                &registry_canister,
            )
            .await;
        }
        SubCommand::GetSubnetPublicKey(cmd) => {
            store_subnet_pk(&registry_canister, cmd.subnet, cmd.target_path.as_path()).await;
        }
        SubCommand::GetRecoveryCup(cmd) => get_recovery_cup(registry_canister, cmd).await,
        SubCommand::ProposeToAddNodeOperator(cmd) => {
            propose_to_add_node_operator(cmd, opts.nns_url, sender).await
        }
        SubCommand::GetNodeOperator(cmd) => {
            let key = make_node_operator_record_key(cmd.node_operator_principal_id)
                .as_bytes()
                .to_vec();

            print_and_get_last_value::<NodeOperatorRecord>(key, &registry_canister).await;
        }
        SubCommand::GetNodeOperatorList => {
            let registry_client =
                RegistryClientImpl::new(Arc::new(NnsDataProvider::new(registry_canister)), None);

            registry_client.fetch_and_start_polling().unwrap();

            let keys = registry_client
                .get_key_family(
                    NODE_OPERATOR_RECORD_KEY_PREFIX,
                    registry_client.get_latest_version(),
                )
                .unwrap();

            println!();
            for key in keys {
                let node_operator_id = key.strip_prefix(NODE_OPERATOR_RECORD_KEY_PREFIX).unwrap();
                println!("{}", node_operator_id);
            }
        }
        SubCommand::UpdateRegistryLocalStore(cmd) => {
            update_registry_local_store(opts.nns_url, cmd).await;
        }
        SubCommand::ProposeToUpdateNodeOperatorConfig(cmd) => {
            propose_to_update_node_operator_config(cmd, opts.nns_url, sender).await
        }
        SubCommand::ProposeToSetFirewallConfig(cmd) => {
            propose_to_set_firewall_config(cmd, opts.nns_url, sender).await
        }
    }
}

fn read_file_fully(path: &PathBuf) -> Vec<u8> {
    let mut f = File::open(path).unwrap_or_else(|_| panic!("Value file not found at: {:?}", path));
    let metadata = metadata(path).expect("Unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read_exact(&mut buffer)
        .unwrap_or_else(|_| panic!("Couldn't read the content of {:?}", path));
    buffer
}

fn parse_json_or_load_pb<'a, T: Default + Message + Deserialize<'a>>(
    value_format: ValueFormat,
    value: &'a str,
) -> T {
    match value_format {
        ValueFormat::Json => serde_json::from_str(value)
            .unwrap_or_else(|e| panic!("Couldn't parse value of type {} from json, because of: '{}'. The input jason was: {:?}", std::any::type_name::<T>(), e, value)),
        ValueFormat::PBFile => {
            let buffer = read_file_fully(&PathBuf::from(value));
            T::decode(&buffer[..]).unwrap_or_else(|e| panic!("Could not decode protobuf of type {} due to: {}. The input file was {}.", std::any::type_name::<T>(), e, value))
        }
    }
}

fn collect_pb_files(path: &PathBuf, ignore_files_with_prefix: Vec<String>) -> Vec<PathBuf> {
    // total function that returns false iff the file_name of the entry starts with
    // `ic_registry_local_store`
    fn is_not_local_store(entry: &DirEntry) -> bool {
        entry
            .file_name()
            .to_str()
            .map(|s| !s.starts_with("ic_registry_local_store"))
            .unwrap_or(true)
    }

    let mut files = Vec::new();
    for entry in WalkDir::new(path)
        .into_iter()
        .filter_entry(is_not_local_store)
        .filter_map(|e| e.ok())
    {
        let entry_path = entry.path();
        let metadata = metadata(&entry_path)
            .unwrap_or_else(|_| panic!("Unable to read the metadata on path: {:?}", entry_path));
        if !metadata.is_dir() {
            let file_name = entry_path.file_name().unwrap().to_str().unwrap();

            // Only collect protobuf (.pb) files
            if !file_name.ends_with(".pb") {
                continue;
            }

            let mut ignore = false;
            // Ignore files starting with the prefixes in the prefix list.
            for prefix in &ignore_files_with_prefix {
                if file_name.starts_with(&prefix.as_str()) {
                    ignore = true;
                }
            }

            if !ignore {
                files.push(entry_path.to_path_buf());
            }
        }
    }
    files
}

fn create_mutation_from_file(path: &PathBuf) -> RegistryMutation {
    let key = path.file_stem().expect("Couldn't get file name.");
    let value = read_file_fully(path);

    println!(
        "Adding registry entry from file: {:?}, Key: {:?}",
        path, key
    );

    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Insert);
    mutation.key = key.as_bytes().to_vec();
    mutation.value = value;
    mutation
}

async fn print_and_get_last_value<T: Message + Default + serde::Serialize>(
    key: Vec<u8>,
    registry: &RegistryCanister,
) -> T {
    let value = registry.get_value(key.clone(), None).await;
    match value.clone() {
        Ok((bytes, version)) => {
            if key.starts_with(b"subnet_record_") {
                // subnet records are emitted as JSON
                let value = SubnetRecordProto::decode(&bytes[..])
                    .expect("Error decoding value from registry.");
                let subnet_record = SubnetRecord::from(&value);

                let mut registry = Registry {
                    version,
                    ..Default::default()
                };

                let record = RegistryRecord {
                    key: std::str::from_utf8(&key)
                        .expect("key is not a str")
                        .to_string(),
                    version,
                    value: RegistryValue::SubnetRecord(subnet_record),
                };

                registry.records.push(record);

                println!("{}", serde_json::to_string_pretty(&registry).unwrap());
            } else if key == b"provisional_whitelist" {
                let value = ProvisionalWhitelistProto::decode(&bytes[..])
                    .expect("Error decoding value from registry.");
                let provisional_whitelist = ProvisionalWhitelistRecord::from(value);

                let mut registry = Registry {
                    version,
                    ..Default::default()
                };
                let record = RegistryRecord {
                    key: std::str::from_utf8(&key)
                        .expect("key is not a str")
                        .to_string(),
                    version,
                    value: RegistryValue::ProvisionalWhitelistRecord(provisional_whitelist),
                };

                registry.records.push(record);

                println!("{}", serde_json::to_string_pretty(&registry).unwrap());
            } else {
                // Everything is dumped as debug representation
                println!(
                    "Fetching the most recent value for key: {:?}",
                    std::str::from_utf8(&key).unwrap()
                );
                let value = T::decode(&bytes[..]).expect("Error decoding value from registry.");
                println!("Most recent version is {:?}. Value:\n{:?}", version, value);
            }
        }
        Err(error) => {
            let msg = match error {
                Error::KeyNotPresent(key) => format!(
                    "Key not present: {}",
                    std::str::from_utf8(&key).expect("key is not a str")
                ),
                _ => format!("{:?}", error),
            };
            panic!(format!("Error getting value from registry: {}", msg));
        }
    };

    value
        .map(|(bytes, _version)| T::decode(&bytes[..]).unwrap())
        .unwrap()
}

// Mutates the registry to contain all the keys (identified by files found in
// `path`).  Each key is pushed individually so that if inserting one key fails,
// it does not fail insertion of others.  Some key insertions are expected to
// fail (e.g. when creating a subsequent subnet and the key already exists as is
// the case with the routing_table).
async fn add_all_files_in_path(path: &PathBuf, nodes_only: bool, registry: &RegistryCanister) {
    async fn do_mutate(file: PathBuf, registry: &RegistryCanister) {
        let mutation = create_mutation_from_file(&file);
        match registry.atomic_mutate(vec![mutation], vec![]).await {
            Err(err) => eprintln!(
                "Registry mutating for {:?} failed with {:?}.  Ignoring and continuing",
                file, err
            ),
            Ok(version) => println!("Registry mutating for {:?} succeeded at {}", file, version),
        }
    }

    let mut ignore_files_with_prefix = vec![
        "sks_data".to_string(),
        "public_keys".to_string(),
        "nns_subnet_id".to_string(),
    ];
    if nodes_only {
        ignore_files_with_prefix.push("subnet_record".to_string());
        ignore_files_with_prefix.push("catch_up_package_contents".to_string());
        ignore_files_with_prefix.push("subnet_list".to_string());
    }

    join_all(
        collect_pb_files(path, ignore_files_with_prefix)
            .into_iter()
            .map(|file| do_mutate(file, registry)),
    )
    .await;
}

async fn add_pb_file_entry(path: &PathBuf, registry: &RegistryCanister) {
    let mutation = create_mutation_from_file(path);

    match registry.atomic_mutate(vec![mutation], vec![]).await {
        Ok(result) => println!("Registry mutated. New version: {:?}", result),
        Err(error) => panic!(format!("Error mutating the registry: {:?}", error)),
    }
}

async fn add_public_key(
    node_id: NodeId,
    key_purpose: KeyPurpose,
    value: PublicKey,
    registry: &RegistryCanister,
) {
    println!(
        "Adding public key: NodeId: {:?}, Key Purpose: {:?}, Value: {:?}",
        node_id, key_purpose, value
    );

    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Insert);
    mutation.key = make_crypto_node_key(node_id, key_purpose)
        .as_bytes()
        .to_vec();
    let mut buf = Vec::new();
    match value.encode(&mut buf) {
        Ok(_) => mutation.value = buf,
        Err(error) => panic!(format!("Error encoding the value to protobuf: {:?}", error)),
    }

    let result = registry.atomic_mutate(vec![mutation], vec![]).await;
    let result = result.expect("Couldn't reach the registry.");
    println!("Registry mutated. New version: {:?}", result);
}

async fn delete_public_key(node_id: NodeId, key_purpose: KeyPurpose, registry: &RegistryCanister) {
    println!(
        "Deleting public key: NodeId: {:?}, Key Purpose: {:?}",
        node_id, key_purpose
    );

    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Delete);
    mutation.key = make_crypto_node_key(node_id, key_purpose)
        .as_bytes()
        .to_vec();

    let result = registry.atomic_mutate(vec![mutation], vec![]).await;
    let result = result.expect("Couldn't reach the registry.");
    println!("Registry mutated. New version: {:?}", result);
}

async fn add_tls_certificate(
    node_id: NodeId,
    value: X509PublicKeyCert,
    registry: &RegistryCanister,
) {
    println!(
        "Adding TLS certificate: NodeId: {:?}, Value: {:?}",
        node_id, value
    );

    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Insert);
    mutation.key = make_crypto_tls_cert_key(node_id).as_bytes().to_vec();
    let mut buf = Vec::new();
    match value.encode(&mut buf) {
        Ok(_) => mutation.value = buf,
        Err(error) => panic!(format!("Error encoding the value to protobuf: {:?}", error)),
    }

    let result = registry.atomic_mutate(vec![mutation], vec![]).await;
    let result = result.expect("Couldn't reach the registry.");
    println!("Registry mutated. New version: {:?}", result);
}

async fn delete_tls_certificate(node_id: NodeId, registry: &RegistryCanister) {
    println!("Deleting TLS certificate: NodeId: {:?}", node_id);

    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Delete);
    mutation.key = make_crypto_tls_cert_key(node_id).as_bytes().to_vec();

    let result = registry.atomic_mutate(vec![mutation], vec![]).await;
    let result = result.expect("Couldn't reach the registry.");
    println!("Registry mutated. New version: {:?}", result);
}

async fn add_node(
    node_id: NodeId,
    subnet_id: SubnetId,
    value: NodeRecord,
    registry: &RegistryCanister,
) {
    println!(
        "Adding node: NodeId: {:?}, Value: {:?} to Subnet {:?}",
        node_id, value, subnet_id
    );

    // Subnet mutation add the node to a subnet record
    let subnet_key = make_subnet_record_key(subnet_id).as_bytes().to_vec();
    let (mut subnet_value, subnet_version) =
        match registry.get_value(subnet_key.clone(), None).await {
            Ok((bytes, version)) => (
                SubnetRecordProto::decode(&bytes[..]).expect("Error decoding value from registry."),
                version,
            ),
            Err(error) => panic!(format!(
                "Error getting subnet value from registry: {:?}",
                error
            )),
        };

    if subnet_value
        .membership
        .iter()
        .map(|n| NodeId::from(PrincipalId::try_from(&n[..]).unwrap()))
        .any(|subnet_node_id| subnet_node_id == node_id)
    {
        panic!(format!(
            "Node {:?} already part of subnet {:?}",
            node_id, subnet_id
        ))
    }

    subnet_value
        .membership
        .push(node_id.clone().get().into_vec());

    let mut subnet_mutation = RegistryMutation::default();
    subnet_mutation.set_mutation_type(registry_mutation::Type::Update);
    subnet_mutation.key = subnet_key.clone();
    let mut buf = Vec::new();
    match subnet_value.encode(&mut buf) {
        Ok(_) => subnet_mutation.value = buf,
        Err(error) => panic!(format!("Error encoding the value to protobuf: {:?}", error)),
    }

    // Mutation for the node record
    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Insert);
    mutation.key = make_node_record_key(node_id).as_bytes().to_vec();
    let mut buf = Vec::new();
    match value.encode(&mut buf) {
        Ok(_) => mutation.value = buf,
        Err(error) => panic!(format!("Error encoding the value to protobuf: {:?}", error)),
    }

    // Preconditions
    let pre_conditions = vec![Precondition {
        key: subnet_key,
        expected_version: subnet_version,
    }];
    let result = registry
        .atomic_mutate(vec![subnet_mutation, mutation], pre_conditions)
        .await;
    let result = result.expect("Couldn't reach the registry.");
    println!("Registry mutated. New version: {:?}", result);
}

async fn remove_node(cmd: RemoveNodeCmd, nns_url: Url, sender: Sender) {
    let handler = RegistryHandler(make_handler(nns_url, REGISTRY_CANISTER_ID, sender, None));
    let response = handler
        .remove_node(RemoveNodePayload {
            node_id: NodeId::from(cmd.node_id),
        })
        .await;
    println!("remove_node response: {:?}", response);
}

async fn add_nodes_to_subnet(
    node_ids: Vec<NodeId>,
    subnet_id: SubnetId,
    registry: &RegistryCanister,
) {
    // Subnet mutation add the node to a subnet record
    let subnet_key = make_subnet_record_key(subnet_id).as_bytes().to_vec();
    let (mut subnet_record, subnet_version) =
        match registry.get_value(subnet_key.clone(), None).await {
            Ok((bytes, version)) => (
                SubnetRecordProto::decode(&bytes[..]).expect("Error decoding value from registry."),
                version,
            ),
            Err(error) => panic!(format!(
                "Error getting subnet value from registry: {:?}",
                error
            )),
        };

    let node_set: BTreeSet<NodeId> = node_ids.iter().cloned().collect();

    let membership: BTreeSet<NodeId> = subnet_record
        .membership
        .iter()
        .map(|n| NodeId::from(PrincipalId::try_from(&n[..]).unwrap()))
        .collect();

    for node_id in membership.intersection(&node_set) {
        eprintln!(
            "Node {:} already member of the subnet {:}, skipping.",
            node_id, subnet_id
        );
    }

    let mut to_be_added = node_set
        .difference(&membership)
        .cloned()
        .map(|n| n.get().into_vec())
        .collect();

    subnet_record.membership.append(&mut to_be_added);

    let new_subnet_record = {
        let mut buf = Vec::new();
        subnet_record
            .encode(&mut buf)
            .expect("Error encoding the value of the subnet record to protobuf");
        buf
    };

    let subnet_mutation = update(subnet_key.clone(), new_subnet_record);

    // Preconditions
    let pre_conditions = vec![Precondition {
        key: subnet_key,
        expected_version: subnet_version,
    }];
    let result = registry
        .atomic_mutate(vec![subnet_mutation], pre_conditions)
        .await;
    let result = result.expect("Problem with mutating the registry with new subnet.");
    println!("Registry mutated. New version: {:?}", result);
}

async fn propose_to_remove_nodes_from_subnet(
    cmd: ProposeToRemoveNodesFromSubnetCmd,
    nns_url: Url,
    sender: Sender,
) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        nns_url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));
    let node_ids = cmd.node_ids.into_iter().map(NodeId::from).collect();
    let payload = RemoveNodesFromSubnetPayload { node_ids };

    let response = handler
        .submit_external_proposal_candid::<RemoveNodesFromSubnetPayload>(
            payload,
            NnsFunction::RemoveNodesFromSubnet,
            parse_proposal_url(cmd.proposal_url),
            "RemoveNodesFromSubnet",
        )
        .await;
    eprintln!(
        "submit_proposal for RemoveNodesFromSubnet response: {:?}",
        response
    );
    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("submit_proposal for RemoveNodesFromSubnet error: {:?}", e);
            std::process::exit(1);
        }
    };
}

/// Just add the node record to the registry, without it being added to a
/// subnet.
async fn just_add_node(node_id: NodeId, value: NodeRecord, registry: &RegistryCanister) {
    println!("Adding node: NodeId: {:?}, Value: {:?}", node_id, value);

    // Mutation for the node record
    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Insert);
    mutation.key = make_node_record_key(node_id).as_bytes().to_vec();
    let mut buf = Vec::new();
    match value.encode(&mut buf) {
        Ok(_) => mutation.value = buf,
        Err(error) => panic!(format!("Error encoding the value to protobuf: {:?}", error)),
    }

    let result = registry.atomic_mutate(vec![mutation], vec![]).await;
    let result = result.expect("Couldn't reach the registry.");
    println!("Registry mutated. New version: {:?}", result);
}

async fn delete_node(node_id: NodeId, registry: &RegistryCanister) {
    println!("Deleting node: NodeId: {:?}", node_id);

    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Delete);
    mutation.key = make_node_record_key(node_id).as_bytes().to_vec();

    let result = registry.atomic_mutate(vec![mutation], vec![]).await;
    let result = result.expect("Couldn't reach the registry.");
    println!("Registry mutated. New version: {:?}", result);
}

#[derive(Serialize)]
struct NodeAndNodeOperatorId {
    node_id: String,
    node_operator_id: String,
}

async fn get_node_list_since(
    version: u64,
    registry: &RegistryCanister,
) -> Vec<NodeAndNodeOperatorId> {
    //Retrieving the nodes added since a given version involves
    //going over all the changes since said version;
    let delta = registry.get_changes_since(version).await;
    let (ds, _) = match delta {
        Err(err) => panic!("Couldn't fetch registry delta: {:?}", err),
        Ok(v) => v,
    };

    let node_records: Vec<NodeAndNodeOperatorId> = ds
        .iter()
        .filter_map(|d| {
            let str_key: &str = std::str::from_utf8(&d.key).unwrap();
            //Since RecordDelta's are stringly typed; we must filter those
            // with the relevant keys.
            if is_node_record_key(str_key) {
                //Getting the actual NodeRecord consists in getting the
                // NodeRecord for this key in the /latest/ version IFF the
                // deletion_marker is not set;
                let mut vals = d.values.clone();
                vals.sort_by(|a, b| a.version.cmp(&b.version));
                vals.last()
                    .filter(|v| !v.deletion_marker)
                    .and_then(|v| NodeRecord::decode(v.value.as_slice()).ok())
                    .map(|res| NodeAndNodeOperatorId {
                        node_id: format!("{}", get_node_record_node_id(str_key).unwrap()),
                        node_operator_id: format!(
                            "{}",
                            PrincipalId::try_from(res.node_operator_id).unwrap()
                        ),
                    })
            } else {
                None
            }
        })
        .collect();

    node_records
}

fn parse_proposal_url(url: Option<Url>) -> String {
    match url {
        Some(url) => {
            if url.scheme() != "https" {
                panic!("proposal-url must use https");
            }
            url.to_string()
        }
        // By default point to the landing page of `nns-proposals` repository.
        None => "https://github.com/dfinity/nns-proposals/".to_string(),
    }
}

fn extract_subnet_ids(subnet_list_record: &SubnetListRecord) -> Vec<SubnetId> {
    subnet_list_record
        .subnets
        .iter()
        .map(|x| {
            SubnetId::from(
                PrincipalId::try_from(x.clone().as_slice()).expect("failed parsing principal id"),
            )
        })
        .collect()
}

async fn get_subnet_ids(registry: &RegistryCanister) -> Vec<SubnetId> {
    let (subnet_list_record, _) = get_subnet_list_record(registry).await;
    extract_subnet_ids(&subnet_list_record)
}

async fn get_subnet_list_record(registry: &RegistryCanister) -> (SubnetListRecord, bool) {
    // First we need to get the current subnet list record.

    let subnet_list_record_result = registry
        .get_value(SUBNET_LIST_KEY.as_bytes().to_vec(), None)
        .await;
    match subnet_list_record_result {
        Ok((bytes, _version)) => match SubnetListRecord::decode(&bytes[..]) {
            Ok(record) => (record, false),
            Err(error) => panic!(format!("Error decoding subnet list record: {:?}", error)),
        },
        Err(error) => match error {
            // It might be the first time we store a subnet, so we might
            // have to update the subnet list record.
            Error::KeyNotPresent(_) => (SubnetListRecord::default(), true),
            _ => panic!(format!(
                "Error while fetching current subnet list record: {:?}",
                error
            )),
        },
    }
}

async fn add_subnet(
    value: SubnetRecordProto,
    dkg: CatchUpPackageContents,
    registry: &RegistryCanister,
) {
    println!("Adding subnet record: Value: {:?}", value);

    let ni_dkg_transcript_record = dkg
        .clone()
        .initial_ni_dkg_transcript_high_threshold
        .unwrap();
    let dkg_id_record = ni_dkg_transcript_record.id.expect("missing NI-DKG id");
    let dkg_id = NiDkgId::try_from(dkg_id_record).expect("invalid NI-DKG id");
    let committee: BTreeSet<NodeId> = ni_dkg_transcript_record
        .committee
        .iter()
        .map(|n| NodeId::from(PrincipalId::try_from(&n[..]).expect("invalid principal id")))
        .collect();
    let transcript = NiDkgTranscript {
        dkg_id,
        threshold: NiDkgThreshold::new(NumberOfNodes::new(ni_dkg_transcript_record.threshold))
            .expect("invalid threshold"),
        committee: NiDkgReceivers::new(committee).expect("invalid committee"),
        registry_version: RegistryVersion::from(0), // Should not matter
        internal_csp_transcript: serde_cbor::from_slice(
            ni_dkg_transcript_record.internal_csp_transcript.as_slice(),
        )
        .unwrap(),
    };

    let subnet_key_der: Vec<u8> =
        ic_crypto::threshold_sig_public_key_to_der(transcript.public_key())
            .expect("failed computing subnet threshold key");
    let subnet_id = SubnetId::new(PrincipalId::new_self_authenticating(
        subnet_key_der.as_slice(),
    ));

    let (mut subnet_list_record, is_new) = get_subnet_list_record(registry).await;
    let is_in_subnet_list = subnet_list_record.subnets.iter().any(|x| {
        SubnetId::from(
            PrincipalId::try_from(x.clone().as_slice()).expect("failed parsing principal id"),
        ) == subnet_id
    });
    if !is_new && is_in_subnet_list {
        panic!(format!(
            "Subnet already present in subnet list record: {:?}",
            subnet_id
        ));
    }

    subnet_list_record.subnets.push(subnet_id.get().into_vec());

    let mut updated_subnet_list = RegistryMutation::default();
    updated_subnet_list.mutation_type = 1;
    // If this is the very first subnet, insert instead of update.
    if is_new {
        updated_subnet_list.mutation_type = 0;
    }
    updated_subnet_list.key = SUBNET_LIST_KEY.as_bytes().to_vec();

    let mut buf = Vec::new();
    match subnet_list_record.encode(&mut buf) {
        Ok(_) => updated_subnet_list.value = buf,
        Err(error) => panic!(format!("Error encoding the value to protobuf: {:?}", error)),
    }

    let mut new_subnet = RegistryMutation::default();
    new_subnet.mutation_type = 0;
    new_subnet.key = make_subnet_record_key(subnet_id).as_bytes().to_vec();
    let mut buf = Vec::new();
    match value.encode(&mut buf) {
        Ok(_) => new_subnet.value = buf,
        Err(error) => panic!(format!("Error encoding the value to protobuf: {:?}", error)),
    }

    let mut new_dkg = RegistryMutation::default();
    new_dkg.mutation_type = 0;
    new_dkg.key = make_catch_up_package_contents_key(subnet_id)
        .as_bytes()
        .to_vec();
    let mut buf = Vec::new();
    match dkg.encode(&mut buf) {
        Ok(_) => new_dkg.value = buf,
        Err(error) => panic!(format!("Error encoding the value to protobuf: {:?}", error)),
    }

    let (routing_table_mutation, precondition) =
        routing_table::add_subnet_to_routing_table(&registry, subnet_id).await;

    let result = registry
        .atomic_mutate(
            vec![
                updated_subnet_list,
                new_subnet,
                new_dkg,
                routing_table_mutation,
            ],
            vec![precondition],
        )
        .await;
    let result = result.expect("Error mutating the registry.");
    println!("Registry mutated. New version: {:?}", result);
}

async fn delete_subnet(subnet_id: SubnetId, registry: &RegistryCanister) {
    println!("Deleting subnet: SubnetId: {:?}", subnet_id);

    let (mut subnet_list_record, is_new) = get_subnet_list_record(registry).await;

    if is_new {
        panic!("The registry doesn't contain any subnets.");
    }

    match subnet_list_record.subnets.iter().position(|x| {
        SubnetId::from(
            PrincipalId::try_from(x.clone().as_slice()).expect("failed parsing principal id"),
        ) == subnet_id
    }) {
        Some(idx) => {
            subnet_list_record.subnets.remove(idx);
        }
        None => panic!(format!(
            "Subnet already present in subnet list record: {:?}",
            subnet_id
        )),
    }

    let mut updated_subnet_list = RegistryMutation::default();
    updated_subnet_list.mutation_type = 1;
    updated_subnet_list.key = SUBNET_LIST_KEY.as_bytes().to_vec();

    let mut buf = Vec::new();
    match subnet_list_record.encode(&mut buf) {
        Ok(_) => updated_subnet_list.value = buf,
        Err(error) => panic!(format!("Error encoding the value to protobuf: {:?}", error)),
    }

    let mut deleted_subnet = RegistryMutation::default();
    deleted_subnet.mutation_type = 2;
    deleted_subnet.key = make_subnet_record_key(subnet_id).as_bytes().to_vec();

    let mut deleted_subnet_dkg = RegistryMutation::default();
    deleted_subnet_dkg.mutation_type = 2;
    deleted_subnet_dkg.key = make_catch_up_package_contents_key(subnet_id)
        .as_bytes()
        .to_vec();

    let result = registry
        .atomic_mutate(
            vec![updated_subnet_list, deleted_subnet, deleted_subnet_dkg],
            vec![],
        )
        .await;
    let result = result.expect("Error mutating the registry.");
    println!("Registry mutated. New version: {:?}", result);
}

async fn delete_subnet_threshold_signing_public_key(
    subnet_id: SubnetId,
    registry: &RegistryCanister,
) {
    println!(
        "Deleting threshold signing public key: SubnetId: {:?}",
        subnet_id
    );

    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Delete);
    mutation.key = make_crypto_threshold_signing_pubkey_key(subnet_id)
        .as_bytes()
        .to_vec();

    let result = registry.atomic_mutate(vec![mutation], vec![]).await;
    let result = result.expect("Couldn't reach the registry.");
    println!("Registry mutated. New version: {:?}", result);
}

async fn submit_initial_registry_version<P: AsRef<Path>>(path: P, registry: &RegistryCanister) {
    let mutations = read_initial_registry_mutations(path);

    let new_version = registry
        .atomic_mutate(mutations, vec![])
        .await
        .expect("Could not mutate registry.");
    // If the registry version is larger than 1, we were not the first to update the
    // registry. Make sure to abort deployment in such a case.
    if new_version != 1 {
        panic!("NNS BOOTSTRAP FAILED. Returned latest registry version is != 1.")
    }

    println!("Registry mutated. New version: {}", new_version);
}

/// Adds the given `ReplicaVersionRecord` to the registry
async fn add_replica_version(
    replica_version_id: String,
    record: ReplicaVersionRecord,
    registry: &RegistryCanister,
) {
    println!("Adding replica version: {:?}", record);

    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Insert);
    mutation.key = make_replica_version_key(replica_version_id)
        .as_bytes()
        .to_vec();

    let mut buf = Vec::new();
    match record.encode(&mut buf) {
        Ok(_) => mutation.value = buf,
        Err(error) => panic!(format!("Error encoding the value to protobuf: {:?}", error)),
    }

    let result = registry.atomic_mutate(vec![mutation], vec![]).await;
    let result = result.expect("Couldn't reach the registry.");
    println!("Registry mutated. New version: {:?}", result);
}

/// Updates the given subnet with the given replica version, bypassing the
/// upgrades handler.
async fn update_subnet_replica_version_bypassing_handler(
    subnet_id: SubnetId,
    replica_version_id: String,
    registry: &RegistryCanister,
) {
    println!(
        "⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠

You're about to update a subnet's record by directly mutating the registry, \
without verifying that this version is blessed.

You can either continue and feel guilty for the rest of your life, \
or you can abort, submit a proposal to bless the version with command \
'propose-to-bless-replica-version', get it voted on, get it executed, \
and then use command 'update_subnet_replica_version' instead.

The result will be identical.

To make this warning annoying enough, we will now wait for 15 seconds \
to give you a chance to CTRL+C.

⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠⚠
"
    );
    std::thread::sleep(std::time::Duration::from_secs(15));
    // check that a valid entry exists for `replica_version_id` in the registry
    let replica_version_key = make_replica_version_key(replica_version_id.clone())
        .as_bytes()
        .to_vec();
    match registry.get_value(replica_version_key, None).await {
        Ok((bytes, _)) => {
            ReplicaVersionRecord::decode(&bytes[..])
                .expect("Error decoding ReplicaVersionRecord from registry");
        }
        Err(error) => panic!(format!("Error getting value from registry: {:?}", error)),
    };

    let subnet_key = make_subnet_record_key(subnet_id).as_bytes().to_vec();
    let mut subnet_record = match registry.get_value(subnet_key.clone(), None).await {
        Ok((bytes, _)) => SubnetRecordProto::decode(&bytes[..])
            .expect("Error decoding SubnetRecord from registry"),
        Err(error) => panic!(format!("Error getting value from registry: {:?}", error)),
    };

    subnet_record.replica_version_id = replica_version_id;

    let mut mutation = RegistryMutation::default();
    mutation.set_mutation_type(registry_mutation::Type::Update);
    mutation.key = subnet_key;

    let mut buf = Vec::new();
    match subnet_record.encode(&mut buf) {
        Ok(_) => mutation.value = buf,
        Err(error) => panic!(format!("Error encoding the value to protobuf: {:?}", error)),
    }

    let result = registry.atomic_mutate(vec![mutation], vec![]).await;
    let result = result.expect("Error mutating the registry.");
    println!("Registry mutated. New version: {:?}", result);
}

async fn store_subnet_pk<P: AsRef<Path>>(
    registry: &RegistryCanister,
    subnet: SubnetDescriptor,
    path: P,
) {
    let subnet_id = subnet.get_id(registry).await;
    let pk = get_subnet_pk(registry, subnet_id).await;
    store_threshold_sig_pk(&pk, path);
}

async fn get_subnet_pk(registry: &RegistryCanister, subnet_id: SubnetId) -> PublicKey {
    let k = make_crypto_threshold_signing_pubkey_key(subnet_id)
        .as_bytes()
        .to_vec();
    match registry.get_value(k.clone(), None).await {
        Ok((bytes, _)) => {
            PublicKey::decode(&bytes[..]).expect("Error decoding PublicKey from registry")
        }
        Err(error) => panic!(format!("Error getting value from registry: {:?}", error)),
    }
}

async fn get_recovery_cup(registry_canister: RegistryCanister, cmd: GetRecoveryCupCmd) {
    let subnet_id = cmd.subnet.get_id(&registry_canister).await;
    let registry_client =
        RegistryClientImpl::new(Arc::new(NnsDataProvider::new(registry_canister)), None);
    registry_client
        .fetch_and_start_polling()
        .expect("Failed to poll client");

    let cup = make_registry_cup(&registry_client, subnet_id).expect("Failed to make registry CUP");

    // This prints JSON with byte array fields in hex format.
    fn to_json_string<T: Serialize>(msg: &T) -> String {
        let mut out = vec![];
        let mut ser = serde_json::Serializer::new(&mut out);
        let ser = serde_bytes_repr::ByteFmtSerializer::hex(&mut ser);
        msg.serialize(ser).expect("Failed to serialize to JSON");
        String::from_utf8(out).expect("UTF8 conversion error")
    }

    // CUP content is printed to stdout as JSON string.
    println!("{}", to_json_string(&cup));
    // Additional information is printed to stderr in human readable form.
    eprintln!(
        "height: {}, time: {}, state_hash: {:?}",
        cup.height(),
        cup.content.block.as_ref().context.time,
        cup.content.state_hash
    );

    if !cmd.output_file.as_os_str().is_empty() {
        let cup_proto = CUPWithOriginalProtobuf::from_cup(cup);
        let mut file =
            std::fs::File::create(cmd.output_file).expect("Failed to open output file for write");
        let mut bytes = Vec::<u8>::new();
        cup_proto
            .protobuf
            .encode(&mut bytes)
            .expect("Failed to encode protobuf");
        file.write_all(&bytes)
            .expect("Failed to write to output file");
    }
}

async fn propose_update_subnet_replica_version(
    cmd: ProposeToUpdateSubnetReplicaVersionCmd,
    url: Url,
    registry_canister: &RegistryCanister,
    sender: Sender,
) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));

    let subnet_id = cmd.subnet.get_id(registry_canister).await;
    let payload = UpdateSubnetReplicaVersionPayload {
        subnet_id: subnet_id.get(),
        replica_version_id: cmd.replica_version_id,
    };

    println!(
        "Submitting proposal to update subnet replica version:\n{:#?}",
        &payload
    );
    let response = handler
        .submit_external_proposal_candid::<UpdateSubnetReplicaVersionPayload>(
            payload,
            NnsFunction::UpdateSubnetReplicaVersion,
            parse_proposal_url(cmd.proposal_url),
            "UpdateSubnetReplicaVersion",
        )
        .await;
    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!(
                "submit_proposal for UpdateSubnetReplicaVersion error: {:?}",
                e
            );
            std::process::exit(1);
        }
    };
}

async fn propose_to_bless_replica_version(
    cmd: ProposeToBlessReplicaVersionCmd,
    url: Url,
    sender: Sender,
) {
    let file_downloader = FileDownloader::new(None);
    let replica_url = format!(
        "https://download.dfinity.systems/ic/{}/x86_64-linux/ic-replica.tar.gz",
        &cmd.commit_hash
    );
    let node_manager_url = format!(
        "https://download.dfinity.systems/ic/{}/x86_64-linux/nodemanager.tar.gz",
        &cmd.commit_hash
    );

    let dir = tempfile::tempdir().unwrap().into_path();
    file_downloader
        .download_and_extract_tar_gz(&replica_url, &dir, None)
        .await
        .unwrap();

    file_downloader
        .download_and_extract_tar_gz(&node_manager_url, &dir, None)
        .await
        .unwrap();

    let replica_sha256_hex = compute_sha256_hex(&dir.join("replica")).unwrap();
    let node_manager_sha256_hex = compute_sha256_hex(&dir.join("nodemanager")).unwrap();

    propose_to_bless_replica_version_flexible(
        ProposeToBlessReplicaVersionFlexibleCmd {
            replica_version_id: cmd.commit_hash.clone(),
            replica_url: Some(replica_url),
            replica_sha256_hex: Some(replica_sha256_hex),
            node_manager_url: Some(node_manager_url),
            node_manager_sha256_hex: Some(node_manager_sha256_hex),
            release_package_url: None,
            release_package_sha256_hex: None,
            proposer: cmd.proposer,
            test_neuron_proposer: cmd.test_neuron_proposer,
            proposal_url: cmd.proposal_url,
        },
        url,
        sender,
    )
    .await;
}

async fn propose_to_bless_replica_version_flexible(
    cmd: ProposeToBlessReplicaVersionFlexibleCmd,
    url: Url,
    sender: Sender,
) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));

    let payload = if let Some(release_package_url) = cmd.release_package_url {
        BlessReplicaVersionPayload {
            replica_version_id: cmd.replica_version_id.clone(),
            binary_url: String::default(),
            sha256_hex: String::default(),
            node_manager_binary_url: String::default(),
            node_manager_sha256_hex: String::default(),
            release_package_url,
            release_package_sha256_hex: cmd
                .release_package_sha256_hex
                .expect("Release package sha256 is rquired if release package is used"),
        }
    } else {
        BlessReplicaVersionPayload {
            replica_version_id: cmd.replica_version_id.clone(),
            binary_url: cmd.replica_url.unwrap_or_else(String::default),
            sha256_hex: cmd.replica_sha256_hex.unwrap_or_else(String::default),
            node_manager_binary_url: cmd.node_manager_url.unwrap_or_else(String::default),
            node_manager_sha256_hex: cmd.node_manager_sha256_hex.unwrap_or_else(String::default),
            release_package_url: "".into(),
            release_package_sha256_hex: "".into(),
        }
    };

    println!(
        "Submitting proposal to bless replica version:\n{:#?}",
        &payload
    );

    let response = handler
        .submit_external_proposal_candid::<BlessReplicaVersionPayload>(
            payload,
            NnsFunction::BlessReplicaVersion,
            parse_proposal_url(cmd.proposal_url),
            "BlessReplicaVersion",
        )
        .await;
    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("submit_proposal for BlessReplicaVersion error: {:?}", e);
            std::process::exit(1);
        }
    };
}

async fn propose_to_create_subnet(cmd: ProposeToCreateSubnetCmd, nns_url: Url, sender: Sender) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        nns_url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));
    let node_ids = cmd
        .node_ids
        .into_iter()
        .map(|node_id| {
            PrincipalId::from_str(&node_id).unwrap_or_else(|err| {
                panic!(
                    "Couldn't convert the node ID `{}` to principal ID: {}",
                    node_id, err
                )
            })
        })
        .map(NodeId::from)
        .collect();
    let payload = CreateSubnetPayload {
        node_ids,
        subnet_id_override: cmd.subnet_id_override,
        // Copy from ProposeToCreateSubnetCmd
        // sadly, ..cmd doesn't work here, as structs are of different type
        ingress_bytes_per_block_soft_cap: cmd.ingress_bytes_per_block_soft_cap,
        max_ingress_bytes_per_message: cmd.max_ingress_bytes_per_message,
        max_ingress_messages_per_block: cmd.max_ingress_messages_per_block,
        replica_version_id: cmd
            .replica_version_id
            .unwrap_or_else(ReplicaVersion::default)
            .to_string(),
        unit_delay_millis: cmd.unit_delay_millis,
        initial_notary_delay_millis: cmd.initial_notary_delay_millis,
        dkg_interval_length: cmd.dkg_interval_length,
        dkg_dealings_per_block: cmd.dkg_dealings_per_block,
        gossip_max_artifact_streams_per_peer: cmd.gossip_max_artifact_streams_per_peer,
        gossip_max_chunk_wait_ms: cmd.gossip_max_chunk_wait_ms,
        gossip_max_duplicity: cmd.gossip_max_duplicity,
        gossip_max_chunk_size: cmd.gossip_max_chunk_size,
        gossip_receive_check_cache_size: cmd.gossip_receive_check_cache_size,
        gossip_pfn_evaluation_period_ms: cmd.gossip_pfn_evaluation_period_ms,
        gossip_registry_poll_period_ms: cmd.gossip_registry_poll_period_ms,
        gossip_retransmission_request_ms: cmd.gossip_retransmission_request_ms,

        start_as_nns: cmd.start_as_nns,

        subnet_type: cmd.subnet_type,
        is_halted: cmd.is_halted,
    };
    println!("submit_proposal proposer {:?}", proposer);
    let response = handler
        .submit_external_proposal_candid::<CreateSubnetPayload>(
            payload,
            NnsFunction::CreateSubnet,
            parse_proposal_url(cmd.proposal_url),
            "CreateSubnet",
        )
        .await;
    eprintln!("submit_proposal for CreateSubnet response: {:?}", response);
    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!(
                "submit_proposal for CreateSubnet error by proposer {:?}: {:?}",
                proposer, e
            );
            std::process::exit(1);
        }
    };
}

async fn propose_to_add_nodes_to_subnet(
    registry: &RegistryCanister,
    cmd: ProposeToAddNodesToSubnetCmd,
    nns_url: Url,
    sender: Sender,
) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        nns_url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));
    let node_ids = cmd.node_ids.into_iter().map(NodeId::from).collect();
    let payload = AddNodesToSubnetPayload {
        subnet_id: cmd.subnet.get_id(registry).await.get(),
        node_ids,
    };
    let response = handler
        .submit_external_proposal_candid::<AddNodesToSubnetPayload>(
            payload,
            NnsFunction::AddNodeToSubnet,
            parse_proposal_url(cmd.proposal_url),
            "AddNodeToSubnet",
        )
        .await;
    eprintln!(
        "submit_proposal for AddNodeToSubnet response: {:?}",
        response
    );
    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("submit_proposal for AddNodeToSubnet error: {:?}", e);
            std::process::exit(1);
        }
    };
}

async fn propose_to_recover_subnet(
    cmd: ProposeToUpdateRecoveryCupCmd,
    nns_url: Url,
    sender: Sender,
    subnet_id: PrincipalId,
) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        nns_url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));

    let node_ids = cmd
        .replacement_nodes
        .map(|nodes| nodes.into_iter().map(NodeId::from).collect());

    let hash = cmd.registry_store_hash.unwrap_or_else(|| "".to_string());
    let registry_version = cmd.registry_version.unwrap_or_else(|| 0);

    let payload = RecoverSubnetPayload {
        subnet_id,
        height: cmd.height,
        time_ns: cmd.time_ns,
        state_hash: hex::decode(cmd.state_hash).expect("The provided state hash was invalid"),
        replacement_nodes: node_ids,
        registry_store_uri: cmd
            .registry_store_uri
            .map(|uri| (uri, hash, registry_version)),
    };

    let response = handler
        .submit_external_proposal_candid::<RecoverSubnetPayload>(
            payload,
            NnsFunction::RecoverSubnet,
            parse_proposal_url(cmd.proposal_url),
            "RecoverSubnet",
        )
        .await;
    eprintln!("submit_proposal for RecoverSubnet response: {:?}", response);
    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("submit_proposal for RecoverSubnet error: {:?}", e);
            std::process::exit(1);
        }
    };
}

async fn propose_to_update_subnet(
    registry: &RegistryCanister,
    cmd: ProposeToUpdateSubnetCmd,
    nns_url: Url,
    sender: Sender,
) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        nns_url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));
    let payload = UpdateSubnetPayload {
        subnet_id: cmd.subnet.get_id(registry).await,
        ingress_bytes_per_block_soft_cap: cmd.ingress_bytes_per_block_soft_cap,
        max_ingress_bytes_per_message: cmd.max_ingress_bytes_per_message,
        unit_delay_millis: cmd.unit_delay_millis,
        initial_notary_delay_millis: cmd.initial_notary_delay_millis,
        dkg_interval_length: cmd.dkg_interval_length,
        dkg_dealings_per_block: cmd.dkg_dealings_per_block,

        max_artifact_streams_per_peer: cmd.gossip_max_artifact_streams_per_peer,
        max_chunk_wait_ms: cmd.gossip_max_chunk_wait_ms,
        max_duplicity: cmd.gossip_max_duplicity,
        max_chunk_size: cmd.gossip_max_chunk_size,
        receive_check_cache_size: cmd.gossip_receive_check_cache_size,
        pfn_evaluation_period_ms: cmd.gossip_pfn_evaluation_period_ms,
        registry_poll_period_ms: cmd.gossip_registry_poll_period_ms,
        retransmission_request_ms: cmd.gossip_retransmission_request_ms,

        set_gossip_config_to_default: cmd.set_gossip_config_to_default,

        start_as_nns: cmd.start_as_nns,

        subnet_type: cmd.subnet_type,
        is_halted: cmd.is_halted,
    };
    let response = handler
        .submit_external_proposal_candid::<UpdateSubnetPayload>(
            payload,
            NnsFunction::UpdateConfigOfSubnet,
            parse_proposal_url(cmd.proposal_url),
            "UpdateConfigOfSubnet",
        )
        .await;
    eprintln!(
        "submit_proposal for UpdateConfigOfSubnet response: {:?}",
        response
    );
    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("submit_proposal for UpdateConfigOfSubnet error: {:?}", e);
            std::process::exit(1);
        }
    };
}

// The "authoritative" data structure is the one defined in `lifeline.mo` and
// this should stay in sync with it
#[derive(CandidType)]
pub struct UpdateRootProposalPayload {
    pub wasm: Vec<u8>,
    pub module_arg: Vec<u8>,
    pub stop_upgrade_start: bool,
}

async fn propose_to_change_nns_canister(
    cmd: ProposeToChangeNnsCanisterCmd,
    nns_url: Url,
    sender: Sender,
) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        nns_url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));

    let canister_id: CanisterId = cmd.canister_id;
    let auth_delta_converter = |arg: &AuthzDeltaArg| -> MethodAuthzChange {
        MethodAuthzChange {
            canister: arg.canister_id.unwrap_or(canister_id),
            method_name: arg.method_name.clone(),
            operation: match arg.op {
                authz::Op::Authorize => AuthzChangeOp::Authorize {
                    // add_self=true only makes sense for AddNnsCanisterProposal. In the
                    // 'Change', case, we always know the id beforehand, so it's not needed.
                    add_self: false,
                },
                authz::Op::Deauthorize => AuthzChangeOp::Deauthorize {},
            },
            principal: Some(arg.caller_id.unwrap_or_else(|| canister_id.get())),
        }
    };

    let wasm_module = read_file_fully(&cmd.wasm_module_path);
    let arg = cmd.arg.map_or(vec![], |path| read_file_fully(&path));
    let (response, log_proposal_name) = if cmd.canister_id == ROOT_CANISTER_ID {
        let stop_before_install = !cmd.skip_stopping_before_installing;
        // This argument tuple must match the signature of `upgrade_root` in
        // lifeline.mo.
        let payload = Encode!(&wasm_module, &arg, &stop_before_install).expect(
            "Could not candid-serialize the argument tuple for the NnsRootUpgrade proposal.",
        );
        let log_proposal_name = "NnsRootUpgrade";
        (
            handler
                .submit_external_proposal_binary(
                    payload,
                    NnsFunction::NnsRootUpgrade,
                    parse_proposal_url(cmd.proposal_url),
                    log_proposal_name.to_string(),
                )
                .await,
            log_proposal_name,
        )
    } else {
        let payload = ChangeNnsCanisterProposalPayload {
            stop_before_installing: !cmd.skip_stopping_before_installing,
            mode: cmd.mode,
            canister_id: cmd.canister_id,
            wasm_module,
            arg,
            compute_allocation: cmd.compute_allocation.map(candid::Nat::from),
            memory_allocation: cmd.memory_allocation.map(candid::Nat::from),
            query_allocation: cmd.query_allocation.map(candid::Nat::from),
            authz_changes: cmd.authz_changes.iter().map(auth_delta_converter).collect(),
        };
        let log_proposal_name = "NnsCanisterUpgrade";
        (
            handler
                .submit_external_proposal_candid(
                    payload,
                    NnsFunction::NnsCanisterUpgrade,
                    parse_proposal_url(cmd.proposal_url),
                    log_proposal_name,
                )
                .await,
            log_proposal_name,
        )
    };

    eprintln!(
        "submit_proposal for {} response: {:?}",
        log_proposal_name, response
    );
    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("submit_proposal error: {:?}", e);
            std::process::exit(1);
        }
    };
}

async fn propose_to_add_nns_canister(
    cmd: ProposeToAddNnsCanisterCmd,
    nns_url: Url,
    sender: Sender,
) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        nns_url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));

    let wasm_module = read_file_fully(&cmd.wasm_module_path);
    let arg = cmd.arg.map_or(vec![], |path| read_file_fully(&path));

    let payload = AddNnsCanisterProposalPayload {
        name: cmd.name,
        wasm_module,
        arg,
        // Hard code to 1 to satisfy the payload requirement. We don't need more since the canister
        // is running on the NNS where no cycles are charged.
        initial_cycles: 1,
        compute_allocation: cmd.compute_allocation.map(candid::Nat::from),
        memory_allocation: cmd.memory_allocation.map(candid::Nat::from),
        query_allocation: cmd.query_allocation.map(candid::Nat::from),
        authz_changes: vec![],
    };
    let log_proposal_name = "NnsCanisterInstall";

    let response = handler
        .submit_external_proposal_candid(
            payload,
            NnsFunction::NnsCanisterInstall,
            parse_proposal_url(cmd.proposal_url),
            log_proposal_name,
        )
        .await;
    eprintln!(
        "submit_proposal for {} response: {:?}",
        log_proposal_name, response
    );
    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("submit_proposal error: {:?}", e);
            std::process::exit(1);
        }
    };
}

async fn add_node_via_nns(cmd: AddNodeViaNnsCmd, nns_url: Url, sender: Sender) {
    let handler = RegistryHandler(make_handler(nns_url, REGISTRY_CANISTER_ID, sender, None));

    // Read the protobuf of PublicKey and X509PublicKeyCert verbatim and add it to
    // the payload
    let node_signing_key = read_file_fully(&cmd.node_signing_pk_path);
    let committee_signing_key = read_file_fully(&cmd.committee_signing_pk_path);
    let ni_dkg_dealing_encryption_key = read_file_fully(&cmd.ni_dkg_dealing_encryption_pk_path);
    let transport_tls_certificate_key = read_file_fully(&cmd.transport_tls_certificate_path);

    let payload = AddNodePayload {
        node_signing_pk: node_signing_key,
        committee_signing_pk: committee_signing_key,
        ni_dkg_dealing_encryption_pk: ni_dkg_dealing_encryption_key,
        transport_tls_cert: transport_tls_certificate_key,

        xnet_endpoint: cmd.xnet_endpoint,
        http_endpoint: cmd.http_endpoint,
        p2p_flow_endpoints: cmd.p2p_flow_endpoint,
        prometheus_metrics_endpoint: cmd.prometheus_metrics_endpoint,
    };

    let response = handler.add_node(payload).await;
    println!("add_node response: {:?}", response);
}

async fn forward_test_neuron_vote(cmd: ForwardTestNeuronVoteCmd, nns_url: Url) {
    let proposal_id = ProposalId(cmd.proposal_id);

    let neuron_handler = GovernanceHandler(Handler {
        agent: Agent::new(
            nns_url.clone(),
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        ),
        handler_id: GOVERNANCE_CANISTER_ID,
        author: Some(NeuronId(TEST_NEURON_1_ID)),
    });

    let response = neuron_handler.forward_vote(proposal_id, Vote::Yes).await;
    println!("forward_vote response: {:?}", response);
}

async fn execute_eligible_proposals(nns_url: Url) {
    let proposals_handler = GovernanceHandler(Handler {
        agent: Agent::new(nns_url, Sender::Anonymous),
        handler_id: GOVERNANCE_CANISTER_ID,
        author: None,
    });

    let response = proposals_handler.execute_eligible_proposals().await;
    println!("execute_eligible_proposals response: {:?}", response);
}

async fn propose_to_clear_provisional_whitelist(
    cmd: ProposeToClearProvisionalWhitelistCmd,
    nns_url: Url,
    sender: Sender,
) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        nns_url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));

    let log_proposal_name = "ClearProvisionalWhitelist";
    let response = handler
        .submit_external_proposal_candid(
            (),
            NnsFunction::ClearProvisionalWhitelist,
            parse_proposal_url(cmd.proposal_url),
            log_proposal_name,
        )
        .await;
    eprintln!(
        "submit_proposal for {} response: {:?}",
        log_proposal_name, response
    );
    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("submit_proposal for {} error: {:?}", log_proposal_name, e);
            std::process::exit(1);
        }
    };
}

async fn propose_to_set_authorized_subnetworks(
    cmd: ProposeToSetAuthorizedSubnetworksCmd,
    nns_url: Url,
    sender: Sender,
) {
    use cycles_minting_canister::SetAuthorizedSubnetworkListArgs;

    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        nns_url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));

    let log_proposal_name = "SetAuthorizedSubnetworks";
    let subnets: Vec<SubnetId> = cmd
        .subnets
        .unwrap_or_default()
        .into_iter()
        .map(SubnetId::from)
        .collect();
    let payload = SetAuthorizedSubnetworkListArgs {
        who: cmd.who,
        subnets,
    };

    let response = handler
        .submit_external_proposal_candid::<SetAuthorizedSubnetworkListArgs>(
            payload,
            NnsFunction::SetAuthorizedSubnetworks,
            parse_proposal_url(cmd.proposal_url),
            log_proposal_name,
        )
        .await;
    eprintln!(
        "submit_proposal for {} response: {:?}",
        log_proposal_name, response
    );
    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("submit_proposal for {} error: {:?}", log_proposal_name, e);
            std::process::exit(1);
        }
    };
}

pub fn store_threshold_sig_pk<P: AsRef<Path>>(pk: &PublicKey, path: P) {
    let pk = ThresholdSigPublicKey::try_from(pk.clone())
        .expect("failed to parse threshold signature PK from protobuf");
    let der_bytes = threshold_sig_public_key_to_der(pk)
        .expect("failed to encode threshold signature PK into DER");

    let mut bytes = vec![];
    bytes.extend_from_slice(b"-----BEGIN PUBLIC KEY-----\r\n");
    for chunk in base64::encode(&der_bytes[..]).as_bytes().chunks(64) {
        bytes.extend_from_slice(chunk);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"-----END PUBLIC KEY-----\r\n");

    let path = path.as_ref();
    std::fs::write(path, bytes)
        .unwrap_or_else(|e| panic!("failed to store public key to {}: {}", path.display(), e));
}

fn get_proposer_and_sender(
    proposer: Option<NeuronId>,
    sender: Sender,
    use_test_neuron: bool,
) -> (NeuronId, Sender) {
    if use_test_neuron {
        return (
            NeuronId(TEST_NEURON_1_ID),
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        );
    }
    let proposer = proposer.expect("A proposal must have a proposer.");
    assert!(
        sender.get_principal_id() != Sender::Anonymous.get_principal_id(),
        "Must specify a keypair to submit a proposal that corresponds to the owner of a neuron."
    );
    (proposer, sender)
}

/// Submit a proposal to add a new node operator record
async fn propose_to_add_node_operator(
    cmd: ProposeToAddNodeOperatorCmd,
    nns_url: Url,
    sender: Sender,
) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        nns_url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));
    let payload = AddNodeOperatorPayload {
        node_operator_principal_id: Some(cmd.node_operator_principal_id),
        node_allowance: cmd.node_allowance,
        node_provider_principal_id: Some(cmd.node_provider_principal_id),
    };

    let response = handler
        .submit_external_proposal_candid::<AddNodeOperatorPayload>(
            payload,
            NnsFunction::AssignNoid,
            parse_proposal_url(cmd.proposal_url),
            "AssignNoid",
        )
        .await;
    eprintln!(
        "submit_proposal for AddNodeOperator response: {:?}",
        response
    );

    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("submit_add_node_operator_proposal error: {:?}", e);
            std::process::exit(1);
        }
    };
}

/// Submit a proposal to add a new node operator record
async fn propose_to_update_node_operator_config(
    cmd: ProposeToUpdateNodeOperatorConfigCmd,
    nns_url: Url,
    sender: Sender,
) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        nns_url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));
    let payload = UpdateNodeOperatorConfigPayload {
        node_operator_id: Some(cmd.node_operator_id),
        node_allowance: cmd.node_allowance,
    };

    let response = handler
        .submit_external_proposal_candid::<UpdateNodeOperatorConfigPayload>(
            payload,
            NnsFunction::UpdateNodeOperatorConfig,
            parse_proposal_url(cmd.proposal_url),
            "UpdateNodeOperatorConfig",
        )
        .await;
    eprintln!(
        "submit_proposal for UpdateNodeOperatorConfig response: {:?}",
        response
    );

    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("submit_update_node_operator_config_proposal error: {:?}", e);
            std::process::exit(1);
        }
    };
}

/// Submit a proposal to set the firewall config
async fn propose_to_set_firewall_config(
    cmd: ProposeToSetFirewallConfigCmd,
    nns_url: Url,
    sender: Sender,
) {
    let (proposer, sender) =
        get_proposer_and_sender(cmd.proposer, sender, cmd.test_neuron_proposer);
    let handler = GovernanceHandler(make_handler(
        nns_url,
        GOVERNANCE_CANISTER_ID,
        sender,
        Some(proposer),
    ));
    let firewall_config = String::from_utf8(read_file_fully(&cmd.firewall_config_file)).unwrap();
    let ipv4_prefixes: Vec<String> = if cmd.ipv4_prefixes.eq("-") {
        vec![]
    } else {
        cmd.ipv4_prefixes
            .split(',')
            .map(|s| s.to_string())
            .collect()
    };
    let ipv6_prefixes: Vec<String> = if cmd.ipv6_prefixes.eq("-") {
        vec![]
    } else {
        cmd.ipv6_prefixes
            .split(',')
            .map(|s| s.to_string())
            .collect()
    };
    let payload = SetFirewallConfigPayload {
        firewall_config,
        ipv4_prefixes,
        ipv6_prefixes,
    };

    let response = handler
        .submit_external_proposal_candid::<SetFirewallConfigPayload>(
            payload,
            NnsFunction::SetFirewallConfig,
            parse_proposal_url(cmd.proposal_url),
            "SetFirewallConfig",
        )
        .await;
    eprintln!(
        "submit_proposal for SetFirewallConfig response: {:?}",
        response
    );

    match response {
        Ok(proposal_id) => {
            println!("{}", proposal_id);
        }
        Err(e) => {
            eprintln!("submit_set_firewall_config_proposal error: {:?}", e);
            std::process::exit(1);
        }
    };
}

fn get_root_subnet_pub_key(
    client: Arc<RegistryClientImpl>,
    version: RegistryVersion,
) -> Result<ThresholdSigPublicKey, String> {
    let root_subnet_id = client
        .get_root_subnet_id(version)
        .map_err(|err| format!("{}", err))?
        .ok_or("Root subnet_id is not found")?;
    client
        .get_threshold_signing_public_key_for_subnet(root_subnet_id, version)
        .map_err(|err| format!("{}", err))?
        .ok_or_else(|| "Root subnet public key is not found".to_string())
}

/// Fetch registry records from the given `nns_url`, and update the local
/// registry store with the new records.
async fn update_registry_local_store(nns_url: Url, cmd: UpdateRegistryLocalStoreCmd) {
    eprintln!("RegistryLocalStore path: {:?}", cmd.local_store_path);
    let local_store = Arc::new(LocalStoreImpl::new(cmd.local_store_path));
    let local_client = Arc::new(RegistryClientImpl::new(local_store.clone(), None));
    local_client
        .fetch_and_start_polling()
        .expect("Local registry client fetch_and_start_polling failed");
    let latest_version = local_client.get_latest_version();
    eprintln!("RegistryLocalStore latest version: {}", latest_version);
    let nns_pub_key = match get_root_subnet_pub_key(local_client.clone(), latest_version) {
        Ok(pub_key) => {
            eprintln!("Root subnet public key found: {:?}", pub_key);
            pub_key
        }
        Err(err) => {
            if cmd.disable_certificate_validation {
                eprintln!("Root subnet public key is not found in RegistryLocalStore. Ignore.");
                // Try again with validation disabled
                use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
                PublicKeyBytes([0; PublicKeyBytes::SIZE]).into()
            } else {
                panic!("Error looking up RegistryLocalStore: {}", err)
            }
        }
    };
    let remote_canister = RegistryCanister::new(vec![nns_url.clone()]);
    let response = remote_canister
        .get_certified_changes_since(latest_version.get(), &nns_pub_key)
        .await;
    let records = match response {
        Ok(response) => response.0,
        Err(err) => {
            let throw_err = |err| panic!("Error retrieving registry records: {:?}", err);
            if cmd.disable_certificate_validation {
                remote_canister
                    .get_changes_since_as_transport_records(latest_version.get())
                    .await
                    .unwrap_or_else(throw_err)
            } else {
                throw_err(err)
            }
            .0
        }
    };

    let changelog = records.iter().fold(Changelog::default(), |mut cl, r| {
        let rel_version = (r.version - latest_version).get();
        if cl.len() < rel_version as usize {
            cl.push(ChangelogEntry::default());
        }
        cl.last_mut().unwrap().push(KeyMutation {
            key: r.key.clone(),
            value: r.value.clone(),
        });
        cl
    });

    changelog
        .into_iter()
        .enumerate()
        .try_for_each(|(i, cle)| {
            let v = latest_version + RegistryVersion::from(i as u64 + 1);
            eprintln!("Writing data of registry version {}", v);
            local_store.store(v, cle)
        })
        .expect("Writing to the filesystem failed: Stop.");

    eprintln!("Finished update.");
}

/// A helper function for the handler code.
fn generate_nonce() -> Vec<u8> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes()
        .to_vec()
}

/// A client-side view of the handler.
struct Handler {
    /// The agent to talk to the IC.
    agent: Agent,

    /// Canister ID of the handler.
    handler_id: CanisterId,

    /// If this handler will perform an operation on behalf of a neuron,
    /// such as submitting a proposal or voting, this must be set to the
    /// id of that neuron.
    author: Option<NeuronId>,
}

impl Handler {
    fn author(&self) -> &NeuronId {
        self.author
            .as_ref()
            .expect("No neuron id to be used as an author was set.")
    }
}

struct RegistryHandler(Handler);
struct GovernanceHandler(Handler);

fn make_handler(
    nns_url: Url,
    handler_id: CanisterId,
    sender: Sender,
    author: Option<NeuronId>,
) -> Handler {
    Handler {
        agent: Agent::new(nns_url, sender),
        handler_id,
        author,
    }
}

impl Handler {
    pub async fn execute_update<S: ToString>(
        &self,
        msg: S,
        arguments: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String> {
        let mut ids_to_try = vec![self.handler_id];
        ids_to_try.extend(ic_nns_constants::ALL_NNS_CANISTER_IDS.iter().cloned());

        for canister_id in ids_to_try {
            let result = self
                .agent
                .execute_update(
                    &canister_id,
                    msg.to_string(),
                    arguments.clone(),
                    generate_nonce(),
                )
                .await;

            match result {
                Ok(result) => return Ok(result),
                Err(error_string) => {
                    if error_string.contains("has no update method") {
                        println!("Couldn't reach NNS canister at id: {:?}", canister_id);
                        continue;
                    }
                    return Err(error_string);
                }
            };
        }
        Err(format!(
            "Could not find method: {} in any NNS canister",
            msg.to_string()
        ))
    }
}

// Note that, unlike other handlers, we don't get ProposalId return types in
// these methods. That is because there is no proposal happening, the message is
// sent directly to the node handler canister and handled there.
impl RegistryHandler {
    pub async fn add_node(&self, payload: AddNodePayload) -> Result<NodeId, String> {
        let serialized = Encode!(&payload)
            .map_err(|e| format!("Cannot candid-serialize the AddNodePayload: {}", e))?;
        let response = self
            .0
            .execute_update("add_node", serialized)
            .await?
            .ok_or_else(|| "add_node replied nothing.".to_string())?;
        Decode!(&response, NodeId).map_err(|e| {
            format!(
                "Cannot candid-deserialize the response from add_node: {}",
                e
            )
        })
    }

    pub async fn remove_node(&self, payload: RemoveNodePayload) -> Result<(), String> {
        let serialized = Encode!(&payload)
            .map_err(|e| format!("Cannot candid-serialize the RemoveNodePayload: {}", e))?;
        let response = self
            .0
            .execute_update("remove_node", serialized)
            .await?
            .ok_or_else(|| "remove_node replied nothing.".to_string())?;

        Decode!(&response, ()).map_err(|e| {
            format!(
                "Cannot candid-deserialize the response from remove_node: {}",
                e
            )
        })
    }
}

impl GovernanceHandler {
    pub async fn forward_vote(&self, proposal_id: ProposalId, vote: Vote) -> Result<(), String> {
        let serialized = Encode!(self.0.author(), &proposal_id, &vote)
            .map_err(|e| format!("Cannot candid-serialize the forward_vote payload: {}", e))?;

        let response = self
            .0
            .execute_update("forward_vote", serialized)
            .await?
            .ok_or_else(|| "forward_vote replied nothing.".to_string())?;
        match Decode!(&response, ManageNeuronResponse)
            .map_err(|e| {
                format!(
                    "Cannot candid-deserialize the response from manage_neuron: {}",
                    e
                )
            })?
            .command
        {
            Some(CommandResponse::RegisterVote(_)) => Ok(()),
            Some(CommandResponse::Error(e)) => Err(e.to_string()),
            _ => Err("Unexpected ManageNeuronResponse".to_string()),
        }
    }

    pub async fn execute_eligible_proposals(&self) -> Result<(), String> {
        let serialized = Encode!(&()).map_err(|e| {
            format!(
                "Cannot candid-serialize the execute_eligible_proposals payload: {}",
                e
            )
        })?;
        let response = self
            .0
            .execute_update("execute_eligible_proposals", serialized)
            .await?
            .ok_or_else(|| "execute_eligible_proposals replied nothing.".to_string())?;
        Decode!(&response, ()).map_err(|e| {
            format!(
                "Cannot candid-deserialize the response from execute_eligible_proposals: {}",
                e
            )
        })
    }

    pub async fn submit_external_proposal_binary(
        &self,
        payload: Vec<u8>,
        external_update_type: NnsFunction,
        url: String,
        log_proposal_name: String,
    ) -> Result<ProposalId, String> {
        self.submit_external_proposal(
            &create_make_proposal_payload(
                create_external_update_proposal_binary(
                    log_proposal_name.to_string(),
                    url,
                    external_update_type,
                    payload,
                ),
                self.0.author(),
            ),
            &log_proposal_name,
        )
        .await
    }

    pub async fn submit_external_proposal_candid<T: CandidType>(
        &self,
        payload: T,
        external_update_type: NnsFunction,
        url: String,
        log_proposal_name: &str,
    ) -> Result<ProposalId, String> {
        self.submit_external_proposal(
            &create_make_proposal_payload(
                create_external_update_proposal_candid(
                    log_proposal_name.to_string(),
                    url,
                    external_update_type,
                    payload,
                ),
                self.0.author(),
            ),
            &log_proposal_name,
        )
        .await
    }

    async fn submit_external_proposal(
        &self,
        submit_proposal_command: &ManageNeuron,
        log_proposal_name: &str,
    ) -> Result<ProposalId, String> {
        let serialized = Encode!(submit_proposal_command).map_err(|e| {
            format!(
                "Cannot candid-serialize the {} payload: {}",
                log_proposal_name, e
            )
        })?;
        let response = self
            .0
            .execute_update("manage_neuron", serialized)
            .await?
            .ok_or_else(|| "submit_proposal replied nothing.".to_string())?;

        decode_make_proposal_response(response)
    }
}
