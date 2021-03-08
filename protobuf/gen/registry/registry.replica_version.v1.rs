/// Information about a Replica version
///
/// Corresponding mutations are handled by the `Upgrades` proposal handler:
/// See /rs/nns/handlers/upgrades/canister/canister.rs
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ReplicaVersionRecord {
    /// The URL against which a HTTP GET request will return a replica binary
    /// that corresponds to this version
    #[prost(string, tag="1")]
    pub binary_url: std::string::String,
    /// The hex-formatted SHA-256 hash of the binary served by 'binary_url'
    #[prost(string, tag="2")]
    pub sha256_hex: std::string::String,
    /// The URL against which a HTTP GET request will return a node manager binary
    /// that corresponds to this version
    #[prost(string, tag="3")]
    pub node_manager_binary_url: std::string::String,
    /// The hex-formatted SHA-256 hash of the binary served by 'node_manager_binary_url'
    #[prost(string, tag="4")]
    pub node_manager_sha256_hex: std::string::String,
    /// The URL against which a HTTP GET request will return a release package
    /// that corresponds to this version
    #[prost(string, tag="5")]
    pub release_package_url: std::string::String,
    /// The hex-formatted SHA-256 hash of the archive file served by 'release_package_url'
    #[prost(string, tag="6")]
    pub release_package_sha256_hex: std::string::String,
}
/// A list of blessed versions of the IC Replica
///
/// New versions are added here after a vote has been accepted by token
/// holders. Subnetworks can then be upgraded to any of those version.
///
/// Corresponding mutations are handled by the `Upgrades` proposal handler:
/// See /rs/nns/handlers/upgrades/canister/canister.rs
#[derive(Clone, PartialEq, ::prost::Message)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BlessedReplicaVersions {
    /// A list of version information ids.
    #[prost(string, repeated, tag="1")]
    pub blessed_version_ids: ::std::vec::Vec<std::string::String>,
}
