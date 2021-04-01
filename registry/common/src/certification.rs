use ic_crypto_tree_hash::{Digest, LabeledTree, MixedHashTree};
use ic_crypto_utils_threshold_sig::verify_combined;
use ic_interfaces::registry::RegistryTransportRecord;
use ic_registry_transport::pb::v1::{
    registry_mutation::Type, CertifiedResponse, RegistryAtomicMutateRequest,
};
use ic_types::{
    consensus::certification::CertificationContent,
    crypto::{threshold_sig::ThresholdSigPublicKey, CombinedThresholdSigOf, CryptoHash},
    time::current_time,
    CanisterId, CryptoHashOfPartialState, RegistryVersion, Time,
};
use prost::Message;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use tree_deserializer::{types::Leb128EncodedU64, LabeledTreeDeserializer};

#[cfg(test)]
mod tests;

/// Describes an error occurred during parsing and validation of the result of a
/// "get_certified_changes_since" method call.
#[derive(Debug)]
pub enum CertificationError {
    /// Failed to deserialize some part of the response.
    DeserError(String),
    /// The signature verification failed.
    InvalidSignature(String),
    /// The value at path "/canister/<cid>/certified_data" doesn't match the
    /// hash computed from the mixed hash tree with registry deltas.
    CertifiedDataMismatch { certified: Digest, computed: Digest },
    /// Parsing and signature verification was successful, but the list of
    /// deltas doesn't satisfy postconditions of the method.
    InvalidDeltas(String),
    /// The hash tree in the response was not well-formed.
    MalformedHashTree(String),
}

#[derive(Deserialize)]
struct CertifiedPayload {
    current_version: Leb128EncodedU64,
    #[serde(default)]
    delta: BTreeMap<u64, Protobuf<RegistryAtomicMutateRequest>>,
}

fn verify_combined_threshold_sig(
    msg: &CryptoHashOfPartialState,
    sig: &CombinedThresholdSigOf<CertificationContent>,
    pk: &ThresholdSigPublicKey,
) -> Result<(), CertificationError> {
    verify_combined(&CertificationContent::new(msg.clone()), sig, pk)
        .map_err(|e| CertificationError::InvalidSignature(e.to_string()))
}

/// Parses the certificate and verifies the signature.  If successful,
/// returns the expected root_hash of the mixed hash tree that holds
/// registry deltas and the timestamp specified in the certificate.
fn check_certificate(
    canister_id: &CanisterId,
    nns_pk: &ThresholdSigPublicKey,
    encoded_certificate: &[u8],
) -> Result<(Digest, Time), CertificationError> {
    #[derive(Deserialize)]
    struct Certificate {
        tree: MixedHashTree,
        signature: CombinedThresholdSigOf<CertificationContent>,
    }

    #[derive(Deserialize)]
    struct CanisterView {
        certified_data: Digest,
    }

    #[derive(Deserialize)]
    struct ReplicaState {
        time: Leb128EncodedU64,
        canister: BTreeMap<CanisterId, CanisterView>,
    }

    let certificate: Certificate = serde_cbor::from_slice(encoded_certificate).map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to decode certificate from canister {}: {}",
            canister_id, err
        ))
    })?;

    let digest = CryptoHashOfPartialState::from(CryptoHash(certificate.tree.digest().to_vec()));

    verify_combined_threshold_sig(&digest, &certificate.signature, nns_pk).map_err(|err| {
        CertificationError::InvalidSignature(format!(
            "failed to verify threshold signature: root_hash={:?}, sig={:?}, pk={:?}, error={:?}",
            digest, certificate.signature, nns_pk, err
        ))
    })?;

    let replica_labeled_tree =
        LabeledTree::<Vec<u8>>::try_from(certificate.tree).map_err(|err| {
            CertificationError::MalformedHashTree(format!(
                "failed to convert hash tree to labeled tree: {:?}",
                err
            ))
        })?;

    let replica_state = ReplicaState::deserialize(LabeledTreeDeserializer::new(
        &replica_labeled_tree,
    ))
    .map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to unpack replica state from a labeled tree: {}",
            err
        ))
    })?;

    let time = Time::from_nanos_since_unix_epoch(replica_state.time.0);

    replica_state
        .canister
        .get(canister_id)
        .map(|canister| (canister.certified_data.clone(), time))
        .ok_or_else(|| {
            CertificationError::MalformedHashTree(format!(
                "cannot find certified_data for canister {} in the tree",
                canister_id
            ))
        })
}

/// Validates that changes in the payload form a valid range.  We want to check
/// the following properties:
///
///   1. The version of the first delta is the successor of `since_version`.
///
///   2. Versions of deltas form a continuous range.
///
///   3. If current_version > since_version, the range contains at least one
///      delta.  Note that It is fine for the registry canister to not return
///      all entries up until the current version.  This can happen, e.g., if
///      the list of updates is too long for a single request.
fn validate_version_range(
    since_version: u64,
    p: &CertifiedPayload,
) -> Result<u64, CertificationError> {
    let last_version = p
        .delta
        .keys()
        .try_fold(since_version, |prev_version, next_version| {
            if *next_version != prev_version + 1 {
                Err(CertificationError::InvalidDeltas(format!(
                    "version range not continuous: {} follows {}",
                    next_version, prev_version,
                )))
            } else {
                Ok(*next_version)
            }
        })?;

    if last_version == since_version && p.current_version.0 > since_version {
        return Err(CertificationError::InvalidDeltas(format!(
            "current version {} is newer than requested {}, but the payload has no deltas",
            p.current_version.0, since_version
        )));
    }

    Ok(p.current_version.0)
}

#[allow(unused)]
/// Parses a response of the "get_certified_changes_since" registry method,
/// validates data integrity and authenticity and returns
///   * The list of changes to apply.
///   * The latest version available (might be greater than the version of the
///     last received delta if there were too many deltas to send in one go).
///   * The time when the received data was last certified by the subnet.
pub fn decode_certified_deltas(
    since_version: u64,
    canister_id: &CanisterId,
    nns_pk: &ThresholdSigPublicKey,
    payload: &[u8],
) -> Result<(Vec<RegistryTransportRecord>, RegistryVersion, Time), CertificationError> {
    decode_certified_deltas_helper(since_version, canister_id, nns_pk, payload, false)
}

/// Similar to decode_certificate_deltas, but with an option to disable
/// certificate validation. `payload` here refers to the serialized
/// and certified set of `RegistryTransportRecord`s,  as returned from
/// `get_certified_changes_since` registry method when querying the
/// registry HTTP endpoint.
pub(crate) fn decode_certified_deltas_helper(
    since_version: u64,
    canister_id: &CanisterId,
    nns_pk: &ThresholdSigPublicKey,
    payload: &[u8],
    disable_certificate_validation: bool,
) -> Result<(Vec<RegistryTransportRecord>, RegistryVersion, Time), CertificationError> {
    let certified_response = CertifiedResponse::decode(payload).map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to decode certified response from {}: {:?}",
            canister_id, err
        ))
    })?;

    // Extract the hash trees from the canister response.
    let hash_tree = certified_response.hash_tree.ok_or_else(|| {
        CertificationError::MalformedHashTree(
            "certified response has an empty hash tree".to_string(),
        )
    })?;
    let mixed_hash_tree = MixedHashTree::try_from(hash_tree).map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to deserialize MixedHashTree from {}: {:?}",
            canister_id, err
        ))
    })?;

    // Verify the authenticity of the root hash stored by the canister in the
    // certified_data field, and get the value of that field.
    let time = if disable_certificate_validation {
        current_time()
    } else {
        let (certified_data, time) =
            check_certificate(canister_id, nns_pk, &certified_response.certificate[..])?;

        // Recompute the root hash of the canister state and compare it to the
        // certified one.
        if mixed_hash_tree.digest() != certified_data {
            return Err(CertificationError::CertifiedDataMismatch {
                computed: mixed_hash_tree.digest(),
                certified: certified_data,
            });
        }
        time
    };

    // Extract structured deltas from their tree representation.
    let labeled_tree = LabeledTree::<Vec<u8>>::try_from(mixed_hash_tree).map_err(|err| {
        CertificationError::MalformedHashTree(format!(
            "failed to convert hash tree to labeled tree: {:?}",
            err
        ))
    })?;

    let certified_payload = CertifiedPayload::deserialize(LabeledTreeDeserializer::new(
        &labeled_tree,
    ))
    .map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to unpack certified payload from the labeled tree: {}",
            err
        ))
    })?;

    // Validate that the deltas form a proper range and convert them to the
    // format that RegistryClient wants.
    let current_version = validate_version_range(since_version, &certified_payload)?;

    let changes = certified_payload
        .delta
        .into_iter()
        .flat_map(|(v, mutate_req)| {
            mutate_req.0.mutations.into_iter().map(move |m| {
                let value = if m.mutation_type == Type::Delete as i32 {
                    None
                } else {
                    Some(m.value)
                };
                RegistryTransportRecord {
                    key: String::from_utf8_lossy(&m.key[..]).to_string(),
                    value,
                    version: RegistryVersion::from(v),
                }
            })
        })
        .collect();

    Ok((changes, RegistryVersion::from(current_version), time))
}

/// An auxiliary type that instructs serde to deserialize blob as a protobuf
/// message.
struct Protobuf<T>(T);

impl<'de, T> serde::Deserialize<'de> for Protobuf<T>
where
    T: prost::Message + Default,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use std::fmt;
        use std::marker::PhantomData;

        struct ProtobufVisitor<T: prost::Message>(PhantomData<T>);

        impl<'de, T: prost::Message + Default> serde::de::Visitor<'de> for ProtobufVisitor<T> {
            type Value = Protobuf<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "Protobuf message of type {}",
                    std::any::type_name::<T>()
                )
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                T::decode(v).map(Protobuf).map_err(E::custom)
            }
        }

        let visitor: ProtobufVisitor<T> = ProtobufVisitor(PhantomData);
        deserializer.deserialize_bytes(visitor)
    }
}
