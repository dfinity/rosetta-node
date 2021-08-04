use crate::invariants::common::{
    get_node_records_from_snapshot, InvariantCheckError, RegistrySnapshot,
};

use std::collections::{BTreeMap, HashMap};

use prost::Message;

use ic_base_types::NodeId;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_nns_common::registry::decode_or_panic;
use ic_protobuf::{
    crypto::v1::NodePublicKeys,
    registry::crypto::v1::{PublicKey, X509PublicKeyCert},
};
use ic_registry_keys::{
    maybe_parse_crypto_node_key, maybe_parse_crypto_tls_cert_key, CRYPTO_RECORD_KEY_PREFIX,
    CRYPTO_TLS_CERT_KEY_PREFIX,
};
use ic_types::crypto::KeyPurpose;

// All crypto public keys found for the nodes or for the subnets in the
// registry.
type AllPublicKeys = BTreeMap<(NodeId, KeyPurpose), PublicKey>;

// All TLS certificates found for the nodes in the registry.
type AllTlsCertificates = BTreeMap<NodeId, X509PublicKeyCert>;

// Checks node invariants related to crypto keys:
//  * every node has the required public keys and these keys are well formed and
//    valid. The required keys are:
//     - node signing public key
//     - committee signing public key
//     - DKG dealing encryption public key
//     - TLS certificate
//  * every node's id (node_id) is correctly derived from its node signing
//    public key
//  * all the public keys and all the TLS certificates belonging to the all the
//    nodes are unique
//
// TODO(NNS1-202): should we also check that there are no "left-over" public
// keys or TLS certificates in the registry, i.e. every key/certificate is
// assigned to some existing node?
#[allow(dead_code)]
fn check_node_crypto_keys_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let nodes = get_node_records_from_snapshot(snapshot);
    let mut pks = get_all_nodes_public_keys(snapshot);
    let mut certs = get_all_tls_certs(snapshot);
    let mut unique_pks: BTreeMap<Vec<u8>, NodeId> = BTreeMap::new();
    let mut unique_certs: HashMap<Vec<u8>, NodeId> = HashMap::new();

    for node_id in nodes.keys() {
        let valid_node_pks = check_node_keys(node_id, &mut pks, &mut certs)?;
        check_node_keys_are_unique(&valid_node_pks, &mut unique_pks)?;
        check_tls_certs_are_unique(&valid_node_pks, &mut unique_certs)?;
    }
    Ok(())
}

// Returns all nodes' public keys in the snapshot.
fn get_all_nodes_public_keys(snapshot: &RegistrySnapshot) -> AllPublicKeys {
    let mut pks = BTreeMap::new();
    for (k, v) in snapshot {
        if k.starts_with(CRYPTO_RECORD_KEY_PREFIX.as_bytes()) {
            let (node_id, key_purpose) = maybe_parse_crypto_node_key(
                &String::from_utf8(k.to_owned()).expect("invalid crypto node key bytes"),
            )
            .expect("invalid crypto node key");
            let pk = decode_or_panic::<PublicKey>(v.clone());
            pks.insert((node_id, key_purpose), pk);
        }
    }
    pks
}

// Returns all TLS certificates in the snapshot.
fn get_all_tls_certs(snapshot: &RegistrySnapshot) -> AllTlsCertificates {
    let mut certs = BTreeMap::new();
    for (k, v) in snapshot {
        if k.starts_with(CRYPTO_TLS_CERT_KEY_PREFIX.as_bytes()) {
            let node_id = maybe_parse_crypto_tls_cert_key(
                &String::from_utf8(k.to_owned()).expect("invalid tls cert key bytes"),
            )
            .expect("invalid tls cert key");
            let cert = decode_or_panic::<X509PublicKeyCert>(v.clone());
            certs.insert(node_id, cert);
        }
    }
    certs
}

fn check_node_keys(
    node_id: &NodeId,
    pks: &mut AllPublicKeys,
    certs: &mut AllTlsCertificates,
) -> Result<ValidNodePublicKeys, InvariantCheckError> {
    let npk = NodePublicKeys {
        version: 0,
        node_signing_pk: pks.remove(&(*node_id, KeyPurpose::NodeSigning)),
        committee_signing_pk: pks.remove(&(*node_id, KeyPurpose::CommitteeSigning)),
        dkg_dealing_encryption_pk: pks.remove(&(*node_id, KeyPurpose::DkgDealingEncryption)),
        tls_certificate: certs.remove(node_id),
    };
    let vnpk = ValidNodePublicKeys::try_from(&npk, *node_id).map_err(|e| InvariantCheckError {
        msg: format!(
            "crypto key validation for node {} failed with {}",
            node_id, e
        ),
        source: None,
    })?;
    Ok(vnpk)
}

fn check_node_keys_are_unique(
    node_pks: &ValidNodePublicKeys,
    unique_pks: &mut BTreeMap<Vec<u8>, NodeId>,
) -> Result<(), InvariantCheckError> {
    for pk in &[
        node_pks.node_signing_key(),
        node_pks.committee_signing_key(),
        node_pks.dkg_dealing_encryption_key(),
    ] {
        let mut pk_bytes: Vec<u8> = vec![];
        pk.encode(&mut pk_bytes).expect("encode cannot fail.");
        match unique_pks.get(&pk_bytes) {
            Some(existing_id) => {
                return Err(InvariantCheckError {
                    msg: format!(
                        "nodes {} and {} use the same public key {:?}",
                        existing_id,
                        node_pks.node_id(),
                        pk
                    ),
                    source: None,
                })
            }
            None => {
                unique_pks.insert(pk_bytes, node_pks.node_id());
            }
        }
    }
    Ok(())
}

fn check_tls_certs_are_unique(
    node_pks: &ValidNodePublicKeys,
    unique_certs: &mut HashMap<Vec<u8>, NodeId>,
) -> Result<(), InvariantCheckError> {
    let mut cert_bytes: Vec<u8> = vec![];
    node_pks
        .tls_certificate()
        .encode(&mut cert_bytes)
        .expect("encode cannot fail.");
    match unique_certs.get(&cert_bytes) {
        Some(existing_id) => Err(InvariantCheckError {
            msg: format!(
                "nodes {} and {} use the same TLS certificate {:?}",
                existing_id,
                node_pks.node_id(),
                node_pks.tls_certificate()
            ),
            source: None,
        }),
        None => {
            unique_certs.insert(cert_bytes, node_pks.node_id());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_crypto::utils::get_node_keys_or_generate_if_missing;
    use ic_nns_common::registry::encode_or_panic;
    use ic_protobuf::registry::node::v1::NodeRecord;
    use ic_registry_keys::{make_crypto_node_key, make_crypto_tls_cert_key, make_node_record_key};
    use ic_test_utilities::crypto::temp_dir::temp_dir;

    fn insert_node_crypto_keys(
        node_id: &NodeId,
        npks: &NodePublicKeys,
        snapshot: &mut RegistrySnapshot,
    ) {
        if npks.node_signing_pk.is_some() {
            snapshot.insert(
                make_crypto_node_key(node_id.to_owned(), KeyPurpose::NodeSigning).into_bytes(),
                encode_or_panic::<PublicKey>(&npks.node_signing_pk.clone().unwrap()),
            );
        };
        if npks.committee_signing_pk.is_some() {
            snapshot.insert(
                make_crypto_node_key(node_id.to_owned(), KeyPurpose::CommitteeSigning).into_bytes(),
                encode_or_panic::<PublicKey>(&npks.committee_signing_pk.clone().unwrap()),
            );
        };
        if npks.dkg_dealing_encryption_pk.is_some() {
            snapshot.insert(
                make_crypto_node_key(node_id.to_owned(), KeyPurpose::DkgDealingEncryption)
                    .into_bytes(),
                encode_or_panic::<PublicKey>(&npks.dkg_dealing_encryption_pk.clone().unwrap()),
            );
        };
        if npks.tls_certificate.is_some() {
            snapshot.insert(
                make_crypto_tls_cert_key(node_id.to_owned()).into_bytes(),
                encode_or_panic::<X509PublicKeyCert>(&npks.tls_certificate.clone().unwrap()),
            );
        };
    }

    fn valid_node_keys_and_node_id() -> (NodePublicKeys, NodeId) {
        let temp_dir = temp_dir();
        get_node_keys_or_generate_if_missing(temp_dir.path())
    }

    fn insert_dummy_node(node_id: &NodeId, snapshot: &mut RegistrySnapshot) {
        snapshot.insert(
            make_node_record_key(node_id.to_owned()).into_bytes(),
            encode_or_panic::<NodeRecord>(&NodeRecord::default()),
        );
    }

    #[test]
    fn node_crypto_keys_invariants_valid_snapshot() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);
        insert_node_crypto_keys(&node_id_2, &npks_2, &mut snapshot);
        assert!(check_node_crypto_keys_invariants(&snapshot).is_ok());
    }

    #[test]
    fn node_crypto_keys_invariants_missing_committee_key() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let incomplete_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: npks_2.node_signing_pk,
            committee_signing_pk: None,
            dkg_dealing_encryption_pk: npks_2.dkg_dealing_encryption_pk,
            tls_certificate: npks_2.tls_certificate,
        };
        insert_node_crypto_keys(&node_id_2, &incomplete_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("committee"));
        assert!(err.to_string().contains("key is missing"));
    }

    #[test]
    fn node_crypto_keys_invariants_missing_node_signing_key() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let incomplete_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: None,
            committee_signing_pk: npks_2.committee_signing_pk,
            dkg_dealing_encryption_pk: npks_2.dkg_dealing_encryption_pk,
            tls_certificate: npks_2.tls_certificate,
        };
        insert_node_crypto_keys(&node_id_2, &incomplete_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("node signing key"));
        assert!(err.to_string().contains("key is missing"));
    }

    #[test]
    fn node_crypto_keys_invariants_missing_tls_cert() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let incomplete_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: npks_2.node_signing_pk,
            committee_signing_pk: npks_2.committee_signing_pk,
            dkg_dealing_encryption_pk: npks_2.dkg_dealing_encryption_pk,
            tls_certificate: None,
        };
        insert_node_crypto_keys(&node_id_2, &incomplete_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("certificate"));
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn node_crypto_keys_invariants_invalid_dkg_encryption_key() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let invalid_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: npks_2.node_signing_pk,
            committee_signing_pk: npks_2.committee_signing_pk,
            dkg_dealing_encryption_pk: Some(PublicKey {
                version: 0,
                algorithm: 0,
                key_value: vec![],
                proof_data: None,
            }),
            tls_certificate: npks_2.tls_certificate,
        };
        insert_node_crypto_keys(&node_id_2, &invalid_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err
            .to_string()
            .contains("invalid DKG dealing encryption key"));
    }

    #[test]
    fn node_crypto_keys_invariants_duplicated_committee_key() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let duplicated_key_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: npks_2.node_signing_pk,
            committee_signing_pk: npks_1.committee_signing_pk,
            dkg_dealing_encryption_pk: npks_2.dkg_dealing_encryption_pk,
            tls_certificate: npks_2.tls_certificate,
        };
        insert_node_crypto_keys(&node_id_2, &duplicated_key_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_1.to_string()));
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("the same public key"));
    }

    #[test]
    fn node_crypto_keys_invariants_duplicated_tls_cert() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let duplicated_cert_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: npks_2.node_signing_pk,
            committee_signing_pk: npks_2.committee_signing_pk,
            dkg_dealing_encryption_pk: npks_2.dkg_dealing_encryption_pk,
            tls_certificate: npks_1.tls_certificate,
        };
        insert_node_crypto_keys(&node_id_2, &duplicated_cert_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("invalid TLS certificate"));
    }

    #[test]
    fn node_crypto_keys_invariants_inconsistent_node_id() {
        // Crypto keys for the test.
        let (npks_1, node_id_1) = valid_node_keys_and_node_id();
        let (npks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, &npks_1, &mut snapshot);

        let (npks_3, _node_id_3) = valid_node_keys_and_node_id();
        let inconsistent_signing_key_npks = NodePublicKeys {
            version: npks_2.version,
            node_signing_pk: npks_3.node_signing_pk,
            committee_signing_pk: npks_2.committee_signing_pk,
            dkg_dealing_encryption_pk: npks_2.dkg_dealing_encryption_pk,
            tls_certificate: npks_2.tls_certificate,
        };
        insert_node_crypto_keys(&node_id_2, &inconsistent_signing_key_npks, &mut snapshot);
        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("invalid node signing key"));
    }
}
