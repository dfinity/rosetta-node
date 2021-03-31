use rand::seq::SliceRandom;
use url::Url;

use ic_canister_client::{Agent, Sender};
use ic_interfaces::registry::RegistryTransportRecord;
use ic_registry_transport::{
    deserialize_atomic_mutate_response, deserialize_get_changes_since_response,
    deserialize_get_value_response, serialize_atomic_mutate_request,
    serialize_get_changes_since_request, serialize_get_value_request,
};
use ic_registry_transport::{
    pb::v1::{Precondition, RegistryDelta, RegistryMutation},
    Error,
};
use ic_types::{crypto::threshold_sig::ThresholdSigPublicKey, CanisterId, RegistryVersion, Time};

/// A higher level helper to interact with the registry canister.
pub struct RegistryCanister {
    canister_id: CanisterId,
    agent: Vec<Agent>,
}

impl RegistryCanister {
    pub fn new(url: Vec<Url>) -> RegistryCanister {
        assert!(
            !url.is_empty(),
            "empty list of URLs passed to RegistryCanister::new()"
        );

        RegistryCanister {
            canister_id: ic_nns_constants::REGISTRY_CANISTER_ID,
            agent: url
                .iter()
                .map(|url| Agent::new(url.clone(), Sender::Anonymous))
                .collect(),
        }
    }

    /// Returns an `Agent` chosen at random
    fn choose_random_agent(&self) -> &Agent {
        self.agent
            .choose(&mut rand::thread_rng())
            .expect("can't fail, ::new asserts list is non-empty")
    }

    /// Queries the registry for all changes that occurred since 'version'.
    ///
    /// On each request a random NNS-hosting replica is chosen to send the
    /// request to.
    pub async fn get_changes_since(
        &self,
        version: u64,
    ) -> Result<(Vec<RegistryDelta>, u64), Error> {
        let payload = serialize_get_changes_since_request(version).unwrap();
        match self
            .choose_random_agent()
            .execute_query(&self.canister_id, "get_changes_since", Some(payload))
            .await
        {
            Ok(result) => match result {
                Some(response) => deserialize_get_changes_since_response(response),
                None => Err(ic_registry_transport::Error::UnknownError(
                    "No response was received from registry_get_changes_since.".to_string(),
                )),
            },
            Err(error_string) => Err(ic_registry_transport::Error::UnknownError(format!(
                "Error on registry_get_changes_since: {}",
                error_string
            ))),
        }
    }

    /// Queries the registry for all the changes that occurred since `version`
    /// using a certified endpoint.
    pub async fn get_certified_changes_since(
        &self,
        version: u64,
        nns_public_key: &ThresholdSigPublicKey,
    ) -> Result<(Vec<RegistryTransportRecord>, RegistryVersion, Time), Error> {
        self.get_certified_changes_since_helper(version, nns_public_key, false)
            .await
    }

    /// Similar to get_certified_changes_since, but with an option to disable
    /// certificate validation.
    pub async fn get_certified_changes_since_helper(
        &self,
        version: u64,
        nns_public_key: &ThresholdSigPublicKey,
        disable_certificate_validation: bool,
    ) -> Result<(Vec<RegistryTransportRecord>, RegistryVersion, Time), Error> {
        let payload = serialize_get_changes_since_request(version).unwrap();
        let response = self
            .choose_random_agent()
            .execute_query(
                &self.canister_id,
                "get_certified_changes_since",
                Some(payload),
            )
            .await
            .map_err(|err| {
                Error::UnknownError(format!(
                    "Failed to query get_certified_changes_since on canister {}: {}",
                    self.canister_id, err,
                ))
            })?
            .ok_or_else(|| {
                Error::UnknownError(format!(
                    "No response was received when queried get_certified_changes_since on {}",
                    self.canister_id,
                ))
            })?;

        crate::certification::decode_certified_deltas_helper(
            version,
            &self.canister_id,
            nns_public_key,
            &response[..],
            disable_certificate_validation,
        )
        .map_err(|err| Error::UnknownError(format!("{:?}", err)))
    }

    /// Obtains the value for 'key'. If 'version_opt' is Some, this will try to
    /// obtain the value at that version, otherwise it will try to obtain
    /// the value at the latest version.
    pub async fn get_value(
        &self,
        key: Vec<u8>,
        version_opt: Option<u64>,
    ) -> Result<(Vec<u8>, u64), Error> {
        let payload = serialize_get_value_request(key, version_opt).unwrap();
        let agent = self.choose_random_agent();

        match agent
            .execute_query(&self.canister_id, "get_value", Some(payload))
            .await
        {
            Ok(result) => match result {
                Some(response) => deserialize_get_value_response(response),
                None => Err(ic_registry_transport::Error::UnknownError(
                    "No response was received from registry_get_value.".to_string(),
                )),
            },
            Err(error_string) => Err(ic_registry_transport::Error::UnknownError(format!(
                "Error on registry_get_value_since: {} using agent {:?}",
                error_string, &agent
            ))),
        }
    }

    /// Applies 'mutations' to the registry.
    pub async fn atomic_mutate(
        &self,
        mutations: Vec<RegistryMutation>,
        pre_conditions: Vec<Precondition>,
    ) -> Result<u64, Vec<Error>> {
        let payload = serialize_atomic_mutate_request(mutations, pre_conditions);
        let nonce = format!("{}", chrono::Utc::now().timestamp_nanos())
            .as_bytes()
            .to_vec();
        match self
            .choose_random_agent()
            .execute_update(&self.canister_id, "atomic_mutate", payload, nonce)
            .await
        {
            Ok(result) => match result {
                Some(response) => deserialize_atomic_mutate_response(response),
                None => Err(vec![ic_registry_transport::Error::UnknownError(
                    "No response was received from registry_atomic_mutate.".to_string(),
                )]),
            },
            Err(error_string) => Err(vec![ic_registry_transport::Error::UnknownError(format!(
                "Error on registry_atomic_mutate: {}",
                error_string
            ))]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn empty_urls_panics() {
        RegistryCanister::new(vec![]);
    }
}
