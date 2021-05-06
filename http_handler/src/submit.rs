//! Module that deals with requests to /api/v2/canister/.../call

use crate::{
    common,
    metrics::HttpHandlerMetrics,
    types::{ApiReqType, RequestType},
};
use hyper::{Body, Response, StatusCode};
use ic_interfaces::crypto::IngressSigVerifier;
use ic_interfaces::execution_environment::ExecutionEnvironment;
use ic_interfaces::execution_environment::{HypervisorError, MessageAcceptanceError};
use ic_interfaces::p2p::IngressEventHandler;
use ic_interfaces::registry::RegistryClient;
use ic_interfaces::state_manager::StateReader;
use ic_logger::{error, info_sample, warn, ReplicaLogger};
use ic_registry_client::helper::{
    provisional_whitelist::ProvisionalWhitelistRegistry, subnet::SubnetRegistry,
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_replicated_state::CanisterState;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    messages::{HttpHandlerError, SignedIngress, SignedRequestBytes},
    time::current_time,
    CountBytes, SubnetId,
};
use ic_validator::validate_request;
use std::convert::TryInto;

fn into_http_status_code(
    acceptance_error: MessageAcceptanceError,
    metrics: &HttpHandlerMetrics,
) -> (StatusCode, String) {
    match acceptance_error {
        MessageAcceptanceError::CanisterNotFound => (
            StatusCode::NOT_FOUND,
            "Requested canister does not exist".to_string(),
        ),
        MessageAcceptanceError::CanisterHasNoWasmModule => (
            StatusCode::NOT_FOUND,
            "Requested canister has no wasm module".to_string(),
        ),
        MessageAcceptanceError::CanisterRejected => {
            metrics.observe_forbidden_request(&RequestType::Submit, "CanisterRejected");
            (
                StatusCode::FORBIDDEN,
                "Requested canister rejected the message".to_string(),
            )
        }
        MessageAcceptanceError::CanisterOutOfCycles => {
            metrics.observe_forbidden_request(&RequestType::Submit, "CanisterOutOfCycles");
            (
                StatusCode::FORBIDDEN,
                "Requested canister doesn't have enough cycles".to_string(),
            )
        }
        MessageAcceptanceError::CanisterExecutionFailed(err) => match err {
            HypervisorError::MethodNotFound(_) => (
                StatusCode::NOT_FOUND,
                "Attempt to execute non-existent method on the canister".to_string(),
            ),
            HypervisorError::CalledTrap(_) => {
                metrics.observe_forbidden_request(&RequestType::Submit, "CalledTrap");
                (
                    StatusCode::FORBIDDEN,
                    "Requested canister rejected the message".to_string(),
                )
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Requested canister failed to process the message acceptance request".to_string(),
            ),
        },
    }
}

/// Handles a call to /api/v2/canister/../call
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle(
    log: &ReplicaLogger,
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    maliciously_disable_ingress_validation: bool,
    ingress_sender: &dyn IngressEventHandler,
    state_reader: &dyn StateReader<State = ReplicatedState>,
    validator: &dyn IngressSigVerifier,
    execution_environment: &dyn ExecutionEnvironment<
        State = ReplicatedState,
        CanisterState = CanisterState,
    >,
    body: Vec<u8>,
    metrics: &HttpHandlerMetrics,
) -> (Response<Body>, ApiReqType) {
    use ApiReqType::*;
    // Actual parsing.
    let msg: SignedIngress = match SignedRequestBytes::from(body).try_into() {
        Ok(msg) => msg,
        Err(e) => {
            let error_code = match e {
                HttpHandlerError::InvalidEncoding(_) => StatusCode::UNPROCESSABLE_ENTITY,
                _ => StatusCode::BAD_REQUEST,
            };
            return (
                common::make_response(
                    error_code,
                    format!("Could not parse body as submit message: {}", e).as_str(),
                ),
                Unknown,
            );
        }
    };

    let message_id = msg.id();

    let max_ingress_bytes_per_message = match registry_client
        .get_ingress_message_settings(subnet_id, registry_client.get_latest_version())
    {
        Ok(Some(settings)) => settings.max_ingress_bytes_per_message,
        Ok(None) => {
            warn!(
                log,
                "No subnet record found for the latest registry version and subnet_id={:?}",
                subnet_id,
            );
            return (
                common::make_response(StatusCode::SERVICE_UNAVAILABLE, "Service not available."),
                Call,
            );
        }
        Err(err) => {
            error!(
                log,
                "Couldn't retrieve max_ingress_bytes_per_message from the registry: {:?}", err
            );
            return (
                common::make_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error."),
                Call,
            );
        }
    };

    // Check size, respond with 413 if too large
    if msg.count_bytes() > max_ingress_bytes_per_message {
        return (
            common::make_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Request {} is too large. ", message_id).as_str(),
            ),
            Call,
        );
    };
    let registry_version = registry_client.get_latest_version();
    if !maliciously_disable_ingress_validation {
        let validity = validate_request(msg.as_ref(), validator, current_time(), registry_version);
        if let Some(response) =
            common::make_response_to_unauthentic_requests(message_id.clone(), validity, log)
        {
            metrics.observe_forbidden_request(&RequestType::Submit, "SubmitReqAuthFailed");
            return (response, Call);
        }
    }

    {
        let provisional_whitelist = match registry_client
            .get_provisional_whitelist(registry_version)
        {
            Ok(Some(list)) => list,
            Ok(None) => {
                error!(log, "At registry version {}, get_provisional_whitelist() returned Ok(None).  Using empty list",
                           registry_version);
                ProvisionalWhitelist::new_empty()
            }
            Err(err) => {
                error!(log, "At registry version {}, get_provisional_whitelist() failed with {}.  Using empty list",
                           registry_version, err);
                ProvisionalWhitelist::new_empty()
            }
        };
        let state = state_reader.get_latest_state().take();
        if let Err(err) = execution_environment.should_accept_ingress_message(
            state,
            &provisional_whitelist,
            msg.content(),
        ) {
            let (status_code, error_msg) = into_http_status_code(err, metrics);
            return (common::make_response(status_code, &error_msg), Call);
        }
    }

    // We're pretty much done, just need to send the message to ingress and
    // make_response to the client
    let ingress_log_entry = msg.log_entry();
    match ingress_sender.on_ingress_message(msg) {
        Err(_e) => (
            common::make_response(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable!"),
            Call,
        ),
        Ok(_) => {
            info_sample!(
                "message_id" => &message_id,
                log,
                "ingress_message_submit";
                ingress_message => ingress_log_entry
            );
            (common::make_response(StatusCode::ACCEPTED, ""), Call)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_types::{
        messages::{Blob, HttpCanisterUpdate, HttpRequestEnvelope, HttpSubmitContent},
        time::current_time_and_expiry_time,
    };
    use std::convert::TryFrom;

    #[test]
    fn check_request_id() {
        let expiry_time = current_time_and_expiry_time().1;
        let content = HttpSubmitContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: "".to_string(),
                arg: Blob(b"".to_vec()),
                nonce: None,
                sender: Blob(vec![0x04]),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let request1 = HttpRequestEnvelope::<HttpSubmitContent> {
            content,
            sender_sig: Some(Blob(vec![])),
            sender_pubkey: Some(Blob(vec![])),
            sender_delegation: None,
        };

        let content = HttpSubmitContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: "".to_string(),
                arg: Blob(b"".to_vec()),
                nonce: None,
                sender: Blob(vec![0x04]),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let request2 = HttpRequestEnvelope::<HttpSubmitContent> {
            content,
            sender_sig: Some(Blob(b"yes this is a signature".to_vec())),
            sender_pubkey: Some(Blob(b"yes this is a public key: prove it is not!".to_vec())),
            sender_delegation: None,
        };

        let message_id = SignedIngress::try_from(request1).unwrap().id();
        let message_id_2 = SignedIngress::try_from(request2).unwrap().id();
        assert_eq!(message_id_2, message_id);
    }
}
