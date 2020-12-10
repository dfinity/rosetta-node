use crate::{
    cbor::{parse_canister_query_response, parse_read_state_response, RequestStatus},
    time_source::SystemTimeTimeSource,
};
use ed25519_dalek::{Keypair, KEYPAIR_LENGTH};
use ic_crypto_tree_hash::Path;
use ic_interfaces::{crypto::DOMAIN_IC_REQUEST, time_source::TimeSource};
use ic_protobuf::types::v1 as pb;
use ic_types::{
    consensus::catchup::CatchUpPackageParam,
    messages::{
        Blob, HttpReadContent, HttpRequestEnvelope, HttpStatusResponse, HttpSubmitContent,
        MessageId, RawHttpRequest,
    },
    CanisterId, PrincipalId, Time,
};
use prost::Message;
use reqwest::{RequestBuilder, Url};
use serde_cbor::value::Value as CBOR;
use std::{convert::TryFrom, error::Error, fmt, sync::Arc, time::Duration};
use tokio::time::delay_for;

/// Maximum time in seconds to wait for a result (successful or otherwise)
/// from an 'execute_update' call.
const INGRESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time in seconds to wait for a result (successful or otherwise)
/// from an 'execute_query' call.
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time in seconds to wait for a result (successful or otherwise)
/// from an 'install_canister' call.
const INSTALL_TIMEOUT: Duration = Duration::from_secs(60);

const QUERY_PATH: &str = &"api/v1/read";
const UPDATE_PATH: &str = &"api/v1/submit";
const NODE_STATUS_PATH: &str = &"api/v1/status";
const CATCH_UP_PACKAGE_PATH: &str = &"/_/catch_up_package";

pub fn to_blob(canister_id: &CanisterId) -> Blob {
    Blob(canister_id.clone().get().into_vec())
}

/// A version of Keypair with a clone instance.
/// Originally this was done with a reference, but I'm avoiding them in async
/// testing because it makes the tests much harder to write.
/// This is a little inefficient, but it's only used for testing
#[derive(Clone, Copy)]
pub struct ClonableKeyPair {
    pub bytes: [u8; KEYPAIR_LENGTH],
}

impl ClonableKeyPair {
    fn new(kp: &Keypair) -> Self {
        ClonableKeyPair {
            bytes: kp.to_bytes(),
        }
    }

    fn get(&self) -> Keypair {
        Keypair::from_bytes(&self.bytes).unwrap()
    }
}

pub type SignF = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, Box<dyn Error>> + Send + Sync>;

/// Represents the identity of the sender.
#[derive(Clone)]
pub enum Sender {
    /// The sender is defined as public/private keypair.
    KeyPair(ClonableKeyPair),
    /// The sender is authenticated via an external HSM devices and the
    /// signature mechanism is specified through the provided function
    /// reference.
    ExternalHsm {
        /// DER encoded public key
        pub_key: Vec<u8>,
        /// Function that abstracts the external HSM.
        sign: SignF,
    },
    /// The anonymous sender is used.
    Anonymous,
}

impl Sender {
    pub fn from_keypair(kp: &Keypair) -> Self {
        Sender::KeyPair(ClonableKeyPair::new(kp))
    }

    pub fn from_external_hsm(pub_key: Vec<u8>, sign: SignF) -> Self {
        Sender::ExternalHsm { pub_key, sign }
    }

    pub fn get_principal_id(&self) -> PrincipalId {
        match self {
            Self::KeyPair(keypair) => PrincipalId::new_self_authenticating(
                &ed25519_public_key_to_der(keypair.get().public.to_bytes().to_vec()),
            ),
            Self::ExternalHsm { pub_key, .. } => PrincipalId::new_self_authenticating(pub_key),
            Self::Anonymous => PrincipalId::new_anonymous(),
        }
    }

    pub fn sign_message_id(&self, msg_id: &MessageId) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        let mut sig_data = vec![];
        sig_data.extend_from_slice(DOMAIN_IC_REQUEST);
        sig_data.extend_from_slice(msg_id.as_bytes());
        self.sign(&sig_data)
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        match self {
            Self::KeyPair(keypair) => Ok(Some(keypair.get().sign(msg).to_bytes().to_vec())),
            Self::ExternalHsm { sign, .. } => sign(msg).map(Some),
            Self::Anonymous => Ok(None),
        }
    }

    pub fn sender_pubkey_der(&self) -> Option<Vec<u8>> {
        match self {
            Self::KeyPair(keypair) => Some(ed25519_public_key_to_der(
                keypair.get().public.to_bytes().to_vec(),
            )),
            Self::ExternalHsm { pub_key, .. } => Some(pub_key.clone()),
            Self::Anonymous => None,
        }
    }
}

/// An agent to talk to the Internet Computer through the public endpoints.
#[derive(Clone)]
pub struct Agent {
    /// Url of the replica to target. This should NOT contain a URL path like
    /// "/api/v1/submit".
    pub url: Url,

    // How long to wait for ingress requests.
    ingress_timeout: Duration,

    // How long to wait for queries.
    query_timeout: Duration,

    // How long to wait for `install_canister` requests.
    pub(crate) install_timeout: Duration,

    // Per reqwest document, cloning a client does not clone the actual connection pool inside.
    // Therefore directly owning a client as opposed to a reference is the standard way to go.
    pub client: reqwest::Client,

    pub sender: Sender,

    /// The values that any 'sender' field should have when issuing
    /// calls with the user corresponding to this Agent.
    pub sender_field: Blob,

    /// The source of time. Generally not changed, unless under test
    pub time_source: Arc<dyn TimeSource>,
}

impl fmt::Debug for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent")
            .field("url", &self.url)
            .field("ingress_timeout", &self.ingress_timeout)
            .field("query_timeout", &self.query_timeout)
            .field("install_timeout", &self.install_timeout)
            .field("sender", &self.sender_field)
            .finish()
    }
}

impl Agent {
    /// Creates an agent.
    ///
    /// `url`: Url of the replica to target. This should NOT contain a URL path
    /// like "/api/v1/submit". It should contain a port, if needed.
    ///
    /// The `sender` identifies the sender on whose behalf the requests are
    /// sent. If the requests are authenticated, the corresponding `pub_key` and
    /// `sender_sig` field are set in the request envelope.
    pub fn new(url: Url, sender: Sender) -> Self {
        Self::new_with_client(reqwest::Client::new(), url, sender)
    }

    /// Creates an agent.
    ///
    /// Same as above except gives the caller the option to retain a
    /// pre-existing reqwest-client.
    pub fn new_with_client(client: reqwest::Client, url: Url, sender: Sender) -> Self {
        let sender_field = Blob(sender.get_principal_id().into_vec());
        Self {
            url,
            client,
            ingress_timeout: INGRESS_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            install_timeout: INSTALL_TIMEOUT,
            sender,
            sender_field,
            time_source: Arc::new(SystemTimeTimeSource::new()),
        }
    }

    /// Sets the timeout for ingress requests.
    pub fn with_ingress_timeout(mut self, ingress_timeout: Duration) -> Self {
        self.ingress_timeout = ingress_timeout;
        self
    }

    /// Sets the timeout for queries.
    pub fn with_query_timeout(mut self, query_timeout: Duration) -> Self {
        self.query_timeout = query_timeout;
        self
    }

    /// Sets the timeout for canister installation.
    pub fn with_install_timeout(mut self, install_timeout: Duration) -> Self {
        self.install_timeout = install_timeout;
        self
    }

    /// Sets the timesource.
    pub fn with_timesource(mut self, time_source: Arc<dyn TimeSource>) -> Self {
        self.time_source = time_source;
        self
    }

    /// Queries the cup endpoint given the provided CatchUpPackageParams.
    pub async fn query_cup_endpoint(
        &self,
        param: Option<CatchUpPackageParam>,
    ) -> Result<Option<pb::CatchUpPackage>, String> {
        let url = self
            .url
            .join(CATCH_UP_PACKAGE_PATH)
            .map_err(|e| format!("{}", e))?;

        let body = param
            .and_then(|param| serde_cbor::to_vec(&param).ok())
            .unwrap_or_default();
        let request = self.prepare_cbor_post_request_body(url, body);

        let bytes = request
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("Sending CUP request failed: {:?}", e))?
            .bytes()
            .await
            .map_err(|e| format!("Receiving from CUP endpoint failed: {:?}", e))?;

        // Response is either empty or a protobuf encoded byte stream.
        let cup = if bytes.is_empty() {
            None
        } else {
            Some(pb::CatchUpPackage::decode(&bytes[..]).map_err(|e| {
                format!(
                    "Failed to deserialize CUP from protobuf, got: {:?} - error {:?}",
                    bytes, e
                )
            })?)
        };

        Ok(cup)
    }

    /// Calls the query method 'method' on the given canister,
    /// optionally with 'arguments'.
    pub async fn execute_query(
        &self,
        canister_id: &CanisterId,
        method: &str,
        arg: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, String> {
        let url = self.url.join(QUERY_PATH).map_err(|e| format!("{}", e))?;
        let envelope = self
            .prepare_query(method, canister_id, arg)
            .map_err(|e| format!("Failed to prepare query: {}", e))?;
        let request = self.prepare_cbor_post_request_body(url, envelope);

        let cbor = match wait_for_one_http_request(request, self.query_timeout).await {
            Ok(c) => Ok(c),
            Err(e) => Err(format!("Canister query call failed: {:?}", e)),
        }?;
        let call_response = parse_canister_query_response(&cbor)?;
        if call_response.status == "replied" {
            Ok(call_response.reply)
        } else {
            Err(format!(
                "The response of a canister query call contained status '{}' and message '{:?}'",
                call_response.status, call_response.reject_message
            ))
        }
    }

    /// Calls the query method 'method' on the canister located at 'url',
    /// optionally with 'arguments'.
    pub async fn execute_update<S: ToString>(
        &self,
        canister_id: &CanisterId,
        method: S,
        arguments: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String> {
        self.execute_update_impl(canister_id, method, arguments, nonce, self.ingress_timeout)
            .await
    }

    /// Calls the query method 'method' on the canister located at 'url',
    /// optionally with 'arguments'.
    pub(crate) async fn execute_update_impl<S: ToString>(
        &self,
        canister_id: &CanisterId,
        method: S,
        arguments: Vec<u8>,
        nonce: Vec<u8>,
        timeout: Duration,
    ) -> Result<Option<Vec<u8>>, String> {
        let (http_body, request_id) = self.prepare_update(canister_id, method, arguments, nonce)?;

        let url = self.url.join(UPDATE_PATH).map_err(|e| format!("{}", e))?;
        let deadline = self.time_source.get_relative_time() + timeout;
        let request = self.prepare_cbor_post_request_body(url, http_body);

        if let Err(e) = request.timeout(timeout).send().await {
            return Err(format!("Error while performing update: {:?}", e));
        }

        // Exponential backoff from 100ms to 10s with a multiplier of 1.3.
        const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);
        const MAX_POLL_INTERVAL: Duration = Duration::from_secs(10);
        const POLL_INTERVAL_MULTIPLIER: f32 = 1.3;

        let mut poll_interval = MIN_POLL_INTERVAL;
        let mut next_poll_time = self.time_source.get_relative_time() + poll_interval;

        while next_poll_time < deadline {
            delay_for(poll_interval).await;

            let wait_timeout = deadline - next_poll_time;
            match self.wait_ingress(request_id.clone(), wait_timeout).await {
                Ok(request_status) => match request_status.status.as_ref() {
                    "replied" => {
                        return Ok(request_status.reply);
                    }
                    "unknown" | "received" | "processing" => {}
                    _ => {
                        return Err(format!(
                            "unexpected result: {:?} - {:?}",
                            request_status.status, request_status.reject_message
                        ))
                    }
                },
                Err(e) => return Err(format!("Unexpected error: {:?}", e)),
            }

            // Bump the poll interval and compute the next poll time (based on current wall
            // time, so we don't spin without delay after a slow poll).
            poll_interval = poll_interval
                .mul_f32(POLL_INTERVAL_MULTIPLIER)
                .max(MAX_POLL_INTERVAL);
            next_poll_time = self.time_source.get_relative_time() + poll_interval;
        }
        Err(format!(
            "Request took longer than {:?} to complete.",
            timeout
        ))
    }

    /// Requests the status of a pending request once.
    ///
    /// This is intended to be used in a loop until a final state is reached.
    ///
    /// Returns the entire CBOR value from the response, without trying to
    /// interpret it.
    async fn request_status_once(
        &self,
        request_id: MessageId,
        timeout: Duration,
    ) -> Result<CBOR, Box<dyn Error>> {
        let url = self.url.join(QUERY_PATH)?;
        let request = self.prepare_cbor_post_request(url);
        let path = Path::new(vec!["request_status".into(), request_id.into()]);
        let status_request_body = self.prepare_read_state(&[path])?;
        wait_for_one_http_request(request.body(status_request_body), timeout).await
    }

    /// Requests the status of a pending canister update call request exactly
    /// once using the `read_state` API.
    ///
    /// This is intended to be used in a loop until a final state is reached.
    pub async fn wait_ingress(
        &self,
        request_id: MessageId,
        timeout: Duration,
    ) -> Result<RequestStatus, String> {
        let cbor = self
            .request_status_once(request_id.clone(), timeout)
            .await
            .map_err(|e| {
                format!(
                    "Couldn't get the status of request {} due to {:?}.",
                    request_id, e
                )
            })?;
        parse_read_state_response(&request_id, cbor)
    }

    /// Requests the version of the public spec supported by this node by
    /// querying /api/v1/status.
    pub async fn ic_api_version(&self) -> Result<String, String> {
        let url = self.url.join(NODE_STATUS_PATH).unwrap();
        let resp = wait_for_one_http_request(self.client.get(url), self.query_timeout)
            .await
            .map_err(|e| format!("{}", e))?;

        let response = serde_cbor::value::from_value::<HttpStatusResponse>(resp)
            .map_err(|source| format!("decoding to HttpStatusResponse failed: {}", source))?;

        Ok(response.ic_api_version)
    }

    /// Requests the Replica impl version of this node by querying
    /// /api/v1/status
    pub async fn impl_version(&self) -> Result<Option<String>, String> {
        let url = self.url.join(NODE_STATUS_PATH).unwrap();
        let resp = wait_for_one_http_request(self.client.get(url), self.query_timeout)
            .await
            .map_err(|e| format!("{}", e))?;

        let response = serde_cbor::value::from_value::<HttpStatusResponse>(resp)
            .map_err(|source| format!("decoding to HttpStatusResponse failed: {}", source))?;

        Ok(response.impl_version)
    }

    fn prepare_cbor_post_request(&self, url: Url) -> RequestBuilder {
        self.client
            .post(url)
            .header("Content-Type", "application/cbor")
    }

    pub(crate) fn prepare_cbor_post_request_body(
        &self,
        url: Url,
        http_body: Vec<u8>,
    ) -> RequestBuilder {
        self.prepare_cbor_post_request(url).body(http_body)
    }
}

/// This is a minimal implementation of DER-encoding for Ed25519, as the keys
/// are constant-length. The format is an ASN.1 SubjectPublicKeyInfo, whose
/// header contains the OID for Ed25519, as specified in RFC 8410:
/// https://tools.ietf.org/html/rfc8410
pub fn ed25519_public_key_to_der(mut key: Vec<u8>) -> Vec<u8> {
    // The constant is the prefix of the DER encoding of the ASN.1
    // SubjectPublicKeyInfo data structure. It can be read as follows:
    // 0x30 0x2A: Sequence of length 42 bytes
    //   0x30 0x05: Sequence of length 5 bytes
    //     0x06 0x03 0x2B 0x65 0x70: OID of length 3 bytes, 1.3.101.112 (where 43 =
    //              1 * 40 + 3)
    //   0x03 0x21: Bit string of length 33 bytes
    //     0x00 [raw key]: No padding [raw key]
    let mut encoded: Vec<u8> = vec![
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    encoded.append(&mut key);
    encoded
}

/// Wraps the content into an envelope that contains the message signature.
///
/// Prerequisite: `content` contains a `sender` field that is compatible with
/// the `keypair` argument.
pub fn sign_submit(
    content: HttpSubmitContent,
    sender: &Sender,
    current_time: Time,
) -> Result<(HttpRequestEnvelope<HttpSubmitContent>, MessageId), String> {
    // Open question: should this also set the `sender` field of the `content`? The
    // two are linked, but it's a bit weird for a function that presents itself
    // as 'wrapping a content into an envelope' to mess up with the content.

    let message_id = match &content {
        HttpSubmitContent::Call { update } => {
            let raw_http_request =
                RawHttpRequest::try_from((update.clone(), current_time)).unwrap();
            MessageId::from(&raw_http_request)
        }
    };

    let pub_key_der = sender.sender_pubkey_der().map(Blob);
    let sender_sig = sender
        .sign_message_id(&message_id)
        .map_err(|e| format!("failed to sign submit message: {}", e))?
        .map(Blob);

    let envelope = HttpRequestEnvelope::<HttpSubmitContent> {
        content,
        sender_pubkey: pub_key_der,
        sender_sig,
        sender_delegation: None,
    };
    Ok((envelope, message_id))
}

/// Wraps the content into an envelope that contains the message signature.
///
/// Prerequisite: if `content` contains a `sender` field (this is the case for
/// queries, but not for request_status), then this 'sender' must be compatible
/// with the `keypair` argument.
pub fn sign_read(
    content: HttpReadContent,
    sender: &Sender,
    current_time: Time,
) -> Result<HttpRequestEnvelope<HttpReadContent>, Box<dyn Error>> {
    let raw_http_request = match &content {
        HttpReadContent::Query { query } => {
            RawHttpRequest::try_from((query.clone(), current_time)).unwrap()
        }
        HttpReadContent::RequestStatus { request_status } => {
            RawHttpRequest::try_from((request_status.clone(), current_time)).unwrap()
        }
        HttpReadContent::ReadState { read_state } => {
            RawHttpRequest::try_from((read_state.clone(), current_time)).unwrap()
        }
    };
    let message_id = MessageId::from(&raw_http_request);
    let pub_key_der = sender.sender_pubkey_der().map(Blob);
    let sender_sig = sender.sign_message_id(&message_id)?.map(Blob);

    Ok(HttpRequestEnvelope::<HttpReadContent> {
        content,
        sender_pubkey: pub_key_der,
        sender_sig,
        sender_delegation: None,
    })
}

/// Sends the given request, waits for the response from the server, and parses
/// it as CBOR.
async fn wait_for_one_http_request(
    request: reqwest::RequestBuilder,
    timeout: Duration,
) -> Result<CBOR, Box<dyn Error>> {
    let bytes = request.timeout(timeout).send().await?.bytes().await?;
    let cbor = serde_cbor::from_slice(&bytes).map_err(|e| {
        format!(
            "Failed to parse result from IC, got: {:?} - error {:?}",
            bytes, e
        )
    })?;
    Ok(cbor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_test_utilities::types::ids::node_test_id;
    use ic_test_utilities::{
        crypto::temp_crypto_component_with_fake_registry, FastForwardTimeSource,
    };
    use ic_types::messages::{
        HttpCanisterUpdate, HttpRequestStatus, HttpUserQuery, SignedIngress, SignedReadRequest,
    };
    use ic_types::{PrincipalId, Time, UserId};
    use ic_validator::{validate_ingress_message, verify_signature};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use tokio_test::assert_ok;

    // The node id of the node that validates message signatures
    const VALIDATOR_NODE_ID: u64 = 42;

    fn time_now() -> Time {
        ic_types::time::UNIX_EPOCH
            + std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time wrapped around")
    }

    /// Create a SignedIngress message with a non-anonymous user and then verify
    /// that `validate_ingress_message` manages to authenticate it.
    #[test]
    fn sign_and_verify_submit_content() {
        let current_time = FastForwardTimeSource::new().get_relative_time();
        let expiry_time = current_time + Duration::from_secs(4 * 60);
        // Set up an arbitrary legal input
        let keypair = {
            let mut rng = ChaChaRng::seed_from_u64(789 as u64);
            ed25519_dalek::Keypair::generate(&mut rng)
        };
        let content = HttpSubmitContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![51]),
                method_name: "foo".to_string(),
                arg: Blob(vec![12, 13, 99]),

                nonce: None,
                sender: Blob(
                    UserId::from(PrincipalId::new_self_authenticating(
                        &ed25519_public_key_to_der(keypair.public.to_bytes().to_vec()),
                    ))
                    .get()
                    .into_vec(),
                ),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let sender = Sender::from_keypair(&keypair);
        let (submit, id) = sign_submit(content.clone(), &sender, current_time).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(submit.content, content);

        // The message id matches one that can be reconstructed from the output
        let signed_ingress = SignedIngress::try_from((submit, current_time)).unwrap();
        assert_eq!(id, MessageId::from(&signed_ingress.content));

        // The envelope can be successfully authenticated
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        validate_ingress_message(&validator, &id, &signed_ingress, time_now()).unwrap();
    }

    /// Create a SignedIngress message with an explicit anonymous user and then
    /// verify that `validate_ingress_message` manages to authenticate it.
    #[test]
    fn sign_and_verify_submit_content_explicit_anonymous() {
        let current_time = FastForwardTimeSource::new().get_relative_time();
        let expiry_time = current_time + Duration::from_secs(4 * 60);

        // Set up an arbitrary legal input
        let content = HttpSubmitContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![51]),
                method_name: "foo".to_string(),
                arg: Blob(vec![12, 13, 99]),

                nonce: None,
                sender: Blob(UserId::from(PrincipalId::new_anonymous()).get().into_vec()),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let (submit, id) = sign_submit(content.clone(), &Sender::Anonymous, current_time).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(submit.content, content);

        // The message id matches one that can be reconstructed from the output
        let signed_ingress = SignedIngress::try_from((submit, current_time)).unwrap();
        assert_eq!(id, MessageId::from(&signed_ingress.content));

        // The envelope can be successfully authenticated
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        validate_ingress_message(&validator, &id, &signed_ingress, time_now()).unwrap();
    }

    #[test]
    fn sign_and_verify_request_status_content_valid_status_request() {
        let current_time = FastForwardTimeSource::new().get_relative_time();
        let expiry_time = current_time + Duration::from_secs(4 * 60);

        // Set up an arbitrary legal input
        let keypair = {
            let mut rng = ChaChaRng::seed_from_u64(51 as u64);
            ed25519_dalek::Keypair::generate(&mut rng)
        };
        let content = HttpReadContent::RequestStatus {
            request_status: HttpRequestStatus {
                request_id: Blob(vec![
                    0, 1, 2, 3, 4, 5, 6, 7, // A valid request id is always 32 bytes
                    3, 3, 3, 3, 3, 3, 3, 3, // but any content is valid
                    5, 5, 5, 5, 5, 5, 5, 5, // so we just use something arbitrary
                    0, 0, 0, 0, 0, 0, 0, 0, // in this test.
                ]),
                nonce: None,
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        // Workaround because HttpReadContent is not cloneable
        let content_copy = serde_cbor::value::from_value::<HttpReadContent>(
            serde_cbor::value::to_value(&content).unwrap(),
        )
        .unwrap();

        let sender = Sender::from_keypair(&keypair);
        let read = sign_read(content, &sender, current_time).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(read.content, content_copy);

        // The signature matches
        let signed_read = SignedReadRequest::try_from((read, current_time)).unwrap();
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        let message_id = signed_read.message_id();
        assert_ok!(verify_signature(
            &validator,
            &message_id,
            signed_read.signature().unwrap(),
            time_now()
        ));
    }

    #[test]
    fn sign_and_verify_request_status_content_valid_query() {
        let current_time = FastForwardTimeSource::new().get_relative_time();
        let expiry_time = current_time + Duration::from_secs(4 * 60);

        // Set up an arbitrary legal input
        let keypair = {
            let mut rng = ChaChaRng::seed_from_u64(89 as u64);
            ed25519_dalek::Keypair::generate(&mut rng)
        };
        let content = HttpReadContent::Query {
            query: HttpUserQuery {
                canister_id: Blob(vec![67, 3]),
                method_name: "foo".to_string(),
                arg: Blob(vec![23, 19, 4]),
                sender: Blob(
                    UserId::from(PrincipalId::new_self_authenticating(
                        &ed25519_public_key_to_der(keypair.public.to_bytes().to_vec()),
                    ))
                    .get()
                    .into_vec(),
                ),
                nonce: None,
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        // Workaround because HttpReadContent is not cloneable
        let content_copy = serde_cbor::value::from_value::<HttpReadContent>(
            serde_cbor::value::to_value(&content).unwrap(),
        )
        .unwrap();

        let sender = Sender::from_keypair(&keypair);
        let read = sign_read(content, &sender, current_time).unwrap();

        // The wrapped content is content, without modification
        assert_eq!(read.content, content_copy);

        // The signature matches
        let signed_read = SignedReadRequest::try_from((read, current_time)).unwrap();
        let validator = temp_crypto_component_with_fake_registry(node_test_id(VALIDATOR_NODE_ID));
        let message_id = signed_read.message_id();
        assert_ok!(verify_signature(
            &validator,
            &message_id,
            &signed_read.signature().unwrap(),
            time_now()
        ));
    }
}
