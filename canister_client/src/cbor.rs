use crate::{
    agent::{sign_read, Agent},
    sign_submit, to_blob,
};
use ic_types::{
    messages::{
        Blob, HttpCanisterUpdate, HttpReadContent, HttpRequestStatus, HttpSubmitContent,
        HttpUserQuery, MessageId,
    },
    time::current_time_and_expiry_time,
    CanisterId,
};
use serde_cbor::value::Value as CBOR;
use std::collections::BTreeMap;
use std::error::Error;

/// A structured representation of a response coming from a call to the IC.
#[derive(Debug)]
pub(crate) struct StatusAndReply<'a> {
    pub status: String,
    pub reject_message: Option<String>,
    pub reply: Option<&'a BTreeMap<CBOR, CBOR>>,
}

#[derive(Debug)]
pub struct CanisterCallResponse {
    pub status: String,
    pub arg: Option<Vec<u8>>,
    pub reject_message: Option<String>,
}

/// Given a top-level CBOR response from call to the IC, extracts:
///
/// - the status string
/// - the 'reply' subtree
/// - the reject message
///
/// This function applies to all responses from the IC, whether corresponding to
/// query requests, update requests, or create canister requests.
pub(crate) fn parse_response(message: &'_ CBOR) -> Result<StatusAndReply<'_>, String> {
    let content = match message {
        CBOR::Map(content) => Ok(content),
        cbor => Err(format!(
            "Expected a Map in the reply root but found {:?}",
            cbor
        )),
    }?;

    let status_key = &CBOR::Text("status".to_string());

    let status = match &content.get(status_key) {
        Some(CBOR::Text(t)) => Ok(t.to_string()),
        Some(cbor) => Err(format!(
            "Expected Text at key '{:?}', but found '{:?}'",
            status_key, cbor
        )),
        None => Err(format!(
            "Key '{:?}' not found in '{:?}'",
            status_key, &content
        )),
    }?;

    let reply_key = CBOR::Text("reply".to_string());
    let reply = match &content.get(&reply_key) {
        Some(CBOR::Map(btree)) => Ok(Some(btree)),
        Some(cbor) => Err(format!(
            "Expected Map at key '{:?}' but found '{:?}'",
            reply_key, cbor
        )),
        None => Ok(None),
    }?;

    // Attempt to extract reject message from reply
    let mut reject_message = None;
    if let Some(rej) = &content.get(&CBOR::Text("reject_message".to_string())) {
        if let CBOR::Text(b) = rej {
            reject_message = Some(b.to_string());
        }
    }

    Ok(StatusAndReply {
        status,
        reply,
        reject_message,
    })
}

/// Given a top-level CBOR response from a call to a canister extracts:
///   - the status string, which must be present
///   - the serialized value of returned by the call
///   - the reject message, if applicable.
///
/// This function is applicable to:
///   - responses to a query call
///   - responses to a status request corresponding to a prior update call
///
/// This function is not applicable to:
///   - responses from canister create call status check.
pub(crate) fn parse_canister_call_response(message: &CBOR) -> Result<CanisterCallResponse, String> {
    let status_and_reply = parse_response(message)?;

    let arg = match status_and_reply.reply {
        None => Ok(None),
        Some(r) => {
            let arg_key = CBOR::Text("arg".to_string());
            match r.get(&arg_key) {
                Some(CBOR::Bytes(bytes)) => Ok(Some(bytes.to_vec())),
                Some(cbor) => Err(format!(
                    "Expected the value of key '{:?}' to be bytes, but found '{:?}'",
                    arg_key, cbor
                )),
                None => Ok(None),
            }
        }
    }?;

    Ok(CanisterCallResponse {
        status: status_and_reply.status,
        arg,
        reject_message: status_and_reply.reject_message,
    })
}

impl Agent {
    /// Prepares and serailizes a CBOR update request.
    pub fn prepare_update<S: ToString>(
        &self,
        canister_id: &CanisterId,
        method: S,
        arguments: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<(Vec<u8>, MessageId), String> {
        let content = HttpSubmitContent::Call {
            update: HttpCanisterUpdate {
                canister_id: to_blob(canister_id),
                method_name: method.to_string(),
                arg: Blob(arguments),
                nonce: Some(Blob(nonce)),
                sender: self.sender_field.clone(),
                ingress_expiry: current_time_and_expiry_time().1.as_nanos_since_unix_epoch(),
            },
        };

        let (submit_request, request_id) = sign_submit(content, &self.sender)?;
        let http_body = serde_cbor::to_vec(&submit_request).map_err(|e| {
            format!(
                "Cannot serialize the submit request in CBOR format because of: {}",
                e
            )
        })?;
        Ok((http_body, request_id))
    }

    /// Prepares and serialized a CBOR query request.
    pub fn prepare_query(
        &self,
        method: &str,
        canister_id: &CanisterId,
        arg: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let content = HttpReadContent::Query {
            query: HttpUserQuery {
                canister_id: super::to_blob(canister_id),
                method_name: method.to_string(),
                arg: Blob(arg.unwrap_or_else(|| vec![0; 33])),
                sender: self.sender_field.clone(),
                nonce: None,
                ingress_expiry: current_time_and_expiry_time().1.as_nanos_since_unix_epoch(),
            },
        };

        let request = sign_read(content, &self.sender)?;
        let cbor: CBOR = serde_cbor::value::to_value(request).unwrap();

        Ok(serde_cbor::to_vec(&cbor).unwrap())
    }

    /// Prepares and serializes a CBOR result check request, i.e. request to
    /// check on the status of a previous request.
    pub fn prepare_update_result_check(
        &self,
        request_id: MessageId,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let content = HttpReadContent::RequestStatus {
            request_status: HttpRequestStatus {
                request_id: Blob(request_id.as_bytes().to_vec()),
                nonce: None,
                ingress_expiry: current_time_and_expiry_time().1.as_nanos_since_unix_epoch(),
            },
        };
        let request = sign_read(content, &self.sender)?;
        Ok(serde_cbor::to_vec(&request)?)
    }
}
