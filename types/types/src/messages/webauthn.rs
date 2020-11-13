use crate::{crypto::SignedBytesWithoutDomainSeparator, messages::Blob, CountBytes};
use base64::URL_SAFE_NO_PAD;
use ic_crypto_sha256::Sha256;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct ClientData {
    r#type: String,
    challenge: String,
    origin: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WebAuthnSignature {
    authenticator_data: Blob,
    client_data_json: Blob,
    pub signature: Blob,
    pub delegation: Option<Blob>,
    pub delegate_signature: Option<Blob>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WebAuthnDelegation {
    pub key: Blob,
    pub expiration: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct WebAuthnEnvelope {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    client_data: ClientData,
    signed_bytes: Vec<u8>,
    // The decoded challenge, this will be either a message id or hash(delegation)
    pub challenge: Vec<u8>,
}

// TODO: Add optional fields if present
impl CountBytes for WebAuthnSignature {
    fn count_bytes(&self) -> usize {
        self.authenticator_data.0.len() + self.client_data_json.0.len() + self.signature.0.len()
    }
}

impl TryFrom<&[u8]> for WebAuthnSignature {
    type Error = String;

    fn try_from(blob: &[u8]) -> Result<Self, Self::Error> {
        let signature: WebAuthnSignature = serde_cbor::from_slice(blob)
            .map_err(|err| format!("Signature CBOR parsing failed with: {}", err))?;
        Ok(signature)
    }
}

impl WebAuthnSignature {
    // The "delegation" field contains a CBOR-encoded WebAuthnDelegation, which is
    // signed by the web authentication key. The "delegate_signature" contains
    // the signature on the CBOR object, so both fields must be present for the
    // WebAuthnDelegation to make sense.
    pub fn webauthn_delegation(&self) -> Result<Option<WebAuthnDelegation>, String> {
        match (&self.delegation, &self.delegate_signature) {
            (None, None) => Ok(None),
            (Some(_), None) => Err("Broken delegation: missing signature".to_string()),
            (None, Some(_)) => Err("Delegation signature found, but no delegation".to_string()),
            // Parse the delegation. We cannot parse the signature here, but we want to ensure
            // it is there since otherwise the message is invalid anyway.
            (Some(delegation), Some(_)) => {
                let webauthn_delegation = serde_cbor::from_slice(&delegation.0)
                    .map_err(|err| format!("Delegation CBOR failed with: {}", err))?;
                Ok(Some(webauthn_delegation))
            }
        }
    }
}

impl TryFrom<&WebAuthnSignature> for WebAuthnEnvelope {
    type Error = String;

    fn try_from(signature: &WebAuthnSignature) -> Result<Self, Self::Error> {
        let client_data: ClientData =
            match serde_json::from_slice(&signature.client_data_json.0[..]) {
                Ok(client_data) => client_data,
                Err(err) => return Err(format!("ClientDataJSON parsing failed with: {}", err)),
            };

        let challenge = match base64::decode_config(&client_data.challenge, URL_SAFE_NO_PAD) {
            Ok(challenge) => challenge,
            Err(err) => return Err(format!("Challenge base64url parsing failed with: {}", err)),
        };

        let mut signed_bytes = signature.authenticator_data.0.clone();
        signed_bytes.append(&mut Sha256::hash(&signature.client_data_json.0.clone()[..]).to_vec());

        Ok(WebAuthnEnvelope {
            client_data_json: signature.client_data_json.0.clone(),
            authenticator_data: signature.authenticator_data.0.clone(),
            client_data,
            signed_bytes,
            challenge,
        })
    }
}

impl SignedBytesWithoutDomainSeparator for WebAuthnEnvelope {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        self.signed_bytes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn try_from_cbor_ok() {
        let cbor_bytes = hex!("D9D9F7A37261757468656E74696361746F725F6461746158252F1B671A93F444B8EC77E0211F9624C9C2612182B864F0D4AC9D335F5B4FE502010000005370636C69656E745F646174615F6A736F6E78987B2274797065223A22776562617574686E2E676574222C226368616C6C656E6765223A225044786863476B74636D56786457567A644331705A43776758334A6C6358566C6333516761575266506A34222C226F726967696E223A2268747470733A2F2F63636763652D62616261612D61616161612D61616161612D63616161612D61616161612D61616161612D712E6963302E617070227D697369676E617475726558473045022100C69C75C6D6C449EA936094476E8BFCAD90D831A6437A87117615ADD6D6A5168802201E2E4535976794286FA264EB81D7B14B3F168AB7F62AD5C0B9D6EBFC64EB0C8C");
        let signature = WebAuthnSignature::try_from(&cbor_bytes[..]);
        assert!(signature.is_ok());
        let signature = signature.ok().unwrap();
        let webauthn_delegation = signature.webauthn_delegation();
        assert!(webauthn_delegation.is_ok());
        let delegation = webauthn_delegation.ok().unwrap();
        assert!(delegation.is_none());
        let result = WebAuthnEnvelope::try_from(&signature);
        assert!(result.is_ok());
        let result = result.ok().unwrap();
        assert_eq!(
            result.challenge,
            [
                60, 60, 97, 112, 105, 45, 114, 101, 113, 117, 101, 115, 116, 45, 105, 100, 44, 32,
                95, 114, 101, 113, 117, 101, 115, 116, 32, 105, 100, 95, 62, 62
            ]
        );
        assert_eq!(
            result.authenticator_data,
            hex!("2f1b671a93f444b8ec77e0211f9624c9c2612182b864f0d4ac9d335f5b4fe5020100000053")
                .to_vec()
        );
        assert_eq!(result.as_signed_bytes_without_domain_separator().to_vec(), hex!("2f1b671a93f444b8ec77e0211f9624c9c2612182b864f0d4ac9d335f5b4fe50201000000537f91225ffff1e2912a0f8ca7a0ef61df01ae3d8898fca283036239259bab4f82").to_vec());
    }

    #[test]
    fn try_with_delegation_from_cbor_ok() {
        let cbor_bytes = hex!("D9D9F7A57261757468656E74696361746F725F6461746158252F1B671A93F444B8EC77E0211F9624C9C2612182B864F0D4AC9D335F5B4FE502010000005370636C69656E745F646174615F6A736F6E78987B2274797065223A22776562617574686E2E676574222C226368616C6C656E6765223A225044786863476B74636D56786457567A644331705A43776758334A6C6358566C6333516761575266506A34222C226F726967696E223A2268747470733A2F2F63636763652D62616261612D61616161612D61616161612D63616161612D61616161612D61616161612D712E6963302E617070227D697369676E617475726558473045022100C69C75C6D6C449EA936094476E8BFCAD90D831A6437A87117615ADD6D6A5168802201E2E4535976794286FA264EB81D7B14B3F168AB7F62AD5C0B9D6EBFC64EB0C8C6A64656C65676174696F6E5873D9D9F7A2636B6579585B3059301306072A8648CE3D020106082A8648CE3D030107034200042D8650927BDFF8C51477A19B6A76115D6FBFE015C3473BE23451139D96A5A6E0E0F560C89B80DC589C48E6A51A78BB8F37EEBC50724E63A320B5E35A94CC70416A65787069726174696F6E1930397264656C65676174655F7369676E617475726558404E95438408225972AB3E2DC321ECF037EA7BB06B79015BACAC353D7E31A7DE6BC377509E266EFF8EE2188CC3C15C23764CA4A363DFB1CCBF744F540AAE9DA83B");
        let signature = WebAuthnSignature::try_from(&cbor_bytes[..]);
        assert!(signature.is_ok());
        let signature = signature.ok().unwrap();
        let webauthn_delegation = signature.webauthn_delegation();
        assert!(webauthn_delegation.is_ok());
        let delegation = webauthn_delegation.ok().unwrap();
        assert!(delegation.is_some());
        let delegation = delegation.unwrap();
        assert_eq!(delegation.key.0, hex!("3059301306072a8648ce3d020106082a8648ce3d030107034200042d8650927bdff8c51477a19b6a76115d6fbfe015c3473be23451139d96a5a6e0e0f560c89b80dc589c48e6a51a78bb8f37eebc50724e63a320b5e35a94cc7041").to_vec());
        assert_eq!(delegation.expiration, 12345);
    }

    #[test]
    fn try_with_js_generated_ok() {
        let cbor_bytes = hex!("d9d9f7a57261757468656e74696361746f725f64617461582549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763010000000d70636c69656e745f646174615f6a736f6e58a27b226368616c6c656e6765223a22346d4f434258554c7a4e356955323430552d3274393066376c426b4b49627878386f795362424636304b41222c22636c69656e74457874656e73696f6e73223a7b7d2c2268617368416c676f726974686d223a225348412d323536222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a38303830222c2274797065223a22776562617574686e2e676574227d7264656c65676174655f7369676e617475726558601e1bababe3ccb0f9da71342195d9bf820aa079f0803ab2f28b0567f2c0c2a12ac3e7677dc7ee6fe12af340843619eef96df8a715963062a3b341c0bd3aa763053c3c6170692d726571756573742d69642c205f726571756573742069645f3e3e6a64656c65676174696f6e583ed9d9f7a26a65787069726174696f6e1b16395cb844077800636b657958205b2a31bf6e5184034c202a5f05c0f2fe116ac123a47619dd19a97193eba6446c697369676e617475726558463044022019352a87008f672b8aae68967106c6a8b0b4b1dd2a426de9b3a54881013105ab022053f0a99e668a2266bac5873778d910256221663f98d3bc8610016316ed9c36c9");
        let signature = WebAuthnSignature::try_from(&cbor_bytes[..]);
        assert!(signature.is_ok());
        let signature = signature.ok().unwrap();
        let webauthn_delegation = signature.webauthn_delegation();
        assert!(webauthn_delegation.is_ok());
        let webauthn_delegation = webauthn_delegation.ok().unwrap();
        assert!(webauthn_delegation.is_some());
        let delegation = webauthn_delegation.unwrap();
        assert_eq!(
            delegation.key.0,
            hex!("5B2A31BF6E5184034C202A5F05C0F2FE116AC123A47619DD19A97193EBA6446C").to_vec()
        );
        assert_eq!(delegation.expiration, 1601413088992000000);
    }
}
