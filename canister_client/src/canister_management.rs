//! Functions for clients to talk to the Management Canister, a.k.a ic:00.
use crate::agent::Agent;

use ic_types::{
    ic00::{CanisterIdRecord, EmptyBlob, InstallCodeArgs, Method, Payload, IC_00},
    CanisterId,
};

impl Agent {
    /// Creates a canister.
    ///
    /// The nonce may be used to force the creation of a new canister, as
    /// opposed to returning the id of a previously-created one.
    pub async fn create_canister(&self, nonce: Vec<u8>) -> Result<CanisterId, String> {
        let creation_result = self
            .execute_update(&IC_00, Method::CreateCanister, EmptyBlob::encode(), nonce)
            .await?;
        let encoded_canister_id = match creation_result {
            None => Err(
                "A call to create a canister returned without a canister id in the reply"
                    .to_string(),
            ),
            Some(bytes) => Ok(bytes),
        }?;

        match CanisterIdRecord::decode(encoded_canister_id.as_slice()) {
            Ok(id) => Ok(id.get_canister_id()),
            Err(e) => Err(format!(
                "Could not decode the canister id returned by a call to create a canister: {}",
                e
            )),
        }
    }

    // Ships a binary wasm module to a canister.
    pub async fn install_canister(&self, install_args: InstallCodeArgs) -> Result<(), String> {
        self.execute_update_impl(
            &IC_00,
            Method::InstallCode,
            install_args.encode(),
            vec![],
            self.install_timeout,
        )
        .await
        .map(|_| ())
    }
}
