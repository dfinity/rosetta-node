//! Data types used for encoding/decoding the Candid payloads of ic:00.
pub use ic_ic00_types::{
    CanisterIdRecord, CanisterSettingsArgs, CanisterStatusResult, CanisterStatusResultV2,
    CreateCanisterArgs, EmptyBlob, InstallCodeArgs, Method, Payload,
    ProvisionalCreateCanisterWithCyclesArgs, ProvisionalTopUpCanisterArgs, SetControllerArgs,
    SetupInitialDKGArgs, SetupInitialDKGResponse, UpdateSettingsArgs, IC_00,
};
