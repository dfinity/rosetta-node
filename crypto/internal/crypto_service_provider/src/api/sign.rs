use super::super::types::{CspPop, CspPublicKey, CspSignature};
use ic_types::crypto::CryptoResult;
use ic_types::crypto::{AlgorithmId, KeyId};

pub trait CspSigner {
    fn sign(
        &self,
        algorithm_id: AlgorithmId,
        msg: &[u8],
        key_id: KeyId,
    ) -> CryptoResult<CspSignature>;

    fn verify(
        &self,
        sig: &CspSignature,
        msg: &[u8],
        algorithm_id: AlgorithmId,
        signer: CspPublicKey,
    ) -> CryptoResult<()>;

    fn verify_pop(
        &self,
        pop: &CspPop,
        algorithm_id: AlgorithmId,
        public_key: CspPublicKey,
    ) -> CryptoResult<()>;

    ///
    fn combine_sigs(
        &self,
        signatures: Vec<(CspPublicKey, CspSignature)>,
        algorithm_id: AlgorithmId,
    ) -> CryptoResult<CspSignature>;

    ///
    fn verify_multisig(
        &self,
        signers: Vec<CspPublicKey>,
        signature: CspSignature,
        msg: &[u8],
        algorithm_id: AlgorithmId,
    ) -> CryptoResult<()>;
}
