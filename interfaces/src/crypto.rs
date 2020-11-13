mod keygen;

pub use keygen::KeyManager;
pub use keygen::Keygen;

mod hash;

pub use hash::CryptoHashDomain;
pub use hash::CryptoHashable;
pub use hash::CryptoHashableTestDummy;
pub use hash::DOMAIN_IC_REQUEST;

mod errors;

mod dkg;

pub use dkg::DkgAlgorithm;
pub use sign::threshold_sig::ni_dkg::NiDkgAlgorithm;

mod sign;

pub use sign::BasicSigVerifier;
pub use sign::BasicSigVerifierByPublicKey;
pub use sign::BasicSigner;
pub use sign::IngressSigVerifier;
pub use sign::MultiSigVerifier;
pub use sign::MultiSigner;
pub use sign::ThresholdSigVerifier;
pub use sign::ThresholdSigVerifierByPublicKey;
pub use sign::ThresholdSigner;
pub use sign::{Signable, SignableMock};

use ic_types::consensus::certification::CertificationContent;
use ic_types::consensus::dkg as consensus_dkg;
use ic_types::consensus::{
    Block, CatchUpContent, FinalizationContent, NotarizationContent, RandomBeaconContent,
    RandomTapeContent,
};
use ic_types::messages::{MessageId, WebAuthnEnvelope};

/// The functionality offered by the crypto component
pub trait Crypto:
    KeyManager
    // Block
    + BasicSigner<Block>
    + BasicSigVerifier<Block>
    // Dealing
    + BasicSigner<consensus_dkg::DealingContent>
    + BasicSigVerifier<consensus_dkg::DealingContent>
    // DKG
    + DkgAlgorithm
    + NiDkgAlgorithm
    // CertificationContent
    + MultiSigner<CertificationContent>
    + MultiSigVerifier<CertificationContent>
    + ThresholdSigner<CertificationContent>
    + ThresholdSigVerifier<CertificationContent>
    + ThresholdSigVerifierByPublicKey<CertificationContent>
    // FinalizationContent
    + MultiSigner<FinalizationContent>
    + MultiSigVerifier<FinalizationContent>
    // NotarizationContent
    + MultiSigner<NotarizationContent>
    + MultiSigVerifier<NotarizationContent>
    // RequestId/WebAuthn
    + BasicSigVerifierByPublicKey<MessageId>
    + BasicSigVerifierByPublicKey<WebAuthnEnvelope>
    // CatchUpPackage
    + ThresholdSigner<CatchUpContent>
    + ThresholdSigVerifier<CatchUpContent>
    + ThresholdSigVerifierByPublicKey<CatchUpContent>
    // RandomBeacon
    + ThresholdSigner<RandomBeaconContent>
    + ThresholdSigVerifier<RandomBeaconContent>
    // RandomTape
    + ThresholdSigner<RandomTapeContent>
    + ThresholdSigVerifier<RandomTapeContent>
    // Traits for signing/verifying a MerkleRoot
    // (both Multi- and ThresholdSig) will be added at a later stage.
    //
    // Also, further traits concerning other functionality of the crypto
    // component (such as key generation) will be added at a later stage.
{
}

/// A classifier for errors returned by the crypto component. Indicates whether
/// a given error is permanent and guaranteed to occur in all replicas.
pub trait ErrorReplication {
    // If true is returned, retrying the failing call will return the same error,
    // and the same error will be encountered by other replicas.
    fn is_replicated(&self) -> bool;
}

// Blanket implementation of Crypto for all types that fulfill requirements
impl<T> Crypto for T where
    T: KeyManager
        + BasicSigner<Block>
        + BasicSigVerifier<Block>
        + BasicSigner<consensus_dkg::DealingContent>
        + BasicSigVerifier<consensus_dkg::DealingContent>
        + DkgAlgorithm
        + NiDkgAlgorithm
        + MultiSigner<CertificationContent>
        + MultiSigVerifier<CertificationContent>
        + ThresholdSigner<CertificationContent>
        + ThresholdSigVerifier<CertificationContent>
        + ThresholdSigVerifierByPublicKey<CertificationContent>
        + MultiSigner<FinalizationContent>
        + MultiSigVerifier<FinalizationContent>
        + MultiSigner<NotarizationContent>
        + MultiSigVerifier<NotarizationContent>
        + BasicSigVerifierByPublicKey<MessageId>
        + BasicSigVerifierByPublicKey<WebAuthnEnvelope>
        + ThresholdSigner<CatchUpContent>
        + ThresholdSigVerifier<CatchUpContent>
        + ThresholdSigVerifierByPublicKey<CatchUpContent>
        + ThresholdSigner<RandomBeaconContent>
        + ThresholdSigVerifier<RandomBeaconContent>
        + ThresholdSigner<RandomTapeContent>
        + ThresholdSigVerifier<RandomTapeContent>
{
}

/// A limited functionality offered by the crypto component especially
/// for node manager, as an intermediate solution before crypto runs in
/// a separate process.
pub trait CryptoForNodeManager:
    KeyManager
    // CatchUpPackage
    + ThresholdSigVerifierByPublicKey<CatchUpContent>

    // TODO(CRP-606): add API for authenticating registry queries.
{
}

// Blanket implementation of CryptoForNodeManager for all types that
// fulfill requirements
impl<T> CryptoForNodeManager for T where
    T: KeyManager + ThresholdSigVerifierByPublicKey<CatchUpContent>
{
}
