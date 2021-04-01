use ic_crypto_internal_fs_ni_dkg::forward_secure::PublicKey as ClibFsNiDkgPublicKey;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::public_key_into_miracl;
use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPok;
use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPublicKey;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use std::convert::TryFrom;
use std::fmt;

#[cfg(test)]
mod tests;

pub fn fs_ni_dkg_pubkey_from_proto(
    pubkey_proto: &PublicKeyProto,
) -> Result<ClibFsNiDkgPublicKey, FsNiDkgPubkeyFromPubkeyProtoError> {
    let csp_pk = CspFsEncryptionPublicKey::try_from(pubkey_proto.clone()).map_err(|e| {
        FsNiDkgPubkeyFromPubkeyProtoError::PublicKeyConversion {
            error: format!("{}", e),
        }
    })?;
    let csp_pok = CspFsEncryptionPok::try_from(pubkey_proto).map_err(|e| {
        FsNiDkgPubkeyFromPubkeyProtoError::PokConversion {
            error: format!("{}", e),
        }
    })?;
    let dkg_dealing_enc_pubkey = clib_fs_ni_dkg_pubkey_from_csp_pubkey_with_pok(&csp_pk, &csp_pok)
        .map_err(|_| FsNiDkgPubkeyFromPubkeyProtoError::InternalConversion)?;
    Ok(dkg_dealing_enc_pubkey)
}

fn clib_fs_ni_dkg_pubkey_from_csp_pubkey_with_pok(
    csp_pubkey: &CspFsEncryptionPublicKey,
    csp_pok: &CspFsEncryptionPok,
) -> Result<ClibFsNiDkgPublicKey, ()> {
    match (csp_pubkey, csp_pok) {
        (
            CspFsEncryptionPublicKey::Groth20_Bls12_381(pubkey),
            CspFsEncryptionPok::Groth20_Bls12_381(pok),
        ) => public_key_into_miracl((&pubkey, &pok)),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsNiDkgPubkeyFromPubkeyProtoError {
    PublicKeyConversion { error: String },
    PokConversion { error: String },
    InternalConversion,
}

impl fmt::Display for FsNiDkgPubkeyFromPubkeyProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKeyConversion { error } => {
                write!(f, "Failed to convert public key: {}", error,)
            }
            Self::PokConversion { error } => {
                write!(f, "Failed to convert proof of knowledge (PoK): {}", error)
            }
            Self::InternalConversion => write!(f, "Internal conversion failed"),
        }
    }
}
