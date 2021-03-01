//! Tests for the CLib NiDKG forward secure encryption
pub use rand::Rng;
pub use rand_chacha::ChaChaRng;
pub use rand_core::SeedableRng;
pub use std::collections::BTreeMap;

mod internal_types {
    pub use ic_crypto_internal_types::curves::bls12_381::Fr as FrBytes;
    pub use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
    pub use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
    pub use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes as ThresholdPublicKeyBytes;
}
mod clib {
    pub use crate::api::keygen as threshold_keygen;
    pub use crate::types::SecretKeyBytes as ThresholdSecretKeyBytes;
}
use super::*;
use internal_types::Epoch;

/// The Fs NiDKG library is compatible with the internal_types
#[test]
fn constants_should_be_compatible() {
    assert_eq!(
        ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::NUM_ZK_REPETITIONS,
        ic_crypto_internal_fs_ni_dkg::nizk_chunking::NUM_ZK_REPETITIONS,
        "NUM_ZK_REPETITIONS differs"
    );
    assert_eq!(
        std::mem::size_of::<Epoch>() * 8,
        ic_crypto_internal_fs_ni_dkg::forward_secure::LAMBDA_T,
        "The size of the epoch is incompatible"
    );
}

/// Keygen should run without panicking.
#[test]
fn keygen_should_work() {
    create_forward_secure_key_pair(Randomness::from([6u8; 32]));
}

#[test]
fn epoch_of_a_new_key_should_be_zero() {
    let key_set = create_forward_secure_key_pair(Randomness::from([6u8; 32]));
    let epoch = epoch_from_miracl_secret_key(&secret_key_into_miracl(&key_set.secret_key));
    assert_eq!(epoch.get(), 0);
}

#[test]
fn single_stepping_a_key_should_increment_current_epoch() {
    let FsEncryptionKeySet { mut secret_key, .. } =
        create_forward_secure_key_pair(Randomness::from([6u8; 32]));
    for epoch in 4..8 {
        let secret_key_epoch = Epoch::from(epoch);
        secret_key =
            update_forward_secure_epoch(&secret_key, secret_key_epoch, Randomness::from([9u8; 32]));
        let key_epoch = epoch_from_miracl_secret_key(&secret_key_into_miracl(&secret_key)).get();
        assert_eq!(
            key_epoch, epoch,
            "Deleted epoch {} but key epoch is {}\n  {:?}",
            epoch, key_epoch, secret_key
        );
    }
}

#[test]
fn correct_keys_should_verify() {
    let key_set = create_forward_secure_key_pair(Randomness::from([6u8; 32]));
    let verification = verify_forward_secure_key(&key_set.public_key, &key_set.pok);
    assert_eq!(verification, Ok(()));
}

#[test]
fn wrong_pok_should_not_verify() {
    let seed = Randomness::from([6u8; 32]);
    let different_seed = Randomness::from([9u8; 32]);
    let FsEncryptionKeySet { public_key, .. } = create_forward_secure_key_pair(seed);
    let FsEncryptionKeySet { pok, .. } = create_forward_secure_key_pair(different_seed);
    let verification = verify_forward_secure_key(&public_key, &pok);
    assert_eq!(verification, Err(()));
}

/// Generates valid threshold keys and the corresponding public coefficients
fn generate_threshold_keys(
    num_receivers: usize,
    threshold: NumberOfNodes,
    seed: Randomness,
) -> (
    internal_types::PublicCoefficientsBytes,
    Vec<clib::ThresholdSecretKeyBytes>,
) {
    let receiver_eligibility = vec![true; num_receivers];
    let (public_coefficients, threshold_keys_maybe) =
        clib::threshold_keygen(seed, threshold, &receiver_eligibility[..])
            .expect("Test fail: Threshold keygen failed");
    let threshold_keys = threshold_keys_maybe
        .iter()
        .map(|key_maybe| key_maybe.unwrap())
        .collect::<Vec<_>>();
    let public_coefficients = internal_types::PublicCoefficientsBytes {
        coefficients: public_coefficients
            .coefficients
            .iter()
            .map(|x| internal_types::ThresholdPublicKeyBytes(x.0))
            .collect(),
    };
    (public_coefficients, threshold_keys)
}

/// Prepares threshold keys for encryption
fn fs_key_message_pairs(
    threshold_keys: &[clib::ThresholdSecretKeyBytes],
    forward_secure_key_sets: &[FsEncryptionKeySet],
) -> Vec<(FsEncryptionPublicKey, FsEncryptionPlaintext)> {
    threshold_keys
        .iter()
        .zip(forward_secure_key_sets)
        .map(|(threshold_key, FsEncryptionKeySet { public_key, .. })| {
            let message = internal_types::FrBytes(threshold_key.0);
            let message = FsEncryptionPlaintext::from(&message);
            (*public_key, message)
        })
        .collect()
}

#[test]
fn encryption_should_work() {
    const NUM_RECEIVERS: u8 = 3;
    let threshold = NumberOfNodes::from(2);

    let (public_coefficients, threshold_keys) = generate_threshold_keys(
        NUM_RECEIVERS as usize,
        threshold,
        Randomness::from([99u8; 32]),
    );

    let forward_secure_keys: Vec<FsEncryptionKeySet> = (0..NUM_RECEIVERS)
        .map(|receiver_index| {
            create_forward_secure_key_pair(Randomness::from([receiver_index | 0x10; 32]))
        })
        .collect();

    encrypt_and_prove(
        Randomness::from([0x69; 32]),
        &fs_key_message_pairs(&threshold_keys, &forward_secure_keys),
        Epoch::from(4),
        &public_coefficients,
    )
    .expect("Encryption failed");
}

/// Verifies that decryption yields the original plaintext.
///
/// # Summary
/// * Generates N key pairs
/// * Encrypts a message for each of the public keys
/// * Decrypting should yield the original plaintexts.
#[test]
fn encrypted_messages_should_decrypt() {
    const NUM_RECEIVERS: u8 = 3;
    let threshold = NumberOfNodes::from(2);

    let (public_coefficients, threshold_keys) = generate_threshold_keys(
        NUM_RECEIVERS as usize,
        threshold,
        Randomness::from([99u8; 32]),
    );

    let forward_secure_keys: Vec<FsEncryptionKeySet> = (0..NUM_RECEIVERS)
        .map(|receiver_index| {
            create_forward_secure_key_pair(Randomness::from([receiver_index | 0x10; 32]))
        })
        .collect();

    let key_message_pairs = fs_key_message_pairs(&threshold_keys, &forward_secure_keys);

    let epoch = Epoch::from(5); // Small epoch as forward-stepping is slow
    let seed = Randomness::from([0x69; 32]);
    let (ciphertext, ..) = encrypt_and_prove(seed, &key_message_pairs, epoch, &public_coefficients)
        .expect("Test failure: Failed to encrypt");

    let secret_keys = forward_secure_keys.iter().map(|key| &key.secret_key);
    let messages = key_message_pairs.iter().map(|key_message| &key_message.1);
    for ((secret_key, message), node_index) in secret_keys.zip(messages).zip(0..) {
        let plaintext_maybe = decrypt(&ciphertext, secret_key, node_index, epoch);
        assert_eq!(
            plaintext_maybe.as_ref(),
            Ok(message),
            "Plaintext doesn't match for node {}",
            node_index
        );
    }
}

/// Verifies that messages cannot be decrypted after an epoch has been deleted
///
/// # Summary
/// * Updates the secret key to an epoch.
/// * Encrypts messages at a range of epochs.
/// * Decrypting should succeed where the encryption epoch is strictly greater
///   than the key epoch.
#[test]
fn decryption_should_fail_below_epoch() {
    const NUM_RECEIVERS: u8 = 3;
    let threshold = NumberOfNodes::from(2);
    let mut rng = ChaChaRng::from_seed([0xbe; 32]);

    let (public_coefficients, threshold_keys) = generate_threshold_keys(
        NUM_RECEIVERS as usize,
        threshold,
        Randomness::from([99u8; 32]),
    );
    let forward_secure_keys: Vec<FsEncryptionKeySet> = (0..NUM_RECEIVERS)
        .map(|receiver_index| {
            create_forward_secure_key_pair(Randomness::from([receiver_index | 0x10; 32]))
        })
        .collect();
    let key_message_pairs = fs_key_message_pairs(&threshold_keys, &forward_secure_keys);

    let secret_key_epoch = Epoch::from(100000); // This will be the current epoch of the secret key
    let encryption_epochs: Vec<Epoch> = (secret_key_epoch.get() - 2..)
        .take(5)
        .map(Epoch::from)
        .collect();
    let ciphertexts_at_epochs: Vec<FsEncryptionCiphertext> = encryption_epochs
        .iter()
        .map(|epoch| {
            encrypt_and_prove(
                Randomness::from(rng.gen::<[u8; 32]>()),
                &key_message_pairs,
                *epoch,
                &public_coefficients,
            )
            .expect("Test error: Failed to encrypt")
            .0
        })
        .collect();

    let secret_keys = forward_secure_keys.iter().map(|key| &key.secret_key);
    let messages = key_message_pairs.iter().map(|key_message| &key_message.1);
    #[allow(clippy::iter_next_loop)] // We test just one of the receivers
    for ((secret_key, message), node_index) in secret_keys.zip(messages).zip(0..).next() {
        // Delete keys below epoch
        let secret_key = update_forward_secure_epoch(
            &secret_key,
            secret_key_epoch,
            Randomness::from(rng.gen::<[u8; 32]>()),
        );

        // Decrypts should succeed only for ciphertexts with higher epochs
        for (ciphertext_epoch, ciphertext) in encryption_epochs
            .iter()
            .cloned()
            .zip(&ciphertexts_at_epochs)
        {
            let plaintext_maybe = decrypt(&ciphertext, &secret_key, node_index, ciphertext_epoch);
            if ciphertext_epoch >= secret_key_epoch {
                assert_eq!(
                    plaintext_maybe.as_ref(),
                    Ok(message),
                    "Plaintext doesn't match for node {}",
                    node_index
                );
            } else {
                assert_eq!(
                    plaintext_maybe,
                    Err(DecryptError::EpochTooOld {
                        ciphertext_epoch,
                        secret_key_epoch
                    }),
                    "Node {} should not be able to decrypt after having deleted the current epoch",
                    node_index
                );
            }
        }
    }
}

#[test]
fn zk_proofs_should_verify() {
    const NUM_RECEIVERS: u8 = 3;
    let threshold = NumberOfNodes::from(2);

    let (public_coefficients, threshold_keys) = generate_threshold_keys(
        NUM_RECEIVERS as usize,
        threshold,
        Randomness::from([99u8; 32]),
    );

    let forward_secure_keys: Vec<FsEncryptionKeySet> = (0..NUM_RECEIVERS)
        .map(|receiver_index| {
            create_forward_secure_key_pair(Randomness::from([receiver_index | 0x10; 32]))
        })
        .collect();

    let key_message_pairs = fs_key_message_pairs(&threshold_keys, &forward_secure_keys);

    let epoch = Epoch::from(5); // Small epoch as forward-stepping is slow
    let seed = Randomness::from([0x69; 32]);
    let (ciphertext, chunking_proof, sharing_proof) =
        encrypt_and_prove(seed, &key_message_pairs, epoch, &public_coefficients)
            .expect("Test failure: Failed to encrypt");

    let public_keys = &(0..)
        .zip(&forward_secure_keys)
        .map(|(index, key)| (index, key.public_key))
        .collect::<BTreeMap<ic_types::NodeIndex, FsEncryptionPublicKey>>();

    verify_zk_proofs(
        &public_keys,
        &public_coefficients,
        &ciphertext,
        &chunking_proof,
        &sharing_proof,
    )
    .expect("Verification failed");
}
