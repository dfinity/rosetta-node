use ic_rosetta_api::convert::{
    amount_, from_hex, from_operations, from_public_key, operations, signed_amount, to_hex,
    to_model_account_identifier,
};
use ic_rosetta_api::models::{
    ConstructionCombineResponse, ConstructionPayloadsResponse, CurveType, PublicKey, Signature,
    SignatureType,
};
use ic_rosetta_api::models::{Error as RosettaError, TransactionIdentifier};
use ic_types::{time, PrincipalId};

use ledger_canister::{AccountIdentifier, BlockHeight, ICPTs, Transfer};

pub use ed25519_dalek::Keypair as EdKeypair;
use log::debug;
use rand::{rngs::StdRng, seq::SliceRandom, thread_rng, SeedableRng};

pub mod rosetta_api_serv;
pub mod sample_data;
pub mod zondax_gen;

use rosetta_api_serv::RosettaApiHandle;

pub fn make_user(seed: u64) -> (AccountIdentifier, EdKeypair, PublicKey, PrincipalId) {
    let mut rng = StdRng::seed_from_u64(seed);
    let keypair = EdKeypair::generate(&mut rng);

    let public_key = PublicKey {
        hex_bytes: to_hex(&keypair.public.to_bytes()),
        // This is a guess
        curve_type: CurveType::EDWARDS25519,
    };

    let public_key_der =
        ic_canister_client::ed25519_public_key_to_der(keypair.public.to_bytes().to_vec());

    assert_eq!(
        from_public_key(&public_key).unwrap(),
        keypair.public.to_bytes()
    );

    let pid = PrincipalId::new_self_authenticating(&public_key_der);
    let user_id: AccountIdentifier = pid.into();

    debug!("[test] created user {}", user_id);

    (user_id, keypair, public_key, pid)
}

pub fn acc_id(seed: u64) -> AccountIdentifier {
    let mut rng = StdRng::seed_from_u64(seed);
    let keypair = EdKeypair::generate(&mut rng);
    let public_key_der =
        ic_canister_client::ed25519_public_key_to_der(keypair.public.to_bytes().to_vec());

    PrincipalId::new_self_authenticating(&public_key_der).into()
}

pub async fn prepare_txn(
    ros: &RosettaApiHandle,
    trans: Transfer,
    sender_public_key: PublicKey,
    accept_suggested_fee: bool,
    ingress_end: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<(ConstructionPayloadsResponse, ICPTs), RosettaError> {
    let (sender_acc, fee) = match trans.clone() {
        Transfer::Send { from, fee, .. } => (from, fee),
        _ => panic!("Only Send supported here"),
    };
    let trans_fee_amount = amount_(fee).unwrap();

    let mut ops = operations(&trans, false).unwrap();

    // first ask for the fee
    let mut dry_run_ops = Vec::new();
    let mut fee_found = false;
    for o in &ops {
        if o._type == "FEE" {
            fee_found = true;
        } else {
            dry_run_ops.push(o.clone());
        }
    }
    // just a sanity check
    assert!(fee_found, "There should be a fee op in operations");
    let pre_res = ros.construction_preprocess(dry_run_ops).await.unwrap()?;
    assert_eq!(
        pre_res.required_public_keys.unwrap(),
        vec![to_model_account_identifier(&sender_acc)],
        "Preprocess should report that sender's pk is required"
    );
    let metadata_res = ros
        .construction_metadata(pre_res.options, Some(vec![sender_public_key.clone()]))
        .await
        .unwrap()?;
    let mut suggested_fee = metadata_res.suggested_fee.unwrap();
    assert_eq!(suggested_fee.len(), 1);
    let dry_run_suggested_fee = suggested_fee.pop().unwrap();
    let fee_icpts = ICPTs::from_e8s(dry_run_suggested_fee.value.parse().unwrap());

    if accept_suggested_fee {
        for o in &mut ops {
            if o._type == "FEE" {
                o.amount = Some(signed_amount(-(fee_icpts.get_e8s() as i128)));
            }
        }
    } else {
        // we assume here that we've got a correct transaction; double check that the
        // fee really is what it should be.
        assert_eq!(dry_run_suggested_fee, trans_fee_amount);
    }

    // now try with operations containing the correct fee
    let pre_res = ros.construction_preprocess(ops.clone()).await.unwrap()?;
    assert_eq!(
        pre_res.required_public_keys.unwrap(),
        vec![to_model_account_identifier(&sender_acc)],
        "Preprocess should report that sender's pk is required"
    );
    let metadata_res = ros
        .construction_metadata(pre_res.options, Some(vec![sender_public_key.clone()]))
        .await
        .unwrap()?;
    let mut suggested_fee = metadata_res.suggested_fee.clone().unwrap();
    assert_eq!(suggested_fee.len(), 1);
    let suggested_fee = suggested_fee.pop().unwrap();

    // The fee reported here should be the same as the one we got from dry run
    assert_eq!(suggested_fee, dry_run_suggested_fee);

    ros.construction_payloads(
        Some(metadata_res.metadata.clone()),
        ops,
        Some(vec![sender_public_key]),
        ingress_end,
        created_at_time,
    )
    .await
    .unwrap()
    .map(|resp| (resp, fee_icpts))
}

pub async fn sign_txn(
    ros: &RosettaApiHandle,
    keypair: &EdKeypair,
    public_key: &PublicKey,
    payloads: ConstructionPayloadsResponse,
) -> Result<ConstructionCombineResponse, RosettaError> {
    use ed25519_dalek::Signer;

    let mut signatures: Vec<Signature> = payloads
        .payloads
        .into_iter()
        .map(|p| {
            let bytes = from_hex(&p.hex_bytes).unwrap();
            let signature_bytes = keypair.sign(&bytes).to_bytes();
            let hex_bytes = to_hex(&signature_bytes);
            Signature {
                signing_payload: p,
                public_key: public_key.clone(),
                signature_type: SignatureType::ED25519,
                hex_bytes,
            }
        })
        .collect();

    // The order of signatures shouldn't matter.
    let mut rng = thread_rng();
    signatures.shuffle(&mut rng);

    ros.construction_combine(payloads.unsigned_transaction, signatures)
        .await
        .unwrap()
}

// If accept_suggested_fee is false, then Transfer needs to contain a correct
// fee. Otherwise the fee value will be ignored and set to whatever ledger
// canister wants. In such case we don't do checks if the transaction
// created matches the one requested.
pub async fn do_txn(
    ros: &RosettaApiHandle,
    keypair: &ed25519_dalek::Keypair,
    public_key: &PublicKey,
    transfer: Transfer,
    accept_suggested_fee: bool,
    ingress_end: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<
    (
        TransactionIdentifier,
        Option<BlockHeight>,
        ICPTs, // charged fee
    ),
    RosettaError,
> {
    let (payloads, charged_fee) = prepare_txn(
        ros,
        transfer.clone(),
        public_key.clone(),
        accept_suggested_fee,
        ingress_end,
        created_at_time,
    )
    .await?;

    let parse_res = ros
        .construction_parse(false, payloads.unsigned_transaction.clone())
        .await
        .unwrap()?;

    if !accept_suggested_fee {
        assert_eq!(
            vec![transfer.clone()],
            from_operations(parse_res.operations, false).unwrap()
        );
    }

    // check that we got enough unsigned messages
    if let Some(ingress_end) = ingress_end {
        let ingress_start = time::current_time().as_nanos_since_unix_epoch();
        let intervals = (ingress_end - ingress_start) / 120_000_000_000;
        assert!(payloads.payloads.len() as u64 + 2 >= intervals * 2);
    }

    let signed = sign_txn(ros, &keypair, &public_key, payloads).await?;

    let parse_res = ros
        .construction_parse(true, signed.signed_transaction.clone())
        .await
        .unwrap()?;

    if !accept_suggested_fee {
        assert_eq!(
            vec![transfer.clone()],
            from_operations(parse_res.operations, false).unwrap()
        );
    }

    let hash_res = ros
        .construction_hash(signed.signed_transaction.clone())
        .await
        .unwrap()?;

    let submit_res = ros
        .construction_submit(signed.signed_transaction.clone())
        .await
        .unwrap()?;

    assert_eq!(
        hash_res.transaction_identifier,
        submit_res.transaction_identifier
    );

    // check idempotency
    let submit_res2 = ros
        .construction_submit(signed.signed_transaction.clone())
        .await
        .unwrap()?;
    assert_eq!(submit_res, submit_res2);

    Ok((
        submit_res.transaction_identifier,
        submit_res.block_index,
        charged_fee,
    ))
}

pub async fn send_icpts(
    ros: &RosettaApiHandle,
    keypair: &ed25519_dalek::Keypair,
    dst: AccountIdentifier,
    amount: ICPTs,
) -> Result<
    (
        TransactionIdentifier,
        Option<BlockHeight>,
        ICPTs, // charged fee
    ),
    RosettaError,
> {
    send_icpts_with_window(ros, keypair, dst, amount, None, None).await
}

pub async fn send_icpts_with_window(
    ros: &RosettaApiHandle,
    keypair: &ed25519_dalek::Keypair,
    dst: AccountIdentifier,
    amount: ICPTs,
    ingress_end: Option<u64>,
    created_at_time: Option<u64>,
) -> Result<
    (
        TransactionIdentifier,
        Option<BlockHeight>,
        ICPTs, // charged fee
    ),
    RosettaError,
> {
    let public_key = PublicKey {
        hex_bytes: to_hex(&keypair.public.to_bytes()),
        // This is a guess
        curve_type: CurveType::EDWARDS25519,
    };

    let public_key_der =
        ic_canister_client::ed25519_public_key_to_der(keypair.public.to_bytes().to_vec());

    let from: AccountIdentifier = PrincipalId::new_self_authenticating(&public_key_der).into();

    let t = Transfer::Send {
        from,
        to: dst,
        amount,
        fee: ICPTs::ZERO,
    };

    do_txn(
        ros,
        keypair,
        &public_key,
        t,
        true,
        ingress_end,
        created_at_time,
    )
    .await
}

pub fn assert_ic_error(err: &RosettaError, code: u32, ic_http_status: u64, text: &str) {
    assert_eq!(err.code, code);
    let details = err.details.as_ref().unwrap();
    assert_eq!(
        details.get("ic_http_status").unwrap().as_u64().unwrap(),
        ic_http_status
    );
    assert!(details
        .get("error_message")
        .unwrap()
        .as_str()
        .unwrap()
        .contains(text));
}

pub fn assert_canister_error(err: &RosettaError, code: u32, text: &str) {
    assert_eq!(err.code, code);
    let details = err.details.as_ref().unwrap();
    assert!(
        details
            .get("error_message")
            .unwrap()
            .as_str()
            .unwrap()
            .contains(text),
        format!("rosetta error {:?} does not contain '{}'", err, text)
    );
}
