pub use ed25519_dalek::Keypair as EdKeypair;
use ed25519_dalek::Signer;
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_rosetta_api::{
    convert::{from_hex, from_public_key, to_arg, to_hex, to_model_account_identifier},
    make_sig_data, models,
    models::{CurveType, Signature, SignatureType, SigningPayload},
};
use ic_types::{
    messages::{
        Blob, HttpCanisterUpdate, HttpRequestEnvelope, HttpSubmitContent, SignedRequestBytes,
    },
    PrincipalId,
};
use ledger_canister::{account_identifier::SUB_ACCOUNT_ZERO, AccountIdentifier, ICPTs, SendArgs};
use rand::RngCore;
use serde_json::json;
use std::iter::once;
use std::{convert::TryFrom, fmt::Display};

fn zondex_icp_format(amount: ICPTs) -> String {
    let int_part_reversed: String = amount
        .get_icpts()
        .to_string()
        // Insert "," separators every 3 chars, going right to left
        .chars()
        .rev()
        .enumerate()
        .flat_map(|(pos, c)| {
            (if pos % 3 == 0 && pos > 0 { "," } else { "" })
                .chars()
                .chain(once(c))
        })
        .collect();
    let int_part: String = int_part_reversed.chars().rev().collect();
    let frac_part_untruncated = format!("{:08}", amount.get_remainder_e8s());
    let frac_part_truncated_rev: String = frac_part_untruncated
        .chars()
        .rev()
        .enumerate()
        .skip_while(|(pos, c)| *c == '0' && *pos < 6)
        .map(|(_, c)| c)
        .collect();
    let frac_part: String = frac_part_truncated_rev.chars().rev().collect();

    format!("{}.{}", int_part, frac_part)
}

pub fn generate_zondax_test(index: u32, keypair: EdKeypair, send_args: SendArgs) -> String {
    let public_key_der =
        ic_canister_client::ed25519_public_key_to_der(keypair.public.to_bytes().to_vec());

    let public_key =
        models::PublicKey::new(hex::encode(public_key_der.clone()), CurveType::EDWARDS25519);

    let pid = PrincipalId::new_self_authenticating(&public_key_der);

    let SendArgs {
        memo,
        amount,
        fee,
        from_subaccount,
        to,
        ..
    } = send_args;

    let update = HttpCanisterUpdate {
        canister_id: Blob(LEDGER_CANISTER_ID.get().to_vec()),
        method_name: "send_pb".to_string(),
        arg: Blob(to_arg(send_args)),
        // TODO work out whether Rosetta will accept us generating a nonce here
        // If we don't have a nonce it could cause one of those nasty bugs that
        // doesn't show it's face until you try to do two
        // identical transactions at the same time
        nonce: None,
        sender: Blob(pid.into_vec()),
        // sender: Blob(from.into_vec()),
        ingress_expiry: 0,
    };

    let from: AccountIdentifier = pid.into();

    let account_identifier = to_model_account_identifier(&from);

    let transaction_payload = SigningPayload {
        address: None,
        account_identifier: Some(account_identifier),
        hex_bytes: hex::encode(make_sig_data(&update.id())),
        signature_type: Some(SignatureType::ED25519),
    };

    let bytes = from_hex(&transaction_payload.hex_bytes).unwrap();
    let signature_bytes = keypair.sign(&bytes).to_bytes();
    let hex_bytes = to_hex(&signature_bytes);

    let transaction_signature = Signature {
        signing_payload: transaction_payload,
        public_key,
        signature_type: SignatureType::ED25519,
        hex_bytes,
    };

    let envelope = HttpRequestEnvelope::<HttpSubmitContent> {
        content: HttpSubmitContent::Call { update },
        sender_pubkey: Some(Blob(ic_canister_client::ed25519_public_key_to_der(
            from_public_key(&transaction_signature.public_key).unwrap(),
        ))),
        sender_sig: Some(Blob(from_hex(&transaction_signature.hex_bytes).unwrap())),
        sender_delegation: None,
    };

    let bytes: Vec<u8> = SignedRequestBytes::try_from(envelope).unwrap().into();

    let from_subaccount = from_subaccount.unwrap_or(SUB_ACCOUNT_ZERO);

    let json = json!({
        "index": index,
        "name": format!("Send tx index {}", index),
        "blob": hex::encode(&bytes),
        "output": [
            "0 | Transaction type : Send ICP",
            format!("1 | From account [1/2] : {}", chunk(from, 0)),
            format!("1 | From account [2/2] : {}", chunk(from, 1)),
            format!("2 | To account [1/2] : {}", chunk(to, 0)),
            format!("2 | To account [2/2] : {}", chunk(to, 1)),
            format!("3 | Payment (ICP) : {}", zondex_icp_format(amount)),
            format!("4 | Maximum fee (ICP) : {}", zondex_icp_format(fee)),
            format!("5 | Memo : {}", memo.0)
        ],
        "output_expert": [
            "0 | Transaction type : Send ICP",
            format!("1 | Sender [1/2] : {}", chunk_pid(pid, 0)),
            format!("1 | Sender [2/2] : {}", chunk_pid(pid, 1)),
            format!("2 | Subaccount [1/2] : {}", chunk(from_subaccount, 0)),
            format!("2 | Subaccount [2/2] : {}", chunk(from_subaccount, 1)),
            format!("3 | From account [1/2] : {}", chunk(from, 0)),
            format!("3 | From account [2/2] : {}", chunk(from, 1)),
            format!("4 | To account [1/2] : {}", chunk(to, 0)),
            format!("4 | To account [2/2] : {}", chunk(to, 1)),
            format!("3 | Payment (IPT) : {}", zondex_icp_format(amount)),
            format!("4 | Maximum fee (ICP) : {}", zondex_icp_format(fee)),
            format!("5 | Memo : {}", memo.0)
        ]
    });

    serde_json::to_string_pretty(&json).unwrap()
}

fn chunk<D: Display>(d: D, chunk: usize) -> String {
    let s = format!("{}", d);
    let chunks = s
        .chars()
        .collect::<Vec<char>>()
        .chunks(32)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>();
    chunks.get(chunk).unwrap().clone()
}

fn chunk_pid(pid: PrincipalId, chunk: usize) -> String {
    let s = format!("{}", pid);
    let chunks = s
        .chars()
        .collect::<Vec<char>>()
        .chunks(18)
        .map(|c| c.iter().take(17).collect::<String>())
        .collect::<Vec<String>>();

    let fst = chunks.get(2 * chunk).unwrap();
    let snd = chunks.get(2 * chunk + 1).unwrap();

    format!("{} : {}", fst, snd)
}

#[test]
fn test_zondax_generator() {
    use rand::{prelude::StdRng, SeedableRng};

    use ledger_canister::{ICPTs, Memo};

    let send_args = SendArgs {
        memo: Memo(0),
        amount: ICPTs::from_icpts(10).unwrap(),
        fee: ICPTs::from_e8s(137),
        from_subaccount: None,
        to: PrincipalId::new_anonymous().into(),
        created_at_time: None,
    };

    let mut rng = StdRng::seed_from_u64(1);
    let keypair = EdKeypair::generate(&mut rng);

    let s = generate_zondax_test(1, keypair, send_args);
    println!("{}", s);
}

#[test]
fn test_pretty_icp_format() {
    assert_eq!(zondex_icp_format(ICPTs::from_e8s(0)), *"0.00");
    assert_eq!(zondex_icp_format(ICPTs::from_e8s(1)), *"0.00000001");
    assert_eq!(zondex_icp_format(ICPTs::from_e8s(10)), *"0.0000001");
    assert_eq!(zondex_icp_format(ICPTs::from_e8s(100)), *"0.000001");
    assert_eq!(zondex_icp_format(ICPTs::from_e8s(1000)), *"0.00001");
    assert_eq!(zondex_icp_format(ICPTs::from_e8s(10000)), *"0.0001");
    assert_eq!(zondex_icp_format(ICPTs::from_e8s(100000)), *"0.001");
    assert_eq!(zondex_icp_format(ICPTs::from_e8s(1000000)), *"0.01");

    // Starting from 10^7 e8s, we need to add at least one "useless" zero
    assert_eq!(zondex_icp_format(ICPTs::from_e8s(10_000_000)), *"0.10");
    assert_eq!(zondex_icp_format(ICPTs::from_e8s(100_000_000)), *"1.00");

    // Full amount of ICPts are wlays formatted with ".00" at the end
    assert_eq!(zondex_icp_format(ICPTs::from_icpts(1).unwrap()), *"1.00");
    assert_eq!(zondex_icp_format(ICPTs::from_icpts(12).unwrap()), *"12.00");
    assert_eq!(
        zondex_icp_format(ICPTs::from_icpts(1234567890).unwrap()),
        *"1,234,567,890.00"
    );

    // Some arbitrary case
    assert_eq!(
        zondex_icp_format(ICPTs::from_e8s(8151012345000)),
        *"81,510.12345"
    );

    // extreme case
    assert_eq!(
        zondex_icp_format(ICPTs::from_e8s(u64::MAX)),
        *"184,467,440,737.09551615"
    );

    // largest power of ten below u64::MAX doms
    assert_eq!(
        zondex_icp_format(ICPTs::from_icpts(100_000_000_000).unwrap()),
        *"100,000,000,000.00"
    );
}

#[allow(dead_code)]
fn main() {
    use rand::{prelude::StdRng, SeedableRng};

    use ledger_canister::Memo;

    let mut rng = StdRng::seed_from_u64(1);

    let mut index = 0;

    for num_trailing_zeros in 0..11 {
        for magnitude in num_trailing_zeros..18 {
            index += 1;
            let multiple_of = 10_u64.pow(num_trailing_zeros);
            // Dividing by, then multiply by, "multiple_of" has the effect of getting the
            // last decimal digits being zero, while keeping the magnitude unchanged.
            let amount = ICPTs::from_e8s(
                ((rng.next_u64() % 10_u64.pow(magnitude)) / multiple_of) * multiple_of,
            );

            // To avoid combinatorial explosion of test cases, we use the same parameters to
            // generate the fee.
            let fee = ICPTs::from_e8s(
                ((rng.next_u64() % 10_u64.pow(magnitude)) / multiple_of) * multiple_of,
            );

            let send_args = SendArgs {
                memo: Memo(0),
                amount,
                fee,
                from_subaccount: None,
                to: PrincipalId::new_anonymous().into(),
                created_at_time: None,
            };

            let keypair = EdKeypair::generate(&mut rng);

            let s = generate_zondax_test(index, keypair, send_args);
            println!("{}", s);
        }
    }
}
