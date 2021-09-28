use ic_types::{CanisterId, PrincipalId};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "principal_neuron",
    about = "Compute ledger account of a neuron"
)]
struct Opts {
    /// Principal ID of the controller.
    #[structopt(long)]
    principal: String,

    #[structopt(long), default="0"]
    memo: u64,
}

pub fn neuron_subaccount(
    controller: PrincipalId,
    neuron_identifier: u64,
) -> Result<[u8; 32], ApiError> {
    let mut state = ic_crypto_sha::Sha256::new();
    state.write(&[0x0c]);
    state.write(b"neuron-stake");
    state.write(&controller.as_slice());
    state.write(&neuron_identifier.to_be_bytes());
    Ok(state.finish())
}

fn main() {
    let opts =
        Opts::from_iter_safe(std::env::args()).expect("failed to parse command line options");
    let principal_id = PrincipalId::try_from(&opts.principal).expect("failed to parse principal");
    let subaccount = neuron_subaccount(principal_id, opts.memo);
    let aid = ledger::AccountIdentifier::new(CanisterId::from_u64(1).get(), Some(subaccount));
    println!("{}", aid);
}
