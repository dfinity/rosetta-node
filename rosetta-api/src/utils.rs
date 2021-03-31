use ic_types::PrincipalId;
use ledger_canister::AccountIdentifier;
use std::convert::TryFrom;
use std::str::FromStr;
use structopt::StructOpt;

/// Some utils for tasks we have to do a lot

fn main() {
    let opt = Opt::from_args();
    for s in opt.convert.into_iter() {
        let bytes: Vec<u8> = hex::decode(s.clone()).unwrap();
        if let Ok(pid) = PrincipalId::from_str(&s).or_else(|_| PrincipalId::try_from(&bytes)) {
            let aid: AccountIdentifier = pid.into();
            println!("{} → {}", s, aid)
        }
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short = "c", long = "convert_address")]
    convert: Vec<String>,
}
