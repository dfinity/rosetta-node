use ic_rosetta_api::{convert, models};
use ic_types::PrincipalId;
use std::str::FromStr;
use structopt::StructOpt;

/// Some utils for tasks we have to do a lot

fn main() {
    let opt = Opt::from_args();
    for s in opt.convert.into_iter() {
        match PrincipalId::from_str(&s) {
            Ok(pi) => {
                let add = convert::account_identifier(&pi);
                println!("{} → {}", pi, add.address);
            }
            Err(_) => {
                if let Ok(pi) = convert::principal_id(&models::AccountIdentifier::new(s.clone())) {
                    println!("{} → {}", s, pi);
                }
            }
        }
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(long = "convert_address")]
    convert: Vec<String>,
}
