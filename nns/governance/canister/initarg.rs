use ic_nns_governance::pb::v1::{Governance, NetworkEconomics};
use prost::Message;

fn main() {
    let canister_init = Governance {
        economics: Some(NetworkEconomics::with_default_values()),
        wait_for_quiet_threshold_seconds: 60 * 60 * 24 * 2, // 2 days
        short_voting_period_seconds: 60 * 60 * 12,          // 12 hours
        ..Default::default()
    };
    let mut buf = Vec::new();
    canister_init.encode(&mut buf).unwrap();
    println!("{}", hex::encode(&buf));
}
