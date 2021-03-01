use dfn_candid::{candid, candid_one};
use dfn_core::println;
use dfn_core::{api::id, over, over_may_reject};
use ic_base_types::PrincipalId;
use lazy_static::lazy_static;
use ledger_canister::{ICPTs, Memo, TransactionNotification};
use std::sync::RwLock;

// This is a canister that gets notified
lazy_static! {
    static ref COUNTER: RwLock<u32> = RwLock::new(0);
}

#[export_name = "canister_update transaction_notification"]
fn transaction_notification_() {
    fn transaction_notification(tn: TransactionNotification) -> Result<(), String> {
        let count = *COUNTER.read().unwrap();
        let res = match count {
            0 => {
                println!("Rejecting");
                Err("Rejected".to_string())
            }
            // Succeeds
            1 => Ok(()),
            _ => Err("This should not be called a third time".to_string()),
        };
        let expected_tn = TransactionNotification {
            from_subaccount: None,
            from: PrincipalId::new_anonymous(),
            to_subaccount: None,
            amount: ICPTs::from_icpts(1).unwrap(),
            memo: Memo(0),
            block_height: 3,
            to: id(),
        };

        // Cause the test to fail
        if tn != expected_tn {
            *COUNTER.write().unwrap() = 99;
        }

        *COUNTER.write().unwrap() = count.checked_add(1).unwrap();
        res
    }
    over_may_reject(candid_one, transaction_notification)
}

#[export_name = "canister_query check_counter"]
fn check_counter_() {
    fn check_counter() -> u32 {
        *COUNTER.read().unwrap()
    }
    over(candid, |()| check_counter())
}

fn main() {}
