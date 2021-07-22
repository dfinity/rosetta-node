use super::*;
use ledger_canister::AccountIdentifier;

struct OperationBuilder(Operation);
impl OperationBuilder {
    fn new(idx: i64, typ: impl ToString) -> Self {
        Self(Operation {
            operation_identifier: OperationIdentifier::new(idx),
            _type: typ.to_string(),
            status: None,
            account: None,
            amount: None,
            coin_change: None,
            metadata: None,
            related_operations: None,
        })
    }

    fn account(self, account: AccountIdentifier) -> Self {
        Self(Operation {
            account: Some(to_model_account_identifier(&account)),
            ..self.0
        })
    }

    fn amount(self, amount: i128) -> Self {
        Self(Operation {
            amount: Some(signed_amount(amount)),
            ..self.0
        })
    }

    fn build(self) -> Operation {
        self.0
    }
}

fn test_account(n: u64) -> AccountIdentifier {
    let mut hash = [0u8; 28];
    hash[0..8].copy_from_slice(&n.to_be_bytes());
    AccountIdentifier { hash }
}

#[test]
fn test_transfer_request_to_operations() {
    assert_eq!(
        requests_to_operations(&[Request::Transfer(Transfer::Send {
            from: test_account(1),
            to: test_account(2),
            amount: ICPTs::from_e8s(100),
            fee: ICPTs::from_e8s(10),
        })]),
        Ok(vec![
            OperationBuilder::new(0, "TRANSACTION")
                .account(test_account(1))
                .amount(-100)
                .build(),
            OperationBuilder::new(1, "TRANSACTION")
                .account(test_account(2))
                .amount(100)
                .build(),
            OperationBuilder::new(2, "FEE")
                .account(test_account(1))
                .amount(-10)
                .build(),
        ])
    );
}

#[test]
fn test_transfer_and_stake_requests_to_operations() {
    assert_eq!(
        requests_to_operations(&[
            Request::Transfer(Transfer::Send {
                from: test_account(1),
                to: test_account(2),
                amount: ICPTs::from_e8s(100),
                fee: ICPTs::from_e8s(10),
            }),
            Request::Stake(Stake {
                account: test_account(2)
            })
        ]),
        Ok(vec![
            OperationBuilder::new(0, "TRANSACTION")
                .account(test_account(1))
                .amount(-100)
                .build(),
            OperationBuilder::new(1, "TRANSACTION")
                .account(test_account(2))
                .amount(100)
                .build(),
            OperationBuilder::new(2, "FEE")
                .account(test_account(1))
                .amount(-10)
                .build(),
            OperationBuilder::new(3, "STAKE")
                .account(test_account(2))
                .build(),
        ])
    );
}

#[test]
fn test_can_handle_multiple_transfers() {
    assert_eq!(
        requests_to_operations(&[
            Request::Transfer(Transfer::Send {
                from: test_account(1),
                to: test_account(2),
                amount: ICPTs::from_e8s(100),
                fee: ICPTs::from_e8s(10),
            }),
            Request::Transfer(Transfer::Send {
                from: test_account(3),
                to: test_account(4),
                amount: ICPTs::from_e8s(200),
                fee: ICPTs::from_e8s(20),
            }),
        ]),
        Ok(vec![
            OperationBuilder::new(0, "TRANSACTION")
                .account(test_account(1))
                .amount(-100)
                .build(),
            OperationBuilder::new(1, "TRANSACTION")
                .account(test_account(2))
                .amount(100)
                .build(),
            OperationBuilder::new(2, "FEE")
                .account(test_account(1))
                .amount(-10)
                .build(),
            OperationBuilder::new(3, "TRANSACTION")
                .account(test_account(3))
                .amount(-200)
                .build(),
            OperationBuilder::new(4, "TRANSACTION")
                .account(test_account(4))
                .amount(200)
                .build(),
            OperationBuilder::new(5, "FEE")
                .account(test_account(3))
                .amount(-20)
                .build(),
        ])
    );
}
