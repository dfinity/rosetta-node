use cycles_minting_canister::{
    create_canister_txn, top_up_canister_txn, CreateCanisterResult, TopUpCanisterResult,
};
use dfn_protobuf::ProtoBuf;
use ic_canister_client::{Agent, HttpClient, Sender};
use ic_types::{CanisterId, PrincipalId};
use lazy_static::lazy_static;
use ledger_canister::{
    self, BlockHeight, ICPTs, NotifyCanisterArgs, Subaccount, TransactionNotificationResult,
};
use on_wire::{FromWire, IntoWire, NewType};
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

pub struct CreateCanister<'a> {
    pub client: HttpClient,
    pub ic_url: Url,
    pub ledger_canister_id: &'a CanisterId,
    pub cycles_canister_id: &'a CanisterId,
    pub sender_keypair: &'a ed25519_dalek::Keypair,
    pub sender_subaccount: Option<Subaccount>,
    pub amount: ICPTs,
    pub controller_id: &'a PrincipalId,
}

impl<'a> CreateCanister<'a> {
    pub async fn execute(self) -> CreateCanisterResult {
        let ledger_agent = Agent::new_with_client(
            self.client.clone(),
            self.ic_url.clone(),
            Sender::from_keypair(&self.sender_keypair),
        );

        let (send_args, subaccount) = create_canister_txn(
            self.amount,
            self.sender_subaccount,
            self.cycles_canister_id,
            self.controller_id,
        );

        let bytes = ledger_agent
            .execute_update(
                self.ledger_canister_id,
                "send_pb",
                ProtoBuf(send_args.clone())
                    .into_bytes()
                    .map_err(|err| (err, None))?,
                get_nonce(),
            )
            .await
            .map_err(|err| (err, None))?
            .unwrap();

        let block: BlockHeight = ProtoBuf::from_bytes(bytes)
            .map_err(|err| (err, None))?
            .into_inner();

        let notify_args = NotifyCanisterArgs::new_from_send(
            &send_args,
            block,
            *self.cycles_canister_id,
            Some(subaccount),
        )
        .map_err(|err| (err, None))?;

        let bytes = ledger_agent
            .execute_update(
                self.ledger_canister_id,
                "notify_pb",
                ProtoBuf(notify_args)
                    .into_bytes()
                    .map_err(|err| (err, None))?,
                get_nonce(),
            )
            .await
            .map_err(|err| (err, None))?
            .unwrap();

        let result: TransactionNotificationResult = ProtoBuf::from_bytes(bytes)
            .map_err(|err| (err, None))?
            .into_inner();

        result
            .decode::<CreateCanisterResult>()
            .map_err(|err| (err, None))?
    }
}

pub struct TopUpCanister<'a> {
    pub client: HttpClient,
    pub ic_url: Url,
    pub ledger_canister_id: &'a CanisterId,
    pub cycles_canister_id: &'a CanisterId,
    pub sender_keypair: &'a ed25519_dalek::Keypair,
    pub sender_subaccount: Option<Subaccount>,
    pub amount: ICPTs,
    pub target_canister_id: &'a CanisterId,
}

impl<'a> TopUpCanister<'a> {
    pub async fn execute(self) -> TopUpCanisterResult {
        let agent = Agent::new_with_client(
            self.client,
            self.ic_url,
            Sender::from_keypair(&self.sender_keypair),
        );

        let (send_args, subaccount) = top_up_canister_txn(
            self.amount,
            self.sender_subaccount,
            self.cycles_canister_id,
            self.target_canister_id,
        );

        let bytes = agent
            .execute_update(
                self.ledger_canister_id,
                "send_pb",
                ProtoBuf(send_args.clone())
                    .into_bytes()
                    .map_err(|err| (err, None))?,
                get_nonce(),
            )
            .await
            .map_err(|err| (err, None))?
            .unwrap();

        let block_idx: BlockHeight = ProtoBuf::from_bytes(bytes)
            .map_err(|err| (err, None))?
            .into_inner();

        let notify_args = NotifyCanisterArgs::new_from_send(
            &send_args,
            block_idx,
            *self.cycles_canister_id,
            Some(subaccount),
        )
        .map_err(|err| (err, None))?;

        let bytes = agent
            .execute_update(
                self.ledger_canister_id,
                "notify_pb",
                ProtoBuf(notify_args)
                    .into_bytes()
                    .map_err(|err| (err, None))?,
                get_nonce(),
            )
            .await
            .map_err(|err| (err, None))?
            .unwrap();

        let result: TransactionNotificationResult = ProtoBuf::from_bytes(bytes)
            .map_err(|err| (err, None))?
            .into_inner();

        result
            .decode::<TopUpCanisterResult>()
            .map_err(|err| (err, None))?
    }
}

lazy_static! {
    static ref NONCE: AtomicU64 = AtomicU64::new(0);
}

fn get_nonce() -> Vec<u8> {
    NONCE.fetch_add(1, Ordering::Relaxed).to_be_bytes().to_vec()
}
