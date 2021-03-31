use crate::protobuf;
use crate::protobuf::transaction::Transfer as PTransfer;
use crate::{
    AccountBalanceArgs, AccountIdentifier, Block, BlockArg, BlockHeight, BlockRes, EncodedBlock,
    GetBlocksArgs, GetBlocksRes, HashOf, ICPTs, Memo, SendArgs, Subaccount, Timestamp,
    TipOfChainRes, TotalSupplyArgs, Transaction, Transfer, HASH_LENGTH, TRANSACTION_FEE,
};
use dfn_protobuf::ToProto;
use std::{
    convert::{TryFrom, TryInto},
    time::Duration,
};

/// The point of this file is to validate protobufs as they're received and turn
/// them into a validated data type
/// ENDPOINTS
impl ToProto for TotalSupplyArgs {
    type Proto = protobuf::TotalSupplyRequest;
    fn from_proto(_: Self::Proto) -> Result<Self, String> {
        Ok(TotalSupplyArgs {})
    }

    fn to_proto(self) -> protobuf::TotalSupplyRequest {
        protobuf::TotalSupplyRequest {}
    }
}

/// Res
impl ToProto for ICPTs {
    type Proto = protobuf::IcpTs;
    fn from_proto(sel: Self::Proto) -> Result<Self, String> {
        Ok(ICPTs::from_doms(sel.doms))
    }

    fn to_proto(self) -> Self::Proto {
        protobuf::IcpTs {
            doms: self.get_doms(),
        }
    }
}

impl ToProto for AccountBalanceArgs {
    type Proto = protobuf::AccountBalanceRequest;
    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        pb.account
            .ok_or_else(|| "Recieved an account balance request with no account".to_string())
            .and_then(AccountIdentifier::from_proto)
            .map(AccountBalanceArgs::new)
    }

    fn to_proto(self) -> Self::Proto {
        protobuf::AccountBalanceRequest {
            account: Some(self.account.to_proto()),
        }
    }
}

impl ToProto for TipOfChainRes {
    type Proto = protobuf::TipOfChainResponse;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let chain_length = pb
            .chain_length
            .ok_or("Didn't recieve a chain length")?
            .height;
        Ok(TipOfChainRes {
            certification: pb.certification.map(|pb| pb.certification),
            tip_index: chain_length,
        })
    }

    fn to_proto(self) -> Self::Proto {
        protobuf::TipOfChainResponse {
            certification: self
                .certification
                .map(|certification| protobuf::Certification { certification }),
            chain_length: Some(protobuf::BlockHeight {
                height: self.tip_index,
            }),
        }
    }
}

impl ToProto for GetBlocksArgs {
    type Proto = protobuf::GetBlocksRequest;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let start = pb
            .start
            .try_into()
            .map_err(|_| format!("{} count not be convered to a usize", pb.start))?;
        let length = pb
            .length
            .try_into()
            .map_err(|_| format!("{} count not be convered to a usize", pb.length))?;
        Ok(GetBlocksArgs { start, length })
    }

    fn to_proto(self) -> Self::Proto {
        protobuf::GetBlocksRequest {
            start: self.start as u64,
            length: self.length as u64,
        }
    }
}

impl ToProto for GetBlocksRes {
    type Proto = protobuf::GetBlocksResponse;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let blocks: Vec<EncodedBlock> = pb
            .blocks
            .into_iter()
            .map(|b| EncodedBlock(b.into_boxed_slice()))
            .collect();
        Ok(GetBlocksRes(blocks))
    }

    fn to_proto(self) -> Self::Proto {
        let blocks = self.0.into_iter().map(|b| b.0.into_vec()).collect();
        protobuf::GetBlocksResponse { blocks }
    }
}

impl ToProto for BlockArg {
    type Proto = protobuf::GetBlocksRequest;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        Ok(BlockArg(pb.start))
    }

    fn to_proto(self) -> Self::Proto {
        protobuf::GetBlocksRequest {
            start: self.0,
            length: 1,
        }
    }
}

impl ToProto for BlockRes {
    type Proto = protobuf::GetBlocksResponse;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let blocks: Option<EncodedBlock> = pb
            .blocks
            .into_iter()
            .map(|b| EncodedBlock(b.into_boxed_slice()))
            .next();
        Ok(BlockRes(blocks))
    }

    fn to_proto(self) -> Self::Proto {
        let blocks = self.0.into_iter().map(|b| b.0.into_vec()).collect();
        protobuf::GetBlocksResponse { blocks }
    }
}
impl ToProto for SendArgs {
    type Proto = protobuf::SendRequest;

    fn from_proto(
        protobuf::SendRequest {
            memo,
            payment,
            max_fee,
            from_subaccount,
            to,
            created_at,
        }: Self::Proto,
    ) -> Result<Self, String> {
        let memo = match memo {
            Some(m) => Memo(m.memo),
            None => Memo(0),
        };
        let amount = payment
            .and_then(|p| p.receiver_gets)
            .ok_or("Payment is missing or incomplete")?;
        let fee = match max_fee {
            Some(f) => ICPTs::from_proto(f)?,
            None => TRANSACTION_FEE,
        };
        let from_subaccount = match from_subaccount {
            Some(sa) => Some(Subaccount::from_proto(sa)?),
            None => None,
        };
        let to = AccountIdentifier::from_proto(
            to.ok_or("The send endpoint requires a field _to to be filled")?,
        )?;
        Ok(SendArgs {
            memo,
            amount: ICPTs::from_proto(amount)?,
            fee,
            from_subaccount,
            to,
            block_height: created_at.map(|height| height.height),
        })
    }
    fn to_proto(self) -> Self::Proto {
        let SendArgs {
            memo,
            amount,
            fee,
            from_subaccount,
            to,
            block_height,
        } = self;
        let amount = amount.to_proto();
        let payment = Some(protobuf::Payment {
            receiver_gets: Some(amount),
        });
        protobuf::SendRequest {
            memo: Some(protobuf::Memo { memo: memo.0 }),
            payment,
            max_fee: Some(fee.to_proto()),
            from_subaccount: from_subaccount.map(|sa| sa.to_proto()),
            to: Some(to.to_proto()),
            created_at: block_height.map(|height| protobuf::BlockHeight { height }),
        }
    }
}

/// TYPES
impl ToProto for Subaccount {
    type Proto = protobuf::Subaccount;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        Subaccount::try_from(&pb.sub_account[..]).map_err(|e| e.to_string())
    }

    fn to_proto(self) -> Self::Proto {
        protobuf::Subaccount {
            sub_account: self.to_vec(),
        }
    }
}

impl ToProto for AccountIdentifier {
    type Proto = protobuf::AccountIdentifier;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        AccountIdentifier::from_slice(&pb.hash[..])
    }

    fn to_proto(self) -> Self::Proto {
        protobuf::AccountIdentifier {
            hash: self.to_vec(),
        }
    }
}

impl ToProto for Block {
    type Proto = protobuf::Block;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let parent_hash = match pb.parent_hash {
            Some(h) => Some(HashOf::from_proto(h)?),
            None => None,
        };

        let transaction = pb.transaction.ok_or("This block lacks a transaction")?;

        let timestamp = pb.timestamp.ok_or("This block lacks a timestamp")?;

        Ok(Block {
            parent_hash,
            transaction: Transaction::from_proto(transaction)?,
            timestamp: Timestamp::from_proto(timestamp)?,
        })
    }

    fn to_proto(self) -> Self::Proto {
        protobuf::Block {
            parent_hash: self.parent_hash.map(|h| h.to_proto()),
            transaction: Some(self.transaction.to_proto()),
            timestamp: Some(self.timestamp.to_proto()),
        }
    }
}

impl ToProto for Transaction {
    type Proto = protobuf::Transaction;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let memo: Memo = match pb.memo {
            Some(m) => Memo(m.memo),
            None => Memo(0),
        };
        let created_at: BlockHeight = pb.created_at.ok_or("Blockheight not found")?.height;
        let transfer = match pb.transfer.ok_or("This block has no transaction")? {
            PTransfer::Burn(protobuf::Burn {
                from: Some(from),
                amount: Some(amount),
            }) => Transfer::Burn {
                from: AccountIdentifier::from_proto(from)?,
                amount: ICPTs::from_proto(amount)?,
            },
            PTransfer::Mint(protobuf::Mint {
                to: Some(to),
                amount: Some(amount),
            }) => Transfer::Mint {
                to: AccountIdentifier::from_proto(to)?,
                amount: ICPTs::from_proto(amount)?,
            },
            PTransfer::Send(protobuf::Send {
                to: Some(to),
                from: Some(from),
                amount: Some(amount),
                max_fee,
            }) => Transfer::Send {
                to: AccountIdentifier::from_proto(to)?,
                from: AccountIdentifier::from_proto(from)?,
                amount: ICPTs::from_proto(amount)?,
                fee: match max_fee {
                    Some(fee) => ICPTs::from_proto(fee)?,
                    None => TRANSACTION_FEE,
                },
            },
            t => return Err(format!("Transaction lacked a required field: {:?}", t)),
        };
        Ok(Transaction {
            memo,
            created_at,
            transfer,
        })
    }

    fn to_proto(self) -> Self::Proto {
        let Transaction {
            memo,
            created_at,
            transfer,
        } = self;
        let transfer = match transfer {
            Transfer::Burn { from, amount } => PTransfer::Burn(protobuf::Burn {
                from: Some(from.to_proto()),
                amount: Some(amount.to_proto()),
            }),

            Transfer::Mint { to, amount } => PTransfer::Mint(protobuf::Mint {
                to: Some(to.to_proto()),
                amount: Some(amount.to_proto()),
            }),

            Transfer::Send {
                to,
                amount,
                from,
                fee,
            } => PTransfer::Send(protobuf::Send {
                to: Some(to.to_proto()),
                amount: Some(amount.to_proto()),
                from: Some(from.to_proto()),
                max_fee: Some(fee.to_proto()),
            }),
        };
        protobuf::Transaction {
            memo: Some(protobuf::Memo { memo: memo.0 }),
            created_at: Some(protobuf::BlockHeight { height: created_at }),
            transfer: Some(transfer),
        }
    }
}

impl<T> ToProto for HashOf<T> {
    type Proto = protobuf::Hash;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let boxed_slice = pb.hash.into_boxed_slice();
        let hash: Box<[u8; 32]> = match boxed_slice.clone().try_into() {
            Ok(s) => s,
            Err(_) => {
                return Err(format!(
                    "Expected a Vec of length {} but it was {}",
                    HASH_LENGTH,
                    boxed_slice.len(),
                ))
            }
        };
        Ok(HashOf::new(*hash))
    }

    fn to_proto(self) -> Self::Proto {
        protobuf::Hash {
            hash: self.into_bytes().to_vec(),
        }
    }
}

impl ToProto for Timestamp {
    type Proto = protobuf::TimeStamp;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let d = Duration::from_nanos(pb.timestamp_nanos);
        Ok(Self::new(d.as_secs(), d.subsec_nanos()))
    }

    fn to_proto(self) -> Self::Proto {
        let timestamp_nanos = self.secs * 1_000_000_000 + self.nanos as u64;
        protobuf::TimeStamp { timestamp_nanos }
    }
}
