use alloy_primitives::{Address, B256, U256};
use ream_consensus_misc::withdrawal::Withdrawal;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{
    FixedVector, VariableList,
    serde_utils::{hex_fixed_vec, hex_var_list, list_of_hex_var_list},
    typenum::{self, U16, U32, U1048576, U1073741824},
};
use tree_hash_derive::TreeHash;

use crate::electra::execution_payload::ExecutionPayload;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalV1 {
    #[serde(with = "serde_utils::u64_hex_be")]
    pub index: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub validator_index: u64,
    pub address: Address,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub amount: u64,
}

impl From<Withdrawal> for WithdrawalV1 {
    fn from(value: Withdrawal) -> Self {
        Self {
            index: value.index,
            validator_index: value.validator_index,
            address: value.address,
            amount: value.amount,
        }
    }
}

impl From<WithdrawalV1> for Withdrawal {
    fn from(value: WithdrawalV1) -> Self {
        Self {
            index: value.index,
            validator_index: value.validator_index,
            address: value.address,
            amount: value.amount,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayloadV3 {
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    #[serde(with = "hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, typenum::U256>,
    pub prev_randao: B256,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub block_number: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub timestamp: u64,
    #[serde(with = "hex_var_list")]
    pub extra_data: VariableList<u8, U32>,
    #[serde(with = "serde_utils::u256_hex_be")]
    pub base_fee_per_gas: U256,

    pub block_hash: B256,
    #[serde(with = "list_of_hex_var_list")]
    pub transactions: VariableList<VariableList<u8, U1073741824>, U1048576>,
    pub withdrawals: VariableList<WithdrawalV1, U16>,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub blob_gas_used: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub excess_blob_gas: u64,
}

impl From<ExecutionPayload> for ExecutionPayloadV3 {
    fn from(value: ExecutionPayload) -> Self {
        ExecutionPayloadV3 {
            parent_hash: value.parent_hash,
            fee_recipient: value.fee_recipient,
            state_root: value.state_root,
            receipts_root: value.receipts_root,
            logs_bloom: value.logs_bloom,
            prev_randao: value.prev_randao,
            block_number: value.block_number,
            gas_limit: value.gas_limit,
            gas_used: value.gas_used,
            timestamp: value.timestamp,
            extra_data: value.extra_data,
            base_fee_per_gas: value.base_fee_per_gas,
            block_hash: value.block_hash,
            transactions: value.transactions,
            withdrawals: VariableList::new(
                value
                    .withdrawals
                    .into_iter()
                    .map(WithdrawalV1::from)
                    .collect(),
            )
            .expect("converting a U16-bounded withdrawal list preserves its length"),
            blob_gas_used: value.blob_gas_used,
            excess_blob_gas: value.excess_blob_gas,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::address;
    use serde_json::json;

    use super::*;

    #[test]
    fn withdrawal_uses_engine_api_hex_quantities() {
        let withdrawal = WithdrawalV1 {
            index: 15,
            validator_index: 16,
            address: address!("0000000000000000000000000000000000000001"),
            amount: 17,
        };

        let encoded = serde_json::to_value(withdrawal).expect("withdrawal should serialize");
        assert_eq!(encoded["index"], json!("0xf"));
        assert_eq!(encoded["validatorIndex"], json!("0x10"));
        assert_eq!(encoded["amount"], json!("0x11"));

        let decoded: WithdrawalV1 =
            serde_json::from_value(encoded).expect("Engine API withdrawal should deserialize");
        assert_eq!(decoded.index, 15);
        assert_eq!(decoded.validator_index, 16);
        assert_eq!(decoded.amount, 17);
    }
}
