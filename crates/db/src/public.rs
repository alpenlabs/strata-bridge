use async_trait::async_trait;
use bitcoin::Txid;
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::{scripts::wots, types::OperatorIdx};

use crate::errors::DbResult;

#[async_trait]
pub trait PublicDb {
    async fn get_wots_public_keys(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
    ) -> DbResult<wots::PublicKeys>;

    async fn set_wots_public_keys(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        public_keys: &wots::PublicKeys,
    ) -> DbResult<()>;

    async fn get_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
    ) -> DbResult<wots::Signatures>;

    async fn set_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: &wots::Signatures,
    ) -> DbResult<()>;

    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Signature>;

    async fn set_signature(
        &self,
        operator_id: u32,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) -> DbResult<()>;

    async fn register_claim_txid(
        &self,
        claim_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()>;

    async fn get_operator_and_deposit_for_claim(
        &self,
        claim_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>>;

    async fn register_post_assert_txid(
        &self,
        post_assert_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()>;

    async fn get_operator_and_deposit_for_post_assert(
        &self,
        post_assert_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>>;

    async fn register_assert_data_txids(
        &self,
        assert_data_txids: [Txid; 7],
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()>;

    async fn get_operator_and_deposit_for_assert_data(
        &self,
        assert_data_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>>;

    async fn register_pre_assert_txid(
        &self,
        pre_assert_data_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()>;

    async fn get_operator_and_deposit_for_pre_assert(
        &self,
        pre_assert_data_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>>;
}
