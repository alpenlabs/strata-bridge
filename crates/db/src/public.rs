use async_trait::async_trait;
use bitcoin::Txid;
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::{scripts::wots, types::OperatorIdx};

#[async_trait]
pub trait PublicDb {
    async fn get_wots_public_keys(&self, operator_id: u32, deposit_txid: Txid) -> wots::PublicKeys;

    async fn set_wots_public_keys(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        public_keys: &wots::PublicKeys,
    );

    async fn get_wots_signatures(&self, operator_id: u32, deposit_txid: Txid) -> wots::Signatures;

    async fn set_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: &wots::Signatures,
    );

    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> Signature;

    async fn set_signature(
        &self,
        operator_id: u32,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    );

    async fn register_claim_txid(
        &self,
        claim_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    );

    async fn get_operator_and_deposit_for_claim(
        &self,
        claim_txid: &Txid,
    ) -> Option<(OperatorIdx, Txid)>;

    async fn register_post_assert_txid(
        &self,
        post_assert_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    );

    async fn get_operator_and_deposit_for_post_assert(
        &self,
        post_assert_txid: &Txid,
    ) -> Option<(OperatorIdx, Txid)>;

    async fn register_assert_data_txids(
        &self,
        assert_data_txids: [Txid; 7],
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    );

    async fn get_operator_and_deposit_for_assert_data(
        &self,
        assert_data_txid: &Txid,
    ) -> Option<(OperatorIdx, Txid)>;

    async fn register_pre_assert_txid(
        &self,
        pre_assert_data_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    );

    async fn get_operator_and_deposit_for_pre_assert(
        &self,
        pre_assert_data_txid: &Txid,
    ) -> Option<(OperatorIdx, Txid)>;
}
