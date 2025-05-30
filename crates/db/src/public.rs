//! Public database interface for the Strata Bridge.

use async_trait::async_trait;
use bitcoin::{OutPoint, Txid};
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::{constants::NUM_ASSERT_DATA_TX, types::OperatorIdx, wots};
use strata_bridge_stake_chain::transactions::stake::StakeTxData;

use crate::errors::DbResult;

/// Interface to expose data that should be publicly available.
///
/// This includes the WOTS public keys and signatures, as well as the Schnorr signatures for the
/// operator's transactions. The interface also includes setters to allow the operator to update the
/// database.
#[async_trait]
pub trait PublicDb {
    /// Returns the WOTS public keys for a given operator and deposit transaction ID.
    async fn get_wots_public_keys(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
    ) -> DbResult<Option<wots::PublicKeys>>;

    /// Sets the WOTS public keys for a given operator and deposit transaction ID.
    async fn set_wots_public_keys(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        public_keys: &wots::PublicKeys,
    ) -> DbResult<()>;

    /// Returns the WOTS signatures for a given operator and deposit transaction ID.
    async fn get_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
    ) -> DbResult<Option<wots::Signatures>>;

    /// Sets the WOTS signatures for a given operator and deposit transaction ID.
    async fn set_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: &wots::Signatures,
    ) -> DbResult<()>;

    /// Returns the Schnorr signature for a given operator, transaction ID, and input index.
    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<Signature>>;

    /// Sets the Schnorr signature for a given operator, transaction ID, and input index.
    async fn set_signature(
        &self,
        operator_id: u32,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) -> DbResult<()>;

    /// Adds a deposit transaction ID.
    async fn add_deposit_txid(&self, deposit_txid: Txid) -> DbResult<()>;

    /// Returns the deposit ID for a given deposit transaction ID.
    async fn get_deposit_id(&self, deposit_txid: Txid) -> DbResult<Option<u32>>;

    /// Adds a stake transaction ID.
    async fn add_stake_txid(&self, operator_id: OperatorIdx, stake_txid: Txid) -> DbResult<()>;

    /// Returns the stake transaction ID for a given operator and stake ID.
    async fn get_stake_txid(
        &self,
        operator_id: OperatorIdx,
        stake_id: u32,
    ) -> DbResult<Option<Txid>>;

    /// Returns all stake data for a given operator.
    async fn get_all_stake_data(&self, operator_id: OperatorIdx) -> DbResult<Vec<StakeTxData>>;

    /// Sets the pre-stake for a given operator.
    async fn set_pre_stake(&self, operator_id: OperatorIdx, pre_stake: OutPoint) -> DbResult<()>;

    /// Returns the pre-stake for a given operator.
    async fn get_pre_stake(&self, operator_id: OperatorIdx) -> DbResult<Option<OutPoint>>;

    /// Adds stake data for a given operator and stake index.
    async fn add_stake_data(
        &self,
        operator_id: OperatorIdx,
        stake_index: u32,
        stake_data: StakeTxData,
    ) -> DbResult<()>;

    /// Returns the stake data for a given operator and stake index.
    async fn get_stake_data(
        &self,
        operator_id: OperatorIdx,
        stake_id: u32,
    ) -> DbResult<Option<StakeTxData>>;

    /// Registers a claim transaction ID.
    async fn register_claim_txid(
        &self,
        claim_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()>;

    /// Returns the operator and deposit for a given claim transaction ID.
    async fn get_operator_and_deposit_for_claim(
        &self,
        claim_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>>;

    /// Registers a post-assert transaction ID.
    async fn register_post_assert_txid(
        &self,
        post_assert_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()>;

    /// Returns the operator and deposit for a given post-assert transaction ID.
    async fn get_operator_and_deposit_for_post_assert(
        &self,
        post_assert_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>>;

    /// Registers assert data transaction IDs.
    async fn register_assert_data_txids(
        &self,
        assert_data_txids: [Txid; NUM_ASSERT_DATA_TX],
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()>;

    /// Returns the operator and deposit for a given assert data transaction ID.
    async fn get_operator_and_deposit_for_assert_data(
        &self,
        assert_data_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>>;

    /// Registers a pre-assert transaction ID.
    async fn register_pre_assert_txid(
        &self,
        pre_assert_data_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()>;

    /// Returns the operator and deposit for a given pre-assert transaction ID.
    async fn get_operator_and_deposit_for_pre_assert(
        &self,
        pre_assert_data_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>>;
}
