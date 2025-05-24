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
    /// Gets, if present, a bundle of Winternitz One-time Signature (WOTS) public keys from the
    /// database, given an [`OperatorIdx`] and a `deposit_txid`.
    async fn get_wots_public_keys(
        &self,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<Option<wots::PublicKeys>>;

    /// Sets a bundle of Winternitz One-time Signature (WOTS) public keys from the database, given
    /// an [`OperatorIdx`] and a `deposit_txid`.
    async fn set_wots_public_keys(
        &self,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
        public_keys: &wots::PublicKeys,
    ) -> DbResult<()>;

    /// Gets, if present, a bundle Winternitz One-time Signature (WOTS) signatures from the
    /// database, given an [`OperatorIdx`] and a `deposit_txid`.
    async fn get_wots_signatures(
        &self,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<Option<wots::Signatures>>;

    /// Sets a bundle Winternitz One-time Signature (WOTS) signatures from the database, given an
    /// [`OperatorIdx`] and a `deposit_txid`.
    async fn set_wots_signatures(
        &self,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
        signatures: &wots::Signatures,
    ) -> DbResult<()>;

    /// Gets, if present, a Schnorr [`Signature`] from the database, given an [`OperatorIdx`], a
    /// [`Txid`] and an `input_index`.
    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<Signature>>;

    /// Sets a Schnorr [`Signature`] from the database, given an [`OperatorIdx`], a [`Txid`] and an
    /// `input_index`.
    async fn set_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) -> DbResult<()>;

    /// Adds a `deposit_txid` to the database, associating it with a new unique deposit ID.
    async fn add_deposit_txid(&self, deposit_txid: Txid) -> DbResult<()>;

    /// Gets the unique ID associated with a `deposit_txid`.
    async fn get_deposit_id(&self, deposit_txid: Txid) -> DbResult<Option<u32>>;

    /// Adds a `stake_txid` for a given [`OperatorIdx`] to the database, associating it with a new
    /// unique stake ID for that operator.
    async fn add_stake_txid(&self, operator_idx: OperatorIdx, stake_txid: Txid) -> DbResult<()>;

    /// Gets, if present, the `stake_txid` associated with an `operator_idx` and a `stake_id`.
    async fn get_stake_txid(
        &self,
        operator_idx: OperatorIdx,
        stake_id: u32,
    ) -> DbResult<Option<Txid>>;

    /// Gets all [`StakeTxData`] for a given [`OperatorIdx`].
    async fn get_all_stake_data(&self, operator_idx: OperatorIdx) -> DbResult<Vec<StakeTxData>>;

    /// Sets the pre-stake [`OutPoint`] for a given [`OperatorIdx`]. This is typically the output
    /// point of the transaction that will be used as an input to the first stake transaction.
    async fn set_pre_stake(&self, operator_idx: OperatorIdx, pre_stake: OutPoint) -> DbResult<()>;

    /// Gets, if present, the pre-stake [`OutPoint`] for a given [`OperatorIdx`].
    async fn get_pre_stake(&self, operator_idx: OperatorIdx) -> DbResult<Option<OutPoint>>;

    /// Adds [`StakeTxData`] for a given [`OperatorIdx`] and `stake_index`.
    async fn add_stake_data(
        &self,
        operator_idx: OperatorIdx,
        stake_index: u32,
        stake_data: StakeTxData,
    ) -> DbResult<()>;

    /// Gets, if present, the [`StakeTxData`] for a given [`OperatorIdx`] and `stake_id`.
    async fn get_stake_data(
        &self,
        operator_idx: OperatorIdx,
        stake_id: u32,
    ) -> DbResult<Option<StakeTxData>>;

    /// Registers a `claim_txid` in the database, associating it with an [`OperatorIdx`] and a
    /// `deposit_txid`.
    async fn register_claim_txid(
        &self,
        claim_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()>;

    /// Gets, if present, the [`OperatorIdx`] and `deposit_txid` associated with a `claim_txid`.
    async fn get_operator_and_deposit_for_claim(
        &self,
        claim_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>>;

    /// Registers a `post_assert_txid` in the database, associating it with an [`OperatorIdx`]
    /// and a `deposit_txid`.
    async fn register_post_assert_txid(
        &self,
        post_assert_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()>;

    /// Gets, if present, the [`OperatorIdx`] and `deposit_txid` associated with a
    /// `post_assert_txid`.
    async fn get_operator_and_deposit_for_post_assert(
        &self,
        post_assert_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>>;

    /// Registers an array of `assert_data_txids` in the database, associating them with an
    /// [`OperatorIdx`] and a `deposit_txid`.
    async fn register_assert_data_txids(
        &self,
        assert_data_txids: [Txid; NUM_ASSERT_DATA_TX],
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()>;

    /// Gets, if present, the [`OperatorIdx`] and `deposit_txid` associated with an
    /// `assert_data_txid`.
    async fn get_operator_and_deposit_for_assert_data(
        &self,
        assert_data_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>>;

    /// Registers a `pre_assert_data_txid` in the database, associating it with an [`OperatorIdx`]
    /// and a `deposit_txid`.
    async fn register_pre_assert_txid(
        &self,
        pre_assert_data_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()>;

    /// Gets, if present, the [`OperatorIdx`] and `deposit_txid` associated with a
    /// `pre_assert_data_txid`.
    async fn get_operator_and_deposit_for_pre_assert(
        &self,
        pre_assert_data_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>>;
}
