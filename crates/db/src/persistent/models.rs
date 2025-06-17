//! This module contains the models for the database tables.
//!
//! These models rely on some common types in [`super::types`] module.

use std::ops::Deref;

use bitcoin::OutPoint;
use sqlx::{self};
use strata_bridge_stake_chain::transactions::stake::StakeTxData;

use super::types::{
    DbAggNonce, DbAmount, DbHash, DbInputIndex, DbOperatorIdx, DbPartialSig, DbPubNonce,
    DbScriptBuf, DbSecNonce, DbSignature, DbTaprootWitness, DbTxid, DbWots256PublicKey,
    DbWotsPublicKeys, DbWotsSignatures,
};

/// The model for WOTS public keys stored in the database.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct WotsPublicKey {
    /// The ID of the operator stored as `INTEGER`.
    #[expect(dead_code)]
    pub(super) operator_idx: DbOperatorIdx,

    /// The hex-serialized deposit txid stored as `TEXT`.
    #[expect(dead_code)]
    pub(super) deposit_txid: DbTxid,

    /// The WOTS public keys that is rkyv-serialized.
    pub(super) public_keys: DbWotsPublicKeys,
}

/// The model for the WOTS signatures stored in the database.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct WotsSignature {
    /// The ID of the operator stored as `INTEGER`.
    #[expect(dead_code)]
    pub(super) operator_idx: DbOperatorIdx,

    /// The hex-serialized deposit txid stored as `TEXT`.
    #[expect(dead_code)]
    pub(super) deposit_txid: DbTxid,

    /// The WOTS signatures that is rkyv-serialized.
    pub(super) signatures: DbWotsSignatures,
}

/// The model for Schnorr signature.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct Signature {
    /// The ID of the operator stored as `INTEGER`.
    #[expect(dead_code)]
    pub(super) operator_idx: DbOperatorIdx,

    // The hex-serialized transaction ID.
    #[expect(dead_code)]
    pub(super) txid: DbTxid,

    /// The index of the input in the bitcoin transaction.
    #[expect(dead_code)]
    pub(super) input_index: i64,

    /// The hex-serialized signature.
    pub(super) signature: DbSignature,
}

/// The model for tracking the stake information.
pub(super) struct DbStakeTxData {
    /// The txid of the transaction used to fund the dust outputs.
    pub(super) funding_txid: DbTxid,

    /// THe vout of the outpoint of the transaction used to fund the dust outputs.
    pub(super) funding_vout: DbInputIndex,

    /// The hash used in the hashlock for the stake transaction.
    pub(super) hash: DbHash,

    /// The WOTS public key used to commit to the withdrawal fulfillment transaction.
    pub(super) withdrawal_fulfillment_pk: DbWots256PublicKey,
}

impl From<StakeTxData> for DbStakeTxData {
    fn from(stake_tx_data: StakeTxData) -> Self {
        Self {
            funding_txid: stake_tx_data.operator_funds.txid.into(),
            funding_vout: stake_tx_data.operator_funds.vout.into(),
            hash: stake_tx_data.hash.into(),
            withdrawal_fulfillment_pk: stake_tx_data.withdrawal_fulfillment_pk.into(),
        }
    }
}

impl From<DbStakeTxData> for StakeTxData {
    fn from(db_stake_tx_data: DbStakeTxData) -> Self {
        StakeTxData {
            operator_funds: OutPoint {
                txid: *db_stake_tx_data.funding_txid,
                vout: *db_stake_tx_data.funding_vout,
            },
            hash: *db_stake_tx_data.hash,
            withdrawal_fulfillment_pk: db_stake_tx_data.withdrawal_fulfillment_pk.deref().clone(),
        }
    }
}

/// The model to map claims to operators and deposit.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct ClaimToOperatorAndDeposit {
    /// The hex-serialized claim txid.
    #[expect(dead_code)]
    pub(super) claim_txid: DbTxid,

    /// The hex-serialized deposit txid.
    pub(super) deposit_txid: DbTxid,

    /// The ID of the operator stored as `INTEGER`.
    pub(super) operator_idx: DbOperatorIdx,
}

/// The model to map post-assert txid to operators and deposit.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct PostAssertToOperatorAndDeposit {
    /// The hex-serialized post-assert txid.
    #[expect(dead_code)]
    pub(super) post_assert_txid: DbTxid,

    /// The hex-serialized deposit txid.
    pub(super) deposit_txid: DbTxid,

    /// The ID of the operator stored as `INTEGER`.
    pub(super) operator_idx: DbOperatorIdx,
}

/// The model to map assert-data txids to operators and deposit.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct AssertDataToOperatorAndDeposit {
    /// The hex-serialized assert-data txid.
    #[expect(dead_code)]
    pub(super) assert_data_txid: DbTxid,

    /// The hex-serialized deposit txid.
    pub(super) deposit_txid: DbTxid,

    /// The ID of the operator stored as `INTEGER`.
    pub(super) operator_idx: DbOperatorIdx,
}

/// The model to map pre-assert txids to operators and deposit.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct PreAssertToOperatorAndDeposit {
    /// The hex-serialized assert-data txid.
    #[expect(dead_code)]
    pub(super) pre_assert_txid: DbTxid,

    /// The hex-serialized deposit txid.
    pub(super) deposit_txid: DbTxid,

    /// The ID of the operator stored as `INTEGER`.
    pub(super) operator_idx: DbOperatorIdx,
}

/// The model to map pubnonces to operators and deposit.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct PubNonces {
    /// The ID of the operator stored as `INTEGER`.
    #[expect(dead_code)]
    pub(super) operator_idx: DbOperatorIdx,

    /// The hex-serialized txid.
    #[expect(dead_code)]
    pub(super) txid: DbTxid,

    /// The index of the input in the bitcoin transaction.
    #[expect(dead_code)]
    pub(super) input_index: DbInputIndex,

    /// The hex-serialized pubnonce.
    pub(super) pubnonce: DbPubNonce,
}

/// The model to map aggregated nonces (without operator_id).
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct AggregatedNonces {
    /// The hex-serialized txid.
    #[expect(dead_code)]
    pub(super) txid: DbTxid,

    /// The index of the input in the bitcoin transaction.
    #[expect(dead_code)]
    pub(super) input_index: DbInputIndex,

    /// The hex-serialized aggregated nonce.
    pub(super) agg_nonce: DbAggNonce,
}

/// The model to map secnonces to operators and deposit.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct Secnonces {
    /// The hex-serialized txid.
    #[expect(dead_code)]
    pub(super) txid: DbTxid,

    /// The index of the input in the bitcoin transaction.
    #[expect(dead_code)]
    pub(super) input_index: DbInputIndex,

    /// The hex-serialized secnonce.
    #[expect(dead_code)]
    pub(super) secnonce: DbSecNonce,
}

/// The model to map witnesses to operators.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct Witnesses {
    /// The ID of the operator stored as `INTEGER`.
    #[expect(dead_code)]
    pub(super) operator_idx: DbOperatorIdx,

    /// The hex-serialized txid.
    #[expect(dead_code)]
    pub(super) txid: DbTxid,

    /// The index of the input in the bitcoin transaction.
    #[expect(dead_code)]
    pub(super) input_index: DbInputIndex,

    /// The hex-serialized witness.
    pub(super) witness: DbTaprootWitness,
}

/// The model for joint query of kickoff txid to FundingInfo.
#[derive(Debug, Clone, sqlx::FromRow, PartialEq)]
pub(super) struct CollectedSigsPerMsg {
    /// The hash of the message stored as `BLOB`.
    pub(super) msg_hash: Vec<u8>,

    /// The ID of the operator stored as `INTEGER`.
    pub(super) operator_idx: DbOperatorIdx,

    /// The hex-serialized partial signature.
    pub(super) partial_signature: DbPartialSig,
}

/// The model for joint query of kickoff txid to FundingInfo.
#[derive(Debug, Clone, sqlx::FromRow)]
#[expect(dead_code)]
pub(super) struct JoinedKickoffInfo {
    /// The hex-serialized kickoff txid.
    #[expect(dead_code)]
    pub(super) ki_txid: DbTxid,

    /// The serialized change address in the kickoff transaction.
    pub(super) ki_change_address: String,

    /// The network of the change address in the kickoff transaction.
    pub(super) ki_change_address_network: String,

    /// The amount of the change as `INTEGER` in the kickoff transaction.
    pub(super) ki_change_amount: DbAmount,

    /// The hex-serialized txid of the input to the kickoff.
    pub(super) fi_input_txid: DbTxid,

    /// The index of the input to the kickoff as `INTEGER`.
    pub(super) fi_vout: DbInputIndex,

    /// The amount of the input to the kickoff as `INTEGER`.
    pub(super) fu_value: DbAmount,

    /// The serialized script pubkey of the input to the kickoff.
    pub(super) fu_script_pubkey: DbScriptBuf,
}

/// The model for outpoints.
#[derive(Debug, Clone, sqlx::FromRow)]
#[expect(dead_code)]
pub(super) struct DbOutPoint {
    /// The hex-serialized txid.
    pub(super) txid: DbTxid,

    /// The index of the output in the bitcoin transaction.
    pub(super) vout: DbInputIndex,
}

/// The model for checkpoint index.
#[derive(Debug, Clone, sqlx::FromRow)]
#[expect(dead_code)]
pub(super) struct CheckPointIdx {
    pub(super) value: u64,
}

/// The model to map partial signatures to operators.
#[derive(Debug, Clone, sqlx::FromRow)]
#[expect(dead_code)]
pub(super) struct PartialSignatures {
    /// The ID of the operator stored as `INTEGER`.
    pub(super) operator_idx: DbOperatorIdx,

    /// The hex-serialized txid.
    #[expect(dead_code)]
    pub(super) txid: DbTxid,

    /// The index of the input in the bitcoin transaction.
    #[expect(dead_code)]
    pub(super) input_index: DbInputIndex,

    /// The hex-serialized partial signature.
    pub(super) partial_signature: DbPartialSig,
}
