//! This module contains the models for the database tables.
//!
//! These models rely on some common types in [`super::types`] module.

use sqlx::{self};

use super::types::{
    DbAmount, DbDutyStatus, DbInputIndex, DbOperatorId, DbPartialSig, DbPubNonce, DbScriptBuf,
    DbSecNonce, DbSignature, DbTransaction, DbTxid, DbWotsPublicKeys, DbWotsSignatures,
};

/// The model for WOTS public keys stored in the database.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct WotsPublicKey {
    /// The ID of the operator stored as `INTEGER`.
    #[expect(dead_code)]
    pub(super) operator_id: DbOperatorId,

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
    pub(super) operator_id: DbOperatorId,

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
    pub(super) operator_id: DbOperatorId,

    // The hex-serialized transaction ID.
    #[expect(dead_code)]
    pub(super) txid: DbTxid,

    /// The index of the input in the bitcoin transaction.
    #[expect(dead_code)]
    pub(super) input_index: i64,

    /// The hex-serialized signature.
    pub(super) signature: DbSignature,
}

/// The model for tracking duty statuses.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct DutyTracker {
    /// The ID of the duty stored as `TEXT`.
    #[expect(dead_code)]
    pub(super) duty_id: DbTxid,

    /// The status of the duty stored as a JSON string.
    pub(super) status: DbDutyStatus,
}

/// The model to track relevant transactions.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct RelevantTxIndex {
    /// The hex-serialized transaction ID.
    #[expect(dead_code)]
    pub(super) txid: DbTxid,

    /// The hex-serialized block hash.
    pub(super) tx: DbTransaction,
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
    pub(super) operator_id: DbOperatorId,
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
    pub(super) operator_id: DbOperatorId,
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
    pub(super) operator_id: DbOperatorId,
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
    pub(super) operator_id: DbOperatorId,
}

/// The model to map pubnonces to operators and deposit.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct CollectedPubnonces {
    /// The hex-serialized txid.
    #[expect(dead_code)]
    pub(super) txid: DbTxid,

    /// The index of the input in the bitcoin transaction.
    #[expect(dead_code)]
    pub(super) input_index: DbInputIndex,

    /// The ID of the operator stored as `INTEGER`.
    pub(super) operator_id: DbOperatorId,

    /// The hex-serialized pubnonce.
    pub(super) pubnonce: DbPubNonce,
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
    pub(super) secnonce: DbSecNonce,
}

/// The model for joint query of kickoff txid to FundingInfo.
#[derive(Debug, Clone, sqlx::FromRow, PartialEq)]
pub(super) struct CollectedSigsPerMsg {
    /// The hash of the message stored as `BLOB`.
    pub(super) msg_hash: Vec<u8>,

    /// The ID of the operator stored as `INTEGER`.
    pub(super) operator_id: DbOperatorId,

    /// The hex-serialized partial signature.
    pub(super) partial_signature: DbPartialSig,
}

/// The model for joint query of kickoff txid to FundingInfo.
#[derive(Debug, Clone, sqlx::FromRow)]
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
pub(super) struct DbOutPoint {
    /// The hex-serialized txid.
    pub(super) txid: DbTxid,

    /// The index of the output in the bitcoin transaction.
    pub(super) vout: DbInputIndex,
}

/// The model for checkpoint index.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct CheckPointIdx {
    pub(super) value: u64,
}
