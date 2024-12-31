use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use super::types::{
    DbDutyStatus, DbOperatorId, DbSignature, DbTxid, DbWotsPublicKeys, DbWotsSignatures,
};

/// The model for WOTS public keys stored in the database.
#[derive(Debug, Clone, FromRow)]
pub struct WotsPublicKey {
    /// The ID of the operator stored as `INTEGER`.
    pub operator_id: DbOperatorId,

    /// The hex-serialized deposit txid stored as `TEXT`.
    pub deposit_txid: DbTxid,

    /// The WOTS public keys that is rkyv-serialized.
    pub public_keys: DbWotsPublicKeys,
}

/// The model for the WOTS signatures stored in the database.
#[derive(Debug, Clone, FromRow)]
pub struct WotsSignature {
    /// The ID of the operator stored as `INTEGER`.
    pub operator_id: DbOperatorId,

    /// The hex-serialized deposit txid stored as `TEXT`.
    pub deposit_txid: DbTxid,

    /// The WOTS signatures that is rkyv-serialized.
    pub signatures: DbWotsSignatures,
}

/// The model for Schnorr signature.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Signature {
    /// The ID of the oeprator stored as `INTEGER`.
    pub operator_id: DbOperatorId,

    // The hex-serialized transaction ID.
    pub txid: DbTxid,

    /// The index of the input in the bitcoin transaction.
    pub input_index: i64,

    /// The hex-serialized signature.
    pub signature: DbSignature,
}

/// The model for an operator's duty.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OperatorDuty {
    /// The ID of the oeprator stored as `INTEGER`.
    pub operator_id: DbOperatorId,

    /// The ID of the duty stored as `TEXT`.
    pub duty_id: DbTxid,

    /// The status of the duty stored as a JSON string.
    pub status: DbDutyStatus,

    /// The data corresponding to the duty.
    pub data: Vec<u8>,
}

/// The model for tracking duty statuses.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct DutyTracker {
    /// The ID of the duty stored as `TEXT`.
    pub duty_id: DbTxid,

    /// The status of the duty stored as a JSON string.
    pub status: DbDutyStatus,

    /// The timestamp when the status was last updated (in secs) stored as `INTEGER`.
    pub last_updated: i64,
}

/// The model to track bitcoin blocks.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct BitcoinBlock {
    /// The height of the block stored as `INTEGER`.
    pub height: i64,

    /// The hex-serialized block hash.
    pub hash: String,

    /// The bincode-serialized block.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct DepositTransaction {
    pub deposit_txid: DbTxid,
    pub operator_id: DbOperatorId,
    pub status: DbDutyStatus,
    pub data: Vec<u8>,
}
