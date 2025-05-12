//! Constants used in the executors

/// The vout of the Deposit Transaction that is spent during reimbursement.
///
/// This is used to seed the secret service for wots keys/signatures.
pub(super) const DEPOSIT_VOUT: u32 = 0;

/// The index used to get the 256-bit WOTS public key from the s2 server for committing to the
/// withdrawal fulfillment txid in the Claim transaction.
pub(super) const WITHDRAWAL_FULFILLMENT_PK_IDX: u32 = 0;
