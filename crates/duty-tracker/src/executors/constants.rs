//! Constants used in the executors

/// The vout of the Deposit Transaction that is spent during reimbursement.
///
/// This is used to seed the secret service for wots keys/signatures.
pub(super) const DEPOSIT_VOUT: u32 = 0;
