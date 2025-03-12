use bitcoin::{Transaction, Txid};
use serde::{Deserialize, Serialize};

use crate::{
    constants::NUM_ASSERT_DATA_TX, deposit::DepositInfo, types::OperatorIdx,
    withdrawal::WithdrawalInfo,
};

#[derive(Clone, Debug)]
#[expect(clippy::large_enum_variant)]
pub enum VerifierDuty {
    VerifyClaim {
        operator_id: OperatorIdx,
        deposit_txid: Txid,

        claim_tx: Transaction,
    },
    VerifyAssertions {
        operator_id: OperatorIdx,
        deposit_txid: Txid,

        post_assert_tx: Transaction,
        claim_tx: Transaction,
        assert_data_txs: [Transaction; NUM_ASSERT_DATA_TX],
    },
}

/// The various duties that can be assigned to an operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum BridgeDuty {
    /// The duty to create and sign a Deposit Transaction so as to move funds from the user to the
    /// Bridge Address.
    ///
    /// This duty is created when a user deposit request comes in, and applies to all operators.
    SignDeposit(DepositInfo),

    /// The duty to fulfill a withdrawal request that is assigned to a particular operator.
    ///
    /// This kicks off the BitVM2-based withdrawal process involving unilateral withdrawal process.
    FulfillWithdrawal(WithdrawalInfo),
}

impl BridgeDuty {
    pub fn get_id(&self) -> Txid {
        match self {
            BridgeDuty::SignDeposit(deposit_info) => deposit_info.deposit_request_outpoint().txid,
            BridgeDuty::FulfillWithdrawal(withdrawal_info) => {
                withdrawal_info.deposit_outpoint().txid
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDuties {
    pub duties: Vec<BridgeDuty>,

    pub start_index: u64,

    pub stop_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BridgeDutyStatus {
    Deposit(DepositStatus),

    Withdrawal(WithdrawalStatus),
}

impl From<DepositStatus> for BridgeDutyStatus {
    fn from(value: DepositStatus) -> Self {
        Self::Deposit(value)
    }
}

impl From<WithdrawalStatus> for BridgeDutyStatus {
    fn from(value: WithdrawalStatus) -> Self {
        Self::Withdrawal(value)
    }
}

impl BridgeDutyStatus {
    pub fn is_done(&self) -> bool {
        match self {
            BridgeDutyStatus::Deposit(deposit_status) => deposit_status.is_done(),
            BridgeDutyStatus::Withdrawal(withdrawal_status) => withdrawal_status.is_done(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DepositStatus {
    /// The duty has been received.
    ///
    /// This usually entails collecting nonces before the corresponding transaction can be
    /// partially signed.
    Received,

    /// The required nonces are being collected.
    CollectingNonces {
        /// The number of nonces collected so far.
        collected: u32,

        /// The indexes of operators that are yet to provide nonces.
        remaining: Vec<OperatorIdx>,
    },

    /// The required nonces have been collected.
    ///
    /// This state can be inferred from the previous state but might still be useful as the
    /// required number of nonces is context-driven and it cannot be determined whether all
    /// nonces have been collected by looking at the above variant alone.
    CollectedNonces,

    /// The partial signatures are being collected.
    CollectingSignatures {
        /// The number of nonces collected so far.
        collected: u32,

        /// The indexes of operators that are yet to provide partial signatures.
        remaining: Vec<OperatorIdx>,
    },

    /// The required partial signatures have been collected.
    ///
    /// This state can be inferred from the previous state but might still be useful as the
    /// required number of signatures is context-driven and it cannot be determined whether all
    /// partial signatures have been collected by looking at the above variant alone.
    CollectedSignatures,

    /// The duty has been executed.
    ///
    /// This means that the required transaction has been fully signed and broadcasted to Bitcoin.
    Executed,

    /// The duty could not be executed.
    ///
    /// Holds the error message as a [`String`] for context and the number of retries for a
    /// particular duty.
    // TODO: this should hold `strata-bridge-exec::ExecError` instead but that requires
    // implementing `BorshSerialize` and `BorshDeserialize`.
    Failed {
        /// The error message.
        error_msg: String,

        /// The number of times a duty has been retried.
        num_retries: u32,
    },

    /// The duty could not be executed even after repeated tries.
    ///
    /// Holds the error message encountered during the last execution.
    Discarded(String),
}

impl DepositStatus {
    pub fn is_done(&self) -> bool {
        matches!(self, Self::Executed) || matches!(self, Self::Discarded(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    Received,

    PaidUser(Txid),

    Claim {
        withdrawal_fulfillment_txid: Txid,
        claim_txid: Txid,
    },

    PreAssert {
        withdrawal_fulfillment_txid: Txid,
        pre_assert_txid: Txid,
    },

    AssertData {
        withdrawal_fulfillment_txid: Txid,
        assert_data_txids: Vec<Txid>, // dynamic for assert data txs that have been broadcasted
    },

    AssertDataComplete,

    PostAssert,

    Executed,

    Failed {
        /// The error message.
        error_msg: String,

        /// The number of times a duty has been retried.
        num_retries: u32,
    },

    Discarded(String),
}

impl WithdrawalStatus {
    pub fn next(&mut self, txid: Txid) {
        match self {
            Self::Received => *self = Self::PaidUser(txid),
            Self::PaidUser(withdrawal_fulfillment_txid) => {
                *self = Self::Claim {
                    withdrawal_fulfillment_txid: *withdrawal_fulfillment_txid,
                    claim_txid: txid,
                }
            }
            Self::Claim {
                withdrawal_fulfillment_txid,
                claim_txid: _,
            } => {
                *self = Self::PreAssert {
                    withdrawal_fulfillment_txid: *withdrawal_fulfillment_txid,
                    pre_assert_txid: txid,
                }
            }
            Self::PreAssert {
                withdrawal_fulfillment_txid,
                pre_assert_txid: _,
            } => {
                *self = Self::AssertData {
                    withdrawal_fulfillment_txid: *withdrawal_fulfillment_txid,
                    assert_data_txids: vec![txid],
                }
            }

            Self::AssertData {
                withdrawal_fulfillment_txid: _,
                assert_data_txids,
            } => {
                assert_data_txids.push(txid);
                if assert_data_txids.len() == NUM_ASSERT_DATA_TX {
                    *self = Self::AssertDataComplete;
                }
            }

            Self::AssertDataComplete => *self = Self::PostAssert,

            Self::PostAssert => *self = Self::Executed,
            _ => {}
        }
    }

    pub fn should_pay(&self) -> bool {
        matches!(self, WithdrawalStatus::Received)
    }

    pub fn should_kickoff(&self) -> Option<Txid> {
        match self {
            WithdrawalStatus::PaidUser(txid) => Some(*txid),
            _ => None,
        }
    }

    pub fn should_claim(&self) -> Option<Txid> {
        match self {
            WithdrawalStatus::PaidUser(withdrawal_fulfillment_txid) => {
                Some(*withdrawal_fulfillment_txid)
            }
            _ => None,
        }
    }

    pub fn should_pre_assert(&self) -> Option<Txid> {
        match self {
            WithdrawalStatus::Claim {
                withdrawal_fulfillment_txid,
                claim_txid: _,
            } => Some(*withdrawal_fulfillment_txid),
            _ => None,
        }
    }

    pub fn should_assert_data(&self, assert_data_index: usize) -> Option<Txid> {
        match self {
            WithdrawalStatus::PreAssert {
                withdrawal_fulfillment_txid,
                pre_assert_txid: _,
            } => Some(*withdrawal_fulfillment_txid),
            WithdrawalStatus::AssertData {
                withdrawal_fulfillment_txid,
                assert_data_txids,
            } if assert_data_txids.len() < assert_data_index + 1
                && assert_data_txids.len() < NUM_ASSERT_DATA_TX =>
            {
                Some(*withdrawal_fulfillment_txid)
            }
            _ => None,
        }
    }

    pub fn should_post_assert(&self) -> bool {
        matches!(self, WithdrawalStatus::AssertDataComplete)
    }

    pub fn should_get_payout(&self) -> bool {
        matches!(self, WithdrawalStatus::PostAssert)
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Executed) || matches!(self, Self::Discarded(_))
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, Txid};

    use super::WithdrawalStatus;
    use crate::constants::NUM_ASSERT_DATA_TX;

    #[test]
    fn test_state_transition() {
        let txid = Txid::from_slice(&[1u8; 32]).expect("32-byte slice must be a valid txid");
        let mut status = WithdrawalStatus::Received;

        assert!(status.should_pay(), "should pay");
        status.next(txid); // broadcast bridge-out
        assert!(matches!(status, WithdrawalStatus::PaidUser(_)));

        assert!(status.should_claim().is_some(), "should claim");
        status.next(txid); // broadcast claim
        assert!(matches!(
            status,
            WithdrawalStatus::Claim {
                withdrawal_fulfillment_txid: _,
                claim_txid: _
            }
        ));

        assert!(status.should_pre_assert().is_some(), "should pre-assert");
        status.next(txid); // broadcast pre-assert
        assert!(matches!(
            status,
            WithdrawalStatus::PreAssert {
                withdrawal_fulfillment_txid: _,
                pre_assert_txid: _
            },
        ));

        for assert_data_index in 0..(NUM_ASSERT_DATA_TX - 1) {
            assert!(
                status.should_assert_data(assert_data_index).is_some(),
                "should assert data"
            );
            status.next(txid); // broadcast assert data
            assert!(matches!(
                status,
                WithdrawalStatus::AssertData {
                    withdrawal_fulfillment_txid: _,
                    assert_data_txids: _
                }
            ));
        }

        assert!(
            status.should_assert_data(NUM_ASSERT_DATA_TX - 1).is_some(),
            "should assert final data"
        );
        status.next(txid);

        assert!(status.should_post_assert(), "should post assert");
        status.next(txid); // broadcast post assert data
        assert!(matches!(status, WithdrawalStatus::PostAssert));

        assert!(status.should_get_payout(), "should get payout");
        status.next(txid); // publish payout tx
        assert!(matches!(status, WithdrawalStatus::Executed));
    }
}
