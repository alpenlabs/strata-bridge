use serde::{Deserialize, Serialize};

use crate::{deposit::DepositInfo, types::OperatorIdx, withdrawal::WithdrawalInfo};

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
    /// This duty is created when a user requests a withdrawal by calling a precompile in the EL
    /// and the [`crate::bridge_state::DepositState`] transitions to
    /// [`crate::bridge_state::DepositState::Dispatched`].
    ///
    /// This kicks off the withdrawal process which involves cooperative signing by the operator
    /// set, or a more involved unilateral withdrawal process (in the future) if not all operators
    /// cooperate in the process.
    FulfillWithdrawal(WithdrawalInfo),
}

impl From<DepositInfo> for BridgeDuty {
    fn from(value: DepositInfo) -> Self {
        Self::SignDeposit(value)
    }
}

impl From<WithdrawalInfo> for BridgeDuty {
    fn from(value: WithdrawalInfo) -> Self {
        Self::FulfillWithdrawal(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDuties {
    pub duties: Vec<BridgeDuty>,

    pub start_index: u64,

    pub stop_index: u64,
}

/// The various states a bridge duty may be in.
///
/// The full state transition looks as follows:
///
/// `Received` --|`CollectingNonces`|--> `CollectedNonces` --|`CollectingPartialSigs`|-->
/// `CollectedSignatures` --|`Broadcasting`|--> `Executed`.
///
/// The duty execution might fail as well at any step in which case the status would be `Failed`.
///
/// # Note
///
/// This type does not dictate the exact state transition path. A transition from `Received` to
/// `Executed` is perfectly valid to allow for maximum flexibility.
// TODO: use a typestate pattern with a `next` method that does the state transition. This can
// be left as is to allow for flexible level of granularity. For example, one could just have
// `Received`, `CollectedSignatures` and `Executed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeDutyStatus {
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

impl Default for BridgeDutyStatus {
    fn default() -> Self {
        Self::Received
    }
}

impl BridgeDutyStatus {
    /// Checks if the [`BridgeDutyStatus`] is in its final state.
    pub fn is_done(&self) -> bool {
        matches!(self, BridgeDutyStatus::Executed)
    }
}
