//! The duties that need to be performed in the Deposit State Machine in response to the state
//! transitions.

use bitcoin::{OutPoint, Transaction};
use musig2::{
    AggNonce,
    secp256k1::{Message, schnorr::Signature},
};

/// The duties that need to be performed to drive the Deposit State Machine forward.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DepositDuty {
    /// publish this operator's nonce for spending the drt
    PublishDepositNonce {
        /// DRT outpoint to ID the signing session
        deposit_out_point: OutPoint,
    },
    /// publish this operator's partial signature for spending the drt
    PublishDepositPartial {
        /// DRT outpoint to resume the earlier signing session
        deposit_out_point: OutPoint,
        /// sighash to be signed for the deposit transaction
        deposit_sighash: Message,
        /// aggregated nonce from all operators for this signing session
        deposit_agg_nonce: AggNonce,
    },
    /// publish the deposit transaction to the Bitcoin network
    PublishDeposit {
        /// fully constructed deposit transaction
        deposit_tx: Transaction,
        /// aggregate signature combining all partial signatures
        agg_signature: Signature,
    },
    /// TODO: (@mukeshdroid)
    FulfillWithdrawal,
    /// TODO: (@mukeshdroid)
    RequestPayoutNonces,
    /// TODO: (@mukeshdroid)
    PublishPayoutNonce,
    /// TODO: (@mukeshdroid)
    RequestPayoutPartials,
    /// TODO: (@mukeshdroid)
    PublishPayoutPartial,
    /// TODO: (@Rajil1213)
    PublishPayout,
}

impl std::fmt::Display for DepositDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let duty_str = match self {
            DepositDuty::PublishDepositNonce { .. } => "PublishDepositNonces",
            DepositDuty::PublishDepositPartial { .. } => "PublishDepositPartials",
            DepositDuty::PublishDeposit { .. } => "PublishDeposit",
            DepositDuty::FulfillWithdrawal => "FulfillWithdrawal",
            DepositDuty::RequestPayoutNonces => "RequestPayoutNonces",
            DepositDuty::PublishPayoutNonce => "PublishPayoutNonce",
            DepositDuty::RequestPayoutPartials => "RequestPayoutPartials",
            DepositDuty::PublishPayoutPartial => "PublishPayoutPartial",
            DepositDuty::PublishPayout => "PublishPayout",
        };
        write!(f, "{}", duty_str)
    }
}
