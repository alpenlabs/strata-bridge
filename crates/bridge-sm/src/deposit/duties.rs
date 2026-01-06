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
    /// Publish this operator's nonce for spending the drt
    PublishDepositNonce {
        /// DRT outpoint to ID the signing session
        deposit_out_point: OutPoint,
    },
    /// Publish this operator's partial signature for spending the drt
    PublishDepositPartial {
        /// DRT outpoint to resume the earlier signing session
        deposit_out_point: OutPoint,
        /// sighash to be signed for the deposit transaction
        deposit_sighash: Message,
        /// aggregated nonce from all operators for this signing session
        deposit_agg_nonce: AggNonce,
    },
    /// Publish the deposit transaction to the Bitcoin network
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
        let display_str = match self {
            DepositDuty::PublishDepositNonce {
                deposit_out_point,
            } => format!("PublishDepositNonce (outpoint: {})", deposit_out_point),
            DepositDuty::PublishDepositPartial {
                deposit_out_point,
                ..
            } => format!("PublishDepositPartial (outpoint: {})", deposit_out_point),
            DepositDuty::PublishDeposit {
                deposit_tx,
                ..
            } => format!("PublishDeposit (txid: {})", deposit_tx.compute_txid()),
            DepositDuty::FulfillWithdrawal => "FulfillWithdrawal".to_string(),
            DepositDuty::RequestPayoutNonces => "RequestPayoutNonces".to_string(),
            DepositDuty::PublishPayoutNonce => "PublishPayoutNonce".to_string(),
            DepositDuty::RequestPayoutPartials => "RequestPayoutPartials".to_string(),
            DepositDuty::PublishPayoutPartial => "PublishPayoutPartial".to_string(),
            DepositDuty::PublishPayout => "PublishPayout".to_string(),
        };
        write!(f, "{}", display_str)
    }
}
