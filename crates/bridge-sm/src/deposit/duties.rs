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
        deposit_transaction: Transaction,
        /// aggregate signature combining all partial signatures
        agg_signature: Signature,
    },
    /// Fulfill the withdrawal for this deposit.
    FulfillWithdrawal {
        /// DRT outpoint to identify the withdrawal fulfillment context.
        deposit_out_point: OutPoint,
    },
    /// Request nonces for the payout signing session.
    RequestPayoutNonces {
        /// DRT outpoint to ID the signing session.
        deposit_out_point: OutPoint,
    },
    /// Publish this operator's nonce for the payout transaction.
    PublishPayoutNonce {
        /// DRT outpoint to ID the signing session.
        deposit_out_point: OutPoint,
    },
    /// Request partial signatures for the payout transaction.
    RequestPayoutPartials {
        /// DRT outpoint to resume the earlier signing session.
        deposit_out_point: OutPoint,
        /// sighash to be signed for the payout transaction.
        payout_sighash: Message,
        /// aggregated nonce from all operators for this signing session.
        payout_agg_nonce: AggNonce,
    },
    /// Publish this operator's partial signature for the payout transaction.
    PublishPayoutPartial {
        /// DRT outpoint to resume the earlier signing session.
        deposit_out_point: OutPoint,
        /// sighash to be signed for the payout transaction.
        payout_sighash: Message,
        /// aggregated nonce from all operators for this signing session.
        payout_agg_nonce: AggNonce,
    },
    /// Publish the payout transaction to the Bitcoin network.
    PublishPayout {
        /// fully constructed payout transaction.
        payout_transaction: Transaction,
        /// aggregate signature combining all partial signatures.
        agg_signature: Signature,
    },
}

impl std::fmt::Display for DepositDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_str = match self {
            DepositDuty::PublishDepositNonce { deposit_out_point } => {
                format!("PublishDepositNonce (outpoint: {})", deposit_out_point)
            }
            DepositDuty::PublishDepositPartial {
                deposit_out_point, ..
            } => format!("PublishDepositPartial (outpoint: {})", deposit_out_point),
            DepositDuty::PublishDeposit {
                deposit_transaction,
                ..
            } => {
                format!(
                    "PublishDeposit (txn: {})",
                    deposit_transaction.compute_txid()
                )
            }
            DepositDuty::FulfillWithdrawal { deposit_out_point } => {
                format!("FulfillWithdrawal (outpoint: {})", deposit_out_point)
            }
            DepositDuty::RequestPayoutNonces { deposit_out_point } => {
                format!("RequestPayoutNonces (outpoint: {})", deposit_out_point)
            }
            DepositDuty::PublishPayoutNonce { deposit_out_point } => {
                format!("PublishPayoutNonce (outpoint: {})", deposit_out_point)
            }
            DepositDuty::RequestPayoutPartials {
                deposit_out_point, ..
            } => format!("RequestPayoutPartials (outpoint: {})", deposit_out_point),
            DepositDuty::PublishPayoutPartial {
                deposit_out_point, ..
            } => format!("PublishPayoutPartial (outpoint: {})", deposit_out_point),
            DepositDuty::PublishPayout {
                payout_transaction, ..
            } => format!("PublishPayout ({:?})", payout_transaction),
        };
        write!(f, "{}", display_str)
    }
}
