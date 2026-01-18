//! The duties that need to be performed in the Deposit State Machine in response to the state
//! transitions.

use bitcoin::{OutPoint, TapSighash, Transaction};
use bitcoin_bosd::Descriptor;
use musig2::{AggNonce, secp256k1::schnorr::Signature};
use strata_bridge_primitives::types::{BitcoinBlockHeight, DepositIdx, OperatorIdx};

/// The duties that need to be performed to drive the Deposit State Machine forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositDuty {
    /// Publish this operator's nonce for spending the DRT.
    PublishDepositNonce {
        /// DRT outpoint to ID the signing session.
        deposit_request_outpoint: OutPoint,
    },
    /// Publish this operator's partial signature for spending the DRT.
    PublishDepositPartial {
        /// DRT outpoint to resume the earlier signing session.
        deposit_outpoint: OutPoint,
        /// Sighash to be signed for the deposit transaction.
        deposit_sighash: TapSighash,
        /// Aggregated nonce for the deposit transaction signing.
        deposit_agg_nonce: AggNonce,
    },
    /// Publish the deposit transaction to the Bitcoin network.
    PublishDeposit {
        /// The deposit transaction to publish.
        deposit_tx: Transaction,
        /// The aggregated signature for the deposit transaction.
        agg_signature: Signature,
    },
    /// Front the user by sending funds to the provided descriptor within the given deadline.
    FulfillWithdrawal {
        /// The index of the deposit.
        deposit_idx: DepositIdx,
        /// Block height deadline for fulfillment.
        deadline: BitcoinBlockHeight,
        /// The user's descriptor where funds are to be sent by the operator.
        recipient_desc: Descriptor,
    },
    /// Request pubnonces from all operators for cooperative payout.
    RequestPayoutNonces {
        /// The index of the deposit.
        deposit_idx: DepositIdx,
    },
    /// Publish the nonce for spending the deposit UTXO cooperatively.
    PublishPayoutNonce {
        /// Outpoint referencing the deposit UTXO.
        deposit_outpoint: OutPoint,
        /// The index of the operator requesting cooperation for payout.
        operator_idx: OperatorIdx,
        /// Descriptor of the operator to receive payout.
        operator_desc: Descriptor,
    },
    /// Publish the partial signature for spending the deposit UTXO cooperatively.
    PublishPayoutPartial {
        /// Outpoint referencing the deposit UTXO.
        deposit_outpoint: OutPoint,
        /// The index of the deposit.
        deposit_idx: DepositIdx,
        /// Aggregated nonce for the payout transaction signing.
        agg_nonce: AggNonce,
    },
    /// Publish the cooperative payout transaction to the Bitcoin network.
    PublishPayout {
        /// The cooperative payout transaction to publish.
        payout_tx: Transaction,
    },
}

impl std::fmt::Display for DepositDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let duty_str = match self {
            DepositDuty::PublishDepositNonce { .. } => "PublishDepositNonce",
            DepositDuty::PublishDepositPartial { .. } => "PublishDepositPartial",
            DepositDuty::PublishDeposit { .. } => "PublishDeposit",
            DepositDuty::FulfillWithdrawal { .. } => "FulfillWithdrawal",
            DepositDuty::RequestPayoutNonces { .. } => "RequestPayoutNonces",
            DepositDuty::PublishPayoutNonce { .. } => "PublishPayoutNonce",
            DepositDuty::PublishPayoutPartial { .. } => "PublishPayoutPartial",
            DepositDuty::PublishPayout { .. } => "PublishPayout",
        };
        write!(f, "{}", duty_str)
    }
}
